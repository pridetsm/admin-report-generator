"""
Infrastructure Report Generator — the rendering engine (data model -> .xlsx).

Pure renderer, no Prometheus and no Django: build a ReportData tree and hand it to
build_report(). The live-data capture that assembles that tree lives in
webapp/reports/network.py (capture_infra_report/build_infrastructure_report), which is
how the webapp reaches this module — the same way it reaches generate_report.py, both
added to sys.path by webapp/config/settings.py's SEND_REPORT_DIR. The standalone CLI
twin is standalone/infrastructure admin report/report_generator.py (kept identical by
hand, same convention as generate_report.py's own standalone twin).

    python infrastructure_report.py data.json out.xlsx     # renders data.json as-is

Layout model
------------
* LEFT tables (Services, CPU/RAM) step one column right per nesting level
  (section -> cluster host -> node): the visual tree indent.
* RIGHT tables (Disk, Cluster Storage, Notes) sit at FIXED columns at every
  nesting level -- one consistent table spacing, so Used % / Fix needed? /
  Resolved / the title badge all line up straight down the page.
* The Notes table lands its Resolved column on the shared right edge,
  column AA (RIGHT_EDGE).
* Every RIGHT table sits a fixed gap column away from its neighbour, Notes
  included -- Notes is not itself a table, so nothing (Cluster Storage,
  Replication, NTP / Time Sync Status) is ever allowed to end flush against
  it (2026-09-11: "tables must be equidistance apart... must not touch any
  tables"). See NOTES_COL's own comment for the dedicated gap column this
  guarantees.
* "Cluster Storage" is rendered only for cluster hosts (a host that owns
  child nodes).
* GOLDEN RULE: MAX_COL stays at least 3 columns past RIGHT_EDGE, always kept
  in that relative position -- not a fixed absolute value -- so the "paint
  every unfilled cell BG" pass (see build_report) leaves a dark margin past
  the report's own right edge instead of raw white Excel starting flush
  against it. If RIGHT_EDGE ever moves again (it has, more than once), move
  MAX_COL the same amount to preserve the margin; don't leave it behind.

Groups written into the workbook
--------------------------------
* named range ``dashboard`` -> AT A GLANCE + NEEDS IMMEDIATE ATTENTION +
  NEEDS ATTENTION
* named range ``banners``   -> the CRITICAL / WARNING banner block
* named range ``RHS_Edge``  -> RIGHT_EDGE (column AA today; tracks the constant, not a
  hardcoded letter, since RIGHT_EDGE has shifted more than once)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.workbook.defined_name import DefinedName
from openpyxl.utils import get_column_letter
from openpyxl.drawing.image import Image as XLImage
from openpyxl.drawing.spreadsheet_drawing import AnchorMarker, OneCellAnchor
from openpyxl.drawing.xdr import XDRPositiveSize2D

# Same brand crest generate_report.py embeds in the System Admin Report's top-left corner --
# "same title designs" per direct instruction means this report gets it too, not just a text
# title. Lives in this same send_report/ folder (see generate_report.Config.logo's own
# default), so no new asset/config wiring is needed.
HERE = Path(__file__).resolve().parent
LOGO_PATH = HERE / "logo.png"


# ---------------------------------------------------------------------------
# Column plan  (1 = A).
#
# LEFT tables tree-indent one column right per nesting level (section ->
# cluster host -> node) -- the visual tree indent, kept from the reference.
# The RIGHT tables sit at FIXED columns; the block is positioned so that even
# at the deepest indent that carries a Disk table (a cluster host, indent 1)
# there is still a clear gap column between CPU/RAM and Disk -- column I is
# that guaranteed gap.  Beyond it, one fixed gap column between each table.
#
#   Services (2+i):(3+i) | gap | CPU/RAM (5+i):(7+i) | gap I | Disk K:O |
#   gap P | Cluster Storage / Replication / NTP Q:T (NTP alone spills to U) |
#   gap V, ALWAYS | Notes  flagged W:Y, Fix Z, Resolved AA
#
# The gap before Notes (V) is now fixed-width regardless of which table
# (Cluster Storage, Replication, NTP, or none) rendered before it (2026-09-11:
# "tables must be equidistance apart... must not touch any tables") -- the
# Notes right edge (Fix needed? / Resolved / the title badge) is always
# column AA.
# ---------------------------------------------------------------------------

def services_col(indent):   return 2 + indent           # B.., C.., D..  (name, status)
def cpuram_col(indent):     return 5 + indent           # E.., F.., G..  (node, cpu, ram)

# Disk (and everything after it) is FIXED -- it never shifts with indent, unlike Services/
# CPU-RAM above -- so it needs a gap column wide enough to survive the deepest indent actually
# used. 3 levels (Active Directory -> Root/Child Domain Controllers -> each DC) need a column
# reserved at J for that; see COL_WIDTHS' own comment for the full gap-consistency equations
# this and D/E/F/G/H/I below are solved together against.
DISK_COL = 11          # K  Host   (L Used %, M Size GB, N Mount, O Free GB)
DISK_LAST = 15         # O
#                       # P  gap
# Q  Pool (R Used %, S Size GB, T Free GB) -- Cluster Storage/Replication's own 4 columns.
# NTP / Time Sync Status (write_ntp_sync) uses one column further, Q-U, its 5th field
# spilling into what would otherwise be the U gap here; that table gets its OWN dedicated
# gap after it (V, below) instead, rather than ending flush against Notes.
CLUSTER_COL = 17       # Q
CLUSTER_LAST = 20      # T
#                       # U  gap for Cluster Storage/Replication -- NTP's own 5th column
#                       #    when NTP is the table actually rendering on that row instead
#                       # V  gap, ALWAYS, regardless of which table (Cluster Storage,
#                       #    Replication, or NTP) is rendering -- tables must sit an equal
#                       #    distance apart and Notes is not a table, so nothing may ever end
#                       #    flush against it (2026-09-11, on request: "tables must be
#                       #    equidistance apart notes section is not a table and must not
#                       #    touch any tables"). Same width as every other gap column here
#                       #    (P, U) -- see COL_WIDTHS.
NOTES_COL = 23         # W  Flagged metric  (merged W:Y), Z Fix needed?, AA Resolved
NOTES_FLAG_LAST = 25   # Y
FIX_COL = 26           # Z
RIGHT_EDGE = 27        # AA  Resolved  ==  shared right edge

DASH_LEFT = 2          # B   dashboard tiles / banners left edge
# I, not J: matches the System Admin Report's own AT A GLANCE/banner width (its B:L span
# totals ~132 width units) as closely as a whole-column boundary allows on this report's own,
# individually wider columns (~173 at I) -- S stretched the band out to ~206, nearly the full
# row width, which read as disproportionately long/distracting next to the System report's
# much narrower one. Can't pull this in any further: attention_panel's own tiles (4 per row)
# each need at least 2 columns for their own label/total sub-split (_frac_tile), so anything
# under 8 columns (B:I) raises a merge-range error -- confirmed live. D/E widened for the
# gap-consistency equations below pushed the natural nearest-match boundary from F (~132, but
# only 5 columns -- too narrow for 4 tiles) out to I.
DASH_RIGHT = 9         # I   dashboard tiles / banners right edge
NOTES_CARD_RIGHT = RIGHT_EDGE

# GOLDEN RULE, enforced structurally (see this module's own docstring): MAX_COL is always
# RIGHT_EDGE + 3, never a standalone literal -- the "paint every unfilled cell BG" pass below
# only reaches MAX_COL, so content ending flush at RIGHT_EDGE would otherwise show raw white
# Excel immediately past it with no margin. Deriving it from RIGHT_EDGE means the next time
# RIGHT_EDGE moves (it has, more than once), this margin moves with it automatically instead
# of quietly going stale.
MAX_COL = RIGHT_EDGE + 3   # 3 dark margin columns past the report's own right edge
MAX_ROW = 260

TITLE_WIDTH = 6

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

BG = "FF0E1620"
CARD = "FF121E2B"
TABLE_HEADER_BG = "FF1B2836"
TEXT_PRIMARY = "FFE7EEF5"
TEXT_SECONDARY = "FFAFBBC7"
TEXT_MUTED = "FF7F93A6"
ACCENT = "FF5BC0D4"

CHIP_GREEN_BG, CHIP_GREEN_TXT = "FF14322B", "FF4CC9A4"
CHIP_AMBER_BG, CHIP_AMBER_TXT = "FF3A2F14", "FFE8B04B"
CHIP_RED_BG, CHIP_RED_TXT = "FF3A1A16", "FFEF6A5A"

# nesting cues -- neutral, on-theme.  Section title brightness AND size step down per
# nesting level (color alone read as too subtle a cue once a 3rd level -- Active Directory >
# Root/Child Domain Controllers > each DC -- put same-size titles at three different depths
# with nothing else to tell them apart at a glance); a spine in the gutter column brackets a
# host with its nodes. Floor stays comfortably above the sz=9 bold panel titles (Services,
# CPU · RAM, ...) a section's own tables use, so even the deepest title still reads as a
# section header, not just another panel inside it.
NEST_TITLE = {0: ACCENT, 1: "FF6F9DB0", 2: "FF5E7686"}
NEST_TITLE_SIZE = {0: 13, 1: 11, 2: 10}
SPINE = {0: "FF17242E", 1: "FF243B4E"}


def title_color(indent: int) -> str:
    return NEST_TITLE.get(indent, NEST_TITLE[max(NEST_TITLE)])


def title_size(indent: int) -> float:
    return NEST_TITLE_SIZE.get(indent, NEST_TITLE_SIZE[max(NEST_TITLE_SIZE)])


def spine_color(indent: int) -> str:
    return SPINE.get(indent, SPINE[max(SPINE)])

TONE_BG = {"green": CHIP_GREEN_BG, "amber": CHIP_AMBER_BG, "red": CHIP_RED_BG}
TONE_TXT = {"green": CHIP_GREEN_TXT, "amber": CHIP_AMBER_TXT, "red": CHIP_RED_TXT}

FONT_NAME = "Times New Roman"

SUBTITLE_DASHBOARD = "Infrastructure Analyses Dashboard"
ROW3_TEXT = ("Static snapshot. Device telemetry captured via host agents and "
             "hypervisor API.   For LIVE, auto-refreshing monitoring, click  →")
LIVE_LINK = "▸  OPEN LIVE INFRASTRUCTURE DASHBOARD"
FOOTER_LINES = [
    ("chip key:  green under 75%   ·   amber 75-90%   ·   red 90% and over"
     "      |      device status UP / DOWN      |      live from host agents / "
     "hypervisor API"),
    ("hosts:  AD-ROOT/AD-CHILD = Active Directory domain controller (forest root "
     "/ child domain)   ·   PC-HOST = private cloud host, each running its own "
     "independent cluster (HCI or otherwise)   ·   DB = standalone database "
     "host   ·   CPU/RAM/Disk are tracked on every host"),
    ("Network devices (routers, switches, links) are tracked in the separate "
     "Network Infrastructure Report, not here."),
]
SENTINEL_NOTE = "No critical or warning metrics this run."


def chip_colors(pct: float) -> tuple[str, str]:
    # A real percentage can never fall outside [0, 100] -- anything that does (e.g. a
    # negative CPU reading from a textfile counter that isn't actually monotonic, so rate()
    # goes negative) is bad DATA, not a low reading. Falling through to the plain `< 75 ->
    # green` case would then render it as the single most reassuring color available, exactly
    # backwards from what it means. Band it amber instead -- "look at this", not "all clear".
    if pct < 0 or pct > 100:
        return CHIP_AMBER_BG, CHIP_AMBER_TXT
    if pct >= 90:
        return CHIP_RED_BG, CHIP_RED_TXT
    if pct >= 75:
        return CHIP_AMBER_BG, CHIP_AMBER_TXT
    return CHIP_GREEN_BG, CHIP_GREEN_TXT


def badge_tone(critical: int, warning: int) -> str:
    if critical > 0:
        return "red"
    if warning > 0:
        return "amber"
    return "green"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ServiceRow:
    name: str
    status: str = "RUNNING"


@dataclass
class CpuRam:
    node: str
    cpu_pct: float
    ram_pct: float
    ram_size: Optional[str] = None


@dataclass
class DiskRow:
    host: str
    used_pct: float
    size_gb: int
    mount: str = "C:"

    @property
    def free_gb(self) -> int:
        return round(self.size_gb * (1 - self.used_pct / 100))


@dataclass
class ClusterStorageRow:
    pool: str
    used_pct: float
    size_gb: int

    @property
    def free_gb(self) -> int:
        return round(self.size_gb * (1 - self.used_pct / 100))


@dataclass
class ReplicationRow:
    """AD replication health with one partner, rolled up across every partition that partner
    replicates (see network.py's own _ad_replication_rows docstring for why partition-level
    detail is collapsed rather than shown as separate rows). Reuses ClusterStorageRow's own
    column slot (see write_replication) rather than a new column block -- a device group is
    never both a cluster host AND a domain controller, so the two tables never need to coexist
    on the same row."""
    partner: str
    status: str = "OK"       # "OK" or "FAILED" -- decided by the capture layer (network.py),
                              # same split as CpuRam.ram_size/DiskRow.free_gb: formatting logic
                              # stays out of the renderer.
    last_success: str = ""   # pre-formatted relative time, e.g. "14m ago" / "never"
    failures: int = 0


@dataclass
class NtpSyncRow:
    """One domain controller's own w32time sync state (2026-09-11, on request, scoped to
    RBZHQ-ROOT-01 only -- the forest's primary time source). Reuses ReplicationRow/
    ClusterStorageRow's own column slot, same reasoning: this device is never also a cluster
    host, and Root DCs (no `ad` collector enabled -- see network.py's own confirmation) never
    carry a Replication table either, so there is no real host where two of these three tables
    would ever need to coexist on the same row. Five columns, one wider than Cluster Storage/
    Replication's own four -- write_ntp_sync borrows the single gap column normally left before
    Notes to fit `dc` as its own column (rather than folding it into the section title), since
    that gap is unused on the one row this table ever actually renders on.
    band/age_band are pre-computed by the capture layer (network.py), same split as
    ReplicationRow.status -- thresholds are a policy decision, not a rendering one."""
    dc: str
    stratum: int
    stratum_band: str          # "green" (<=3) / "amber" (>3) / "red" (==16, unsynced)
    source: str
    last_sync: str             # pre-formatted datetime, Africa/Harare local (UTC+2, no DST),
                                # e.g. "11 Sep 2026, 14:32:05" -- the raw metric is UTC; the
                                # capture layer (network.py) converts before this ever renders
    sync_age: str              # pre-formatted "Xh Ym"
    sync_age_band: str         # "green" (<=300s) / "amber" (<=900s) / "red" (>900s)


@dataclass
class NoteRow:
    flagged_metric: str
    fix_needed: str = ""
    resolved: str = ""
    comment: str = ""
    # This row's OWN severity ("red"/"amber"/"" for informational) -- 2026-09-04, on request:
    # "by system admin report convention comments are never red". A group-level "is this
    # group critical at all" check coloured EVERY row in a group red the moment ANY of its
    # flags was critical, including a purely informational row (e.g. "Cluster's own view of
    # node membership") that isn't itself describing a problem. Matches the Systems Admin
    # Report's own generate_report.py convention: a flagged row is coloured by ITS OWN
    # flag.band, never by another row's.
    band: str = ""


@dataclass
class DeviceGroup:
    title: str
    services: list[ServiceRow] = field(default_factory=list)
    cpu_ram: list[CpuRam] = field(default_factory=list)
    disks: list[DiskRow] = field(default_factory=list)
    cluster_storage: list[ClusterStorageRow] = field(default_factory=list)
    replication: list[ReplicationRow] = field(default_factory=list)
    ntp_sync: list[NtpSyncRow] = field(default_factory=list)
    notes: list[NoteRow] = field(default_factory=list)
    critical: int = 0
    warning: int = 0
    count: int = 0
    count_label: str = "devices"
    signed_by: str = "Pride Moyo"
    children: list["DeviceGroup"] = field(default_factory=list)

    @property
    def is_cluster_host(self) -> bool:
        return bool(self.children) and bool(self.cpu_ram or self.disks)


@dataclass
class SummaryMetric:
    label: str
    value: Union[str, int]
    sublabel: str = ""
    tone: str = "green"


@dataclass
class SummaryNote:
    group: str
    comment: str


@dataclass
class BannerRow:
    label: str
    detail: str


@dataclass
class Banner:
    severity: str
    title: str
    subtitle: str
    rows: list[BannerRow] = field(default_factory=list)
    note: str = ""

    @property
    def tone(self) -> str:
        return "red" if self.severity.upper() == "CRITICAL" else "amber"

    @property
    def heading(self) -> str:
        return f"{self.severity} — {self.title} — {self.subtitle}"


@dataclass
class ReportData:
    generated_at: str
    nodes_total: int
    cluster_count: int
    cluster_nodes: int
    cluster_resources_total: int
    last_checked: str
    needs_attention: list[SummaryMetric]
    watch_list: list[SummaryMetric]
    summary_notes: list[SummaryNote]
    groups: list[DeviceGroup]
    banners: list[Banner] = field(default_factory=list)
    summary_signed_by: str = "Pride Moyo"
    components_total: int = 0
    # Masthead title + sheet-tab name (2026-09-11: Active Directory split into its own report,
    # reusing this same renderer -- see network.build_infrastructure_report's own caller).
    # Defaulted to the original literal so every existing caller (the combined Infrastructure
    # Report, the standalone CLI twin) keeps reading "INFRASTRUCTURE ADMIN REPORT" unchanged.
    report_title: str = "INFRASTRUCTURE ADMIN REPORT"


# ---------------------------------------------------------------------------
# Sheet helper
# ---------------------------------------------------------------------------

class Sheet:
    def __init__(self, ws):
        self.ws = ws

    def put(self, row, col, value=None, *, sz=8.0, bold=False, italic=False,
            color=TEXT_PRIMARY, bg=None, halign=None, valign="center",
            wrap=False):
        cell = self.ws.cell(row=row, column=col)
        if value is not None:
            cell.value = value
        cell.font = Font(name=FONT_NAME, size=sz, bold=bold, italic=italic,
                         color=color)
        if bg:
            cell.fill = PatternFill(fill_type="solid", fgColor=bg)
        if halign or wrap or valign != "center":
            cell.alignment = Alignment(horizontal=halign, vertical=valign,
                                       wrap_text=wrap)

    def merge(self, r1, c1, r2, c2, bg=None):
        self.ws.merge_cells(start_row=r1, start_column=c1, end_row=r2,
                            end_column=c2)
        if bg:
            self.ws.cell(row=r1, column=c1).fill = PatternFill(
                fill_type="solid", fgColor=bg)

    def fill(self, r1, c1, r2, c2, color):
        for r in range(r1, r2 + 1):
            for c in range(c1, c2 + 1):
                self.ws.cell(row=r, column=c).fill = PatternFill(
                    fill_type="solid", fgColor=color)

    def rowh(self, row, height):
        self.ws.row_dimensions[row].height = height

    def spine(self, r1, r2, color, col=1):
        """Paint the gutter column for a nesting bracket, without overwriting a
        deeper (already-painted) child bracket."""
        for r in range(r1, r2 + 1):
            cell = self.ws.cell(row=r, column=col)
            rgb = cell.fill.fgColor.rgb if cell.fill and cell.fill.fill_type else None
            if rgb in (None, "00000000", BG):
                cell.fill = PatternFill(fill_type="solid", fgColor=color)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def write_header(sh: Sheet, data: ReportData) -> None:
    # company crest, top-left -- same brand mark and anchor/size generate_report.py uses,
    # shifted up 2 rows to line up with this report's title on row 1 (not row 3). Row 4's
    # height below is padded to give the full-size logo the same vertical room generate_report
    # gives it across its own 4 header rows, so nothing gets visually clipped.
    try:
        img = XLImage(str(LOGO_PATH))
        marker = AnchorMarker(col=1, colOff=448946, row=0, rowOff=95250)
        img.anchor = OneCellAnchor(_from=marker, ext=XDRPositiveSize2D(cx=503554, cy=990599))
        sh.ws.add_image(img)
    except Exception as exc:                      # missing/unreadable logo -> carry on
        print(f"[!] logo not embedded ({exc})", file=sys.stderr)
    sh.put(1, 3, data.report_title, sz=22, bold=True, color=TEXT_PRIMARY,
           bg=BG, halign="left")
    sh.rowh(1, 26.25)
    sh.put(2, 3, f"snapshot generated {data.generated_at}      •      "
                 f"{SUBTITLE_DASHBOARD}", sz=9, color=TEXT_MUTED, bg=BG,
           halign="left")
    # Text and button live in SEPARATE merged column ranges (not just adjacent single cells)
    # so a long text value can never visually run into the button, matching how
    # generate_report.py's own row-5 text (cols 3-8) and button (cols 9-13) are structured.
    sh.merge(3, 3, 3, 8, bg=BG)
    sh.put(3, 3, ROW3_TEXT, sz=9, color=TEXT_SECONDARY, bg=BG, halign="left")
    # 12pt, matching generate_report.py's own live-dashboard button exactly (was 10pt) --
    # no hyperlink target wired here: unlike generate_report.py's cfg.grafana (a real,
    # configured URL), no live Infrastructure dashboard URL exists in ReportData to link to
    # yet, and inventing one would be exactly the kind of fabrication this module's own
    # docstring says not to do.
    sh.merge(3, 9, 3, 14, bg=BG)
    sh.put(3, 9, LIVE_LINK, sz=12, bold=True, color=ACCENT, bg=BG, halign="left")
    for r in (2, 3):
        sh.rowh(r, 15.0)
    sh.rowh(4, 30.0)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def _split_cols(left, right, n):
    """Divide [left, right] into n contiguous column spans; any extra width
    goes to the rightmost spans."""
    total = right - left + 1
    base, extra = divmod(total, n)
    spans, c = [], left
    for i in range(n):
        w = base + (1 if i >= n - extra else 0)
        spans.append((c, c + w - 1))
        c += w
    return spans


# The dashboard + banner sections copy the System Admin Report's visual
# treatment: a compact 2-row AT A GLANCE band, "count / total" fraction tiles
# for the two attention panels, and full-bleed severity-tinted banner blocks.

def _parse_total(sublabel: str) -> tuple[str, str]:
    """'down | 10 total' -> ('DOWN', '10');  'nodes | 10 total' -> ('NODES','10')."""
    left, sep, right = sublabel.partition("|")
    unit = left.strip().upper() if sep else ""
    toks = right.strip().split()
    return unit, (toks[0] if toks else "")


def _glance_tile(sh, row, c1, c2, label, value):
    # Thick accent-coloured left border, same divider generate_report.py's own card()/panel()
    # use between adjacent AT A GLANCE tiles -- without it, every tile here shares the same
    # background (TABLE_HEADER_BG) with no state colour to tell them apart by, so the whole
    # band reads as one undifferentiated block instead of six distinct readings.
    bar = Border(left=Side(style="thick", color=ACCENT))
    sh.merge(row, c1, row, c2, bg=TABLE_HEADER_BG)
    sh.put(row, c1, label, sz=8, bold=True, color=TEXT_MUTED, bg=TABLE_HEADER_BG,
           halign="center")
    sh.merge(row + 1, c1, row + 1, c2, bg=TABLE_HEADER_BG)
    sh.put(row + 1, c1, value, sz=22, bold=True, color=ACCENT, bg=TABLE_HEADER_BG,
           halign="center")
    for r in (row, row + 1):
        sh.ws.cell(r, c1).border = bar


def _frac_tile(sh, lbl_row, c1, c2, label, sub_l, sub_r, val_l, val_r, tint,
               val_txt):
    # Thick accent-coloured left border on the tile's own first column, matching
    # generate_report.py's card()/panel() -- this IS the "gap" between adjacent tiles: two
    # differently-tinted tiles sitting flush against each other read as separated because of
    # this bar, not because of an actual blank spacer column.
    bar = Border(left=Side(style="thick", color=val_txt))
    div = Border(left=Side(style="thin", color=TEXT_MUTED))   # divider between sub-columns
    mid = (c1 + c2) // 2
    sh.merge(lbl_row, c1, lbl_row, c2, bg=tint)
    sh.put(lbl_row, c1, label, sz=8, bold=True, color=TEXT_MUTED, bg=tint,
           halign="center")
    for i, (a, b, sv, vv) in enumerate(((c1, mid, sub_l, val_l), (mid + 1, c2, sub_r, val_r))):
        sh.merge(lbl_row + 1, a, lbl_row + 1, b, bg=tint)
        sh.put(lbl_row + 1, a, sv, sz=8, bold=True, color=TEXT_MUTED, bg=tint,
               halign="center")
        sh.merge(lbl_row + 2, a, lbl_row + 2, b, bg=tint)
        sh.put(lbl_row + 2, a, vv, sz=22, bold=True, color=val_txt, bg=tint,
               halign="center")
        if i:
            sh.ws.cell(lbl_row + 1, a).border = div
            sh.ws.cell(lbl_row + 2, a).border = div
    for r in range(lbl_row, lbl_row + 3):
        sh.ws.cell(r, c1).border = bar


def write_dashboard(sh: Sheet, data: ReportData) -> tuple[int, int, int, int]:
    sh.put(5, 2, "Summary", sz=13, bold=True, color=ACCENT, bg=BG, halign="left")
    sh.rowh(5, 18.0)
    sh.put(6, 2, "  AT A GLANCE  ·  inventory & readings", sz=8, bold=True,
           color=TEXT_MUTED, bg=BG, halign="left")
    sh.rowh(6, 14.0)

    glance = [
        ("DEVICES", data.nodes_total),
        ("COMPONENTS", data.components_total),
        ("CLUSTER COUNT", data.cluster_count),
        ("CLUSTER NODES", data.cluster_nodes),
        ("CLUSTER RESOURCES", data.cluster_resources_total),
        ("LAST CHECKED", data.last_checked),
    ]
    for (c1, c2), (label, value) in zip(
            _split_cols(DASH_LEFT, DASH_RIGHT, len(glance)), glance):
        _glance_tile(sh, 7, c1, c2, label, value)
    sh.rowh(8, 30.0)

    def attention_panel(hdr_row, title, metrics, tone_of):
        sh.put(hdr_row, 2, f"  {title}", sz=8, bold=True, color=TEXT_MUTED, bg=BG,
               halign="left")
        sh.rowh(hdr_row, 14.0)
        for (c1, c2), m in zip(_split_cols(DASH_LEFT, DASH_RIGHT, len(metrics)),
                               metrics):
            unit, total = _parse_total(m.sublabel)
            tone = tone_of(m)
            _frac_tile(sh, hdr_row + 1, c1, c2, m.label, unit or "COUNT", "TOTAL",
                       str(m.value), total, TONE_BG[tone], TONE_TXT[tone])
        sh.rowh(hdr_row + 3, 30.0)

    def _nii_tone(m):
        try:
            return "green" if int(str(m.value).split()[0]) == 0 else "red"
        except ValueError:
            return "green"

    attention_panel(9, "NEEDS IMMEDIATE ATTENTION", data.needs_attention,
                    _nii_tone)
    attention_panel(13, "NEEDS ATTENTION", data.watch_list,
                    lambda m: m.tone)

    watch_end = 16
    sh.rowh(17, 8.0)

    # ----- banners (System Admin Report style: consecutive, full-bleed) ---
    r = 18
    banner_start = r
    for banner in data.banners:
        tint = TONE_BG[banner.tone]
        head_txt = TONE_TXT[banner.tone]
        sh.merge(r, DASH_LEFT, r, DASH_RIGHT, bg=tint)
        sh.put(r, DASH_LEFT,
               f"  {banner.severity}  —  {banner.title}  —  {banner.subtitle}",
               sz=10, bold=True, color=head_txt, bg=tint, halign="left",
               valign="top", wrap=True)
        sh.rowh(r, 20.0)
        r += 1
        for br in banner.rows:
            sh.merge(r, DASH_LEFT, r, DASH_LEFT + 3, bg=tint)
            sh.put(r, DASH_LEFT, f"  {br.label}", sz=9, bold=True,
                   color=TEXT_PRIMARY, bg=tint, halign="left", valign="top",
                   wrap=True)
            sh.merge(r, DASH_LEFT + 4, r, DASH_RIGHT, bg=tint)
            sh.put(r, DASH_LEFT + 4, br.detail, sz=9, color=TEXT_SECONDARY,
                   bg=tint, halign="left", valign="top", wrap=True)
            sh.rowh(r, 18.0)
            r += 1
        sh.merge(r, DASH_LEFT, r, DASH_RIGHT, bg=tint)
        sh.put(r, DASH_LEFT, f"  {banner.note}", sz=8, color=TEXT_MUTED, bg=tint,
               halign="left", valign="top", wrap=True)
        sh.rowh(r, 34.0)
        r += 1
    banner_end = (r - 1) if data.banners else watch_end
    left_end = banner_end

    # ----- Summary Notes panel (right) -----------------------------------
    nc = NOTES_COL
    notes = data.summary_notes
    by_row = max(left_end, 8 + 3 * max(1, len(notes))) + 1

    sh.merge(7, nc, 7, RIGHT_EDGE, bg=CARD)
    sh.put(7, nc, "Summary Notes", sz=9, bold=True, color=ACCENT, bg=CARD,
           halign="left")

    sh.put(8, nc, "#", sz=8, bold=True, color=TEXT_SECONDARY, bg=TABLE_HEADER_BG,
           halign="center")
    sh.merge(8, nc + 1, 8, nc + 2, bg=TABLE_HEADER_BG)
    sh.put(8, nc + 1, "Group", sz=8, bold=True, color=TEXT_SECONDARY,
           bg=TABLE_HEADER_BG, halign="left")
    sh.merge(8, nc + 3, 8, RIGHT_EDGE, bg=TABLE_HEADER_BG)
    sh.put(8, nc + 3, "Comment", sz=8, bold=True, color=TEXT_SECONDARY,
           bg=TABLE_HEADER_BG, halign="left")

    sh.fill(9, nc, by_row, RIGHT_EDGE, CARD)
    if notes:
        spans = _split_cols(9, by_row - 1, len(notes))
        for i, (nt, (r1, r2)) in enumerate(zip(notes, spans), start=1):
            sh.merge(r1, nc, r2, nc, bg=CARD)
            sh.put(r1, nc, str(i), sz=9, color=TEXT_PRIMARY, bg=CARD,
                   halign="center", valign="top")
            sh.merge(r1, nc + 1, r2, nc + 2, bg=CARD)
            sh.put(r1, nc + 1, nt.group, sz=9, color=TEXT_PRIMARY, bg=CARD,
                   halign="left", valign="top", wrap=True)
            sh.merge(r1, nc + 3, r2, RIGHT_EDGE, bg=CARD)
            sh.put(r1, nc + 3, nt.comment, sz=9, color=TEXT_MUTED, bg=CARD,
                   halign="left", valign="top", wrap=True)

    sh.put(by_row, nc, "By  ", sz=8, color=TEXT_MUTED, bg=CARD, halign="right")
    sh.merge(by_row, nc + 1, by_row, RIGHT_EDGE, bg=CARD)
    sh.put(by_row, nc + 1, data.summary_signed_by, sz=9, color=TEXT_PRIMARY,
           bg=CARD, halign="left")

    return by_row + 2, watch_end, banner_start, banner_end


# ---------------------------------------------------------------------------
# Device section
# ---------------------------------------------------------------------------

def _notes_title(title: str, indent: int) -> str:
    if indent == 1 and "(" in title and ")" in title:
        return title[title.index("(") + 1:title.index(")")] + " Notes"
    if indent >= 2:
        return title + " Notes"
    return title.split(" (")[0] + " Notes"


def _flagged_style(note: "NoteRow") -> tuple[str, bool]:
    """Per-ROW, not per-group (2026-09-04: "comments are never red" -- a group merely
    CONTAINING a critical flag must not turn every other, unrelated row in it red too)."""
    if note.flagged_metric.strip() == SENTINEL_NOTE:
        return TEXT_MUTED, True
    if note.band == "red":
        return CHIP_RED_TXT, False
    if note.band == "amber":
        return CHIP_AMBER_TXT, False
    return TEXT_MUTED, False


def write_title_bar(sh: Sheet, row: int, indent: int, group: DeviceGroup) -> None:
    left = services_col(indent)
    sh.fill(row, left, row, RIGHT_EDGE, CARD)
    sh.merge(row, left, row, left + TITLE_WIDTH - 1, bg=CARD)
    sh.put(row, left, f"▌  {group.title}", sz=title_size(indent), bold=True,
           color=title_color(indent), bg=CARD, halign="left")
    badge_col = left + TITLE_WIDTH + 1
    tone = badge_tone(group.critical, group.warning)
    sh.merge(row, badge_col, row, RIGHT_EDGE, bg=CARD)
    sh.put(row, badge_col,
           f"{group.critical} critical  ·  {group.warning} warning  ·  "
           f"{group.count} {group.count_label}",
           sz=9, color=TONE_TXT[tone], bg=CARD, halign="right")
    sh.rowh(row, 15.75)


def write_services(sh, top, scol, group) -> int:
    sh.merge(top, scol, top, scol + 1, bg=CARD)
    sh.put(top, scol, "Services", sz=9, bold=True, color=ACCENT, bg=CARD,
           halign="left")
    r = top + 2
    sh.put(r, scol, "  SYSTEM SERVICES", sz=8, bold=True, color=TEXT_MUTED,
           bg=CARD, halign="left")
    r += 1
    grouped = len(group.cpu_ram) > 1
    hosts = [cr.node for cr in group.cpu_ram] if grouped else [None]
    chips = []          # (row, status) for every service row -- re-stamped after the fill below
    for host in hosts:
        if host is not None:
            sh.put(r, scol, f"    {host}", sz=8, italic=True, color=TEXT_MUTED,
                   bg=CARD, halign="left")
            r += 1
        for svc in group.services:
            sh.put(r, scol, svc.name, sz=8.5, color=TEXT_PRIMARY, bg=CARD,
                   halign="left")
            chips.append((r, svc.status))
            r += 1
    end = r - 1
    # fill() repaints the whole card CARD-colored, which would wipe out any chip background
    # set inside the loop above -- stamp status chips in a second pass, after the fill, not
    # before it.
    sh.fill(top, scol, end, scol + 1, CARD)
    sh.put(top + 1, scol, "Service Name", sz=8, bold=True, color=TEXT_SECONDARY,
           bg=TABLE_HEADER_BG, halign="left")
    sh.put(top + 1, scol + 1, "Status", sz=8, bold=True, color=TEXT_SECONDARY,
           bg=TABLE_HEADER_BG, halign="left")
    for row, status in chips:
        sbg, stxt = ((CHIP_GREEN_BG, CHIP_GREEN_TXT) if status.upper() == "RUNNING"
                    else (CHIP_RED_BG, CHIP_RED_TXT))
        sh.put(row, scol + 1, status, sz=8, bold=True, color=stxt, bg=sbg,
               halign="center")
    return end


def write_cpu_ram(sh, top, ccol, rows) -> int:
    sh.merge(top, ccol, top, ccol + 2, bg=CARD)
    sh.put(top, ccol, "CPU · RAM", sz=9, bold=True, color=ACCENT, bg=CARD,
           halign="left")
    for j, lab in enumerate(("Node", "CPU", "RAM")):
        sh.put(top + 1, ccol + j, lab, sz=8, bold=True, color=TEXT_SECONDARY,
               bg=TABLE_HEADER_BG, halign="left")
    r = top + 2
    for cr in rows:
        cbg, ctxt = chip_colors(cr.cpu_pct)
        rbg, rtxt = chip_colors(cr.ram_pct)
        ram = (f"{cr.ram_pct:.0f}% · {cr.ram_size}" if cr.ram_size
               else f"{cr.ram_pct:.0f}%")
        sh.put(r, ccol, cr.node, sz=8.5, color=TEXT_SECONDARY, bg=CARD,
               halign="left")
        sh.put(r, ccol + 1, f"{cr.cpu_pct:.0f}%", sz=8, bold=True, color=ctxt,
               bg=cbg, halign="center")
        sh.put(r, ccol + 2, ram, sz=8, bold=True, color=rtxt, bg=rbg,
               halign="center")
        r += 1
    return r - 1


def _fixed_table(sh, top, col, last, title, headers):
    sh.merge(top, col, top, last, bg=CARD)
    sh.put(top, col, title, sz=9, bold=True, color=ACCENT, bg=CARD, halign="left")
    for j, lab in enumerate(headers):
        sh.put(top + 1, col + j, lab, sz=8, bold=True, color=TEXT_SECONDARY,
               bg=TABLE_HEADER_BG, halign="left")


def write_disk(sh, top, rows) -> int:
    _fixed_table(sh, top, DISK_COL, DISK_LAST, "Disk",
                 ("Host", "Used %", "Size GB", "Mount", "Free GB"))
    r = top + 2
    for d in sorted(rows, key=lambda x: x.host):
        ubg, utxt = chip_colors(d.used_pct)
        sh.put(r, DISK_COL, d.host, sz=8.5, color=TEXT_SECONDARY, bg=CARD,
               halign="left")
        sh.put(r, DISK_COL + 1, f"{d.used_pct:.0f}%", sz=8, bold=True, color=utxt,
               bg=ubg, halign="center")
        sh.put(r, DISK_COL + 2, d.size_gb, sz=8.5, color=TEXT_SECONDARY, bg=CARD,
               halign="center")
        sh.put(r, DISK_COL + 3, d.mount, sz=8.5, color=TEXT_SECONDARY, bg=CARD,
               halign="left")
        sh.put(r, DISK_COL + 4, d.free_gb, sz=8.5, color=TEXT_SECONDARY, bg=CARD,
               halign="center")
        r += 1
    return r - 1


def write_cluster_storage(sh, top, rows) -> int:
    _fixed_table(sh, top, CLUSTER_COL, CLUSTER_LAST, "Cluster Storage",
                 ("Pool", "Used %", "Size GB", "Free GB"))
    r = top + 2
    for s in rows:
        ubg, utxt = chip_colors(s.used_pct)
        sh.put(r, CLUSTER_COL, s.pool, sz=8.5, color=TEXT_SECONDARY, bg=CARD,
               halign="left")
        sh.put(r, CLUSTER_COL + 1, f"{s.used_pct:.0f}%", sz=8, bold=True,
               color=utxt, bg=ubg, halign="center")
        sh.put(r, CLUSTER_COL + 2, s.size_gb, sz=8.5, color=TEXT_SECONDARY,
               bg=CARD, halign="center")
        sh.put(r, CLUSTER_COL + 3, s.free_gb, sz=8.5, color=TEXT_SECONDARY,
               bg=CARD, halign="center")
        r += 1
    return r - 1


def write_replication(sh, top, rows) -> int:
    """AD replication, at CLUSTER_COL -- the same 4-column slot write_cluster_storage uses
    (Pool/Used%/Size GB/Free GB there vs. Partner/Status/Last Success/Failures here). Never
    drawn for the same group as Cluster Storage (a domain controller is never also a cluster
    host), so there is no real collision to design around -- reusing the slot avoids adding a
    whole new fixed-column block (and the RIGHT_EDGE/MAX_COL renumbering that would require,
    see this module's own GOLDEN RULE) for a table that's mutually exclusive with the one
    already sitting there."""
    _fixed_table(sh, top, CLUSTER_COL, CLUSTER_LAST, "AD Replication",
                 ("Partner", "Status", "Last Success", "Failures"))
    r = top + 2
    for rep in sorted(rows, key=lambda x: x.partner):
        ok = rep.status.upper() == "OK"
        rbg, rtxt = (CHIP_GREEN_BG, CHIP_GREEN_TXT) if ok else (CHIP_RED_BG, CHIP_RED_TXT)
        sh.put(r, CLUSTER_COL, rep.partner, sz=8.5, color=TEXT_SECONDARY, bg=CARD,
               halign="left")
        sh.put(r, CLUSTER_COL + 1, rep.status, sz=8, bold=True, color=rtxt,
               bg=rbg, halign="center")
        sh.put(r, CLUSTER_COL + 2, rep.last_success, sz=8.5, color=TEXT_SECONDARY,
               bg=CARD, halign="center")
        sh.put(r, CLUSTER_COL + 3, rep.failures, sz=8, bold=not ok,
               color=(TEXT_SECONDARY if ok else CHIP_RED_TXT), bg=CARD, halign="center")
        r += 1
    return r - 1


def write_ntp_sync(sh, top, rows) -> int:
    """NTP / Time Sync Status, at CLUSTER_COL -- one column wider than Cluster Storage/
    Replication's own four (DC/Stratum/Source/Last Sync/Sync Age), spilling into what would
    otherwise be their own gap column (CLUSTER_LAST+1) -- but NEVER into the dedicated gap
    that sits after that (see NOTES_COL's own comment: "tables must be equidistance apart...
    must not touch any tables", 2026-09-11), so Notes still starts a full clear column away
    regardless of which of these three tables actually rendered on a given row. Safe for the
    same reason write_replication's own docstring gives: never coexists on a row with Cluster
    Storage (not a cluster host) or Replication (Root DCs have no `ad` collector enabled,
    confirmed live -- see network.py)."""
    _fixed_table(sh, top, CLUSTER_COL, CLUSTER_LAST + 1, "NTP / Time Sync Status",
                 ("DC", "Stratum", "Source", "Last Sync", "Sync Age"))
    r = top + 2
    for row in rows:
        sbg, stxt = TONE_BG[row.stratum_band], TONE_TXT[row.stratum_band]
        abg, atxt = TONE_BG[row.sync_age_band], TONE_TXT[row.sync_age_band]
        sh.put(r, CLUSTER_COL, row.dc, sz=8.5, color=TEXT_SECONDARY, bg=CARD, halign="left")
        sh.put(r, CLUSTER_COL + 1, row.stratum, sz=8, bold=True, color=stxt, bg=sbg, halign="center")
        sh.put(r, CLUSTER_COL + 2, row.source, sz=8.5, color=TEXT_SECONDARY, bg=CARD, halign="left")
        sh.put(r, CLUSTER_COL + 3, row.last_sync, sz=8.5, color=TEXT_SECONDARY, bg=CARD, halign="center")
        sh.put(r, CLUSTER_COL + 4, row.sync_age, sz=8, bold=True, color=atxt, bg=abg, halign="center")
        r += 1
    return r - 1


# Widening a column only helps up to a point -- some flagged-metric text (e.g. the Root DCs'
# "reachable, but CPU/RAM/Disk have not been published yet..." note) runs well past what any
# reasonable column width could hold on one line. Wrap instead, and grow the row to fit rather
# than truncating -- ~100 chars/line is what the Notes table's merged width (U:W) fits at this
# font/size without the row growing for the common short one-line case.
def _wrapped_row_height(text: str, chars_per_line: int = 100, line_height: float = 15.75) -> float:
    lines = max(1, -(-len(text) // chars_per_line))
    return line_height * lines


def write_notes(sh, top, indent, title, notes, group, by_row) -> None:
    nc = NOTES_COL
    ref_letter = get_column_letter(FIX_COL)

    sh.fill(top, nc, by_row, RIGHT_EDGE, CARD)
    sh.merge(top, nc, top, RIGHT_EDGE, bg=CARD)
    sh.put(top, nc, title, sz=9, bold=True, color=ACCENT, bg=CARD, halign="left")

    hdr = top + 1
    sh.merge(hdr, nc, hdr, NOTES_FLAG_LAST, bg=TABLE_HEADER_BG)
    sh.put(hdr, nc, "  Flagged metric", sz=8, bold=True, color=TEXT_SECONDARY,
           bg=TABLE_HEADER_BG, halign="left")
    sh.put(hdr, FIX_COL, "Fix needed?", sz=8, bold=True, color=TEXT_SECONDARY,
           bg=TABLE_HEADER_BG, halign="center")
    sh.put(hdr, RIGHT_EDGE, "Resolved", sz=8, bold=True, color=TEXT_SECONDARY,
           bg=TABLE_HEADER_BG, halign="center")

    r = hdr + 1
    for n in notes:
        color, italic = _flagged_style(n)
        sh.merge(r, nc, r, NOTES_FLAG_LAST, bg=CARD)
        sh.put(r, nc, f"  {n.flagged_metric}", sz=8, italic=italic, color=color,
               bg=CARD, halign="left", valign="top", wrap=True)
        sh.rowh(r, _wrapped_row_height(n.flagged_metric))
        if n.fix_needed:
            sh.put(r, FIX_COL, n.fix_needed, sz=8, color=TEXT_SECONDARY, bg=CARD,
                   halign="center")
            sh.put(r, RIGHT_EDGE,
                   f'=IF({ref_letter}{r}="No","Yes",IF({ref_letter}{r}="Yes",'
                   f'"No",""))',
                   sz=8, color=TEXT_SECONDARY, bg=CARD, halign="center")
        r += 1
    sh.merge(r, nc, r, RIGHT_EDGE, bg=CARD)
    sh.put(r, nc, "  Comment", sz=8, bold=True, color=TEXT_MUTED, bg=CARD,
           halign="left")
    r += 1
    for n in notes:
        if n.comment:
            sh.merge(r, nc, r, RIGHT_EDGE, bg=CARD)
            sh.put(r, nc, n.comment, sz=8, color=TEXT_PRIMARY, bg=CARD,
                   halign="left", valign="top", wrap=True)
            sh.rowh(r, 25.5)
            r += 1

    sh.put(by_row, nc, "By  ", sz=8, color=TEXT_MUTED, bg=CARD, halign="right")
    sh.merge(by_row, nc + 1, by_row, RIGHT_EDGE, bg=CARD)
    sh.put(by_row, nc + 1, group.signed_by, sz=9, color=TEXT_PRIMARY, bg=CARD,
           halign="left")


def _notes_content_end(top, notes) -> int:
    r = top + 2
    r += len(notes)
    r += 1
    r += sum(1 for n in notes if n.comment)
    return r - 1


def _section_span(group: DeviceGroup) -> int:
    """Rows write_section would consume for this group's OWN title+tables+notes+gap block
    (its children excluded) -- pure arithmetic, no sheet writes, mirroring write_section's
    exact math (top = start+2, ends[], by_row = max(ends)+1, return by_row+2) with start=0 so
    callers get a SPAN rather than an absolute row. Lets sibling sections' natural heights be
    compared and equalized (see write_section's children loop) before any of them are actually
    written -- e.g. one HCI cluster node currently has a live Services table the other three
    (not yet reporting) don't, which made its own section visibly taller and threw off the
    gap between node sections. Keep in sync with write_section/write_services if either
    changes shape."""
    top = 2
    has_tables = any((group.services, group.cpu_ram, group.disks, group.cluster_storage,
                      group.replication, group.ntp_sync, group.notes))
    if not has_tables:
        return top
    ends = [top]
    if group.services:
        # +2 (not -1): write_services' "SYSTEM SERVICES" subheader consumes its own row
        # ahead of the per-host/per-service loop, on top of the title+column-header rows
        # every other table's ends already include -- see write_services itself.
        grouped = len(group.cpu_ram) > 1
        loop_rows = (len(group.cpu_ram) * (1 + len(group.services)) if grouped
                    else len(group.services))
        ends.append(top + 2 + loop_rows)
    if group.cpu_ram:
        ends.append(top + 2 + len(group.cpu_ram) - 1)
    if group.disks:
        ends.append(top + 2 + len(group.disks) - 1)
    if group.cluster_storage:
        ends.append(top + 2 + len(group.cluster_storage) - 1)
    if group.replication:
        ends.append(top + 2 + len(group.replication) - 1)
    if group.ntp_sync:
        ends.append(top + 2 + len(group.ntp_sync) - 1)
    ends.append(_notes_content_end(top, group.notes) if group.notes else top)
    by_row = max(ends) + 1
    return by_row + 2


def write_section(sh: Sheet, row: int, indent: int, group: DeviceGroup) -> int:
    start = row
    write_title_bar(sh, row, indent, group)
    top = row + 2

    has_tables = any((group.services, group.cpu_ram, group.disks, group.cluster_storage,
                      group.replication, group.ntp_sync, group.notes))
    if has_tables:
        notes_title = _notes_title(group.title, indent)
        notes_content_end = (_notes_content_end(top, group.notes)
                             if group.notes else top)

        ends = [top]
        if group.services:
            ends.append(write_services(sh, top, services_col(indent), group))
        if group.cpu_ram:
            ends.append(write_cpu_ram(sh, top, cpuram_col(indent), group.cpu_ram))
        if group.disks:
            ends.append(write_disk(sh, top, group.disks))
        if group.cluster_storage:
            ends.append(write_cluster_storage(sh, top, group.cluster_storage))
        if group.replication:
            ends.append(write_replication(sh, top, group.replication))
        if group.ntp_sync:
            ends.append(write_ntp_sync(sh, top, group.ntp_sync))
        ends.append(notes_content_end)
        by_row = max(ends) + 1
        write_notes(sh, top, indent, notes_title, group.notes, group, by_row)
        row = by_row + 2
    else:
        row = top

    # Pad every child to the tallest sibling's own natural span, so the gap between child
    # sections reads the same no matter which one currently has more content (see
    # _section_span's own docstring for why that happens at all -- e.g. HCI cluster nodes not
    # yet reporting have no Services table, making a currently-reporting node's own section
    # taller than its siblings').
    sibling_span = max((_section_span(c) for c in group.children), default=0)
    for child in group.children:
        child_start = row
        row = write_section(sh, row, indent + 1, child)
        row = max(row, child_start + sibling_span)

    # nesting bracket: a group with children gets a gutter spine spanning its
    # whole subtree; children have already painted their (deeper) portions.
    if group.children:
        sh.spine(start, max(start, row - 2), spine_color(indent))

    return row


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

def write_footer(sh: Sheet, row: int) -> None:
    r = row
    for line in FOOTER_LINES:
        sh.put(r, 2, line, sz=8, color=TEXT_MUTED, bg=BG, halign="left")
        r += 1


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

# Some columns do double duty -- a gap at one nesting level, a data column at
# another -- so widths are sized for the widest role each column can take.
COL_WIDTHS = {
    "A": 6.43,                                             # gutter / nesting spine
    # D through J are gap columns at SOME indent, real content at others -- Services/CPU-RAM
    # shift one column per indent level (services_col/cpuram_col) while Disk stays fixed at
    # DISK_COL, so the column that sits blank as "the gap before Disk" is different at every
    # indent, and shrinks by one column each level deeper (nothing left to shrink is exactly
    # the bug 3 levels ran into: indent 2's CPU/RAM ram column landed ON TOP of the old
    # DISK_COL, leaving zero gap at all -- see DISK_COL's own comment). Column widths are
    # per-column, not per-row, so whatever value a column has here is what EVERY indent that
    # reuses it gets, whether that indent needs it as a gap or as real content.
    #
    # Solved for 3 indent levels (0/1/2 -- Active Directory > Root/Child Domain Controllers >
    # each DC, or any group nested that deep) so that, AT EACH indent, the Services<->CPU/RAM
    # gap equals that same indent's own CPU/RAM<->Disk gap (the "table spacing consistent
    # within a section" rule from earlier still has to hold at every depth, not just 0 and 1):
    #   indent 0: Gap1 = D            Gap2 = H + I + J        -> D = H+I+J
    #   indent 1: Gap1 = E            Gap2 = I + J            -> E = I+J
    #   indent 2: Gap1 = F            Gap2 = J                -> F = J
    # F, G, H, I carry real minimum widths from whichever indent actually uses them as data
    # (node/cpu/ram values, hostnames) -- F=15 and H=13 were already sized for that at indents
    # 0/1; G widened 13->15 so indent 2's own "node" column (a full hostname, not a bare %)
    # fits as comfortably as indent 0/1's already do; I=13 fits indent 2's "ram" column the
    # same way G/H already fit theirs. J is NEVER real content at any indent actually in use
    # (only ever the deepest gap) so it's free -- set to 15 to keep F a real, comfortable
    # width, which then fixes E=I+J=28 and D=H+I+J=41 by the equations above.
    #
    # B:J scaled by 0.7 (indentation 30% narrower, on request) AFTER solving the equations
    # above -- a uniform scale preserves every equality exactly (0.7*D = 0.7*H+0.7*I+0.7*J
    # still holds whenever D = H+I+J did), so the gap-consistency work doesn't need re-solving,
    # just resizing. K onward (Disk/Cluster/Notes) intentionally NOT scaled -- those are fixed
    # regardless of indent, so they carry no "indentation" to reduce.
    #
    # B further reduced by 10% on top of that (20.16 = 22.4*0.9), then another 3% (19.5552):
    # B is what actually produces the level-1 step -- indent 1's title starts right after it --
    # and, unlike D/E/.../J, it never appears in the gap-consistency equations above (it's
    # purely indent 0's own Services "name" column, no gap or indent-2 role to protect), so it
    # can move on its own without touching anything those equations depend on.
    #
    # C cut 20% (11.2 -> 8.96): the step that produces level 2 (indent 2's title starts right
    # after it), same reasoning as B -- C is indent 0's own Services "status" column and
    # indent 1's "name" column, neither a gap role, so it's equally free to move alone. Content
    # risk worth flagging though, unlike B: indent 1's OWN Services table (HCI Cluster Node's
    # service names -- "Hyper-V Virtual Machine Management" is 34 characters) uses C as its
    # NAME column, with D (a real Status chip, never blank) immediately to its right -- Excel
    # only lets text overflow into a truly EMPTY neighbor, so a name longer than ~9 characters
    # will visibly clip here, not just overflow harmlessly. B never hit this because indent 0's
    # own equivalent long names (HCI Cluster Host's rolled-up "Cluster Service (HRE-HCIHOST-01)")
    # sit at a still-generous 19.56 wide.
    "B": 19.5552, "C": 8.96, "D": 28.7,                    # Services (name/status, shifts by indent) -- B widened for names like "DFSR (SYSVOL replication) (RBZ-HQ-ROOT-02)"
    "E": 19.6, "F": 10.5, "G": 10.5, "H": 9.1, "I": 9.1,   # CPU / RAM (shifts by indent) -- E/F/G fit e.g. "HRE-HCIHOST-01"
    "J": 10.5,                                             # guaranteed gap: CPU/RAM <-> Disk -- see the equations above
    "K": 14, "L": 8, "M": 8, "N": 8.43, "O": 8,            # Disk (fixed)
    # P was 3 -- much narrower than F/J (both 10.5, the Services<->CPU/RAM and CPU/RAM<->Disk
    # gaps the equations above already keep equal at indent 2). Matched to 10.5 here too
    # (2026-09-11, on request: "equal distance between these tables Services / CPU·RAM / Disk
    # / AD Replication") so all three gaps at the level these four tables actually coexist
    # (a DC's own per-host card, indent 2) read as genuinely the same width, not just the
    # first two.
    "P": 10.5,                                             # gap: Disk <-> Cluster Storage/Replication/NTP
    # Q-T do double duty (same "widest role each column can take" rule as D-J above):
    # Cluster Storage (Pool/Used%/Size GB/Free GB) and Replication (Partner/Status/Last
    # Success/Failures) both fit comfortably in the original, narrower sizing, but NTP / Time
    # Sync Status (write_ntp_sync's own DC/Stratum/Source/Last Sync) needs real room for a
    # full hostname, an NTP source name ("0.pool.ntp.org"), and a full datetime ("11 Sep
    # 2026, 06:52:18") -- widened here for that, 2026-09-11. Cluster Storage/Replication's own
    # short values just sit in a more generous column than they strictly need; nothing there
    # was sized to fit exactly, so there's no risk of clipping the other direction.
    "Q": 14, "R": 7, "S": 16, "T": 20,                     # Cluster Storage / Replication / NTP
    "U": 9,                                                # gap for Cluster Storage/Replication;
                                                            # NTP's own "Sync Age" (e.g. "0h 5m")
                                                            # when NTP is the table rendering
    "V": 3,                                                # gap, ALWAYS -- see NOTES_COL's own
                                                            # comment; never absorbed as data by
                                                            # any table, so Notes never touches one
    "W": 36, "X": 12, "Y": 12,                             # Notes: Flagged metric (W:Y)
    "Z": 13, "AA": 13,                                     # Notes: Fix needed? / Resolved
}


def build_report(data: ReportData, out_path: str) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = data.report_title.title()   # "INFRASTRUCTURE ADMIN REPORT" -> "Infrastructure Admin Report"
    ws.sheet_view.showGridLines = False
    sh = Sheet(ws)

    for col, w in COL_WIDTHS.items():
        ws.column_dimensions[col].width = w

    write_header(sh, data)
    first_row, watch_end, banner_start, banner_end = write_dashboard(sh, data)
    row = first_row
    for group in data.groups:
        row = write_section(sh, row, 0, group)
    write_footer(sh, row)

    for r in range(1, MAX_ROW + 1):
        rd = ws.row_dimensions[r]
        if rd.height is None:
            rd.height = 15.0
        for c in range(1, MAX_COL + 1):
            cell = ws.cell(row=r, column=c)
            rgb = cell.fill.fgColor.rgb if cell.fill and cell.fill.fill_type else None
            if rgb in (None, "00000000"):
                cell.fill = PatternFill(fill_type="solid", fgColor=BG)

    sn = "Infrastructure Admin Report"
    dl = get_column_letter(DASH_LEFT)
    dr = get_column_letter(DASH_RIGHT)
    we = get_column_letter(RIGHT_EDGE)
    wb.defined_names["dashboard"] = DefinedName(
        "dashboard", attr_text=f"'{sn}'!${dl}$6:${dr}${watch_end}")
    wb.defined_names["banners"] = DefinedName(
        "banners", attr_text=f"'{sn}'!${dl}${banner_start}:${dr}${banner_end}")
    wb.defined_names["RHS_Edge"] = DefinedName(
        "RHS_Edge", attr_text=f"'{sn}'!${we}:${we}")

    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True

    wb.save(out_path)


# ---------------------------------------------------------------------------
# JSON loading
# ---------------------------------------------------------------------------

def _banner_from_dict(b) -> Banner:
    return Banner(
        severity=b["severity"], title=b["title"], subtitle=b["subtitle"],
        rows=[BannerRow(*r) if isinstance(r, list) else BannerRow(**r)
              for r in b.get("rows", [])],
        note=b.get("note", ""),
    )


def _service_row(s):
    return ServiceRow(**s) if isinstance(s, dict) else ServiceRow(s)


def load_data(path: str) -> ReportData:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    def group_from_dict(g) -> DeviceGroup:
        return DeviceGroup(
            title=g["title"],
            services=[_service_row(s) for s in g.get("services", [])],
            cpu_ram=[CpuRam(**c) for c in g.get("cpu_ram", [])],
            disks=[DiskRow(**d) for d in g.get("disks", [])],
            cluster_storage=[ClusterStorageRow(**s)
                             for s in g.get("cluster_storage", [])],
            replication=[ReplicationRow(**s) for s in g.get("replication", [])],
            ntp_sync=[NtpSyncRow(**s) for s in g.get("ntp_sync", [])],
            notes=[NoteRow(**n) for n in g.get("notes", [])],
            critical=g.get("critical", 0),
            warning=g.get("warning", 0),
            count=g.get("count", 0),
            count_label=g.get("count_label", "devices"),
            signed_by=g.get("signed_by", "Pride Moyo"),
            children=[group_from_dict(c) for c in g.get("children", [])],
        )

    return ReportData(
        generated_at=raw["generated_at"],
        nodes_total=raw["nodes_total"],
        cluster_count=raw["cluster_count"],
        cluster_nodes=raw["cluster_nodes"],
        cluster_resources_total=raw["cluster_resources_total"],
        last_checked=raw["last_checked"],
        needs_attention=[SummaryMetric(**m) for m in raw["needs_attention"]],
        watch_list=[SummaryMetric(**m) for m in raw["watch_list"]],
        summary_notes=[SummaryNote(**n) for n in raw["summary_notes"]],
        groups=[group_from_dict(g) for g in raw["groups"]],
        banners=[_banner_from_dict(b) for b in raw.get("banners", [])],
        summary_signed_by=raw.get("summary_signed_by", "Pride Moyo"),
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python report_generator.py data.json out.xlsx")
        sys.exit(1)
    build_report(load_data(sys.argv[1]), sys.argv[2])
    print(f"wrote {sys.argv[2]}")
