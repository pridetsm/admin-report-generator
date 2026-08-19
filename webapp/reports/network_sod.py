"""The Network Infrastructure SOD (Start-of-Day) Report.

A DIFFERENT report from the Network Admin Report next door in network.py, running on the
same rails, picker included. That one is a live SNMP snapshot of the devices Prometheus
scrapes; this one is the checklist the on-duty engineer works through every morning across
four vendor consoles — SolarWinds Orion, Cisco Catalyst 9800 WLC, Perfstack and Radware —
none of which this app integrates with. The picker still earns its keep here even though
the estate is fixed: it thins the ENTRY SCREEN down to what the engineer is actually
covering this morning (skip a device under maintenance rather than staring at a field for
it) — the workbook itself keeps every row of the fixed estate regardless, blank where the
picker left something out, exactly as a blank already means "not captured".

That gap is the whole design constraint. Almost every reading on this sheet comes from a
console we cannot query, so the module is built to carry BLANKS honestly rather than to
invent numbers: every field defaults to empty, ``collect()`` fills in only the handful the
monitoring stack can actually answer for, and the engineer types the rest on the screen.
A blank cell here means "not captured", which is a true statement; a fabricated 3 ms would
not be.

The layout is a 1-1 reproduction of the approved workbook
(standalone/network admin report/Network_Infrastructure_SOD_Report_18_Aug_2026.xlsx) — same
sections in the same order, same columns, same merges, same row heights. Only the VALUES
change from one morning to the next. Colours come from gr.PALETTES via gr.palette(), exactly
as network.build_report does, so "dark" and "light" mean one thing across all three reports
and a palette tweak reaches every one of them.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List

import generate_report as gr

from . import network


# =======================================================================================
#  THE CHECKLIST CATALOGUE
#
#  One definition, read by BOTH the entry screen and the workbook builder. Written as data
#  rather than as markup in the template plus a mirrored writer in the builder, because the
#  two drifting apart is exactly how a field ends up on screen that never reaches the sheet
#  (or worse, the reverse — a column in the report nobody was asked to fill in).
#
#  `key` is what the form field is named and what the POST comes back as. It must never
#  change once shipped: a renamed key silently drops whatever the engineer typed.
# =======================================================================================

@dataclass
class Check:
    """One ping-style row: a name, a reading, and a status chip."""
    key: str
    label: str
    # Filled by collect() when the monitoring stack genuinely knows the answer. Blank
    # otherwise — see the module docstring.
    result: str = ""
    status: str = ""
    # True on the rows collect() answered, so the screen can say WHY a field arrived
    # pre-filled and the engineer knows not to re-key it from the console.
    live: bool = False
    source: str = ""


@dataclass
class Group:
    """A labelled run of checks inside a section, e.g. the Sophos box under FIREWALLS."""
    label: str
    checks: List[Check] = field(default_factory=list)


@dataclass
class Circuit:
    key: str
    provider: str
    download: str = ""
    upload: str = ""
    latency: str = ""
    jitter: str = ""
    loss: str = ""
    quality: str = ""


@dataclass
class Controller:
    key: str
    site: str
    wlans: str = ""
    aps: str = ""
    clients: str = ""
    rogue: str = ""
    interferers: str = ""


@dataclass
class DrLink:
    key: str
    label: str
    utilization: str = ""
    discards: str = ""
    errors: str = ""
    status: str = ""


# ---- Core switches and WAN routers ----------------------------------------------------
# "All WAN Links (below)" is a roll-up row, not a device: it restates the DR link table
# further down so the top section reads as a complete answer on its own.
CORE_WAN = [
    ("ho_core",       "Head-Office Core Switch"),
    ("mazowe_core",   "Mazowe DR Core Switch"),
    ("harare_wan",    "Harare WAN Router"),
    ("bulawayo_wan",  "Bulawayo WAN Router"),
    ("bulawayo_core", "Bulawayo Core Switch"),
    ("wan_links",     "All WAN Links (below)"),
]

# ---- Firewalls, in the two labelled boxes the reference sheet uses ---------------------
FIREWALL_GROUPS = [
    ("APPLICATIONS & MAIN FIREWALLS", [
        ("ho_app_fw",  "HO Application Firewall"),
        ("main_fmc",   "Main FMC"),
        ("main_ftd",   "Main FTD Firewall"),
        ("mazowe_ftd", "Mazowe FTD Firewall"),
    ]),
    ("SOPHOS FIREWALL", [
        ("hq_sophos", "HQ Sophos Firewall"),
    ]),
]

# ---- Floor switches -------------------------------------------------------------------
# Reviewed as a set on the Orion dashboard rather than pinged one by one, so its status
# vocabulary is REVIEWED, not OK/DOWN. Its own section for exactly that reason.
FLOOR_SWITCHES = [
    ("cisco_floor", "Cisco Floor Switches"),
]
FLOOR_NOTE = "Checked via SolarWinds (hre-pmapp01) Orion dashboard — Cisco floor switch view."

CIRCUIT_PROVIDERS = [
    ("telecontract", "Telecontract"),
    ("dandemutande", "Dandemutande"),
    ("radius_flame", "Radius Flame LT (Liquid)"),
    ("wafanyakazi",  "Wafanyakazi"),
]
CIRCUIT_NOTE = ("Speed/latency/jitter/packet-loss readings from Cloudflare speed test, "
                "captured per circuit this morning.")

CONTROLLER_SITES = [
    ("harare",   "Harare"),
    ("bulawayo", "Bulawayo"),
]
CONTROLLER_NOTE = ("Source: Cisco Catalyst 9800-CL Wireless Controller dashboards, "
                   "Harare & Bulawayo.")

DR_LINK_DEFS = [
    ("dfa",    "Dark Fibre Africa Link"),
    ("telone", "Telone Tegius Link"),
]
DR_NOTE = ("Source: Perfstack link-utilization graphs, last 12 hours — no received errors "
           "or discards on either link.")

# ---- Radware WAF ----------------------------------------------------------------------
# The reference sheet lays these out in three columns: two with a Status beside them and a
# third, narrower one without. That asymmetry is reproduced rather than tidied, because the
# sheet is signed off in this shape and checked against a console screenshot that matches it.
WAF_APPS = [
    "beam.rbz.co.zw", "intranetfiles.rbz.co.zw", "Lms.rbz.co.zw",
    "cepecept.excon.rbz.co.zw", "bsa.rbz.co.zw", "collateralregistry.rbz.co.zw",
    "Rbzconnect.rbz.co.zw", "Cms.rbz.co.zw", "Frs.rbz.co.zw",
    "Forex.rbz.co.zw", "Crs.rbz.co.zw", "Edms.rbz.co.zw",
    "bdctrs.rbz.co.zw", "esf.rbz.co.zw", "esfexec.rbz.co.zw", "www.rbz.co.zw",
]
# Protected-application count as the Radware console reports it. Deliberately a SEPARATE
# number from len(WAF_APPS): the console reports more applications than the captured list
# shows, and the reference sheet says so in a footnote rather than quietly showing 16.
WAF_PROTECTED_TOTAL = 18

FOOTER_NOTE = ("Report generated for internal RBZ network operations use — sourced from "
               "SolarWinds, Cisco WLC, Perfstack and Radware consoles.")
SOLARWINDS_LABEL = "▸  OPEN SOLARWINDS DASHBOARD"
HEADER_NOTE = "Manual SOD checklist — captured once each morning by the on-duty engineer."

# Status vocabulary for the ping-style rows. OK/DOWN drive the chip colour; REVIEWED is the
# floor-switch answer; "" is an uncaptured row and renders as a neutral, uncoloured blank.
STATUS_CHOICES = ["", "OK", "DOWN", "REVIEWED"]
STATUS_BAND = {"OK": "green", "DOWN": "red", "REVIEWED": "green"}


def blank_checklist() -> dict:
    """A fully-blank checklist in the reference sheet's own order and shape.

    Every builder and every screen starts from this, so a section can never be half-declared:
    if a key is not here it does not exist anywhere, and if it is here it renders even when
    the engineer leaves it empty. That is what makes "blank" a reportable answer rather than
    a missing row.
    """
    return {
        "core_wan": [Check(k, lbl) for k, lbl in CORE_WAN],
        "firewalls": [Group(label, [Check(k, lbl) for k, lbl in checks])
                      for label, checks in FIREWALL_GROUPS],
        "floor": [Check(k, lbl) for k, lbl in FLOOR_SWITCHES],
        "circuits": [Circuit(k, name) for k, name in CIRCUIT_PROVIDERS],
        "controllers": [Controller(k, site) for k, site in CONTROLLER_SITES],
        "dr_links": [DrLink(k, lbl) for k, lbl in DR_LINK_DEFS],
        "waf": [{"name": a, "status": ""} for a in WAF_APPS],
    }


# =======================================================================================
#  LIVE COLLECTION
#
#  The only SOD rows this app can answer for itself are the ones whose device is already an
#  SNMP target in Prometheus. Today that is network.DEVICES — one core switch — so exactly
#  one row prefills and the rest stay blank.
#
#  A SOD row is matched to a monitored device by KEY, not by fuzzy name match:
#  "Head-Office Core Switch" and network.py's "Core Switch" are the same box under two
#  names, and a matcher clever enough to join those is also clever enough to join the
#  wrong two. Onboarding the firewall or a WAN router later is a line here, not a rewrite.
# =======================================================================================
LIVE_DEVICE_FOR = {
    "ho_core": "core-switch",
}


def collect() -> Dict[str, dict]:
    """Live readings for the SOD rows the monitoring stack genuinely knows about.

    Returns ``{sod_key: {"result", "status", "source"}}`` carrying ONLY rows that resolved.
    A device Prometheus has never scraped is left out entirely rather than reported as
    blank-but-known: the caller could not otherwise tell "we asked and it is down" apart
    from "we never asked", and those need different handling on screen.

    Never raises. An unreachable Prometheus means the whole sheet is hand-keyed, which is
    exactly what the engineer did before this screen existed — it must not fail the report.
    """
    out: Dict[str, dict] = {}
    if not LIVE_DEVICE_FOR:
        return out
    try:
        inventory = {d["key"]: d for d in network.device_inventory()}
    except Exception:                                    # noqa: BLE001 - see docstring
        return out

    for sod_key, dev_key in LIVE_DEVICE_FOR.items():
        dev = inventory.get(dev_key)
        if not dev or not dev.get("known"):
            # No `up` series at all — Prometheus has never scraped it. Leave the row blank
            # rather than asserting anything about a device we are not watching.
            continue
        reachable = bool(dev.get("reachable"))
        out[sod_key] = {
            # The reference sheet's Result column holds an ICMP latency, which nothing here
            # measures — there is no blackbox ICMP job, only HTTP probes. So the honest
            # reading is the reachability we DO have, worded as what it actually is.
            "result": "Responding" if reachable else "Not responding",
            "status": "OK" if reachable else "DOWN",
            "source": "SNMP scrape of {}".format(dev.get("target", "")).strip(),
        }
    return out


def prefilled_checklist() -> dict:
    """A blank checklist with the live rows filled in and marked as such."""
    data = blank_checklist()
    live = collect()
    for chk in data["core_wan"] + data["floor"] + [c for g in data["firewalls"] for c in g.checks]:
        hit = live.get(chk.key)
        if hit:
            chk.result = hit["result"]
            chk.status = hit["status"]
            chk.source = hit.get("source", "")
            chk.live = True
    return data


def scoped_for_display(data: dict, selected) -> dict:
    """The subset of `data` the picker chose, for the entry screen only.

    `summarise()` and `build_report()` keep working from the FULL checklist — a blank row
    there is "not captured", not "does not exist" (see the module docstring), and the
    reference sheet's shape is fixed regardless of what a given morning's picker covers.
    This view exists only so the entry screen asks the engineer about what they said they
    are covering today, the same way the systems report only asks about the systems picked
    on its own picker.
    """
    sel = set(selected or ())
    return {
        "core_wan": [c for c in data["core_wan"] if c.key in sel],
        "firewalls": [Group(g.label, [c for c in g.checks if c.key in sel])
                      for g in data["firewalls"] if any(c.key in sel for c in g.checks)],
        "floor": [c for c in data["floor"] if c.key in sel],
        "circuits": [c for c in data["circuits"] if c.key in sel],
        "controllers": [c for c in data["controllers"] if c.key in sel],
        "dr_links": [d for d in data["dr_links"] if d.key in sel],
        "waf": data["waf"] if "waf" in sel else [],
    }


# =======================================================================================
#  READING THE SUBMITTED FORM
# =======================================================================================
def from_post(post) -> dict:
    """Rebuild the checklist from a submitted form.

    Values are taken verbatim and merely trimmed — no parsing, no unit inference, no
    "helpfully" turning 5.7 into 5.70%. What the engineer read off the console is what the
    report says, because this sheet gets signed and a number the app reformatted is a number
    nobody typed.
    """
    data = blank_checklist()

    def val(name: str) -> str:
        return (post.get(name, "") or "").strip()

    for chk in data["core_wan"] + data["floor"] + [c for g in data["firewalls"] for c in g.checks]:
        chk.result = val("result__" + chk.key)
        status = val("status__" + chk.key)
        chk.status = status if status in STATUS_CHOICES else ""

    for c in data["circuits"]:
        c.download = val("dl__" + c.key)
        c.upload = val("ul__" + c.key)
        c.latency = val("lat__" + c.key)
        c.jitter = val("jit__" + c.key)
        c.loss = val("loss__" + c.key)
        c.quality = val("qual__" + c.key)

    for w in data["controllers"]:
        w.wlans = val("wlans__" + w.key)
        w.aps = val("aps__" + w.key)
        w.clients = val("clients__" + w.key)
        w.rogue = val("rogue__" + w.key)
        w.interferers = val("intf__" + w.key)

    for d in data["dr_links"]:
        d.utilization = val("util__" + d.key)
        d.discards = val("disc__" + d.key)
        d.errors = val("err__" + d.key)
        status = val("drstatus__" + d.key)
        d.status = status if status in STATUS_CHOICES else ""

    for i, app in enumerate(data["waf"]):
        app["status"] = val("waf__{}".format(i))

    return data


# =======================================================================================
#  DERIVED SUMMARY
#
#  Everything in the AT A GLANCE and NEEDS ATTENTION strips is COUNTED from the entries
#  above, never typed. A summary that can disagree with the table under it is worse than no
#  summary, and on a sheet that gets signed it is the number people quote in the stand-up.
# =======================================================================================
_NUMBER_WORDS = {0: "none", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}


def loss_short(loss: str) -> str:
    """The Pkt Loss cell's own text: the reading without any explanatory parenthetical.

    "Failed (connection timed out)" is written as "Failed" in the narrow table column and the
    cause is carried by the banner instead — which is how the reference sheet reads, and the
    only way the cause fits anywhere at all in a 7-wide column.
    """
    text = (loss or "").strip()
    if "(" in text and text.endswith(")"):
        return text[:text.index("(")].strip()
    return text


def _plural_circuits(n: int) -> str:
    """"two circuits are" / "one circuit is" — spelled out, as the reference sheet writes it."""
    word = _NUMBER_WORDS.get(n, str(n))
    return "{} circuit{} {}".format(word, "" if n == 1 else "s", "is" if n == 1 else "are")


def summarise(data: dict) -> dict:
    """Counts and warning banners derived from the filled-in checklist."""
    firewall_checks = [c for g in data["firewalls"] for c in g.checks]
    ping_checks = data["core_wan"] + firewall_checks

    links_down = sum(1 for c in ping_checks if c.status == "DOWN")

    # A circuit is degraded when the morning's test SAYS something bad about it: measurable
    # packet loss above zero, a packet-loss test that actively failed, or a quality aspect
    # that came back Poor.
    #
    # Deliberately NOT flagged: a reading of "—" or a quality of "Test incomplete". Those
    # mean the test never produced an answer, which is not the same claim as the circuit
    # being bad — and the banner counts circuits "affected", not circuits unmeasured. The
    # reference sheet draws the line in exactly this place: it flags Telecontract, whose
    # loss test failed, but not Wafanyakazi, whose test simply did not run.
    _NIL = ("", "0", "0%", "0.0%", "—", "-", "n/a")

    def _failed_loss(loss: str) -> bool:
        return "fail" in loss.strip().lower()

    def degraded(c: Circuit) -> bool:
        loss = c.loss.strip().lower()
        if _failed_loss(loss):
            return True
        if loss not in _NIL:
            return True
        return "poor" in c.quality.strip().lower()

    # Worst first, so the circuit that actually measured badly leads the banner rather than
    # the one whose test merely errored. The reference sheet lists Dandemutande (5.70% loss,
    # Poor gaming) above Telecontract (loss test failed) for the same reason.
    def _circuit_rank(c: Circuit) -> int:
        if "poor" in c.quality.strip().lower():
            return 0
        if not _failed_loss(c.loss) and c.loss.strip().lower() not in _NIL:
            return 1
        return 2

    degraded_circuits = sorted((c for c in data["circuits"] if degraded(c)),
                               key=_circuit_rank)

    # The Quality column is a Stream/Game/Chat triple. The banner names the aspects that are
    # not Good rather than echoing the raw "Average/Poor/Average", because "Online Gaming:
    # Poor" is the sentence someone acts on and the triple is not readable without the key.
    _ASPECTS = ("Video Streaming", "Online Gaming", "Chat")

    def _quality_detail(quality: str) -> List[str]:
        parts = [p.strip() for p in quality.split("/")]
        if len(parts) != len(_ASPECTS):
            # Not a triple — a free-text note like "Test incomplete". Pass it through whole
            # rather than trying to split something that is not a rating.
            return [quality.strip()] if quality.strip() else []
        bad = [(name, rating) for name, rating in zip(_ASPECTS, parts)
               if rating and rating.lower() != "good"]
        # Worst first, so the reason the circuit was flagged leads the line rather than
        # trailing behind a milder aspect that happens to come first in the triple.
        rank = {"poor": 0, "bad": 0, "average": 1, "fair": 1}
        bad.sort(key=lambda nr: rank.get(nr[1].lower(), 2))
        # Two at most. The banner is a headline, not the table — the Quality column below
        # carries the full triple, and the reference sheet names the two worst aspects and
        # stops there rather than reciting all three.
        return ["{}: {}".format(name, rating) for name, rating in bad[:2]]

    def _circuit_detail(c: Circuit) -> str:
        if _failed_loss(c.loss):
            # The loss test itself errored; the quality ratings from the same run are not
            # trustworthy enough to recite beside it.
            #
            # A parenthetical in the loss field is carried through, so an engineer who types
            # "Failed (connection timed out)" gets the cause in the banner instead of a bare
            # "failed to complete" that leaves the reader asking why.
            because = ""
            if "(" in c.loss and c.loss.strip().endswith(")"):
                because = " " + c.loss[c.loss.index("("):].strip()
            return "Packet-loss measurement failed to complete" + because
        bits = []
        if c.loss.strip() and c.loss.strip().lower() not in _NIL:
            bits.append("Packet loss {}".format(c.loss.strip()))
        bits.extend(_quality_detail(c.quality))
        return "  ·  ".join(bits)

    def rogue_count(w: Controller) -> int:
        try:
            return int(str(w.rogue).strip() or 0)
        except ValueError:
            return 0

    rogue_controllers = [w for w in data["controllers"] if rogue_count(w) > 0]

    banners = []
    if degraded_circuits:
        banners.append({
            "band": "amber",
            "headline": "WARNING  —  INTERNET CIRCUIT DEGRADATION  —  {} of {} circuits affected".format(
                len(degraded_circuits), len(data["circuits"])),
            # "Dandemutande Internet", matching how the WLAN banner says "Harare WLAN
            # Controller" — the banner names the LINK, while the table below names the
            # provider supplying it.
            "rows": [{"name": "{} Internet".format(c.provider), "detail": _circuit_detail(c)}
                     for c in degraded_circuits],
            "note": ("Core WAN links ({}) and the remaining {} within normal range. "
                     "Monitor {} if gaming/latency-sensitive traffic is routed via {}."
                     # "this circuit" regardless of how many were flagged: the sentence names
                     # ONE circuit to watch (the worst), so the pronoun refers to that one.
                     .format(", ".join(lbl for _k, lbl in DR_LINK_DEFS).replace(" Link", ""),
                             _plural_circuits(len(data["circuits"]) - len(degraded_circuits)),
                             degraded_circuits[0].provider,
                             "this circuit")),
        })
    if rogue_controllers:
        banners.append({
            "band": "amber",
            "headline": "WARNING  —  ROGUE ACCESS POINTS  —  elevated on {}".format(
                "both WLAN controllers" if len(rogue_controllers) > 1
                else "the {} WLAN controller".format(rogue_controllers[0].site)),
            "rows": [{"name": "{} WLAN Controller".format(w.site),
                      "detail": "  ·  ".join(p for p in [
                          "{} rogue APs detected".format(w.rogue) if w.rogue.strip() else "",
                          "{} interferers on 2.4GHz".format(w.interferers) if w.interferers.strip() else "",
                      ] if p)}
                     for w in rogue_controllers],
            "note": ("Review the rogue AP / SSID list on both controllers for unauthorised "
                     "devices in range."),
        })

    waf_clear = all((a["status"] or "").strip().lower() in ("", "protected")
                    for a in data["waf"])

    return {
        "core_wan_count": len(data["core_wan"]),
        "firewall_count": len(firewall_checks),
        "circuit_count": len(data["circuits"]),
        "controller_count": len(data["controllers"]),
        "waf_count": WAF_PROTECTED_TOTAL,
        "links_down": links_down,
        "ping_total": len(ping_checks),
        "degraded_circuits": len(degraded_circuits),
        "rogue_controllers": len(rogue_controllers),
        "banners": banners,
        "waf_clear": waf_clear,
    }


def sod_report_filename(theme: str = "dark", when=None) -> str:
    """Named like the reference workbook, so a morning's sheet files beside its predecessors.

    The theme is NOT in this name, unlike the systems and network reports. Those are ad-hoc
    downloads that may be run twice in a day; this one is the day's signed record, and two
    files differing only by "(light)" would read as two different mornings.
    """
    when = when or datetime.datetime.now()
    return "Network_Infrastructure_SOD_Report_{:%d_%b_%Y}.xlsx".format(when)


# =======================================================================================
#  THE WORKBOOK
#
#  A 1-1 reproduction of the approved reference sheet: the same sections in the same order,
#  the same columns, the same merges and the same row heights. The reference was measured
#  rather than eyeballed — every merge range and height below came out of the signed-off
#  file — because this sheet is checked side by side against yesterday's, and a column that
#  shifted by one would make the two impossible to compare at a glance.
#
#  Written directly rather than through gr.build_report_bytes for the same reason
#  network.build_report is: that builder renders the systems engine's Store — disks,
#  services, certificates — none of which appears on a SOD checklist. Only the COLOURS are
#  shared, via gr.palette().
# =======================================================================================

# Column widths, straight off the reference sheet. A is the crest gutter.
_WIDTHS = {"A": 6.43, "B": 30, "C": 12, "D": 16, "E": 12, "H": 22, "I": 12, "J": 7,
           "L": 11, "M": 2, "N": 30, "O": 13, "P": 11, "Q": 2, "R": 13, "S": 11, "V": 9}

# The row heights the reference uses for each kind of row, named so the builder reads as
# layout rather than as magic numbers.
_H_SECTION = 19.5      # a "▌ SECTION NAME" bar
_H_COLHEAD = 18.0      # the Check / Result / Status strip
_H_ROW = 18.0          # a data row
_H_GROUP = 15.75       # a labelled sub-group inside a section
_H_NOTE = 15.75        # the small grey source note under a table
_H_SPACER = 9.75       # the gap between sections
_H_BANNER = 19.5
_H_BANNER_NOTE = 27.75

_LAST_COL = 22         # V — the sign-off block's right edge, so paint covers the sheet


def build_report(data: dict, *, theme: str = "dark", author: str,
                 when=None, summary_comment: str = "") -> bytes:
    """Render the SOD checklist as .xlsx.

    `data` is a checklist dict as returned by blank_checklist()/from_post(). Blank fields
    are written as blanks — see the module docstring; that is the point of the sheet, not a
    gap in it.
    """
    import io

    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    if theme not in gr.PALETTES:
        theme = "dark"
    when = when or datetime.datetime.now()
    summary = summarise(data)

    with gr.palette(theme):
        T = gr.Theme

        def rgb(c):
            """Engine colours are 00RRGGBB; re-stamp them as FFRRGGBB — OPAQUE.

            The leading pair is the ALPHA channel. Excel ignores it, but LibreOffice, Google
            Sheets and several web previewers do not: they read 00 as fully transparent and
            drop every fill and font colour on the sheet, which renders this dark report as
            unstyled black-on-white and looks nothing like the approved file. The reference
            workbook stores FF throughout, so match it and the sheet survives whatever it is
            opened in.
            """
            return "FF" + str(c)[-6:]
        BG, CARD, HDR = rgb(T.BG), rgb(T.CARD), rgb(T.HDR)
        BORDER, INK, GREY = rgb(T.BORDER), rgb(T.WHITE), rgb(T.GREY)
        CYAN, SUB = rgb(T.CYAN), rgb(T.SUB)
        CHIP = {k: (rgb(v[0]), rgb(v[1])) for k, v in T.CHIP.items()}

        page = PatternFill("solid", fgColor=BG)
        card = PatternFill("solid", fgColor=CARD)
        head = PatternFill("solid", fgColor=HDR)
        edge = Side(style="thin", color=BORDER)
        box = Border(left=edge, right=edge, top=edge, bottom=edge)

        mono = lambda size=9, bold=False, color=None: Font(
            name="Consolas", size=size, bold=bold, color=color or INK)
        left = Alignment(horizontal="left", vertical="center")
        centre = Alignment(horizontal="center", vertical="center")
        wrap = Alignment(horizontal="left", vertical="top", wrap_text=True)
        # Banner notes wrap onto two lines but sit centred in the taller row, unlike the
        # sign-off block which is top-aligned because it is a stack of labelled lines.
        wrapc = Alignment(horizontal="left", vertical="center", wrap_text=True)

        wb = Workbook()
        ws = wb.active
        ws.title = "SOD Report"
        ws.sheet_view.showGridLines = False
        ws.sheet_properties.tabColor = CYAN
        for col, width in _WIDTHS.items():
            ws.column_dimensions[col].width = width

        def paint(row, fill=None):
            """Fill a whole row edge to edge.

            The canvas is painted rather than left to Excel's default white: on the dark
            theme an unpainted sheet frames the report in white and reads as broken. Both
            sibling reports paint for the same reason.
            """
            for c in range(1, _LAST_COL + 1):
                ws.cell(row, c).fill = fill or page

        def put(row, col, value, *, font=None, align=None, fill=None, merge=None):
            cell = ws.cell(row, col, value)
            cell.font = font or mono()
            cell.alignment = align or left
            if fill is not None:
                cell.fill = fill
            if merge:
                # The tail cells are deliberately left unstyled: Excel paints a merged range
                # from its anchor, and the reference sheet stores them unfilled too. Writing
                # a fill onto a MergedCell is a no-op in openpyxl anyway.
                ws.merge_cells(start_row=row, start_column=col,
                               end_row=row, end_column=merge)
            return cell

        # ---- header ------------------------------------------------------------------
        # The crest floats over the grid rather than sitting in a cell, exactly as it does
        # in the other two reports. A missing or unreadable logo is not worth failing a
        # report over, so it is skipped with a note on stderr.
        for row, ht in {1: 6, 2: 18, 3: 25.5, 4: 15, 5: 19.5, 6: 30}.items():
            ws.row_dimensions[row].height = ht
            paint(row)
        try:
            from openpyxl.drawing.image import Image as XLImage
            from openpyxl.drawing.spreadsheet_drawing import AnchorMarker, OneCellAnchor
            from openpyxl.drawing.xdr import XDRPositiveSize2D
            cfg = gr.load_config()
            img = XLImage(cfg.logo)
            img.anchor = OneCellAnchor(
                _from=AnchorMarker(col=cfg.logo_from_col, colOff=cfg.logo_from_coloff,
                                   row=cfg.logo_from_row, rowOff=cfg.logo_from_rowoff),
                ext=XDRPositiveSize2D(cx=cfg.logo_cx, cy=cfg.logo_cy))
            ws.add_image(img)
        except Exception as exc:                          # noqa: BLE001
            import sys as _sys
            print("[!] logo not embedded ({})".format(exc), file=_sys.stderr)

        put(3, 3, "NETWORK INFRASTRUCTURE SOD REPORT",
            font=mono(22, True, INK), fill=page, merge=12)
        put(4, 3, "snapshot generated {:%d %b %Y}  ·  Start-of-Day checklist".format(when),
            font=mono(9, False, SUB), fill=page, merge=12)
        put(5, 3, HEADER_NOTE, font=mono(9, False, GREY), fill=page, merge=8)
        put(5, 9, SOLARWINDS_LABEL, font=mono(12, True, CYAN), align=centre,
            fill=page, merge=13)

        # ---- summary strip -----------------------------------------------------------
        ws.row_dimensions[7].height = 18
        paint(7)
        put(7, 2, "Summary", font=mono(13, True, CYAN), fill=page)
        # Smaller and on the card fill, unlike "Summary" — it is the panel's caption rather
        # than a section heading, and the reference sheet sets it that way.
        put(7, 14, "Sign-off", font=mono(9, True, CYAN), fill=card, merge=22)

        ws.row_dimensions[8].height = 13.5
        paint(8)
        put(8, 2, "  AT A GLANCE  ·  daily checks & readings",
            font=mono(8, True, SUB), fill=page)
        # The sign-off panel spans N8:V13 in the reference — one wrapped cell, not six rows
        # of labels, so the engineer signs a block rather than a table.
        signoff = ("Date\n{:%d/%m/%Y}\n\nEngineer / Analyst\n{}\n\nSignature\n"
                   "________________________".format(when, author or ""))
        ws.merge_cells(start_row=8, start_column=14, end_row=13, end_column=22)
        so = ws.cell(8, 14, signoff)
        so.font = mono(9, False, GREY)
        so.alignment = wrap
        for r in range(8, 14):
            for c in range(14, 23):
                ws.cell(r, c).fill = card

        # the five headline counts, in the reference's own column groups
        stats = [
            (2, 2,  "  CORE & WAN CHECKS",  summary["core_wan_count"]),
            (3, 4,  "  FIREWALL CHECKS",    summary["firewall_count"]),
            (5, 6,  "  INTERNET CIRCUITS",  summary["circuit_count"]),
            (7, 9,  "  WLAN CONTROLLERS",   summary["controller_count"]),
            (10, 12, "  WAF APPS PROTECTED", summary["waf_count"]),
        ]
        ws.row_dimensions[9].height = 13.5
        ws.row_dimensions[10].height = 30
        paint(9)
        paint(10)
        for col, end, label, value in stats:
            put(9, col, label, font=mono(8, True, SUB), fill=head,
                merge=end if end > col else None)
            put(10, col, "  {}".format(value), font=mono(22, True, CYAN), fill=head,
                merge=end if end > col else None)

        # ---- needs attention ---------------------------------------------------------
        ws.row_dimensions[11].height = 13.5
        paint(11)
        put(11, 2, "  NEEDS ATTENTION", font=mono(8, True, SUB), fill=page)

        for r, ht in ((12, 18), (13, 25.5), (14, 15.75)):
            ws.row_dimensions[r].height = ht
            paint(r)
        attention = [
            (2, 3,  "LINKS DOWN",        summary["links_down"],
             "of {} checked".format(summary["ping_total"]),
             "red" if summary["links_down"] else "green"),
            (5, 6,  "DEGRADED CIRCUITS", summary["degraded_circuits"],
             "of {} circuits".format(summary["circuit_count"]),
             "amber" if summary["degraded_circuits"] else "green"),
            (8, 9,  "ROGUE APS FLAGGED", summary["rogue_controllers"],
             "of {} controllers".format(summary["controller_count"]),
             "amber" if summary["rogue_controllers"] else "green"),
        ]
        for col, end, label, value, sub, band in attention:
            fg, bg = CHIP[band]
            tint = PatternFill("solid", fgColor=bg)
            put(12, col, label, font=mono(8, True, SUB), align=centre, fill=tint, merge=end)
            put(13, col, str(value), font=mono(22, True, fg), align=centre, fill=tint, merge=end)
            put(14, col, sub, font=mono(8, False, SUB), align=centre, fill=tint, merge=end)

        ws.row_dimensions[15].height = _H_SPACER
        paint(15)
        r = 16

        # ---- warning banners ---------------------------------------------------------
        # The gaps here are the reference sheet's own: a 15pt breather BETWEEN banners, then
        # 9.75 + 7.5 after the last one before the first section bar. Getting this wrong
        # shifts every section below it by a row, which is exactly what makes two mornings'
        # sheets impossible to compare side by side.
        for i, banner in enumerate(summary["banners"]):
            fg, bg = CHIP[banner["band"]]
            tint = PatternFill("solid", fgColor=bg)
            ws.row_dimensions[r].height = _H_BANNER
            paint(r, tint)
            put(r, 2, "  " + banner["headline"], font=mono(10, True, fg), fill=tint, merge=12)
            r += 1
            for row in banner["rows"]:
                ws.row_dimensions[r].height = _H_ROW
                paint(r, tint)
                put(r, 2, "  " + row["name"], font=mono(9, True, INK), fill=tint, merge=5)
                put(r, 6, row["detail"], font=mono(9, False, GREY), fill=tint, merge=12)
                r += 1
            ws.row_dimensions[r].height = _H_BANNER_NOTE
            paint(r, tint)
            put(r, 2, "  " + banner["note"], font=mono(8, False, SUB),
                align=wrapc, fill=tint, merge=12)
            r += 1
            last = (i == len(summary["banners"]) - 1)
            ws.row_dimensions[r].height = _H_SPACER if last else 15.0
            paint(r)
            r += 1
        if summary["banners"]:
            ws.row_dimensions[r].height = 7.5
            paint(r)
            r += 1

        # ---- section helpers ---------------------------------------------------------
        def section(title):
            nonlocal r
            ws.row_dimensions[r].height = _H_SECTION
            paint(r, card)
            put(r, 2, "▌  " + title, font=mono(13, True, CYAN), fill=card, merge=12)
            r += 1

        def columns(labels):
            """The Check/Result/Status strip. `labels` is [(col, text), ...]."""
            nonlocal r
            ws.row_dimensions[r].height = _H_COLHEAD
            paint(r, head)
            for col, text in labels:
                put(r, col, text, font=mono(8, True, GREY), fill=head)
            for c in range(2, 13):
                ws.cell(r, c).fill = head
            r += 1

        def status_cell(row, col, status):
            """A status chip, or a plain blank when the row was never captured.

            An empty status deliberately gets NO chip colour: a green "OK"-shaped blank
            would read as a pass, and the whole point of this sheet is that an unanswered
            check is visibly unanswered.
            """
            if not status:
                put(row, col, "", fill=page)
                return
            fg, bg = CHIP[STATUS_BAND.get(status, "green")]
            put(row, col, status, font=mono(8, True, fg), align=centre,
                fill=PatternFill("solid", fgColor=bg))

        def data_row(values):
            """One table row: [(col, text, font), ...]."""
            nonlocal r
            ws.row_dimensions[r].height = _H_ROW
            paint(r)
            for col, text, fnt in values:
                put(r, col, text, font=fnt, fill=page)
            r += 1

        def note(text):
            nonlocal r
            ws.row_dimensions[r].height = _H_NOTE
            paint(r)
            put(r, 2, "  " + text, font=mono(8, False, SUB), fill=page, merge=12)
            r += 1

        def spacer(height=_H_SPACER):
            nonlocal r
            ws.row_dimensions[r].height = height
            paint(r)
            r += 1

        def check_rows(checks):
            nonlocal r
            for chk in checks:
                ws.row_dimensions[r].height = _H_ROW
                paint(r)
                put(r, 2, "  " + chk.label, font=mono(9, False, GREY), fill=page)
                # Readings are centred under their header, as in the reference — a column of
                # "3 ms" / "0 ms" left-aligned against a 12-wide column reads as ragged.
                put(r, 3, chk.result, font=mono(9, False, GREY), align=centre, fill=page)
                status_cell(r, 4, chk.status)
                r += 1

        # ---- core switches & WAN links -----------------------------------------------
        section("CORE SWITCHES & WAN LINKS")
        columns([(2, "Check"), (3, "Result"), (4, "Status")])
        check_rows(data["core_wan"])
        spacer()

        # ---- firewalls ---------------------------------------------------------------
        section("FIREWALLS")
        columns([(2, "Check"), (3, "Result"), (4, "Status")])
        for grp in data["firewalls"]:
            ws.row_dimensions[r].height = _H_GROUP
            paint(r, head)
            put(r, 2, "  " + grp.label, font=mono(8, True, CYAN), fill=head, merge=4)
            r += 1
            check_rows(grp.checks)
        spacer()

        # ---- floor switches ----------------------------------------------------------
        section("FLOOR SWITCHES")
        columns([(2, "Check"), (3, "Result"), (4, "Status")])
        check_rows(data["floor"])
        note(FLOOR_NOTE)
        spacer()

        # ---- internet circuits -------------------------------------------------------
        section("INTERNET CIRCUITS")
        columns([(2, "Provider"), (3, "Download"), (4, "Upload"), (5, "Latency"),
                 (6, "Jitter"), (7, "Pkt Loss"), (8, "Quality (Stream / Game / Chat)")])
        # The Pkt Loss column carries its own verdict in the reference: green for a clean
        # zero, amber for any loss or a failed test, muted grey for a reading that was never
        # taken. It is the one number on this table someone scans for, so it is coloured
        # rather than left to be read.
        def _reading_colour(text, bad_is_amber=True):
            t = str(text).strip().lower()
            if t in ("", "—", "-", "n/a"):
                return SUB                       # never measured — not a pass, not a fault
            if t in ("0", "0%", "0.0%"):
                return CHIP["green"][0]
            return CHIP["amber"][0] if bad_is_amber else GREY

        for c in data["circuits"]:
            data_row([(2, c.provider, mono(9, False, GREY)),
                      (3, c.download, mono(9, False, GREY)),
                      (4, c.upload,   mono(9, False, GREY)),
                      (5, c.latency,  mono(9, False, GREY)),
                      (6, c.jitter,   mono(9, False, GREY)),
                      (7, loss_short(c.loss), mono(9, False, _reading_colour(c.loss))),
                      (8, c.quality,  mono(9, False, GREY))])
        note(CIRCUIT_NOTE)
        spacer()

        # ---- wireless LAN controllers ------------------------------------------------
        section("WIRELESS LAN CONTROLLERS")
        columns([(2, "Site"), (3, "WLANs"), (4, "APs Active"), (5, "Clients Active"),
                 (6, "Rogue APs"), (7, "Interferers (2.4GHz)")])
        for w in data["controllers"]:
            data_row([(2, w.site,        mono(9, False, GREY)),
                      (3, w.wlans,       mono(9, False, GREY)),
                      (4, w.aps,         mono(9, False, GREY)),
                      (5, w.clients,     mono(9, False, GREY)),
                      # Coloured on the same rule as packet loss — a rogue-AP count is the
                      # other number on this sheet that is scanned rather than read.
                      (6, w.rogue,       mono(9, False, _reading_colour(w.rogue))),
                      (7, w.interferers, mono(9, False, GREY))])
        note(CONTROLLER_NOTE)
        spacer()

        # ---- DR Mazowe WAN links -----------------------------------------------------
        section("DR MAZOWE WAN LINKS")
        columns([(2, "Link"), (3, "Utilization (12h)"), (4, "Discards"), (5, "Errors"),
                 (6, "Status")])
        for d in data["dr_links"]:
            ws.row_dimensions[r].height = _H_ROW
            paint(r)
            put(r, 2, "  " + d.label, font=mono(9, False, GREY), fill=page)
            # Centred under their headers, as in the reference: these are short readings
            # ("Low", "0", "0") in wide columns, and left-aligning them reads as ragged.
            put(r, 3, d.utilization, font=mono(9, False, GREY), align=centre, fill=page)
            put(r, 4, d.discards, font=mono(9, False, GREY), align=centre, fill=page)
            put(r, 5, d.errors, font=mono(9, False, GREY), align=centre, fill=page)
            status_cell(r, 6, d.status)
            r += 1
        note(DR_NOTE)
        spacer()

        # ---- Radware WAF -------------------------------------------------------------
        section("RADWARE WEB APPLICATION FIREWALL")
        if summary["waf_clear"]:
            fg, bg = CHIP["green"]
            tint = PatternFill("solid", fgColor=bg)
            ws.row_dimensions[r].height = _H_BANNER
            paint(r, tint)
            put(r, 2, "  ALL CLEAR — No issues reported across {} protected "
                      "applications".format(WAF_PROTECTED_TOTAL),
                font=mono(10, True, fg), fill=tint, merge=12)
            r += 1
        spacer(6)

        # Three columns, the third without a Status beside it — the reference's own shape.
        apps = data["waf"]
        col1, col2, col3 = apps[0:6], apps[6:12], apps[12:16]
        ws.row_dimensions[r].height = _H_COLHEAD
        paint(r, head)
        for col, text in ((2, "Application"), (3, "Status"),
                          (8, "Application"), (9, "Status"),
                          (14, "Application"), (15, "Status")):
            put(r, col, text, font=mono(8, True, GREY), fill=head)
        r += 1
        for i in range(max(len(col1), len(col2), len(col3))):
            ws.row_dimensions[r].height = _H_ROW
            paint(r)
            for group, name_col in ((col1, 2), (col2, 8), (col3, 14)):
                if i < len(group):
                    put(r, name_col, "  " + group[i]["name"],
                        font=mono(9, False, GREY), fill=page)
                    # A chip, matching the OK/DOWN chips above rather than plain text: this
                    # column reads as a column of verdicts and the reference styles it so.
                    # An unanswered app stays an uncoloured blank, as everywhere else.
                    st = (group[i]["status"] or "").strip()
                    if st:
                        band = "green" if st.lower() == "protected" else "red"
                        fg, bg = CHIP[band]
                        put(r, name_col + 1, st, font=mono(8, True, fg), align=centre,
                            fill=PatternFill("solid", fgColor=bg))
                    else:
                        put(r, name_col + 1, "", fill=page)
            r += 1
        note("{} applications shown as protected in the Radware console; {} domains captured "
             "in this morning's view ({} additional not visible in the captured list)."
             .format(WAF_PROTECTED_TOTAL, len(apps), WAF_PROTECTED_TOTAL - len(apps)))

        # ---- the engineer's own note, when there is one -------------------------------
        # Placed above the footer rather than in the sign-off block: the block is what gets
        # signed and must stay a fixed shape, while this is free text that may run long.
        if summary_comment:
            spacer(12)
            ws.row_dimensions[r].height = _H_BANNER_NOTE
            paint(r)
            put(r, 2, "  " + summary_comment, font=mono(9, False, GREY),
                align=wrap, fill=page, merge=12)
            r += 1

        spacer(12)
        ws.row_dimensions[r].height = _H_NOTE
        paint(r)
        put(r, 2, FOOTER_NOTE, font=mono(7, False, SUB), fill=page, merge=12)
        r += 1

        # Paint a tail of blank rows so the dark canvas does not stop mid-screen. The
        # reference sheet carries its background to row 140, so match that floor rather than
        # stopping wherever this morning's content happened to end — otherwise a quiet day
        # produces a visibly shorter page than a busy one.
        for tail in range(r, max(141, r + 20)):
            ws.row_dimensions[tail].height = 15
            paint(tail)

        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()
