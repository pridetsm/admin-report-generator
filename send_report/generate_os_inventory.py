#!/usr/bin/env python3
"""
OS Inventory report — Windows and Linux versions for every monitored host.

Everything here comes straight out of Prometheus; no agent changes and no extra
exporters are needed. Two metrics carry the whole picture:

    windows_os_info{product, version, build_number, major_version,
                    minor_version, revision}      <- windows_exporter, `os` collector
    node_os_info{name, pretty_name, id, id_like,
                 version, version_id}             <- node_exporter, `os` collector

Both are constant gauges (value is always 1) — the data lives in the LABELS, so
they are scraped for labels rather than aggregated. A host that is down drops out
of the result set entirely instead of reporting a stale version, so "missing" here
means unreachable, not unknown.

Two more fill in the identity columns:

    windows_os_hostname{hostname, fqdn, domain}
    node_uname_info{nodename, release, machine}   <- kernel release

Lifecycle status is NOT from Prometheus. It comes from the vendor support dates in
LIFECYCLE below, evaluated against the report date. Those dates are hand-maintained
— re-check them against the vendor before quoting this report to anyone.

Patch level, by contrast, is self-contained: each host's minor version is compared
against the newest minor of that same OS major *running in this estate*. So "behind"
means behind your own newest build, which needs no external reference to stay true.

Usage
    python generate_os_inventory.py                       # dark theme, default output
    python generate_os_inventory.py --theme light
    python generate_os_inventory.py -o C:\\path\\OS.xlsx
    python generate_os_inventory.py --prom http://10.100.248.249:9090

Requires  Python 3.8+  and  openpyxl.
"""
from __future__ import annotations

import argparse
import datetime
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import openpyxl
from openpyxl.styles import Alignment, Border, Side
from openpyxl.utils import get_column_letter

from generate_report import Prometheus, Theme, load_config, palette

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "OS_Inventory.xlsx"


# ============================================================================ #
#  LIFECYCLE  (vendor support dates — hand-maintained, verify before quoting)
# ============================================================================ #
#  key      -> matched against the OS id + major version
#  full     -> date full/mainstream/premier support ends
#  extended -> date extended/ELS/maintenance support ends (None = no extended phase)
#  label    -> what to print in the Note column
LIFECYCLE: Dict[str, dict] = {
    # ---- Windows (matched on the product string) ----
    "win:2025": dict(full="2029-10-09", extended="2034-10-09",
                     label="Mainstream to 09 Oct 2029, extended to 09 Oct 2034"),
    "win:2022": dict(full="2026-10-13", extended="2031-10-13",
                     label="Mainstream to 13 Oct 2026, extended to 13 Oct 2031"),
    "win:2019": dict(full="2024-01-09", extended="2029-01-09",
                     label="Mainstream ended 09 Jan 2024, extended to 09 Jan 2029"),
    "win:2016": dict(full="2022-01-11", extended="2027-01-12",
                     label="Mainstream ended 11 Jan 2022, extended to 12 Jan 2027"),
    "win:2012": dict(full="2018-10-09", extended="2023-10-10",
                     label="Extended support ended 10 Oct 2023 — unsupported"),

    # ---- Oracle Linux (Premier -> Extended) ----
    "ol:9": dict(full="2032-06-30", extended=None,
                 label="Premier support to Jun 2032"),
    "ol:8": dict(full="2029-07-31", extended=None,
                 label="Premier support to Jul 2029"),
    "ol:7": dict(full="2024-12-31", extended="2028-06-30",
                 label="Premier ended Dec 2024, Extended Support to Jun 2028"),

    # ---- Red Hat Enterprise Linux (Maintenance -> ELS) ----
    "rhel:9": dict(full="2032-05-31", extended=None,
                   label="Maintenance support to 31 May 2032"),
    "rhel:8": dict(full="2029-05-31", extended=None,
                   label="Maintenance support to 31 May 2029"),
    "rhel:7": dict(full="2024-06-30", extended="2028-06-30",
                   label="Maintenance ended 30 Jun 2024, ELS to 30 Jun 2028"),

    # ---- CentOS ----
    "centos:8": dict(full="2021-12-31", extended=None,
                     label="CentOS 8 EOL 31 Dec 2021 — unsupported"),
    "centos:7": dict(full="2024-06-30", extended=None,
                     label="CentOS 7 EOL 30 Jun 2024 — unsupported, no vendor patches"),

    # ---- Ubuntu LTS (standard -> ESM) ----
    "ubuntu:24": dict(full="2029-04-30", extended="2036-04-30",
                      label="Standard support to Apr 2029, ESM to Apr 2036"),
    "ubuntu:22": dict(full="2027-06-30", extended="2032-04-30",
                      label="Standard support to Jun 2027, ESM to Apr 2032"),
    "ubuntu:20": dict(full="2025-05-31", extended="2030-04-30",
                      label="Standard support ended May 2025, ESM to Apr 2030"),
}

# id_like / id normalisation -> the LIFECYCLE key prefix
DISTRO_KEY = {
    "ol": "ol", "oracle": "ol",
    "rhel": "rhel", "redhatenterpriseserver": "rhel", "redhat": "rhel",
    "centos": "centos",
    "ubuntu": "ubuntu",
    "debian": "debian",
}


def lifecycle(key: str, today: datetime.date) -> Tuple[str, str, str]:
    """-> (status, band, note). Bands feed the chip colours: green/amber/red."""
    row = LIFECYCLE.get(key)
    if not row:
        return "Unknown", "amber", "No lifecycle data on file — verify with vendor"
    full = datetime.date.fromisoformat(row["full"])
    ext = datetime.date.fromisoformat(row["extended"]) if row["extended"] else None
    if today <= full:
        return "Supported", "green", row["label"]
    if ext and today <= ext:
        return "Extended only", "amber", row["label"]
    return "End of life", "red", row["label"]


# ============================================================================ #
#  HOSTS
# ============================================================================ #
@dataclass
class Host:
    system: str = "unassigned"
    component: str = ""         # friendly name, e.g. "RTGS Frontend 1"
    role: str = ""              # the raw scrape label, e.g. "frontend1" / "database"
    instance: str = ""          # ip:port, as Prometheus knows the target
    ip: str = ""
    port: str = ""
    platform: str = ""          # Windows | Linux
    hostname: str = ""
    product: str = ""           # "Windows Server 2022 Standard" / "Oracle Linux Server 8.10"
    version: str = ""           # "10.0.20348" / "8.10"
    build: str = ""             # Windows build+revision, or the Linux kernel release
    key: str = ""               # LIFECYCLE key, e.g. "ol:8"
    major: str = ""
    minor: Tuple[int, ...] = field(default_factory=tuple)   # sortable patch level
    status: str = ""
    band: str = "green"
    note: str = ""
    patch: str = ""
    patch_band: str = "green"


def _win_key(product: str) -> str:
    m = re.search(r"Windows Server\s+(\d{4})", product or "")
    return f"win:{m.group(1)}" if m else "win:?"


def _linux_key(labels: dict) -> Tuple[str, str]:
    """-> (lifecycle key, major). Falls back through id -> id_like -> name."""
    ident = (labels.get("id") or "").strip().lower()
    if ident not in DISTRO_KEY:
        for alt in (labels.get("id_like") or "").lower().split():
            if alt in DISTRO_KEY:
                ident = alt
                break
    if ident not in DISTRO_KEY:
        squashed = re.sub(r"[^a-z]", "", (labels.get("name") or "").lower())
        ident = next((k for k in DISTRO_KEY if k and k in squashed), ident)
    base = DISTRO_KEY.get(ident, ident or "?")
    ver = labels.get("version_id") or labels.get("version") or ""
    major = (re.match(r"\d+", ver) or [""])[0] if ver else ""
    return f"{base}:{major}", major


def _minor(ver: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", ver or ""))


def _component(labels: dict) -> str:
    """The friendly name, falling back to role then a bare dash for unlabelled targets."""
    return (labels.get("display") or labels.get("role") or "—").strip()


def _role(labels: dict) -> str:
    """The scrape `role` label. Windows targets mostly lack one, so fall back to the
       trailing word of the display name — "Efin DB" -> "db", "CRB Web" -> "web"."""
    role = (labels.get("role") or "").strip()
    if role:
        return role
    tail = (labels.get("display") or "").strip().rsplit(" ", 1)
    return tail[-1].lower() if len(tail) > 1 else ""


def _split(instance: str) -> Tuple[str, str]:
    """'10.100.249.243:9100' -> ('10.100.249.243', '9100'). Two Eagle targets share an
       IP and differ only by port, so the port earns its own column."""
    ip, _, port = instance.partition(":")
    return ip, port


def fetch(prom: Prometheus) -> List[Host]:
    hosts: Dict[str, Host] = {}

    # ---- Windows ---------------------------------------------------------- #
    # 10.0.212.3 is scraped by BOTH windows_exporter and the hourly swift_transactions
    # job, so it returns two identical series. Key on instance and let the real
    # windows_exporter row win — the swift row carries no `system` label.
    for s in prom.query("windows_os_info"):
        m = s["labels"]
        inst = m.get("instance", "")
        existing = hosts.get(inst)
        if existing and m.get("job") != "windows_exporter":
            continue
        build = m.get("build_number", "")
        rev = m.get("revision", "")
        ip, port = _split(inst)
        hosts[inst] = Host(
            system=m.get("system") or "unassigned",
            component=_component(m),
            role=_role(m),
            instance=inst,
            ip=ip,
            port=port,
            platform="Windows",
            product=m.get("product", ""),
            version=m.get("version", ""),
            build=f"Build {build}.{rev}" if rev else f"Build {build}",
            key=_win_key(m.get("product", "")),
            major=(re.search(r"(\d{4})", m.get("product", "")) or [None, ""])[1]
                  if re.search(r"(\d{4})", m.get("product", "")) else "",
            minor=_minor(rev),
        )

    for s in prom.query("windows_os_hostname"):
        m = s["labels"]
        if m.get("instance") in hosts:
            hosts[m["instance"]].hostname = m.get("hostname", "")

    # ---- Linux ------------------------------------------------------------ #
    for s in prom.query("node_os_info"):
        m = s["labels"]
        inst = m.get("instance", "")
        key, major = _linux_key(m)
        ip, port = _split(inst)
        hosts[inst] = Host(
            system=m.get("system") or "unassigned",
            component=_component(m),
            role=_role(m),
            instance=inst,
            ip=ip,
            port=port,
            platform="Linux",
            product=m.get("pretty_name") or m.get("name", ""),
            version=m.get("version_id") or m.get("version", ""),
            key=key,
            major=major,
            minor=_minor(m.get("version_id") or m.get("version", "")),
        )

    for s in prom.query("node_uname_info"):
        m = s["labels"]
        h = hosts.get(m.get("instance", ""))
        if h:
            h.hostname = m.get("nodename", "")
            h.build = m.get("release", "")

    return list(hosts.values())


def annotate(hosts: List[Host], today: datetime.date) -> None:
    """Fill in lifecycle status and patch level.

    Patch level compares each host against the newest minor of the same OS major
    running ANYWHERE in this estate — a self-contained yardstick that stays true
    without a vendor lookup. Windows compares the revision within one build."""
    newest: Dict[str, Tuple[int, ...]] = {}
    for h in hosts:
        grp = h.key if h.platform == "Linux" else f"{h.key}/{h.version}"
        if h.minor and h.minor > newest.get(grp, ()):
            newest[grp] = h.minor

    for h in hosts:
        h.status, h.band, h.note = lifecycle(h.key, today)
        grp = h.key if h.platform == "Linux" else f"{h.key}/{h.version}"
        top = newest.get(grp, ())
        if not h.minor or not top:
            h.patch, h.patch_band = "—", "green"
        elif h.minor >= top:
            h.patch, h.patch_band = "Current", "green"
        else:
            shown = ".".join(str(p) for p in top)
            h.patch, h.patch_band = f"Behind ({shown})", "amber"


# ============================================================================ #
#  WORKBOOK
# ============================================================================ #
BAND_RANK = {"red": 0, "amber": 1, "green": 2}


class Report:
    WIDTHS = {"A": 3, "B": 14, "C": 26, "D": 15, "E": 17, "F": 7, "G": 21,
              "H": 10, "I": 38, "J": 11, "K": 30, "L": 15, "M": 17, "N": 54}
    HEADERS = ["System", "Component", "Role", "IP address", "Port", "Host name",
               "Platform", "OS / Distribution", "Version", "Build / Kernel",
               "Lifecycle", "Patch level", "Support note"]

    def __init__(self, hosts: List[Host], prom_url: str, today: datetime.date):
        self.hosts = hosts
        self.prom_url = prom_url
        self.today = today
        self.wb = openpyxl.Workbook()
        self._thin = Side(style="thin", color=Theme.BORDER)

    # -- primitives (same shape as the daily report's, so the two files match) --
    def _cell(self, ws, r, c, v="", font=None, bg=None, al="left", border=False):
        x = ws.cell(r, c)
        x.value = v
        x.font = font or Theme.font()
        x.fill = Theme.fill(bg if bg is not None else Theme.BG)
        x.alignment = Alignment(horizontal=al, vertical="center")
        if border:
            x.border = Border(self._thin, self._thin, self._thin, self._thin)
        return x

    def _merge(self, ws, r, c1, c2, v, font, bg=None, al="left"):
        for c in range(c1, c2 + 1):
            self._cell(ws, r, c, v if c == c1 else "", font, bg, al)
        ws.merge_cells(start_row=r, start_column=c1, end_row=r, end_column=c2)

    def _chip(self, ws, r, c, text, band):
        fg, bg = Theme.CHIP[band]
        self._cell(ws, r, c, text, Theme.font(9, True, fg), bg=bg, al="center", border=True)

    def _canvas(self, ws, rows=80, cols=12):
        for r in range(1, rows + 1):
            for c in range(1, cols + 1):
                self._cell(ws, r, c)

    def _title(self, ws, row, text, sub, span=(2, 12)):
        self._merge(ws, row, span[0], span[1], text, Theme.font(14, True, Theme.CYAN))
        ws.row_dimensions[row].height = 22
        self._merge(ws, row + 1, span[0], span[1], sub, Theme.font(8, False, Theme.SUB))
        return row + 3

    # -- sheets ------------------------------------------------------------- #
    def build(self):
        self._inventory()
        self._summary()
        self._attention()
        # Summary reads first; openpyxl silently ignores an out-of-range offset, and
        # "Summary" is created at index 1, so -1 is the only move that lands.
        self.wb.move_sheet("Summary", offset=-1)
        self.wb.active = self.wb.sheetnames.index("Summary")
        return self.wb

    def _inventory(self):
        ws = self.wb.active
        ws.title = "OS Inventory"
        ws.sheet_view.showGridLines = False
        for col, w in self.WIDTHS.items():
            ws.column_dimensions[col].width = w
        self._canvas(ws, rows=len(self.hosts) + 12, cols=14)

        stamp = self.today.strftime("%d %b %Y")
        row = self._title(ws, 2, "Operating System Inventory",
                          f"{len(self.hosts)} monitored hosts · sourced live from "
                          f"{self.prom_url} · generated {stamp}", span=(2, 14))

        head = row
        for i, h in enumerate(self.HEADERS):
            self._cell(ws, head, 2 + i, h, Theme.font(9, True, Theme.CYAN),
                       bg=Theme.HDR, al="center", border=True)
        ws.row_dimensions[head].height = 18

        # worst-first: EOL at the top, then extended, then by system name
        ordered = sorted(self.hosts, key=lambda h: (BAND_RANK[h.band],
                                                    BAND_RANK[h.patch_band],
                                                    h.system.lower(), h.component.lower()))
        r = head
        for h in ordered:
            r += 1
            zebra = Theme.CARD if (r - head) % 2 == 0 else Theme.BG
            vals = [h.system, h.component, h.role, h.ip, h.port, h.hostname,
                    h.platform, h.product, h.version, h.build]
            for i, v in enumerate(vals):
                self._cell(ws, r, 2 + i, v, Theme.font(9), bg=zebra,
                           al="center" if i == 4 else "left", border=True)
            self._chip(ws, r, 12, h.status, h.band)
            self._chip(ws, r, 13, h.patch, h.patch_band)
            self._cell(ws, r, 14, h.note, Theme.font(8, False, Theme.SUB),
                       bg=zebra, border=True)

        ws.auto_filter.ref = f"B{head}:N{r}"
        ws.freeze_panes = ws.cell(head + 1, 5)      # System / Component / Role stay visible
        self._cell(ws, r + 2, 2,
                   "Lifecycle dates are vendor support data held in this script, not Prometheus — "
                   "re-verify before circulating. Patch level compares each host to the newest "
                   "minor of the same OS major running in this estate.",
                   Theme.font(8, False, Theme.SUB))

    def _summary(self):
        ws = self.wb.create_sheet("Summary")
        ws.sheet_view.showGridLines = False
        for col, w in {"A": 3, "B": 40, "C": 12, "D": 16, "E": 54}.items():
            ws.column_dimensions[col].width = w
        self._canvas(ws, rows=60, cols=5)

        row = self._title(ws, 2, "OS Inventory — Summary",
                          f"Generated {self.today.strftime('%d %b %Y')} from {self.prom_url}",
                          span=(2, 5))

        # ---- headline counts ---- #
        eol = [h for h in self.hosts if h.band == "red"]
        ext = [h for h in self.hosts if h.band == "amber"]
        behind = [h for h in self.hosts if h.patch_band == "amber"]
        wins = [h for h in self.hosts if h.platform == "Windows"]
        lin = [h for h in self.hosts if h.platform == "Linux"]

        tiles = [("Hosts", len(self.hosts), "green"),
                 ("Windows", len(wins), "green"),
                 ("Linux", len(lin), "green"),
                 ("End of life", len(eol), "red" if eol else "green"),
                 ("Extended only", len(ext), "amber" if ext else "green"),
                 ("Behind on patches", len(behind), "amber" if behind else "green")]
        for label, count, band in tiles:
            self._cell(ws, row, 2, label, Theme.font(9, False, Theme.GREY),
                       bg=Theme.CARD, border=True)
            self._chip(ws, row, 3, str(count), band)
            self._cell(ws, row, 4, "", bg=Theme.CARD, border=True)
            self._cell(ws, row, 5, "", bg=Theme.CARD, border=True)
            row += 1
        row += 2

        # ---- breakdown by OS build ---- #
        self._merge(ws, row, 2, 5, "Estate by operating system",
                    Theme.font(11, True, Theme.CYAN))
        row += 1
        for i, h in enumerate(["Operating system", "Hosts", "Lifecycle", "Support note"]):
            self._cell(ws, row, 2 + i, h, Theme.font(9, True, Theme.CYAN),
                       bg=Theme.HDR, al="center", border=True)
        head = row

        groups: Dict[str, List[Host]] = {}
        for h in self.hosts:
            groups.setdefault(h.product or "(unknown)", []).append(h)

        for name, members in sorted(groups.items(),
                                    key=lambda kv: (BAND_RANK[kv[1][0].band], -len(kv[1]))):
            row += 1
            zebra = Theme.CARD if (row - head) % 2 == 0 else Theme.BG
            self._cell(ws, row, 2, name, Theme.font(9), bg=zebra, border=True)
            self._cell(ws, row, 3, len(members), Theme.font(9, True), bg=zebra,
                       al="center", border=True)
            self._chip(ws, row, 4, members[0].status, members[0].band)
            self._cell(ws, row, 5, members[0].note, Theme.font(8, False, Theme.SUB),
                       bg=zebra, border=True)

    def _attention(self):
        """Only the hosts that need a decision — EOL, extended-only, or behind."""
        flagged = [h for h in self.hosts if h.band != "green" or h.patch_band != "green"]
        ws = self.wb.create_sheet("Needs attention")
        ws.sheet_view.showGridLines = False
        for col, w in {"A": 3, "B": 14, "C": 26, "D": 15, "E": 17, "F": 21,
                       "G": 38, "H": 11, "I": 30, "J": 15, "K": 54}.items():
            ws.column_dimensions[col].width = w
        self._canvas(ws, rows=len(flagged) + 12, cols=11)

        row = self._title(ws, 2, "Needs attention",
                          f"{len(flagged)} of {len(self.hosts)} hosts are past full vendor "
                          "support or behind the newest minor you run", span=(2, 11))
        if not flagged:
            self._cell(ws, row, 2, "Nothing flagged.", Theme.font(10, True, Theme.CHIP["green"][0]))
            return

        for i, h in enumerate(["System", "Component", "Role", "IP address", "Host name",
                               "OS / Distribution", "Version", "Lifecycle",
                               "Patch level", "Support note"]):
            self._cell(ws, row, 2 + i, h, Theme.font(9, True, Theme.CYAN),
                       bg=Theme.HDR, al="center", border=True)
        head = row
        for h in sorted(flagged, key=lambda h: (BAND_RANK[h.band], BAND_RANK[h.patch_band],
                                                h.system.lower())):
            row += 1
            zebra = Theme.CARD if (row - head) % 2 == 0 else Theme.BG
            for i, v in enumerate([h.system, h.component, h.role, h.ip, h.hostname,
                                   h.product, h.version]):
                self._cell(ws, row, 2 + i, v, Theme.font(9), bg=zebra, border=True)
            self._chip(ws, row, 9, h.status, h.band)
            self._chip(ws, row, 10, h.patch, h.patch_band)
            self._cell(ws, row, 11, h.note, Theme.font(8, False, Theme.SUB), bg=zebra, border=True)

        ws.freeze_panes = ws.cell(head + 1, 5)      # System / Component / Role stay visible


# ============================================================================ #
#  CLI
# ============================================================================ #
def main(argv=None) -> int:
    cfg = load_config()
    ap = argparse.ArgumentParser(description="Build the OS inventory workbook.")
    ap.add_argument("--prom", default=cfg.prom, help="Prometheus base URL")
    ap.add_argument("-o", "--out", default=str(DEFAULT_OUT), help="output .xlsx path")
    ap.add_argument("--theme", choices=("dark", "light"), default="dark")
    args = ap.parse_args(argv)

    prom = Prometheus(args.prom)
    try:
        prom.ping()
    except Exception as exc:
        print(f"cannot reach Prometheus at {args.prom}: {exc}", file=sys.stderr)
        return 2

    today = datetime.date.today()
    hosts = fetch(prom)
    if not hosts:
        print("no windows_os_info / node_os_info series returned — is the `os` "
              "collector enabled on the exporters?", file=sys.stderr)
        return 1
    annotate(hosts, today)

    with palette(args.theme):
        wb = Report(hosts, args.prom, today).build()
    out = Path(args.out)
    wb.save(out)

    eol = sum(1 for h in hosts if h.band == "red")
    ext = sum(1 for h in hosts if h.band == "amber")
    print(f"wrote {out}  ({len(hosts)} hosts, {eol} end-of-life, {ext} extended-support-only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
