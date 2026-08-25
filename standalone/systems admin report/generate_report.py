#!/usr/bin/env python3
"""
generate_report.py
==================================================================================
System Admin Report generator.

Captures live metrics straight from a Prometheus server and renders a themed,
dark-mode XLSX report that mirrors the Grafana "System Admin Dashboard (Green)":

    • An overview band  - coverage + health KPIs (accented left-bar cards) and a
      live link to the Grafana dashboard.
    • One card per system - Services | Memory | Disk laid out side by side, with
      green / amber / red status chips.

The script is fully self-contained: the system topology, the service checks and
the visual theme are all declared below, so the only external dependency at run
time is a reachable Prometheus endpoint.

The same engine backs three callers, so they always agree:
    • this CLI (scheduled runs / run.bat),
    • mail_report.py --attach (the xlsx e-mailed with the daily snapshot),
    • the Django Report Generator webapp (reports/services.py -> build_report_bytes).

    Usage:
        python generate_report.py
        python generate_report.py --theme light --author "P. Moyo" --stamp
        python generate_report.py --systems "RTGS,T24" --out scoped.xlsx
        python generate_report.py --prom http://10.100.248.249:9090 --out report.xlsx

    Requirements:
        Python 3.8+   and   openpyxl   (pip install openpyxl)
==================================================================================
"""
from __future__ import annotations

import argparse
import configparser
import contextlib
import datetime
import io
import json
import math
import re
import ssl
import sys
import threading
import urllib.parse
import urllib.request
from collections import namedtuple
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import openpyxl
from openpyxl.utils import get_column_letter
from openpyxl.drawing.image import Image as XLImage
from openpyxl.drawing.spreadsheet_drawing import AnchorMarker, OneCellAnchor
from openpyxl.drawing.xdr import XDRPositiveSize2D
from openpyxl.styles import Alignment, Border, Color, Font, PatternFill, Side
from openpyxl.worksheet.datavalidation import DataValidation


# ============================================================================ #
#  CONFIGURATION
# ============================================================================ #
@dataclass
class Config:
    prom: str = "https://10.100.248.249:9090"
    grafana: str = (
        "https://10.100.248.249:3000/d/05e1d489-469b-4557-a0e9-73d782b60e844/"
        "system-admin-dashboard-green?orgId=1&from=now-5m&to=now&timezone=browser"
        "&var-Filters=&refresh=30s"
    )
    out: str = "System Admin Report.xlsx"
    prometheus_yml: str = "../prometheus.yml"   # topology source (system labels), just outside this folder
    logo: str = "logo.png"         # company logo (transparent PNG, with reflection)
    # exact logo placement, captured from the approved report layout (EMU; 1 px = 9525 EMU)
    logo_from_col: int = 1         # anchored in column B (0-indexed)
    logo_from_coloff: int = 448946 # ~47 px into the column
    logo_from_row: int = 2         # row 3 (0-indexed)
    logo_from_rowoff: int = 95250  # ~10 px down
    logo_cx: int = 503554          # display width  ~53 px
    logo_cy: int = 990599          # display height ~104 px
    overview_threshold: int = 85   # headline "disk/ram usage over N%" counters
    chip_amber: int = 75           # per-cell chip thresholds (used % >= amber -> amber)
    chip_red: int = 90             # used % >= red -> red
    http_timeout: int = 20
    # LDAP / auth service probe: the blackbox `probe_success` instance label that reports whether
    # the authentication service (that GCMS, GMS, ... depend on) is up. Blank = not monitored.
    ldap_target: str = "vault.rbz.co.zw:7272"
    # set false for an internal Prometheus serving a self-signed cert (matches the verify_tls
    # pattern already used for [auth]/[keycloak] elsewhere in this app)
    verify_tls: bool = True


HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.ini"


def load_config(path=None) -> "Config":
    """Build a Config from config.ini, falling back to the dataclass defaults."""
    cfg = Config()
    cp = configparser.ConfigParser()
    if cp.read(path or DEFAULT_CONFIG):
        if cp.has_section("prometheus"):
            cfg.prom = cp["prometheus"].get("url", cfg.prom)
            cfg.prometheus_yml = cp["prometheus"].get("yml", cfg.prometheus_yml)
            cfg.verify_tls = cp["prometheus"].getboolean("verify_tls", cfg.verify_tls)
        if cp.has_section("grafana"):
            cfg.grafana = cp["grafana"].get("url", cfg.grafana)
        if cp.has_section("report"):
            r = cp["report"]
            cfg.out = r.get("output", cfg.out)
            cfg.overview_threshold = r.getint("overview_threshold", cfg.overview_threshold)
            cfg.chip_amber = r.getint("chip_amber", cfg.chip_amber)
            cfg.chip_red = r.getint("chip_red", cfg.chip_red)
            cfg.ldap_target = r.get("ldap_target", cfg.ldap_target).strip()
        if cp.has_section("logo"):
            g = cp["logo"]
            cfg.logo = g.get("path", cfg.logo)
            cfg.logo_from_col = g.getint("from_col", cfg.logo_from_col)
            cfg.logo_from_coloff = g.getint("from_coloff", cfg.logo_from_coloff)
            cfg.logo_from_row = g.getint("from_row", cfg.logo_from_row)
            cfg.logo_from_rowoff = g.getint("from_rowoff", cfg.logo_from_rowoff)
            cfg.logo_cx = g.getint("cx", cfg.logo_cx)
            cfg.logo_cy = g.getint("cy", cfg.logo_cy)
    # resolve asset / output / topology paths relative to this package folder
    if not Path(cfg.logo).is_absolute():
        cfg.logo = str(HERE / cfg.logo)
    if not Path(cfg.out).is_absolute():
        cfg.out = str(HERE / cfg.out)
    if not Path(cfg.prometheus_yml).is_absolute():
        cfg.prometheus_yml = str((HERE / cfg.prometheus_yml).resolve())
    return cfg


# ============================================================================ #
#  THEME  (palette + small style factories, lifted from the original template)
# ============================================================================ #
class Theme:
    BG, CARD, HDR, BORDER = "000E1620", "00121E2B", "001B2836", "0026323F"
    WHITE, GREY, CYAN, SUB = "00E7EEF5", "00AFBBC7", "005BC0D4", "007F93A6"
    CHIP = {                                   # (font, background) per status band
        "green": ("004CC9A4", "0014322B"),
        "amber": ("00E8B04B", "003A2F14"),
        "red":   ("00EF6A5A", "003A1A16"),
        # "critical" — reserved for unreachable components alone: the highest-severity
        # finding, since it means Prometheus itself has lost visibility (every other red
        # finding is at least still being measured). Same tint as "red" (a slight escalation,
        # not a new visual language); a punchier, more saturated accent than the warm-coral
        # "red" carries it. Always paired with an explicit label, never color alone.
        "critical": ("00FF4438", "003A1A16"),
    }
    INFO = ("005BC0D4", "001B2836")            # neutral overview accent

    @staticmethod
    def font(size: int = 9, bold: bool = False, color: Optional[str] = None) -> Font:
        return Font(name="Times New Roman", size=size, bold=bold, color=Color(rgb=color or Theme.WHITE))

    @staticmethod
    def fill(color: str) -> PatternFill:
        return PatternFill(patternType="solid", fgColor=color)


# -- selectable palettes (dark is the default; light is the same layout, re-coloured).
#    Values are swapped onto the Theme class for the duration of a build (see `palette`),
#    so the whole builder re-themes without touching its ~80 Theme.* references. --------
# ---------------------------------------------------------------------------------------
#  BANNER SEVERITY — three levels, named on every banner.
#
#  The label is written into the headline, not just implied by an accent colour, so the
#  escalation survives a black-and-white print and a reader who does not know the palette.
#
#    imminent  an outage is underway, or we have lost the ability to see one
#    critical  not down yet, but it will take the service down if left
#    warning   needs attention; nothing is failing because of it right now
#
#  `chip` maps a severity onto the existing colour bands, so this adds a vocabulary rather
#  than a new visual language.
# ---------------------------------------------------------------------------------------
SEVERITY = {
    "imminent": {"label": "IMMINENT", "chip": "critical", "rank": 0},
    "critical": {"label": "CRITICAL", "chip": "red", "rank": 1},
    "warning": {"label": "WARNING", "chip": "amber", "rank": 2},
}


_THEME_KEYS = ("BG", "CARD", "HDR", "BORDER", "WHITE", "GREY", "CYAN", "SUB", "CHIP", "INFO")

PALETTES: Dict[str, Dict[str, object]] = {
    "dark": {   # the original, unchanged palette (kept identical so dark output never shifts)
        "BG": "000E1620", "CARD": "00121E2B", "HDR": "001B2836", "BORDER": "0026323F",
        "WHITE": "00E7EEF5", "GREY": "00AFBBC7", "CYAN": "005BC0D4", "SUB": "007F93A6",
        "CHIP": {"green": ("004CC9A4", "0014322B"), "amber": ("00E8B04B", "003A2F14"),
                 "red": ("00EF6A5A", "003A1A16"), "critical": ("00FF4438", "003A1A16")},
        "INFO": ("005BC0D4", "001B2836"),
    },
    "light": {  # matched to the approved reference (webapp/System_Admin_Report_Light.xlsx):
                # white canvas, dark slate text, vivid chips — higher contrast than a soft theme
        "BG": "00FFFFFF", "CARD": "00F2F5F8", "HDR": "00F5F7FA", "BORDER": "00E1E6EA",
        "WHITE": "0016232E", "GREY": "005B6B78", "CYAN": "000E7C93", "SUB": "0051707F",
        "CHIP": {"green": ("000E9C74", "00E8F6F0"), "amber": ("00B8790A", "00FFF6E0"),
                 "red": ("00D14A3A", "00FDEBEA"), "critical": ("00B02318", "00FDEBEA")},
        "INFO": ("000E7C93", "00F5F7FA"),
    },
}
_palette_lock = threading.RLock()


@contextlib.contextmanager
def palette(name: str):
    """Swap the Theme palette to `name` ('dark'|'light') for the duration of a build, then
       restore it. Serialised by a lock so concurrent builds in one process can't interleave
       palettes. Colours are baked into the workbook cells during build(), so saving after the
       context exits is safe."""
    if name not in PALETTES:
        name = "dark"
    with _palette_lock:
        saved = {k: getattr(Theme, k) for k in _THEME_KEYS}
        try:
            for k, v in PALETTES[name].items():
                setattr(Theme, k, v)
            yield
        finally:
            for k, v in saved.items():
                setattr(Theme, k, v)


# ============================================================================ #
#  PROMETHEUS CLIENT
# ============================================================================ #
class Prometheus:
    """Minimal read-only client for the Prometheus HTTP API (instant queries)."""

    def __init__(self, base: str, timeout: int = 20, verify_tls: bool = True):
        self.base = base.rstrip("/")
        self.timeout = timeout
        # unverified context only when explicitly opted out (verify_tls=False) — e.g. an
        # internal Prometheus serving a self-signed cert. None = urllib's normal verification.
        self._ssl_context = None if verify_tls else ssl._create_unverified_context()

    def query(self, expr: str) -> List[dict]:
        body = urllib.parse.urlencode({"query": expr}).encode()
        req = urllib.request.Request(self.base + "/api/v1/query", data=body)
        with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
            payload = json.loads(resp.read().decode())
        if payload.get("status") != "success":
            raise RuntimeError(f"query failed: {payload.get('error', 'unknown error')}")
        return [{"labels": s["metric"], "value": float(s["value"][1])}
                for s in payload["data"]["result"]]

    def scalar(self, expr: str) -> Optional[float]:
        res = self.query(expr)
        return res[0]["value"] if res else None

    def ping(self) -> None:
        self.query("vector(1)")


# ============================================================================ #
#  TOPOLOGY  (what to capture, grouped by system)
# ============================================================================ #
@dataclass
class Component:
    label: str
    instance: str
    os: str = ""                 # "windows" | "linux" | "" when the scrape job doesn't say


@dataclass
class Service:
    name: Optional[str]          # fixed display name ...
    expr: str
    name_label: Optional[str] = None   # ... or pull the name from this series label
    kind: str = "system"         # "system" = keeps the platform running · "offered" = delivered to users
    shorten: bool = True         # run the generic name tidier (off for T24 path-style names)
    prefix: str = ""             # prepended to the per-series name — disambiguates rows whose
                                 # label value collides with another check (e.g. FE vs backend JBoss)
    group: Optional[str] = None  # fixed component sub-group; None -> take it from each series'
                                 # `display` label (the host/component the metric belongs to)


# the two service classes, with the captions used as in-table sub-headers
SERVICE_KIND_LABELS = {
    "system":  "SYSTEM SERVICES",      # infrastructure: keeps the platform running
    "offered": "OFFERED SERVICES",     # business endpoints: delivered to users
}
SERVICE_KIND_ORDER = {"system": 0, "offered": 1}


@dataclass
class System:
    name: str
    components: List[Component]
    services: List[Service] = field(default_factory=list)


# -- small PromQL builders so the service table stays readable ----------------
def win_service(name: str, inst: str) -> str:
    # keep `display` in the aggregation so the row self-attributes to its host/component
    # (the sub-group under SYSTEM SERVICES); the value is unchanged since display is constant here.
    return f'max by (name, display) (windows_service_state{{name="{name}", instance="{inst}"}})'


def systemd(inst: str, name: str, type_: Optional[str] = None) -> str:
    typ = f', type="{type_}"' if type_ else ""
    return f'node_systemd_unit_state{{instance="{inst}", name="{name}", state="active"{typ}}}'


def probe(inst: str) -> str:
    return f'probe_success{{instance="{inst}"}}'


def host_up(inst: str) -> str:
    return f'up{{job="windows_exporter", instance="{inst}"}}'


def _t24_label(name: str) -> str:
    """Tidy a T24 TSA service path for display: drop the BNK/ product prefix
    (e.g. 'BNK/SWIFT.IN' -> 'SWIFT.IN'). Leaves anything else untouched."""
    return name[4:] if name.startswith("BNK/") else name


# -- service-health checks per system (PromQL); the host topology itself is read
#    from prometheus.yml. Keyed by NORMALISED system name (lower-case, alnum only)
#    so it matches whatever the `system` label says in prometheus.yml.
# Each Service carries a `kind`:  "system"  (infrastructure that keeps the platform
# running — DBs, listeners, web/app servers, proxies, OS daemons)  vs  "offered"
# (business endpoints delivered to users — site probes, the T24 TSA services, the
# named application/API services). Flip a `kind=` to reclassify a single row.
SERVICE_CHECKS: Dict[str, List[Service]] = {
    "rtgs": [
        Service(None, "jboss_status", name_label="name"),
        Service(None, "fe_jboss_status", name_label="component"),   # front-end JBoss: id'd by `component` (no `name` label); its component sub-group distinguishes it from backend
        Service(None, "max by (service, display) (oracle_listener_instance_status)", name_label="service"),   # keep `display` -> row groups under RTGS Database (per the "RTGS DB Services" panel)
        Service("RTGS apache2 Service", systemd("10.100.246.70:9100", "apache2.service", "forking")),
    ],
    "rtgstest": [
        Service("RTGS site", probe("https://rtgs.rbz.co.zw/"), kind="offered"),
        Service("RTGS reverse Proxy", probe("10.100.246.70")),
        Service("Apache2", systemd("10.100.249.67:9100", "apache2")),
    ],
    "temenos": [
        # BrowserWeb is monitored as a WEB LINK (see LINK_CHECKS) — not duplicated here
        Service("MSSQLSERVER", win_service("MSSQLSERVER", "10.0.212.4:9182")),
        # T24 TSA business services (BNK/SWIFT.IN, BNK/PAYNET, ...): name from the
        # `service` label, 1 = running / 0 = expected-but-down (see t24_services.yml)
        Service(None, "t24_service_up", name_label="service", kind="offered", shorten=False),
    ],
    "efin": [
        Service("Oracle DB Listener", win_service("OracleOraDB19Home1TNSListener", "10.0.201.3:9182")),
        Service("EFINL service", win_service("OracleServiceEFINL", "10.0.201.3:9182")),
        Service("EFINT service", win_service("OracleServiceEFINT", "10.0.201.3:9182")),
        Service("DBARCL service", win_service("OracleServiceDBARCL", "10.0.201.3:9182")),
        Service("DBARCT service", win_service("OracleServiceDBARCT", "10.0.201.3:9182")),
        Service("RCUL service", win_service("OracleServiceRCUL", "10.0.201.3:9182")),
    ],
    "cms": [Service("CMS Service", systemd("10.100.248.10:9100", "currency.service", "simple"), kind="offered")],
    "csd": [Service("InternalServiceHost", host_up("10.100.240.116:9182"), kind="offered"),
            Service("InternalApi", host_up("10.100.240.116:9182"), kind="offered")],
    "esf": [Service("ESF httpd Service", systemd("10.100.245.70:9100", "httpd.service"))],
    "esfexec": [Service("ESFEXEC httpd Service", systemd("10.100.245.240:9100", "httpd.service"))],
    "rbzwebsite": [Service("apache2 httpd Service", systemd("10.100.245.46:9100", "apache2.service"))],
    "eagle": [Service("Eagle httpd Service", systemd("10.100.245.70:9100", "httpd.service"))],
    "cepecs": [Service("InternalServiceHost", host_up("10.100.240.116:9182"), kind="offered"),
               Service("InternalApi", host_up("10.100.240.116:9182"), kind="offered")],
    "cebas": [Service("InternalServiceHost", host_up("10.100.240.116:9182"), kind="offered"),
              Service("InternalApi", host_up("10.100.240.116:9182"), kind="offered")],
    "crb": [Service("InternalServiceHost", host_up("10.100.240.116:9182"), kind="offered"),
            Service("InternalApi", host_up("10.100.240.116:9182"), kind="offered")],
    "intranet": [Service("Apache2", systemd("10.100.248.40:9100", "apache2.service", "forking")),
                 Service("MySQL",   systemd("10.100.248.40:9100", "mysql.service", "notify"))],
    "frs": [Service("Apache2", systemd("10.100.245.150:9100", "apache2.service", "forking")),
            Service("MySQL",   systemd("10.100.245.150:9100", "mysql.service", "notify"))],
    "bsa": [Service("MSSQLSERVER",   win_service("MSSQLSERVER", "10.0.206.5:9182")),
            Service("BSAv50Monitor", win_service("BSAv50Monitor", "10.0.206.5:9182")),
            Service("BSAv50Parser",  win_service("BSAv50Parser", "10.0.206.5:9182")),
            Service("Nginx Reverse Proxy", systemd("192.168.25.156:9100", "nginx.service", "forking")),
            Service("Docker",             systemd("10.0.206.6:9100", "docker.service", "notify"))],
    "collateralregistry": [Service("IIS (W3SVC)", win_service("W3SVC", "10.0.207.8:9182")),
                           Service("MSSQLSERVER", win_service("MSSQLSERVER", "10.0.207.9:9182"))],
    "edms": [Service("MSSQLSERVER", win_service("MSSQLSERVER", "10.0.206.11:9182")),
             Service("IIS (W3SVC)", win_service("W3SVC", "10.0.206.12:9182"))],
    "ebis": [Service("IIS (W3SVC)", win_service("W3SVC", "10.0.207.20:9182")),
             Service("MSSQLSERVER", win_service("MSSQLSERVER", "10.0.207.21:9182"))],
    "refinitivreuters": [
        Service("Post Trade 1.9 Conversation Printer RESZ",
                win_service("PT_1.9_CONVPRT_RESZ", "10.100.245.216:9182")),
        Service("Post Trade 1.9 Feeds Administrator",
                win_service("PT_1.9_FeedsGUI", "10.100.245.216:9182")),
        Service("Post Trade 1.9 Ticket Feed (TOF) RESZ",
                win_service("PT_1.9_TOF_RESZ", "10.100.245.216:9182")),
        Service("Post Trade 1.9 Ticket Printer RESZ",
                win_service("PT_1.9_TKTPRT_RESZ", "10.100.245.216:9182")),
    ],
    # "Assets Mgt" (assetsmgt.service) was removed 2026-08-24: confirmed via a full active-unit
    # listing on this host that the unit no longer exists at all (not failed/stopped -- gone,
    # not in node_exporter's systemd collector output under any state), so this check had been
    # reporting DOWN on every single report regardless of the app's real health -- a standing
    # false alarm, not a real finding. asset-management.service is the live, currently-active
    # unit and is the one actually worth watching (confirmed active).
    "assetregistry": [
        Service("Asset Management", systemd("10.100.245.249:9100", "asset-management.service", "simple")),
        Service("MySQL",            systemd("10.100.245.249:9100", "mysql.service", "notify")),
    ],
    # httpd/postgres run INSIDE Docker containers on both hosts, not as systemd units — no
    # cAdvisor/docker exporter is deployed here, so container internals aren't visible to
    # Prometheus at all yet. Docker.service itself is the only real, checkable signal for now
    # (confirmed live, type="notify" on both) — a docker.service that's down definitely means
    # the containers are down too, but "up" doesn't guarantee httpd/postgres inside are healthy.
    "attendancesystem": [
        Service("Docker", systemd("10.0.207.16:9100", "docker.service", "notify"), group="Attendance App"),
        Service("Docker", systemd("10.0.207.17:9100", "docker.service", "notify"), group="Attendance DB"),
    ],
}

# preferred display order (known systems first); anything else is appended A-Z
SYSTEM_ORDER = ["RTGS", "RTGSTEST", "Temenos", "Efin", "CMS", "CSD", "ESF",
                "ESFEXEC", "RBZ Website", "Intranet", "FRS", "SmartHR", "Eagle", "CEPECS", "CEBAS", "BDTRS", "LMS", "CRB", "Paytyme", "GCMS", "GMS", "BSA", "Collateral Registry", "EDMS", "EBIS", "Refinitiv (Reuters)", "Asset Registry", "Attendance System"]

# BACKUP POLICY — how many calendar days old a host's newest backup may be and still count
# as CURRENT. Almost every system backs up daily, so the default of 1 means "today or
# yesterday" and nothing changes for them. A system on a slower cycle needs its interval
# here, otherwise the days between its runs are misreported as NO BACKUP even though the
# policy is being met. Keyed by the exporter instance that publishes backup_file (the same
# instance the backup_monitor script writes its .prom on).
#   BSA: MSSQL full backup runs every 3rd day (e.g. 30 Jul, then 2 Aug), never daily —
#        set with -MaxAgeDays in backup_monitor/check_backup_bsa.ps1. Keep the two in step.
BACKUP_MAX_AGE_DAYS = {
    "10.0.206.5:9182": 3,          # BSA Database
}
DEFAULT_BACKUP_MAX_AGE_DAYS = 1    # daily backup = today or yesterday

# Weekdays (Python's date.weekday(): Monday=0 .. Sunday=6) a host is NOT expected to back up
# at all — distinct from BACKUP_MAX_AGE_DAYS's fixed rolling window: RTGS/CSD run daily
# EXCEPT Sunday, so a flat "N days back" window would either miss real Tue-Sat gaps (if
# widened to 2 every day) or wrongly flag Saturday's backup as stale on a Monday-morning
# check (at 1). backup_cutoff() instead walks back from `now`, skipping any day listed here,
# until it has counted BACKUP_MAX_AGE_DAYS real (non-off) days — so Monday's cutoff reaches
# back to Saturday specifically, while every other day keeps the normal 1-day window.
#   RTGS/CSD: confirmed 2026-08-24 -- neither system runs a backup on Sundays by design.
BACKUP_OFF_WEEKDAYS = {
    "10.100.249.220:9100": {6},    # RTGS Database
    "10.100.250.82:9100": {6},     # CSD Database
}

# Hosts that back up ONCE A WEEK on one fixed weekday — a third shape, distinct from both of
# the above: not a rolling N-day window (BACKUP_MAX_AGE_DAYS, e.g. BSA's every-3rd-day cycle,
# which doesn't land on the same weekday twice running) and not "daily except one off day"
# (BACKUP_OFF_WEEKDAYS). backup_weekly_gap_expected/backup_weekly_comment below suppress and
# explain the gap on every day that ISN'T the expected weekday, on the same policy-not-
# evidence basis as backup_gap_expected (see its own docstring for why): FRS's backup check
# script reports the identical signature RTGS/CSD's does (confirmed live 2026-08-25 —
# backup_check_success=1, backup_file_count=0, no backup_file series persisted from one day to
# the next), so there's no older mtime for backup_cutoff to find even with a widened window.
#   FRS: backs up once a week, Fridays only.
BACKUP_WEEKLY_DAY = {
    "10.100.245.150:9100": 4,      # FRS App/DB, Friday=4
}

# Hosts that back up ONCE A MONTH, at month-end (the actual last calendar day of the month —
# never a fixed "31st", since not every month has one). A fourth shape, no better served by
# BACKUP_WEEKLY_DAY (a fixed weekday) or the rolling-window BACKUP_MAX_AGE_DAYS than either of
# those fit a weekly cadence. See backup_monthly_gap_expected's own docstring for the one
# thing that makes this different from every policy shape above: it does NOT gate on the
# check's own ok/success value.
#   Intranet: backs up once a month, at month-end. Newly deployed (confirmed live
#   2026-08-25 — backup_check_success=0, backup_file_count=0, since the very first sample);
#   unlike BSA/FRS/RTGS/CSD's scripts (which report success=1 even with zero files, as long
#   as the script itself ran), THIS script reports success=0 whenever it hasn't found a fresh
#   file — meaning it will read as a FAILED check for the entire month until the month-end
#   file actually appears, not "succeeded, nothing due yet". The usual "never suppress a real
#   check failure" guard (ok is False) would keep this flagged as NO BACKUP for the whole
#   month regardless of any policy configured here, so backup_monthly_gap_expected ignores
#   `ok` entirely for instances in this set. The trade-off, stated plainly: this is a
#   full-month blind spot for a genuine script failure on this host, wider than even FRS's
#   weekly one — there is no way to tell "still waiting for month-end" from "actually broken"
#   without file evidence the script doesn't have yet.
BACKUP_MONTHLY_INSTANCES = {"10.100.248.40:9100"}   # Intranet App/DB


def _month_end(d: datetime.date) -> datetime.date:
    """The last calendar day of d's month (handles 28/29/30/31 correctly)."""
    first_of_next = (d.replace(day=28) + datetime.timedelta(days=4)).replace(day=1)
    return first_of_next - datetime.timedelta(days=1)

# Overridable at runtime via the webapp's Backup Policy screen (Configuration -> Backup
# policy) rather than only by editing the dicts above and redeploying. BACKUP_POLICY_PATH
# sits next to config.ini — a per-deployment file, same as config.ini itself, not one this
# repo tracks — and reload_backup_policy() re-reads it fresh at the top of every capture()
# (see below), so an admin's edit takes effect on the very next report with no restart.
# Absent or unparseable: BACKUP_MAX_AGE_DAYS/BACKUP_OFF_WEEKDAYS simply stay at the
# hardcoded defaults above — those are also what the config screen shows on its very
# first-ever load, before anyone has saved a policy yet (see
# webapp/reports/backup_policy_admin.py).
BACKUP_POLICY_PATH = HERE / "backup_policy.json"


def reload_backup_policy() -> None:
    """Repopulate BACKUP_MAX_AGE_DAYS/BACKUP_OFF_WEEKDAYS from BACKUP_POLICY_PATH if it
    exists and parses — called at the top of every capture() so a policy edit takes effect
    on the very next report. Never raises: a missing or broken file just leaves the current
    values in place rather than reverting every host to the daily default mid-incident."""
    global BACKUP_MAX_AGE_DAYS, BACKUP_OFF_WEEKDAYS
    try:
        raw = json.loads(BACKUP_POLICY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    except (OSError, ValueError):
        return
    BACKUP_MAX_AGE_DAYS = {inst: int(fields["frequency_days"])
                           for inst, fields in raw.items()
                           if isinstance(fields, dict) and "frequency_days" in fields}
    BACKUP_OFF_WEEKDAYS = {inst: {int(d) for d in fields["off_weekdays"]}
                           for inst, fields in raw.items()
                           if isinstance(fields, dict) and fields.get("off_weekdays")}


def backup_cutoff(instance: str, now: datetime.datetime | None = None) -> float:
    """Oldest mtime that still counts as a CURRENT backup for `instance` (unix seconds).

    Midnight-based, matching how the backup_monitor scripts judge age, so the verdict
    doesn't drift with the time of day the report happens to run. Hosts absent from
    BACKUP_MAX_AGE_DAYS get the daily default = yesterday-midnight, exactly as before.

    Walks back day by day, skipping any weekday listed in BACKUP_OFF_WEEKDAYS for this
    instance, until BACKUP_MAX_AGE_DAYS real (non-off) days have been counted. A host with
    no off-days behaves exactly as before (every day is "counted", so this is just
    today - max_age days); RTGS/CSD's Sunday-off policy makes a Monday check's cutoff land
    on Saturday specifically, without loosening any other day's 1-day window.
    """
    now = now or datetime.datetime.now()
    max_age = BACKUP_MAX_AGE_DAYS.get(instance, DEFAULT_BACKUP_MAX_AGE_DAYS)
    off_days = BACKUP_OFF_WEEKDAYS.get(instance, ())
    d = now.date()
    counted = 0
    while counted < max_age:
        d -= datetime.timedelta(days=1)
        if d.weekday() not in off_days:
            counted += 1
    cutoff_dt = datetime.datetime(d.year, d.month, d.day)
    return cutoff_dt.timestamp()


def backup_gap_expected(instance: str, ok: Optional[bool], now: datetime.datetime | None = None) -> bool:
    """True when a host with NO fresh backup file today is exactly where BACKUP_OFF_WEEKDAYS
    says to expect one: yesterday was a day this host doesn't back up on at all (RTGS/CSD,
    Sundays). Deliberately a SEPARATE question from backup_cutoff's widened window: the
    check scripts on these hosts only ever report a file dated today or yesterday (confirmed
    live 2026-08-24 — backup_check_success=1, backup_file_count=0, no backup_file series at
    all on a Monday) — there is no older mtime for backup_cutoff's widening to find. Changing
    that script-side window was considered and explicitly rejected: the app should be
    informed by the backup POLICY (which can change), not by hand-editing a remote script to
    match it. So this suppresses the finding on policy grounds alone, without any file data
    to point to as evidence.

    Only ever fires on the single day right after the off-day, and never when the check
    itself failed (ok is False, e.g. "FOLDER UNREADABLE") — a real check failure is a real
    fault regardless of what day it is. The inherent trade-off, stated plainly: if the LAST
    real backup (Saturday, for a Sunday-off host) also failed, this masks that too, for
    exactly the one day the expected gap would otherwise hide it behind — there is no way to
    tell "skipped by design" from "also broken" without the script itself reporting how old
    the newest file really is, which is the one change ruled out here.
    """
    if ok is False:
        return False
    off_days = BACKUP_OFF_WEEKDAYS.get(instance)
    if not off_days:
        return False
    now = now or datetime.datetime.now()
    yesterday = (now.date() - datetime.timedelta(days=1)).weekday()
    return yesterday in off_days


_WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def backup_policy_comment(instance: str, now: datetime.datetime | None = None) -> str:
    """The automatic explanation for a policy-expected backup gap (see backup_gap_expected) —
    names the off-day(s) and computes the actual date the next backup is due, rather than a
    static "off-day policy" label. Written to stand alone wherever it's shown (the Backups
    panel row today; anywhere else an auto-explained finding is wanted later) — a reader
    should not need to go check backup_policy.json to know what it means or when this stops
    being true. Returns "" if `instance` has no off-days configured (nothing to explain).
    """
    now = now or datetime.datetime.now()
    off_days = BACKUP_OFF_WEEKDAYS.get(instance)
    if not off_days:
        return ""
    names = " and ".join(f"{_WEEKDAY_NAMES[d]}s" for d in sorted(off_days))
    d = now.date()
    while d.weekday() in off_days:              # first day ON/AFTER today that isn't off
        d += datetime.timedelta(days=1)
    when = "today" if d == now.date() else d.strftime("%A %d %b %Y")
    return (f"Backup policy states that no backup is expected on {names} — this is expected, "
            f"not a fault. The next backup file is expected {when}.")


def backup_weekly_gap_expected(instance: str, ok: Optional[bool], now: datetime.datetime | None = None) -> bool:
    """True when a host with a single fixed weekly backup day (BACKUP_WEEKLY_DAY) has no
    fresh file, on the same policy-not-evidence grounds as backup_gap_expected (see its own
    docstring for the full reasoning). Unlike the off-day case this suppresses on EVERY day
    except the expected weekday itself, not just the single day after — a strictly wider
    blind spot, inherent to "weekly" rather than "daily except one day": there is no way to
    tell "still waiting for Friday" from "Friday came and went and nothing happened" without
    the file evidence the script doesn't persist (same limitation as backup_gap_expected's
    own trade-off). Never fires when the check itself failed (ok is False)."""
    if ok is False:
        return False
    if instance not in BACKUP_WEEKLY_DAY:
        return False
    now = now or datetime.datetime.now()
    return now.weekday() != BACKUP_WEEKLY_DAY[instance]


def backup_weekly_comment(instance: str, now: datetime.datetime | None = None) -> str:
    """The automatic explanation for a weekly-cadence backup gap (see
    backup_weekly_gap_expected) — names the expected weekday and computes the actual date the
    next backup is due, same shape as backup_policy_comment's off-day version. Returns "" if
    `instance` has no weekly-day policy configured."""
    now = now or datetime.datetime.now()
    day = BACKUP_WEEKLY_DAY.get(instance)
    if day is None:
        return ""
    name = _WEEKDAY_NAMES[day]
    d = now.date()
    while d.weekday() != day:                       # first upcoming occurrence of that weekday
        d += datetime.timedelta(days=1)
    when = "today" if d == now.date() else d.strftime("%A %d %b %Y")
    return (f"Backup policy states that this host backs up once a week, on {name}s, not daily "
            f"— this is expected, not a fault. The next backup is expected {when}.")


def backup_monthly_gap_expected(instance: str, ok: Optional[bool], now: datetime.datetime | None = None) -> bool:
    """True for any host in BACKUP_MONTHLY_INSTANCES — unconditionally, deliberately NOT gated
    on `ok` (see BACKUP_MONTHLY_INSTANCES' own comment for exactly why this one policy shape
    breaks from every other function here). `ok` is still accepted as a parameter, purely so
    this has the same call signature as backup_gap_expected/backup_weekly_gap_expected and
    backup_gap_expected_any can dispatch to all three uniformly."""
    return instance in BACKUP_MONTHLY_INSTANCES


def backup_monthly_comment(instance: str, now: datetime.datetime | None = None) -> str:
    """The automatic explanation for a monthly-cadence backup gap (see
    backup_monthly_gap_expected) — names the actual month-end date (never a fixed "31st").
    Returns "" if `instance` has no monthly policy configured."""
    if instance not in BACKUP_MONTHLY_INSTANCES:
        return ""
    now = now or datetime.datetime.now()
    end = _month_end(now.date())
    when = "today" if end == now.date() else end.strftime("%A %d %b %Y")
    return (f"Backup policy states that this host backs up once a month, at month-end, not "
            f"daily — this is expected, not a fault. The next backup is expected {when}.")


def backup_gap_expected_any(instance: str, ok: Optional[bool], now: datetime.datetime | None = None) -> bool:
    """True under any policy-expected-gap shape currently supported: a single off-day
    (backup_gap_expected), a fixed weekly cadence (backup_weekly_gap_expected), or a monthly
    one (backup_monthly_gap_expected). Single dispatch point so callers don't need to know how
    many policy shapes exist or OR them together by hand — add a new shape here once, not at
    every call site."""
    return (backup_gap_expected(instance, ok, now)
            or backup_weekly_gap_expected(instance, ok, now)
            or backup_monthly_gap_expected(instance, ok, now))


def backup_gap_comment(instance: str, now: datetime.datetime | None = None) -> str:
    """Whichever explanation applies for backup_gap_expected_any — off-day first, then
    weekly-cadence, then monthly. Only meaningful when backup_gap_expected_any is already
    True."""
    return (backup_policy_comment(instance, now)
            or backup_weekly_comment(instance, now)
            or backup_monthly_comment(instance, now))


def backup_frequency_comment(instance: str, now: datetime.datetime | None = None) -> str:
    """The automatic explanation for a SLOWER-than-daily backup cadence (see
    BACKUP_MAX_AGE_DAYS) — e.g. BSA's MSSQL full backup, which only runs every 3rd day.
    Distinct from backup_policy_comment (an ABSENCE explained by an off-day policy): this
    explains a file that IS present and within policy, just older than a daily reader would
    expect (rendered as PRESENT in the Backups panel, named by weekday rather than "today"/
    "yesterday" — see _system_card's own file-bucketing). Returns "" for any host on the
    ordinary 1-day cadence (nothing unusual to explain)."""
    now = now or datetime.datetime.now()
    days = BACKUP_MAX_AGE_DAYS.get(instance, DEFAULT_BACKUP_MAX_AGE_DAYS)
    if days <= 1:
        return ""
    return (f"This host's backup policy expects a full backup only every {days} days, not "
            f"daily — a file from earlier in that cycle is still within policy, not a fault.")


# Close-of-business (T24) does not run on Sundays -- same "policy-expected gap" shape as
# BACKUP_OFF_WEEKDAYS, but for a single global metric (cob_time) rather than a per-host
# backup check, so it's a plain set of weekdays rather than a per-instance dict, and it's
# only ever relevant to the one system that owns COB.
COB_OFF_WEEKDAYS = {6}          # Sunday
COB_OWNER_SYSTEM = "Temenos"    # T24 -- the only system cob_policy_comment ever attaches to


def cob_policy_comment(now: datetime.datetime | None = None) -> str:
    """Names which day's close-of-business run the report's COB figure actually reflects,
    whenever "yesterday" was a day COB doesn't run on (Sunday) — regardless of whether the
    metric currently reads N/A or a real-looking number. cob_time only turns NaN once it's
    been stale long enough (see capture()'s own note on the collector), so a report generated
    on or shortly after a COB off-day can still show a plain minutes figure that's actually
    carried over from the LAST real run (Saturday), not evidence Sunday's non-existent COB
    completed. Unlike backup_gap_expected this fires purely off the calendar — it isn't
    gating a flag, just always naming which day is really being shown whenever that isn't
    obviously "yesterday". Returns "" on a normal day (yesterday was a real COB day)."""
    now = now or datetime.datetime.now()
    yesterday = now.date() - datetime.timedelta(days=1)
    if yesterday.weekday() not in COB_OFF_WEEKDAYS:
        return ""
    last_real = yesterday
    while last_real.weekday() in COB_OFF_WEEKDAYS:
        last_real -= datetime.timedelta(days=1)
    nxt = now.date()
    while nxt.weekday() in COB_OFF_WEEKDAYS:
        nxt += datetime.timedelta(days=1)
    when = "today" if nxt == now.date() else nxt.strftime("%A %d %b %Y")
    names = " and ".join(f"{_WEEKDAY_NAMES[d]}s" for d in sorted(COB_OFF_WEEKDAYS))
    return (f"The time shown for COB is from this {last_real.strftime('%A')}. COB policy "
            f"states that no COB is expected on {names}. The next COB is expected {when}.")


def cob_policy_notes_for_system(sysm: "System", now: datetime.datetime | None = None) -> List[str]:
    """Informational note for the COB owner's own card (see cob_policy_comment) — never a
    Flag, mirrors backup_policy_notes_for_system's own non-actionable shape. Purely
    calendar-driven (no store/metric lookup needed): only fires for COB_OWNER_SYSTEM, and
    only on the day(s) right after a COB off-day."""
    if sysm.name != COB_OWNER_SYSTEM:
        return []
    text = cob_policy_comment(now)
    return [text] if text else []


# The Comment box's own fallback when a system has neither a flagged metric nor any other
# note (policy-driven or admin-typed) to show — used by _system_card directly (so a CLI/
# scheduled report still gets it, not just the web-form path) and by
# webapp/reports/services.py to pre-fill the same text into the form's comment box, so the
# xlsx and the web form always agree on what an all-clear system's box says. Chosen over
# leaving the box blank or removing it entirely: a reader scanning every card for something
# written in the box shouldn't have to distinguish "nothing to report" from "this card was
# skipped" -- every card says something.
NO_ISSUES_COMMENT = "No pending issues detected on this run. All clear."


def system_comment_text(store: "Store", sysm: "System", flagged: list,
                         annotations: Optional[dict],
                         now: datetime.datetime | None = None) -> str:
    """What ONE system's Comment box says, right now: the admin's own typed text if the web
    form gave one, else the same auto-notes (backup/COB policy) the box falls back to on its
    own, else NO_ISSUES_COMMENT when the system is flag-free with nothing else to say, else
    "" when it's flagged and awaiting a real admin comment (an empty box, not a fabricated
    one). Computed the SAME way regardless of caller, so _system_card's own box and
    _overview's Summary Notes per-system listing can never disagree — and, critically, so
    Summary Notes is populated straight from live data (store/systems), not from whatever the
    web form's summary box happened to be submitted with. That's what makes it show up in a
    CLI/scheduled report too, where there's no web form step and annotations is always {}."""
    ann = annotations.get(sysm.name, {}) if annotations else {}
    comment = ann.get("comment") if isinstance(ann, dict) else None
    if comment:
        return comment
    if flagged:
        return ""
    notes = backup_policy_notes_for_system(store, sysm, now) + cob_policy_notes_for_system(sysm, now)
    # single newline between a system's OWN multiple notes (keeps them visually grouped as
    # one block), reserving the blank-line (\n\n) separator for BETWEEN different systems --
    # see _overview's Summary Notes, which would otherwise read a multi-note system as two
    # separate entries with no way to tell it apart from a real system boundary.
    return "\n".join(notes) if notes else NO_ISSUES_COMMENT


# Systems that depend on the shared LDAP / authentication service — if LDAP is down these
# systems can't authenticate users. Source of truth for the "LDAP dependency" banner; extend
# as more dependents are identified. (Names must match the `system` labels in prometheus.yml.)
LDAP_DEPENDENTS = {"GCMS", "GMS", "Attendance System"}
# folder_exporter target name -> (volume/mount it lives on, expected size as a FRACTION of
# that volume's own total capacity), for the Folders table (see _system_card / FOLDER OVER
# EXPECTED SIZE banner / folder_expected_gb). Percentage-of-drive rather than a fixed GB
# number so the threshold scales with the actual volume the folder lives on and moves
# automatically if that volume is ever resized -- a flat number (T24 Log File was 5 GB) reads
# as a false alarm the moment the drive is bigger than the number assumed. T24 Log File lives
# on T24 DB's F: (a 500 GB volume dedicated to logging), so 80% is ~400 GB of headroom before
# this is worth a look -- generous on purpose, this is "keep an eye on it", not a hard cap.
# A folder over its expectation is ALWAYS a warning here, never critical, however far over it
# grows. Extend as more logging-role folders are watched.
FOLDER_EXPECTED_PCT: Dict[str, Tuple[str, float]] = {"T24 Log File": ("F:", 0.80)}


def folder_expected_gb(store: "Store", instance: Optional[str], name: str) -> Optional[float]:
    """Expected size for a watched folder (see FOLDER_EXPECTED_PCT) -- computed fresh, every
    report, from the actual current size of the volume it lives on. None if `name` isn't a
    watched folder, or that host's disk data for the configured volume isn't available
    (host unreachable this capture)."""
    cfg = FOLDER_EXPECTED_PCT.get(name)
    if cfg is None or instance is None:
        return None
    mount, pct = cfg
    size = store.disk.get(instance, {}).get(mount, {}).get("size")
    return size * pct if size is not None else None
# `system` label values that are not real systems. "rbz network" is the core switch / network
# device estate (see the `snmp` job in prometheus.yml and DEVICES in webapp/reports/network.py)
# — those get their own Network Admin Report and are deliberately excluded here so a switch
# never appears among RTGS and Temenos on the System Admin side. "rtgstest" is RTGS's own
# test environment, not a business system anyone needs a report on — kept OUT of the System
# Admin estate the same way, rather than reporting on non-production infrastructure alongside
# the real one. (DR/staging role components -- Eagle's "dr", LMS's "staging", etc. -- are
# left alone: those are real infrastructure belonging to a real system, not test systems in
# their own right, so excluding them here would be wrong.)
SKIP_SYSTEMS = {"unassigned", "prometheus", "", "rbz network", "rtgstest"}

# `system` label values that ARE real systems, but belong to Infrastructure Admin's own
# estate (hyper-converged clusters, standalone DB hosts — the underlying hardware) rather
# than System Admin's business-systems topology. Same split SKIP_SYSTEMS already makes for
# "rbz network" above, just for a second, non-network estate with its own report screens
# (see webapp/reports/roles.py's Infrastructure Admin role and views.infra_form/infra_report).
INFRA_SYSTEMS = {"hci cluster", "oracle hosts", "root domain controllers"}

# Scrape jobs whose targets carry a `system` label for a DIFFERENT feature's benefit, not
# because the target is a host this report should track CPU/RAM/disk on. folder_exporter's
# target (Temenos/T24 Interface Folders — queue backlog, not a server) is grouped under
# `system: "Temenos"` purely so Folder Watch can find it; load_topology used to sweep it into
# Temenos's host list anyway, which gave it permanent "no data" CPU/RAM/disk findings for
# metrics it was never going to report — a component nobody meant to add, since nobody did.
SKIP_JOBS = {"folder_exporter"}

# Web links (blackbox HTTP probes) become a "WEB LINKS" service class inside a
# system's Services table. A link is auto-attributed to the system whose name
# appears in its URL (e.g. 'cepecs' in 'cepecsrpt.excon.rbz.co.zw' -> CEPECS).
# Only list a system here when its name is NOT derivable from the URL — these
# NORMALISED-name -> URL-substring overrides win over auto-detection. Any link
# matching no system falls to the standalone "Web Links & SSL" section.
LINK_CHECKS: Dict[str, List[str]] = {
    "temenos":    ["browserweb", "10.0.212.3:9089"],   # T24 BrowserWeb endpoint (no 'temenos' in URL)
    "smarthr":    ["smartess", "10.100.245.133"],      # SmartESS is the SmartHR web app (no 'smarthr' in URL)
    "rbzwebsite": ["www.rbz.co.zw"],                    # main site (no 'rbzwebsite' in URL)
    "bdtrs":      ["bdctrs.rbz.co.zw", "bdctrs"],       # domain is 'bdctrs' (extra c) -> won't name-match
    "gcms":       ["vault.rbz.co.zw", "vault"],         # GCMS web app lives at vault.rbz.co.zw (no 'gcms' in URL)
    "frs":        ["frs.rbz.co.zw", "10.100.245.150"],  # FRS web app at https://frs.rbz.co.zw (trusted Sectigo cert). Probe by HOSTNAME, not the bare IP: the cert's SAN is frs.rbz.co.zw with no IP SAN, so probing 10.100.245.150 fails TLS verification. IP kept here only to still attribute any stale IP-based series.
}


def _link_match(url: str, keys: List[str]) -> bool:
    u = url.lower()
    return any(k.lower() in u for k in keys)


def _link_display(url: str) -> str:
    """Compact label for a link row: host (+path), no scheme or trailing slash."""
    return re.sub(r"^https?://", "", url, flags=re.IGNORECASE).rstrip("/")


def assign_link(url: str, systems: List["System"]) -> Optional[str]:
    """Normalised system name that owns a link, or None. Explicit LINK_CHECKS
       overrides win; otherwise the present system whose normalised name appears
       in the URL (longest match), so 'cepecs' in 'cepecsrpt...' -> CEPECS."""
    present = {_norm(s.name) for s in systems}
    for nrm, keys in LINK_CHECKS.items():
        if nrm in present and _link_match(url, keys):
            return nrm
    nurl = _norm(re.sub(r"^https?://", "", url, flags=re.IGNORECASE))
    best = None
    for s in systems:
        ns = _norm(s.name)
        if ns and ns in nurl and (best is None or len(ns) > len(best)):
            best = ns
    return best


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _component_label(display: Optional[str], role: Optional[str], system: str, instance: str) -> str:
    """Human label for a host: prefer display (system prefix stripped), then role, then address."""
    if display:
        d = display
        if d.lower().startswith(system.lower()):
            d = d[len(system):].lstrip(" /-:·")
        return d or display
    if role:
        return role.replace("-", " ").replace("_", " ").title()
    return instance


#: default listen ports of the two host exporters, used only as a fallback when the job name
#: itself is uninformative (a site that named its jobs "hosts-prod" / "hosts-dc2" still gets
#: classified). Ports are the exporters' documented defaults, so this is a weak-but-safe hint.
#: Kept in step with connect._PORT_OS, which reads the same convention for the same reason.
_EXPORTER_PORTS = {"9182": "windows", "9100": "linux", "9101": "linux"}


def platform_of_job(job_name: str, target: str = "") -> str:
    """Which OS a scrape target runs, as "windows" / "linux" / "" (don't know).

    Read off the SCRAPE JOB rather than a metric: the picker renders straight from
    prometheus.yml with no Prometheus round-trip at all (see list_systems), so anything
    requiring a live query would defeat the point of that screen being free.

    Only host exporters classify. blackbox_http targets are URLs that happen to carry a
    `system` label and land in the same grouping — calling those "linux" because they answer
    on :80 would put a penguin on a web probe, so everything unrecognised stays "".
    """
    j = (job_name or "").lower()
    if "blackbox" in j or "probe" in j:
        return ""
    if "windows" in j or "wmi" in j:          # windows_exporter, and its pre-2021 name
        return "windows"
    if "node" in j or "linux" in j or "unix" in j:
        return "linux"
    port = target.rsplit(":", 1)[-1] if ":" in target else ""
    return _EXPORTER_PORTS.get(port, "")


def platform_of_system(components: List[Component]) -> str:
    """A system's platform: "windows" / "linux" / "hybrid" / "" when nothing classified.

    Hybrid is real but uncommon here — a system is usually built on one stack — so it is
    reported honestly rather than collapsed into whichever OS happens to hold the majority:
    an admin reading the picker should see that the estate spans both before they pick it.
    Unclassified components (web probes) are ignored, NOT counted as a third platform;
    otherwise every system carrying a link would read as hybrid.

    Read through getattr because the webapp pickles whole snapshots into its cache: one
    captured before Component gained `os` unpickles without the attribute, and it must degrade
    to "platform unknown" rather than 500 the report page for the life of that cache entry.
    """
    kinds = {getattr(c, "os", "") for c in components}
    kinds.discard("")
    if not kinds:
        return ""
    return kinds.pop() if len(kinds) == 1 else "hybrid"


def platform_host_counts(systems: List[System]) -> Tuple[int, int]:
    """(windows_hosts, linux_hosts) across every component in every system -- the AT A
    GLANCE platform tiles' numerator. Counted per HOST, not per system: a hybrid system
    (see platform_of_system) has hosts of both kinds, and a system-level tally would hide
    that split. Components with no classified os (web probes; see os_of_job) count toward
    neither, so the two numbers don't have to sum to the total host count -- same reasoning
    as platform_of_system not forcing every system into "windows" or "linux"."""
    windows = sum(1 for s in systems for c in s.components if getattr(c, "os", "") == "windows")
    linux = sum(1 for s in systems for c in s.components if getattr(c, "os", "") == "linux")
    return windows, linux


def platform_host_pcts(systems: List[System]) -> Tuple[int, int]:
    """(linux_pct, windows_pct) — the single PLATFORMS tile's "linux% | windows%" pair.
    Rounded independently, against the FULL host count (not windows+linux), so the two
    numbers don't have to sum to 100 -- same honesty as platform_host_counts not forcing
    every host into one of the two camps. Single source of truth so the xlsx/web/e-mail
    tile can never round differently and disagree by a point."""
    hosts = sum(len(s.components) for s in systems)
    if not hosts:
        return 0, 0
    windows, linux = platform_host_counts(systems)
    return round(linux / hosts * 100), round(windows / hosts * 100)


def load_topology(prometheus_yml: str, *, scope: str = "business") -> List[System]:
    """Read the system -> hosts topology from prometheus.yml (grouped by the `system` label).

    `scope` picks which estate comes back:
      "business" (default, every existing caller) — everything except SKIP_SYSTEMS and
          INFRA_SYSTEMS. This is the System Admin topology.
      "infra"    — ONLY the INFRA_SYSTEMS entries, for Infrastructure Admin's own picker/
          report (see webapp/reports/views.infra_form/infra_report).
      "all"      — everything except SKIP_SYSTEMS (both estates together) — used by the
          webapp's Connect screen, which quick-launches to any monitored host regardless of
          which report estate owns it.
    "business" and "infra" are mutually exclusive, so a system never appears in both
    estates' reports.
    """
    import yaml  # PyYAML — see requirements.txt
    with open(prometheus_yml, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    grouped: Dict[str, List[Component]] = {}
    for job in doc.get("scrape_configs", []) or []:
        job_name = job.get("job_name") or ""
        if job_name in SKIP_JOBS:
            continue
        for sc in job.get("static_configs", []) or []:
            labels = sc.get("labels", {}) or {}
            system = (labels.get("system") or "").strip()
            if system.lower() in SKIP_SYSTEMS:
                continue
            is_infra = system.lower() in INFRA_SYSTEMS
            if scope == "business" and is_infra:
                continue
            if scope == "infra" and not is_infra:
                continue
            role, display = labels.get("role"), labels.get("display")
            for target in sc.get("targets", []) or []:
                grouped.setdefault(system, []).append(
                    Component(_component_label(display, role, system, target), target,
                              platform_of_job(job_name, target)))
    order = {name: i for i, name in enumerate(SYSTEM_ORDER)}
    names = sorted(grouped, key=lambda n: (order.get(n, len(order)), n))
    return [System(name, grouped[name], SERVICE_CHECKS.get(_norm(name), [])) for name in names]


# ============================================================================ #
#  DATA CAPTURE
# ============================================================================ #
@dataclass
class Store:
    disk: Dict[str, Dict[str, dict]]            # instance -> mount -> {used, free, size}
    ram: Dict[str, float]                       # instance -> used %
    cpu: Dict[str, float]                       # instance -> busy % (100 - idle)
    cob: Optional[float]
    swift: Optional[float]
    services: Dict[str, List[Tuple[str, bool, str, str]]]  # system -> [(name, is_up, kind, component)]
    up: Dict[str, float]                        # instance -> 1 reachable / 0 unreachable (Prometheus `up`)
    links: Dict[str, dict]                      # URL -> {up, code, ssl, cert_days, tls, duration} (blackbox HTTP probes)
    backups: Dict[str, dict]                    # instance -> {files, count, ok, ts} (textfile backup check)
    ldap_up: Optional[bool] = None              # LDAP/auth probe: True up / False down / None not monitored
    # lower(system name) -> [(target_label, size_gb, source_ip), ...]. Keyed by SYSTEM, not
    # host instance: a watched log folder (folder_exporter, kind="logs", role="logging")
    # belongs to the estate, not to one host's windows_exporter identity, and folder_exporter
    # scrapes on its own port so there's no instance string in common with a Component.
    # source_ip (the exporter's own IP, port stripped) is carried alongside so _system_card
    # can still attribute the row to whichever host it actually lives on, by IP rather than a
    # guess. Deliberately separate from `disk`: a folder's size has no capacity to be a % OF,
    # so it must never enter total_disks()/disk_high()/disk_near_full(), which all read
    # `disk` directly. Rendered in its own Folders table instead (see _system_card), each
    # entry judged against FOLDER_EXPECTED_PCT rather than banded like a real volume.
    log_files: Dict[str, List[Tuple[str, float, str]]] = field(default_factory=dict)


# filters reused across every node_filesystem / windows_logical_disk query
_FS = 'fstype=~"ext.*|xfs|btrfs",mountpoint!~".*pod.*|.*container.*|^/snap/|^/var/snap"'
_VOL = 'volume!~"HarddiskVolume.+"'
_HASH = re.compile(r"[0-9a-f]{20,}")
_INSTANCE_RE = re.compile(r'instance="([^"]+)"')   # pulls the target host out of a Service.expr


def _shorten(name: str) -> str:
    for suffix in (" Service", " service"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    if len(name) > 17 and "." in name:        # collapse long dotted CI names
        name = name.split(".")[-1]
    return name


def _stable(expr: str, lookback: str = "6h") -> str:
    """Wrap a PromQL vector expr so a single missed scrape doesn't drop it from a count.
       Returns the LAST sample in the window (not max/avg) — a genuine transition to
       down/gone is still reflected at the very next scrape; this only survives GAPS.
       Used only for "does this entity exist at all, count it" queries (services, web
       links, backups, LDAP) — NEVER for point-in-time readings (RAM/CPU/disk/COB/SWIFT/
       `up`), where a stale value would be actively wrong."""
    return f"last_over_time(({expr})[{lookback}:1m])"


def capture(prom: Prometheus, systems: List[System], cfg: Config) -> Store:
    reload_backup_policy()   # fresh on every report — see BACKUP_POLICY_PATH above
    disk: Dict[str, Dict[str, dict]] = {}
    ram: Dict[str, float] = {}

    def index(result: List[dict], field_: str, key: Callable[[dict], Optional[str]]) -> None:
        for row in result:
            inst, k = row["labels"].get("instance"), key(row["labels"])
            if inst and k is not None:
                disk.setdefault(inst, {}).setdefault(k, {})[field_] = row["value"]

    # ---- disk: uniform USED% / FREE GB / SIZE GB for linux + windows ----------
    index(prom.query(f"100*(1-node_filesystem_avail_bytes{{{_FS}}}/node_filesystem_size_bytes{{{_FS}}})"),
          "used", lambda m: m.get("mountpoint"))
    index(prom.query(f"node_filesystem_avail_bytes{{{_FS}}}/1024/1024/1024"), "free", lambda m: m.get("mountpoint"))
    index(prom.query(f"node_filesystem_size_bytes{{{_FS}}}/1024/1024/1024"), "size", lambda m: m.get("mountpoint"))
    index(prom.query(f"100*(1-windows_logical_disk_free_bytes{{{_VOL}}}/windows_logical_disk_size_bytes{{{_VOL}}})"),
          "used", lambda m: m.get("volume"))
    index(prom.query(f"windows_logical_disk_free_bytes{{{_VOL}}}/1024/1024/1024"), "free", lambda m: m.get("volume"))
    index(prom.query(f"windows_logical_disk_size_bytes{{{_VOL}}}/1024/1024/1024"), "size", lambda m: m.get("volume"))

    # ---- memory: uniform RAM% for linux + windows ----------------------------
    for r in prom.query("100*(1-node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes)"):
        ram[r["labels"]["instance"]] = r["value"]
    for r in prom.query("100*(1-windows_memory_physical_free_bytes/windows_memory_physical_total_bytes)"):
        ram[r["labels"]["instance"]] = r["value"]

    # ---- cpu: uniform BUSY% (100 - idle, 5-min avg) for linux + windows ------
    cpu: Dict[str, float] = {}
    for r in prom.query('100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'):
        cpu[r["labels"]["instance"]] = r["value"]
    for r in prom.query('100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[5m])) * 100)'):
        cpu[r["labels"]["instance"]] = r["value"]

    # ---- reachability: Prometheus `up` per target (0 = scrape failed = unreachable) ----
    up: Dict[str, float] = {}
    for r in prom.query("max by (instance) (up)"):
        up[r["labels"]["instance"]] = r["value"]

    # ---- LDAP / auth service (blackbox probe on the auth endpoint) ------------
    # True up / False down / None when not monitored (no probe target configured or no series).
    ldap_up: Optional[bool] = None
    if cfg.ldap_target:
        rows = prom.query(_stable(f'probe_success{{instance="{cfg.ldap_target}"}}'))
        if rows:
            ldap_up = max(r["value"] for r in rows) >= 1

    # ---- log files: rendered in their own Folders table, not the Disk one -- see
    # Store.log_files. Reuses folder_exporter (already deployed for the interface/queue
    # folders — see SKIP_JOBS) rather than a new textfile check. role="logging" (not just
    # kind="logs") is deliberate: BACKUP.LOGS on the same exporter is ALSO kind="logs" but
    # role="backup" — that one belongs to the backup posture, not this table, and matching
    # only kind="logs" pulled it in by mistake.
    log_files: Dict[str, List[Tuple[str, float, str]]] = {}
    for r in prom.query('folder_size_bytes{kind="logs",role="logging"}/1024/1024/1024'):
        sysname = (r["labels"].get("system") or "").strip().lower()
        target = r["labels"].get("target") or "Log File Size"
        # folder_exporter scrapes on its OWN port (9847), so its `instance` label never
        # matches a Component's directly -- just its IP does. Kept alongside the row so
        # _system_card can attribute it to the right host instead of guessing by label text
        # (which put T24's log folder on "T24 App" when it actually lives on T24 DB).
        source_ip = (r["labels"].get("instance") or "").split(":")[0]
        if sysname:
            log_files.setdefault(sysname, []).append((target, r["value"], source_ip))

    # ---- specials -------------------------------------------------------------
    cob = prom.scalar("cob_time")
    swift = prom.scalar("swift_transactions_total")

    # ---- services -------------------------------------------------------------
    services: Dict[str, List[Tuple[str, bool, str, str]]] = {}
    for sysm in systems:
        rows, seen = [], set()
        comp_order = {c.label: i for i, c in enumerate(sysm.components)}   # topology order for sub-groups
        for svc in sysm.services:
            try:
                result = prom.query(_stable(svc.expr))
            except Exception:
                result = []
            for r in result:
                name = r["labels"].get(svc.name_label) if svc.name_label else svc.name
                if not name or _HASH.fullmatch(name):
                    continue
                name = _shorten(name) if svc.shorten else _t24_label(name)
                name = svc.prefix + name
                # component sub-group: explicit override, else the series' own `display`
                # (the host/component it belongs to), else the system as a whole
                group = svc.group or r["labels"].get("display") or sysm.name
                if (group, name) in seen:      # de-dupe per component, so same name on two hosts both show
                    continue
                seen.add((group, name))
                rows.append((name, r["value"] >= 1, svc.kind, group))
            # A NAMED check (svc.name fixed, not a dynamic name_label list like the T24 TSA
            # services) that produced NO series at all is a service we explicitly monitor —
            # whether the host went unreachable or the check just isn't reporting, it must
            # still show as DOWN rather than silently vanishing from the table and the
            # SERVICES count. Without this, a system's service count shrinks the moment a
            # host goes unreachable, understating what we actually monitor.
            if svc.name and not result:
                m = _INSTANCE_RE.search(svc.expr)
                inst = m.group(1) if m else None
                group = svc.group or next((c.label for c in sysm.components if c.instance == inst), sysm.name)
                name = svc.prefix + svc.name
                if (group, name) not in seen:
                    seen.add((group, name))
                    rows.append((name, False, svc.kind, group))
        # SYSTEM services first, then OFFERED; within a class, cluster rows by component
        # (in topology order) so each sub-group is contiguous for the sub-header pass
        rows.sort(key=lambda t: (SERVICE_KIND_ORDER.get(t[2], 99),
                                 comp_order.get(t[3], 999), t[3]))
        services[sysm.name] = rows

    # ---- LDAP / auth dependency, shown as a service row under each dependent system ----
    # Makes the dependency visible in-context (GCMS, GMS, ...). Status from the shared probe:
    # DOWN only when the probe positively reports down; otherwise up (the system authenticates
    # through it). Prepended so it sits at the top of the system's SYSTEM SERVICES.
    if cfg.ldap_target:
        for sysm in systems:
            if sysm.name in LDAP_DEPENDENTS:
                services.setdefault(sysm.name, []).insert(
                    0, (f"LDAP / auth ({cfg.ldap_target})", ldap_up is not False, "system", sysm.name))

    # ---- web links (blackbox HTTP probes) -------------------------------------
    links = capture_links(prom)

    # ---- backups (textfile collector: backup_file / _count / _success / _ts) ----
    backups = capture_backups(prom)

    return Store(disk, ram, cpu, cob, swift, services, up, links, backups, ldap_up=ldap_up,
                log_files=log_files)


def _is_url(inst: Optional[str]) -> bool:
    """A blackbox HTTP target (its `instance` is a URL) — not an ICMP-ping host."""
    return bool(inst) and inst.lower().startswith(("http://", "https://"))


def capture_links(prom: Prometheus) -> Dict[str, dict]:
    """Per-URL reachability + SSL/TLS snapshot from the blackbox exporter.
       Queries are unfiltered (robust to whatever the scrape job is named); we
       keep only http/https instances, so ICMP-ping targets are excluded."""
    links: Dict[str, dict] = {}

    def index(expr: str, field_: str, conv=lambda v: v) -> None:
        try:
            result = prom.query(_stable(expr))
        except Exception:
            result = []
        for r in result:
            inst = r["labels"].get("instance")
            if _is_url(inst):
                links.setdefault(inst, {})[field_] = conv(r["value"])

    index("probe_success", "up", lambda v: v >= 1)
    index("probe_http_status_code", "code", lambda v: int(v))
    index("probe_http_ssl", "ssl", lambda v: v >= 1)
    index("(probe_ssl_earliest_cert_expiry - time()) / 86400", "cert_days")
    index("probe_duration_seconds", "duration")
    # TLS version travels in the `version` label of probe_tls_version_info
    try:
        for r in prom.query(_stable("probe_tls_version_info")):
            inst, ver = r["labels"].get("instance"), r["labels"].get("version")
            if _is_url(inst) and ver:
                links.setdefault(inst, {})["tls"] = ver
    except Exception:
        pass
    return links


def capture_backups(prom: Prometheus) -> Dict[str, dict]:
    """Per-host backup snapshot from the textfile collector (backup_monitor scripts).
       instance -> {files: [names], count: int|None, ok: bool|None, ts: float|None}.
       `backup_file` carries one series per fresh file (filename in the `file` label);
       the *_count / *_success / *_timestamp series describe the check itself."""
    data: Dict[str, dict] = {}

    def slot(inst: str) -> dict:
        return data.setdefault(inst, {"files": [], "count": None, "ok": None, "ts": None})

    def scan(expr: str, apply: Callable[[dict, dict], None]) -> None:
        try:
            result = prom.query(_stable(expr))
        except Exception:
            result = []
        for r in result:
            inst = r["labels"].get("instance")
            if inst:
                apply(slot(inst), r)

    # backup_file value carries the file's mtime (unix secs) = when it was generated
    scan("backup_file", lambda d, r: d["files"].append(
        (r["labels"].get("file", ""), r["labels"].get("day", ""), r["value"])))
    scan("backup_file_count", lambda d, r: d.__setitem__("count", int(r["value"])))
    scan("backup_check_success", lambda d, r: d.__setitem__("ok", r["value"] >= 1))
    scan("backup_check_timestamp_seconds", lambda d, r: d.__setitem__("ts", r["value"]))

    # each file is (name, day, mtime); order today first, then yesterday, then by name
    for d in data.values():
        d["files"] = sorted((ft for ft in d["files"] if ft[0]),
                            key=lambda ft: (0 if ft[1] == "today" else 1, ft[0]))
    return data


# ============================================================================ #
#  PRESSURE METRICS  (shared by the report overview AND the e-mail KPI strip so
#  both tell one story: how many HOSTS — and how many DRIVES — breach a level)
# ============================================================================ #
def disk_pressure(store: "Store", systems: List["System"], thr: int) -> Tuple[int, int]:
    """Return (hosts, disks) over thr%:
       hosts = servers with AT LEAST ONE disk over thr%  (each server counted once)
       disks = the total number of individual disks over thr%."""
    hosts = disks = 0
    for s in systems:
        for c in s.components:
            over = [d for d in store.disk.get(c.instance, {}).values() if d.get("used", 0) > thr]
            if over:
                hosts += 1
                disks += len(over)
    return hosts, disks


def disk_high(store: "Store", systems: List["System"], amber: int, red: int
              ) -> Tuple[int, int, str]:
    """The honest 'high disk usage' total for the summary tile: EVERY disk over the
       elevated threshold, counting elevated (amber..red) and near-full (>= red)
       together. Counting every high disk directly (rather than only the merely-elevated
       band) means the tile can never read 0 while the DISK NEAR-FULL banner lists disks —
       a near-full disk is a high disk, so it is counted here too (they are the same disks).
       Returns (hosts, disks, state):
         state good -> no high disk (so 0 is always green — the colour rule holds)
               bad  -> at least one disk is near-full (>= red)
               warn -> disks are high but none near-full yet."""
    hosts = disks = worst = 0
    for s in systems:
        for c in s.components:
            high = [u for u in (d.get("used", 0)
                    for d in store.disk.get(c.instance, {}).values()) if u > amber]
            if high:
                hosts += 1
                disks += len(high)
                worst = max(worst, max(high))
    return hosts, disks, ("good" if disks == 0 else ("bad" if worst >= red else "warn"))


def total_disks(store: "Store", systems: List["System"]) -> int:
    """Every monitored disk/volume across every component — the denominator for the
       HIGH DISK USAGE tile's DISKS count (elevated disks out of ALL disks), matching the
       affected-out-of-TOTAL convention every other number on that tile already follows."""
    return sum(len(store.disk.get(c.instance, {})) for s in systems for c in s.components)


def disk_near_full(store: "Store", systems: List["System"], red: int) -> List[Tuple[str, str, str, float]]:
    """Every disk AT/OVER red% -> [(system, host, mount, used%)], worst first.
       These are the imminent-outage volumes that used to fill the DISK NEAR-FULL
       tile; they are now surfaced as a worded banner instead."""
    out: List[Tuple[str, str, float]] = []
    for s in systems:
        for c in s.components:
            for mp, dd in store.disk.get(c.instance, {}).items():
                used = dd.get("used", 0)
                if used >= red:
                    out.append((s.name, c.label, mp, used))
    out.sort(key=lambda t: -t[3])
    return out


def _usage_pressure(values: Dict[str, float], systems: List["System"], amber: int, red: int) -> Tuple[int, str]:
    """For a summary usage tile (RAM / CPU): the hosts carrying a warning-or-worse
       marker (>= amber%) and the colour BAND OF THEIR AVERAGE usage. Returns (count, state):
         good -> no host at/over amber
         warn -> the average of those hosts is in [amber, red)
         bad  -> the average is >= red  (critical)"""
    vals = [values[c.instance] for s in systems for c in s.components
            if values.get(c.instance, 0) >= amber]
    if not vals:
        return 0, "good"
    return len(vals), ("bad" if (sum(vals) / len(vals)) >= red else "warn")


def ram_pressure(store: "Store", systems: List["System"], amber: int, red: int) -> Tuple[int, str]:
    """Hosts at/over amber% RAM + the band of their average (see _usage_pressure)."""
    return _usage_pressure(store.ram, systems, amber, red)


def cpu_pressure(store: "Store", systems: List["System"], amber: int, red: int) -> Tuple[int, str]:
    """Hosts at/over amber% CPU + the band of their average — a pegged host is an early
       warning just like high RAM (see _usage_pressure)."""
    return _usage_pressure(store.cpu, systems, amber, red)


def cert_rollup(store: "Store", horizon_days: int = 30) -> Tuple[List[Tuple[str, float]], List[Tuple[str, float]]]:
    """SSL certificate expiry rollup across ALL monitored HTTPS endpoints (system-attributed
       or standalone). Returns (expired, expiring), each a [(host, days)] list, soonest first:
         expired  -> cert_days < 0            (already lapsed — the site is effectively down)
         expiring -> 0 <= cert_days <= horizon (valid but due to renew within `horizon_days`)."""
    expired: List[Tuple[str, float]] = []
    expiring: List[Tuple[str, float]] = []
    for url, d in store.links.items():
        if not url.lower().startswith("https"):
            continue
        cd = d.get("cert_days")
        if cd is None:
            continue
        if cd < 0:
            expired.append((_link_display(url), cd))
        elif cd <= horizon_days:
            expiring.append((_link_display(url), cd))
    expired.sort(key=lambda t: t[1])
    expiring.sort(key=lambda t: t[1])
    return expired, expiring


def cert_monitored(store: "Store") -> int:
    """Total HTTPS endpoints with a known certificate expiry — the denominator for the
       EXPIRED CERTS tile, same filter cert_rollup uses, so 0 expired out of N never reads
       as if N endpoints simply weren't being watched."""
    return sum(1 for url, d in store.links.items()
               if url.lower().startswith("https") and d.get("cert_days") is not None)


def is_unreachable(store: "Store", instance: str) -> bool:
    """True when a configured target isn't reporting: up==0 (scrape failing) OR no up
       series at all (never scraped - target added but Prometheus not reloaded, or a
       target error). The 'no up series' case is only trusted when up data exists for
       OTHER targets, so a total up-query failure can't flag every host at once."""
    u = store.up.get(instance)
    if u is not None:
        return u < 1
    return bool(store.up)


def unreachable(store: "Store", systems: List["System"]) -> List[Tuple[str, str, str]]:
    """Components Prometheus can no longer scrape -> [(system, component, instance)].
       up==0 means the exporter isn't responding: host down or a network/connectivity issue."""
    return [(s.name, c.label, c.instance)
            for s in systems for c in s.components if is_unreachable(store, c.instance)]


def links_down(store: "Store") -> int:
    """Monitored web links whose blackbox probe reports them unreachable (probe_success=0).
       Web links are rendered as a service class ('WEB LINKS') inside each system's card, so a
       DOWN link is a DOWN service and must feed the overview 'SERVICES DOWN' count. Without
       this, the overview can read 0 while a card shows a WEB LINK as DOWN — e.g. an HTTPS
       endpoint whose untrusted/self-signed cert fails the probe's TLS verification. Reachability
       only (cert expiry rolls up separately); missing 'up' -> down, matching _link_status."""
    return sum(1 for d in store.links.values() if not d.get("up", False))


def services_down(store: "Store") -> int:
    """Total DOWN across BOTH service classes: PromQL service checks (store.services) AND web-link
       probes (store.links). Single source of truth for the overview 'SERVICES DOWN' tile and the
       e-mail KPI, so every renderer agrees with what the per-system cards show as DOWN."""
    svc = sum(1 for v in store.services.values() for row in v if not row[1])
    return svc + links_down(store)


def total_services(store: "Store") -> int:
    """SYSTEM/OFFERED services + web links — the SERVICES tile's total, and the denominator
       for SERVICES DOWN. Single source of truth shared by the xlsx, the webapp screen and
       the e-mail, so the three can never disagree on this number."""
    return sum(len(v) for v in store.services.values()) + len(store.links)


def _link_owner_name(url: str, systems: List["System"]) -> str:
    """assign_link's result, mapped back to the real System.name -- assign_link itself
    returns a NORMALISED name (lowercased, punctuation/spaces stripped, e.g. "SmartHR" ->
    "smarthr", "Collateral Registry" -> "collateralregistry") meant for matching against a
    URL, not for display. Every banner that names a link's owning system goes through this,
    not assign_link directly, so it never shows the normalised form by mistake."""
    nrm = assign_link(url, systems)
    if nrm:
        for s in systems:
            if _norm(s.name) == nrm:
                return s.name
    return "Unassigned"


def services_down_detail(store: "Store", systems: List["System"]) -> List[Tuple[str, str]]:
    """Every DOWN service/link as (system, label) pairs -- the named list behind the
    SERVICES DOWN tile/count. Combines both classes services_down() counts (PromQL checks
    AND web links) so the banner this feeds can never name fewer things than the count
    says are down. A down link falls back to "Unassigned" only if assign_link can't place
    it in this report's systems at all -- in practice everything real has an owner."""
    rows: List[Tuple[str, str]] = []
    for sysname, svcs in store.services.items():
        for name, up, _kind, _group in svcs:
            if not up:
                rows.append((sysname, name))
    for url, d in store.links.items():
        if not d.get("up", False):
            rows.append((_link_owner_name(url, systems), _link_display(url)))
    return rows


def http_links_detail(store: "Store", systems: List["System"]) -> List[Tuple[str, str]]:
    """Every monitored web link still on plain HTTP (not HTTPS), as (system, label) pairs --
    the named list behind the WEB ENCRYPTION tile's http count. Reachability is separate
    (see services_down_detail/links_down) -- a plain-HTTP link that's UP still belongs here,
    since the risk is the missing encryption, not whether the link currently answers."""
    return [(_link_owner_name(url, systems), _link_display(url))
            for url in store.links if url.lower().startswith("http://")]


def folder_over_expected_detail(store: "Store", systems: List["System"]) -> List[Tuple[str, str, float, float]]:
    """Every watched folder (see Store.log_files / FOLDER_EXPECTED_PCT) currently over its
    expected size -> [(system, name, expected_gb, actual_gb), ...]. Always a WARNING, never
    escalated to critical no matter how far over expected the folder grows -- this is "keep
    an eye on it" (e.g. a log file not being rotated), not an outage like a near-full disk."""
    rows: List[Tuple[str, str, float, float]] = []
    by_sys = {_norm(s.name): s for s in systems}
    for sysname_lower, entries in store.log_files.items():
        sysm = by_sys.get(_norm(sysname_lower))
        real_name = sysm.name if sysm else sysname_lower
        for name, gb, source_ip in entries:
            instance = next((c.instance for c in (sysm.components if sysm else [])
                             if c.instance.split(":")[0] == source_ip), None)
            expected = folder_expected_gb(store, instance, name)
            if expected is not None and gb > expected:
                rows.append((real_name, name, expected, gb))
    return rows


def ldap_alert(store: "Store", systems: List["System"]) -> Optional[List[str]]:
    """If the LDAP / auth service is DOWN, the list of dependent systems to warn about; else None.

    Only fires when the probe positively reports down (store.ldap_up is False) — never on an
    unmonitored/absent signal (None). Lists the LDAP_DEPENDENTS that are IN this report's systems
    so a scoped report names what's relevant; falls back to all known dependents if none are in
    scope (LDAP being down still matters). Shared by all three report renderers.
    """
    if store.ldap_up is not False:          # True (up) or None (not monitored) -> no banner
        return None
    present = [s.name for s in systems if s.name in LDAP_DEPENDENTS]
    return present or sorted(LDAP_DEPENDENTS)


def backup_missing(store: "Store", systems: List["System"]) -> List[Tuple[str, str, str]]:
    """Reporting hosts with NO fresh backup -> [(system, host, reason)].
       Freshness is re-judged from each file's mtime AT REPORT TIME, against that host's
       own backup policy (see backup_cutoff — daily for nearly all, wider for systems that
       don't run every day), exactly as the per-system Backups panel does, so a frozen
       check that stopped running correctly reads as missing. Hosts that don't run the
       backup check at all are skipped (they produce no row)."""
    now = datetime.datetime.now()
    missing: List[Tuple[str, str, str]] = []
    for s in systems:
        for c in s.components:
            d = store.backups.get(c.instance)
            if d is None:
                continue
            cutoff = backup_cutoff(c.instance, now)
            fresh = any(mt and mt >= cutoff for _n, _day, mt in (d.get("files") or []))
            if not fresh and not backup_gap_expected_any(c.instance, d.get("ok"), now):
                missing.append((s.name, c.label,
                                "FOLDER UNREADABLE" if d.get("ok") is False else "NO BACKUP"))
    return missing


def backup_tracked_hosts(store: "Store", systems: List["System"]) -> int:
    """Total HOST components with a backup check reporting at all — the denominator for the
       MISSING BACKUPS tile. backup_missing only judges hosts in this set (an untracked host
       produces no row either way), so this is the honest "out of how many" for that count."""
    return sum(1 for s in systems for c in s.components if c.instance in store.backups)


def backup_untracked(store: "Store", systems: List["System"]) -> List[str]:
    """Systems where NO component reports the backup check at all (no instance in
       store.backups) -> [system names]. These are a blind spot: backup_missing skips
       them (nothing to judge), so they never show as MISSING despite being unmonitored.
       Unfiltered — includes BACKUP_UNTRACKED_EXEMPT systems too. Use
       backup_untracked_unexplained wherever an untracked system should actually count
       against something (a flag, a banner, the Backup Tracking tile) — exempt systems have
       a stated reason, not a gap, so nothing here should read as if they're a problem."""
    return [s.name for s in systems
            if not any(c.instance in store.backups for c in s.components)]


# Systems deliberately excluded from the BACKUPS UNTRACKED warning/flag -- not because they
# ARE backed up (there's no on-host check here to verify that), but because monitoring a
# local backup genuinely doesn't apply, for a stated reason rather than a silent gap. Distinct
# from every BACKUP_* policy above (which explain a GAP in an EXISTING check): this explains
# why there's no check to begin with. Surfaced as an automatic comment on the system's own
# card (see backup_policy_notes_for_system) instead of the amber UNTRACKED flag, the same
# "explain, don't just suppress" principle every other automatic comment here follows.
BACKUP_UNTRACKED_EXEMPT = {
    "Refinitiv (Reuters)": ("Admins maintain this system backs up directly to the vendor's "
                            "cloud, not to local storage — there is nothing on-host for this "
                            "app to check."),
    "GMS": "This system is currently under development — backup monitoring has not been set up yet.",
}


def backup_untracked_unexplained(store: "Store", systems: List["System"]) -> List[str]:
    """backup_untracked(), minus BACKUP_UNTRACKED_EXEMPT -- the subset that actually counts as
    a monitoring gap, as opposed to every system with zero on-host backup check. This is what
    every real consumer uses: flagged_for_system's amber flag, the BACKUPS UNTRACKED banner/
    email block, and the Backup Tracking tile's own count -- an exempt system reads as tracked/
    expected everywhere, not as an untracked one with a footnote. backup_untracked() itself is
    the raw, unfiltered fact (kept for anything that genuinely needs to know "no check exists
    here at all", exemption or not)."""
    return [s for s in backup_untracked(store, systems) if s not in BACKUP_UNTRACKED_EXEMPT]


# One flagged item on a system's card: something the admin must answer for. `key` is a
# STABLE id (survives between the web form's preview and generation) used to marry an
# admin's answer back to the right row; `band` is red (critical) / amber (warning).
Flag = namedtuple("Flag", "key text band category")


def flagged_for_system(store: "Store", sysm: "System", cfg: "Config") -> List[Flag]:
    """Every critical/warning item on one system's card, in render order (critical first).
       Single source of truth shared by the xlsx Notes table AND the web form, so the form
       asks about exactly the rows the report will show. Derived purely from `store`."""
    flags: List[Flag] = []
    # disks (worst-first within each host, hosts in topology order)
    for c in sysm.components:
        for mount, dd in sorted(store.disk.get(c.instance, {}).items(), key=lambda kv: -kv[1].get("used", 0)):
            u = dd.get("used", 0)
            band = "red" if u >= cfg.chip_red else ("amber" if u >= cfg.chip_amber else None)
            if band:
                flags.append(Flag(f"disk:{c.label}:{mount}", f"{c.label} · {mount} {u:.0f}%", band, "disk"))
    # unreachable host / high RAM (one pass per component, mirroring the Memory panel)
    for c in sysm.components:
        if is_unreachable(store, c.instance):
            flags.append(Flag(f"unreachable:{c.label}", f"{c.label} · unreachable", "red", "unreachable"))
        else:
            v = store.ram.get(c.instance)
            if v is not None and v >= cfg.chip_red:
                flags.append(Flag(f"ram:{c.label}", f"{c.label} · RAM {v:.0f}%", "red", "ram"))
            elif v is not None and v >= cfg.chip_amber:
                flags.append(Flag(f"ram:{c.label}", f"{c.label} · RAM {v:.0f}%", "amber", "ram"))
    # high CPU
    for c in sysm.components:
        cu = store.cpu.get(c.instance)
        if cu is None:
            continue
        band = "red" if cu >= cfg.chip_red else ("amber" if cu >= cfg.chip_amber else None)
        if band:
            flags.append(Flag(f"cpu:{c.label}", f"{c.label} · CPU {cu:.0f}%", band, "cpu"))
    # services down
    for name, up, _kind, group in store.services.get(sysm.name, []):
        if not up:
            loc = f"{group} · " if group and group != sysm.name else ""
            flags.append(Flag(f"service:{group}:{name}", f"{loc}{name} DOWN", "red", "service"))
    # backups: a reporting host with no fresh file (freshness re-judged at report time,
    # against that host's own backup policy — see backup_cutoff)
    now = datetime.datetime.now()
    for c in sysm.components:
        d = store.backups.get(c.instance)
        if d is None:
            continue
        cutoff = backup_cutoff(c.instance, now)
        fresh = any(mt and mt >= cutoff for _n, _day, mt in (d.get("files") or []))
        if not fresh and not backup_gap_expected_any(c.instance, d.get("ok"), now):
            reason = "FOLDER UNREADABLE" if d.get("ok") is False else "NO BACKUP"
            flags.append(Flag(f"backup:{c.label}", f"{c.label} · {reason}", "red", "backup"))
    # untracked: no host on the system runs the backup check at all -- except systems in
    # BACKUP_UNTRACKED_EXEMPT, where that's expected (a stated reason, not a gap); those get
    # an explanatory comment instead (see backup_policy_notes_for_system), never this flag.
    if (sysm.name not in BACKUP_UNTRACKED_EXEMPT
            and not any(c.instance in store.backups for c in sysm.components)):
        flags.append(Flag(f"untracked:{sysm.name}",
                          f"{sysm.name} · UNTRACKED (no backup check on any host)", "amber", "untracked"))
    flags.sort(key=lambda f: 0 if f.band == "red" else 1)   # critical first (stable)
    return flags


def backup_policy_notes_for_system(store: "Store", sysm: "System",
                                    now: datetime.datetime | None = None) -> List[str]:
    """Informational, non-actionable notes for a system's components currently sitting in
    either of two policy-explainable backup states — deliberately separate from
    flagged_for_system's Flags (those drive the web form's Fix-needed/Resolved decision, and
    neither of these is ever a fault, so neither must appear as one):

    1. A policy-expected GAP (see backup_gap_expected/backup_policy_comment) — e.g. RTGS/CSD
       DB the Monday after their Sunday off-day: no fresh file at all, even under the
       widened cutoff window.
    2. A slower-than-daily CADENCE (see backup_frequency_comment) — e.g. BSA's MSSQL full
       backup, which only runs every 3rd day: a file IS present and within policy, just older
       than today/yesterday, which is what makes it "fresh" only under the widened window and
       not under the plain (today, yesterday) pair a daily reader would expect.

    3. An UNTRACKED exemption (BACKUP_UNTRACKED_EXEMPT) — no component reports the backup
       check at all, but for a stated reason (backs up to the vendor's cloud, still under
       development, ...) rather than an unexplained monitoring gap. Returned alone, since
       there's nothing else to check on a system with zero tracked components.

    Mirrors flagged_for_system's own backup freshness check (same cutoff) so this and the
    xlsx Backups panel never disagree about which components are in either state."""
    now = now or datetime.datetime.now()
    reason = BACKUP_UNTRACKED_EXEMPT.get(sysm.name)
    if reason and not any(c.instance in store.backups for c in sysm.components):
        return [reason]
    notes: List[str] = []
    ymid = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp() - 86400
    for c in sysm.components:
        d = store.backups.get(c.instance)
        if d is None:
            continue
        files = d.get("files") or []
        cutoff = backup_cutoff(c.instance, now)
        widely_fresh = any(mt and mt >= cutoff for _n, _day, mt in files)
        if not widely_fresh:
            if backup_gap_expected_any(c.instance, d.get("ok"), now):
                text = backup_gap_comment(c.instance, now)
                if text:
                    notes.append(f"{c.label} — {text}")
        elif not any(mt and mt >= ymid for _n, _day, mt in files):
            # fresh only via the widened window, not today/yesterday -> a slower cadence
            text = backup_frequency_comment(c.instance, now)
            if text:
                notes.append(f"{c.label} — {text}")
    return notes


def backup_missing_band(count: int) -> str:
    """Card state for the overview MISSING BACKUPS tile. No misses -> good (green).
       Freshness is judged on a (today, yesterday) pair. Work days are Mon–Sat,
       Sunday is the non-work day: whenever YESTERDAY is Sunday (i.e. today is
       Monday) the pair straddles the non-work day, so a missing backup is only a
       warning (amber). On every other day both members of the pair are work days,
       so a missing backup is critical (red)."""
    if count == 0:
        return "good"
    yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
    return "warn" if yesterday.weekday() == 6 else "bad"   # yesterday Sunday (today Monday) -> amber


# ============================================================================ #
#  REPORT BUILDER
# ============================================================================ #
class ReportBuilder:
    # column widths (A gutter, then Services | gap | Memory | gap | Disk | gap | Backups | gap | Notes)
    # D, H and N (the gaps before Memory·CPU, Disk and Backups) are the exact values from the
    # approved reference workbook (standalone/systems admin report/System Admin Report -
    # 2026-08-19 2051 (dark).xlsx) -- Excel AutoFit widths, not round numbers, kept precise
    # rather than rounded so this matches that file exactly. R (gap before Notes) stays 2,
    # tighter than the other three, matching that same reference. Each of D/H/N is shared
    # with real content in the overview tile band above (D = HIGH CPU USAGE's 3rd sub-column,
    # H = HIGH DISK USAGE's 2nd), but _split_by_width there divides by WIDTH, not column
    # count, so a narrow gap column just merges into the wider sub-column beside it (e.g.
    # C-D becomes "TOTAL"'s span) instead of clipping -- verified against live data for both.
    # I-M are the Disk table (Host | Mount | Used % | Free GB | Size GB); J=20 (not the ~12
    # you'd expect) because Mount now also holds folder_exporter log-folder names ("T24 Log
    # File") that a tight column clipped -- same fix as the AT A GLANCE platforms tile, same
    # column-sharing reason: J is also WEB ENCRYPTION's 2nd sub-column in the watch row and
    # SERVICES DOWN's 3rd in the immediate row, both of which only ever hold short values, so
    # widening it here costs them nothing.
    WIDTHS = {"A": 6.43, "B": 22, "C": 9, "D": 8.140625, "E": 14, "F": 8,
              "G": 8, "H": 7.5703125, "I": 14, "J": 20, "K": 7, "L": 7,   # G = Memory·CPU's CPU % column
              "M": 11, "N": 7.85546875, "O": 30, "P": 13, "Q": 11,   # O-Q = Backups (File | Generated | Status)
              "R": 2,                                        # gap before Notes
              "S": 13, "T": 11, "U": 11, "V": 11, "W": 9}  # S-W = notes column
    CARD_GROUPS = [(2, 4), (5, 7), (8, 9), (10, 12)]   # 4 overview cards across the width

    def __init__(self, cfg: Config, *, author: Optional[str] = None,
                 annotations: Optional[dict] = None, summary_comment: Optional[str] = None):
        self.cfg = cfg
        # admin-supplied inputs from the web form (all optional — CLI runs leave them blank):
        #   author           -> the master "By" name, mirrored across every card
        #   summary_comment  -> free text in the Summary Notes box
        #   annotations      -> {system_name: {"flags": {flag_key: "Yes"|"No"},
        #                                       "comment": str}}  pre-fills each card's Notes
        self.author = (author or "").strip() or None
        self.summary_comment = (summary_comment or "").strip() or None
        self.annotations = annotations or {}
        self.wb = openpyxl.Workbook()
        self.ws = self.wb.active
        self.ws.title = "System Admin Report"
        for col, width in self.WIDTHS.items():
            self.ws.column_dimensions[col].width = width
        self._thin = Side(style="thin", color=Theme.BORDER)
        self._first_by = None        # the master "By" cell; later systems mirror it via a formula
        self._link_owner: Dict[str, Optional[str]] = {}   # url -> normalised owning system (or None)

    # -- primitive helpers ----------------------------------------------------
    # bg defaults to None (NOT Theme.BG) so the *current* palette is read at call time — a
    # default of `bg=Theme.BG` would freeze to whatever palette was active at class-definition
    # (dark), so the palette() swap would never reach cells that rely on the default background.
    def _cell(self, r, c, v="", font=None, bg=None, al="left", border=False):
        x = self.ws.cell(r, c)
        x.value = v
        x.font = font or Theme.font()
        x.fill = Theme.fill(bg if bg is not None else Theme.BG)
        x.alignment = Alignment(horizontal=al, vertical="center")
        if border:
            x.border = Border(self._thin, self._thin, self._thin, self._thin)
        return x

    def _merge(self, r, c1, c2, v, font, bg=None, al="left"):
        for c in range(c1, c2 + 1):
            self._cell(r, c, v if c == c1 else "", font, bg, al)
        self.ws.merge_cells(start_row=r, start_column=c1, end_row=r, end_column=c2)

    def _split_by_width(self, c1, c2, n) -> List[Tuple[int, int]]:
        """Split columns c1..c2 into n contiguous sub-columns of ~equal PIXEL width (not
           equal column count), so a divider between them sits centered even when the
           underlying columns differ in width. Each sub-column gets at least one column."""
        cols = list(range(c1, c2 + 1))
        w = [self.ws.column_dimensions[get_column_letter(c)].width or 8.43 for c in cols]
        total = sum(w)
        spans, start = [], 0
        for i in range(1, n):
            target = total * i / n                       # ideal cumulative width at this boundary
            # candidate split indices keep >=1 col for this sub-column and each remaining one
            best_j, best_d = start + 1, None
            for j in range(start + 1, len(cols) - (n - i) + 1):
                d = abs(sum(w[:j]) - target)
                if best_d is None or d < best_d:
                    best_d, best_j = d, j
            spans.append((cols[start], cols[best_j - 1]))
            start = best_j
        spans.append((cols[start], cols[-1]))
        return spans

    def _band_spans(self, tiles) -> List[int]:
        """Column counts for a row of overview tiles across cols 2..12. Every tile gets AT
           LEAST as many physical columns as it has sub-columns, with a 2-column floor for
           any panel that splits into 2+ sub-columns — 1 column is never enough for a
           2-number panel (HOSTS | TOTAL): the split would degenerate to a single sub-column
           holding both labels merged into one narrow cell and clip (this is what happened to
           HIGH RAM USAGE's "HOSTS" label before the column was widened). A single-number
           panel (no divider to draw) is exempt from that floor and can sit in just 1 column.
           Every panel here is a 2-number one (its own affected | TOTAL) and lands at the
           2-column floor, six panels' worth summing to the row's historical 11 columns — so
           there is no room for a 3rd/4th sub-column without dropping another panel's own
           TOTAL to pay for it (HIGH DISK USAGE briefly did this at BACKUP TRACKING's expense;
           reverted, since a row where one tile's total is missing so another's can have two
           of them just moves the problem). Any spare width beyond each tile's own minimum
           goes first to the widest-need panel(s)."""
        n = len(tiles)
        subcols = lambda t: len(t[2]) if t[0] == "panel" else 1
        spans = [max(2, subcols(t)) if subcols(t) > 1 else 1 for t in tiles]
        ncols = max(11, sum(spans))
        spare = ncols - sum(spans)
        order = sorted(range(n), key=lambda i: (-subcols(tiles[i]), i))   # widest need first
        i = 0
        while spare > 0:
            spans[order[i % n]] += 1
            i, spare = i + 1, spare - 1
        return spans

    def _chip(self, r, c, text, band, sz=10):
        fg, bg = Theme.CHIP[band]
        self._cell(r, c, text, Theme.font(sz, True, fg), bg=bg, al="center", border=True)

    def _chip_span(self, r, c1, c2, text, band, sz=9):
        """A status chip spanning c1..c2 (band=None -> neutral grey dash cell)."""
        if band is None:
            for c in range(c1, c2 + 1):
                self._cell(r, c, text if c == c1 else "", Theme.font(sz, False, Theme.SUB),
                           bg=Theme.BG, al="center", border=True)
        else:
            fg, bg = Theme.CHIP[band]
            for c in range(c1, c2 + 1):
                self._cell(r, c, text if c == c1 else "", Theme.font(sz, True, fg),
                           bg=bg, al="center", border=True)
        if c2 > c1:
            self.ws.merge_cells(start_row=r, start_column=c1, end_row=r, end_column=c2)

    def _band(self, used: float) -> str:
        return "red" if used >= self.cfg.chip_red else ("amber" if used >= self.cfg.chip_amber else "green")

    @staticmethod
    def _code_band(code: Optional[int]) -> str:
        if not code:
            return "red"
        return "green" if 200 <= code < 300 else ("amber" if 300 <= code < 500 else "red")

    @staticmethod
    def _cert_band(days: Optional[float]) -> Optional[str]:
        if days is None:
            return None
        return "red" if days < 7 else ("amber" if days < 24 else "green")  # thresholds from the links dashboard

    @staticmethod
    def _link_status(d: dict, url: str) -> Tuple[Optional[str], Optional[str]]:
        """One chip for a link service: reachability first, then cert urgency.
           expired / ≤7 days = critical (red) · <24 days = warning (amber)."""
        if not d:
            return None, None                      # no probe data -> neutral dash
        if not d.get("up", False):
            return "DOWN", "red"
        cd = d.get("cert_days")
        if url.lower().startswith("https") and cd is not None:
            if cd < 0:
                return "EXPIRED", "red"
            if cd < 7:
                return f"{cd:.0f}d", "red"
            if cd < 24:
                return f"{cd:.0f}d", "amber"
        return "UP", "green"

    # -- sections -------------------------------------------------------------
    def _header(self, store: Store):
        # ---- company logo: a brand crest in the top-left (floats over the grid) ----
        try:
            img = XLImage(self.cfg.logo)
            marker = AnchorMarker(col=self.cfg.logo_from_col, colOff=self.cfg.logo_from_coloff,
                                  row=self.cfg.logo_from_row, rowOff=self.cfg.logo_from_rowoff)
            img.anchor = OneCellAnchor(_from=marker,
                                       ext=XDRPositiveSize2D(cx=self.cfg.logo_cx, cy=self.cfg.logo_cy))
            self.ws.add_image(img)
        except Exception as exc:                      # missing/unreadable logo -> carry on
            print(f"[!] logo not embedded ({exc})", file=sys.stderr)
        for row, ht in {1: 6, 2: 18, 3: 26, 4: 15, 5: 20, 6: 34, 7: 18}.items():
            self.ws.row_dimensions[row].height = ht
        # ---- title block, set to the RIGHT of the crest ----
        self._merge(3, 3, 12, "SYSTEM ADMIN REPORT", Theme.font(22, True, Theme.WHITE))
        self._merge(4, 3, 12,
                    f"snapshot generated {datetime.datetime.now():%d %b %Y  ·  %H:%M}      •      "
                    "System Admin Dashboard (Green)",
                    Theme.font(9, False, Theme.SUB))
        self._merge(5, 3, 8,
                    "Static snapshot.   For LIVE, auto-refreshing monitoring, click  →",
                    Theme.font(9, False, Theme.GREY))
        # Grafana link — turquoise TEXT (no fill, no underline), merged wide enough to read in full
        for c in range(9, 14):
            self._cell(5, c, "", Theme.font(12, True, Theme.CYAN), bg=Theme.BG, al="center")
        self.ws.merge_cells(start_row=5, start_column=9, end_row=5, end_column=13)
        btn = self.ws.cell(5, 9)
        btn.value = "▸  OPEN LIVE GRAFANA DASHBOARD"
        btn.hyperlink = self.cfg.grafana

    def _overview(self, store: Store, systems: List[System]):
        # section heading above the summary cards
        self._merge(7, 2, 12, "Summary", Theme.font(13, True, Theme.CYAN), bg=Theme.BG)
        hosts = sum(len(s.components) for s in systems)
        # SERVICES inventory counts BOTH classes shown on the cards: PromQL checks + web links,
        # so the 'SERVICES DOWN' count (which now includes down links) can never exceed it.
        nsvc = total_services(store)
        down = services_down(store)   # PromQL service checks + down web-link probes (see services_down)
        thr = self.cfg.overview_threshold
        ram_hosts, ram_state = ram_pressure(store, systems, self.cfg.chip_amber, self.cfg.chip_red)
        cpu_hosts, cpu_state = cpu_pressure(store, systems, self.cfg.chip_amber, self.cfg.chip_red)
        # COB is "missing" when the metric is absent OR NaN. The collector writes NaN
        # when the value is out of range (abnormally high) — which means the close-of-
        # business procedure most likely did not run the previous day. Both read as "no
        # COB", shown as N/A rather than a bogus number.
        cob_missing = store.cob is None or (isinstance(store.cob, float) and math.isnan(store.cob))
        cob = "N/A" if cob_missing else f"{store.cob/60:.1f} min"
        swift_missing = store.swift is None or (isinstance(store.swift, float) and math.isnan(store.swift))
        swift = f"{store.swift:.0f}" if store.swift is not None else "N/A"
        # web-encryption posture: how many monitored endpoints are HTTPS vs plain HTTP
        n_https = sum(1 for u in store.links if u.lower().startswith("https"))
        n_http = sum(1 for u in store.links if u.lower().startswith("http://"))

        palette = {"info": Theme.INFO, "good": Theme.CHIP["green"],
                   "bad": Theme.CHIP["red"], "warn": Theme.CHIP["amber"],
                   "critical": Theme.CHIP["critical"]}

        def card(rtop, group, label, value, state, vrow=None):
            """Standard card: title (rtop) + big value. vrow lets row 2 bottom-align
               its value so it lines up with the taller disk panel.

               Centered, matching panel()'s alignment — the two are the same "tile" component
               with two shapes (one number vs several), so a reader shouldn't see one row's
               tiles hug the left edge while every other row's are centered. Left-alignment
               also pushed a wide value's tail toward the next tile's border with no margin
               to protect it, which is what made a 2-part value like "64% | 34%" look cramped
               against the accent bar on one side and squeezed on the other."""
            c1, c2 = group
            accent, tint = palette[state]
            vrow = rtop + 1 if vrow is None else vrow
            bar = Border(left=Side(style="thick", color=accent))   # accent bar on the LEFT
            self._merge(rtop, c1, c2, label, Theme.font(8, True, Theme.SUB), bg=tint, al="center")
            for r in range(rtop + 1, vrow):                        # keep the card solid if it spans 3 rows
                self._merge(r, c1, c2, "", Theme.font(8), bg=tint, al="center")
            self._merge(vrow, c1, c2, value, Theme.font(22, True, accent), bg=tint, al="center")
            for r in range(rtop, vrow + 1):
                self.ws.cell(r, c1).border = bar
            self.ws.row_dimensions[vrow].height = 30

        def panel(rtop, group, title, cols, state):
            """A titled panel with a CENTERED title, split into len(cols) sub-columns.
               cols = [(sublabel, value), ...]  (1 column for RAM, 2 for disk)."""
            c1, c2 = group
            accent, tint = palette[state]
            bar = Border(left=Side(style="thick", color=accent))
            div = Border(left=Side(style="thin", color=Theme.SUB))   # divider between sub-columns
            self._merge(rtop, c1, c2, title, Theme.font(8, True, Theme.SUB), bg=tint, al="center")
            if len(cols) == 1:                                       # single centered column (RAM)
                sub, val = cols[0]
                self._merge(rtop + 1, c1, c2, sub, Theme.font(8, True, Theme.SUB), bg=tint, al="center")
                self._merge(rtop + 2, c1, c2, str(val), Theme.font(22, True, accent), bg=tint, al="center")
            else:                                                   # sub-columns share the FULL card width (disk)
                # split by WIDTH, not column count, so each sub-column holds an equal share of
                # the panel's pixels and the divider lands centered even though the underlying
                # columns differ in width (fixes the off-centre disk divider).
                for i, ((a, b), (sub, val)) in enumerate(zip(self._split_by_width(c1, c2, len(cols)), cols)):
                    self._merge(rtop + 1, a, b, sub, Theme.font(8, True, Theme.SUB), bg=tint, al="center")
                    self._merge(rtop + 2, a, b, str(val), Theme.font(22, True, accent), bg=tint, al="center")
                    if i:                                           # divider on every sub-column after the first
                        self.ws.cell(rtop + 1, a).border = div
                        self.ws.cell(rtop + 2, a).border = div
            for r in range(rtop, rtop + 3):
                self.ws.cell(r, c1).border = bar
            self.ws.row_dimensions[rtop + 2].height = 30

        def caption(row, text, end_col=12):
            """Thin label above a band of cards, so the two rows read as one group each."""
            self._merge(row, 2, end_col, "  " + text, Theme.font(8, True, Theme.SUB), bg=Theme.BG, al="left")
            self.ws.row_dimensions[row].height = 14

        ur = unreachable(store, systems)           # needed for the Unreachable KPI below

        # ---- ROW 1 · static stats: inventory + point-in-time readings (neutral cyan) ----
        # widths chosen so the wide readings sit in the wide groups. Systems, Hosts and
        # Services are short 1-2 digit numbers, so they share the narrow 1-column shape
        # SYSTEMS already proved works. LINUX | WINDOWS's "64% | 34%" is 9 characters at the
        # same large value font every card uses — too wide for 2 columns (it clipped: see
        # commit fixing this), so it gets 3, the same shape COB's similarly-long "44.6 min"
        # already uses; SWIFT loses a column to pay for it since "685"/"N/A" never needs 3.
        caption(8, "AT A GLANCE  ·  inventory & readings")
        linux_pct, win_pct = platform_host_pcts(systems)
        static = [((2, 2),  "SYSTEMS",              str(len(systems))),
                  ((3, 3),  "HOSTS",                 str(hosts)),
                  ((4, 4),  "SERVICES",              str(nsvc)),
                  ((5, 7),  "LINUX | WINDOWS",       f"{linux_pct}% | {win_pct}%"),
                  ((8, 9),  "SWIFT TXNS",            swift),
                  ((10, 12), "COB · T24",            cob)]
        for group, label, value in static:
            card(9, group, label, value, "info", vrow=10)

        # ---- ROW 2 · live health signals, SPLIT BY URGENCY -------------------
        # Two bands, each 3 rows tall (title · sub-labels · value):
        #   NEEDS IMMEDIATE ATTENTION — failing now (missing backups, unreachable,
        #       services down, and a near-full disk, which is an imminent outage).
        #   NEEDS ATTENTION — degrading but not yet failing (high RAM, elevated disk).
        # Disk is the only signal that moves: >= chip_red -> immediate, else watch.
        miss = backup_missing(store, systems)
        nmiss = len(miss)
        # SSL rollup: expired certs are failing NOW (immediate); those expiring within 30
        # days are a silent-failure risk to renew (attention/banner below).
        cert_expired, cert_expiring = cert_rollup(store)

        imm_tiles = [
            # missing out of TRACKED hosts (an untracked host isn't judged either way —
            # see backup_tracked_hosts / the separate BACKUP TRACKING tile for those).
            ("panel", "MISSING BACKUPS", [("MISSING", nmiss), ("TRACKED", backup_tracked_hosts(store, systems))],
             backup_missing_band(nmiss)),
            # unreachable/down out of the TOTAL we monitor, so the count never reads as if
            # fewer components/services exist just because some are currently failing.
            ("panel", "UNREACHABLE COMPONENTS", [("UNREACHABLE", len(ur)), ("TOTAL", hosts)],
             "good" if not ur else "critical"),
            ("panel", "SERVICES DOWN", [("DOWN", down), ("TOTAL", nsvc)],
             "good" if down == 0 else "bad"),
            ("panel", "EXPIRED CERTS", [("EXPIRED", len(cert_expired)), ("TOTAL", cert_monitored(store))],
             "good" if not cert_expired else "bad"),
        ]
        # This tile counts EVERY high disk (>= thr) — elevated and near-full together —
        # so it can never read 0 while the DISK NEAR-FULL banner below lists disks; those
        # near-full disks ARE high disks and are included here. The banner still carries
        # the named per-host detail. State follows the count: red if any disk is near-full,
        # amber if only elevated, green when zero — so 0 is always green (the colour rule).
        _disk_high_h, disk_high_d, disk_high_state = disk_high(
            store, systems, thr, self.cfg.chip_red)
        # systems with no backup check at all (a monitoring blind spot) -> amber when any.
        # BACKUP_UNTRACKED_EXEMPT systems don't count here either -- a stated reason, not a
        # gap, so they read as tracked/expected rather than pulling this tile down.
        n_untracked = len(backup_untracked_unexplained(store, systems))
        n_tracked = len(systems) - n_untracked
        # web-encryption posture: green ONLY when no endpoint is plain HTTP; red when plain
        # HTTP endpoints OUTNUMBER the encrypted ones; amber for anything in between.
        web_state = "good" if n_http == 0 else ("bad" if n_http > n_https else "warn")
        # Every tile reads affected-out-of-TOTAL. A bare count cannot be judged: 3 is alarming
        # out of 5 hosts and unremarkable out of 56, and the tile has to say which.
        total_hosts = sum(len(sy.components) for sy in systems)
        watch_tiles = [
            ("panel", "HIGH CPU USAGE", [("HOSTS", cpu_hosts), ("TOTAL", total_hosts)], cpu_state),
            ("panel", "HIGH RAM USAGE", [("HOSTS", ram_hosts), ("TOTAL", total_hosts)], ram_state),
            # DISKS/TOTAL only — the affected-HOSTS count dropped from here. A disk can be
            # high without its host being flagged for CPU/RAM, so the host count wasn't
            # redundant, but every tile in this row must show its own total, and freeing this
            # panel down to 2 columns is what lets BACKUP TRACKING have one back (see
            # _band_spans).
            ("panel", f"HIGH DISK USAGE  ·  ≥{thr}%",
             [("DISKS", disk_high_d), ("TOTAL", total_disks(store, systems))],
             disk_high_state),
            # https out of ALL monitored endpoints. The old https-vs-http pair made a fully
            # encrypted estate read "12 | 0", which looks like half a number, not a pass.
            ("panel", "WEB ENCRYPTION", [("HTTPS", n_https), ("TOTAL", n_https + n_http)], web_state),
            ("panel", "BACKUP TRACKING", [("TRACKED", n_tracked), ("TOTAL", len(systems))],
             "good" if n_untracked == 0 else "warn"),
        ]

        def band(cap_row, title, tiles):
            """Lay a row of tiles across columns 2..12 under a caption, so the band reads as
               one group however many tiles it holds. Width is shared by _band_spans (wider
               panels get more room)."""
            spans = self._band_spans(tiles)
            caption(cap_row, title, end_col=1 + sum(spans))
            trow = cap_row + 1
            start = 2
            for t, span in zip(tiles, spans):
                grp = (start, start + span - 1)
                start += span
                if t[0] == "card":
                    _, label, value, state = t
                    card(trow, grp, label, value, state, vrow=trow + 2)
                else:
                    _, ptitle, cols, state = t
                    panel(trow, grp, ptitle, cols, state)
            return trow + 2

        b1_bottom = band(11, "NEEDS IMMEDIATE ATTENTION", imm_tiles)
        content_bottom = band(b1_bottom + 1,
                              "NEEDS ATTENTION", watch_tiles)

        # ---- full-width alert banners (below the tile bands) -------------------
        # A banner is a stacked, wrapped, accent-barred callout across cols 2..12,
        # used for conditions that need words rather than a bare count: an imminent
        # near-full disk, a component Prometheus can't reach, or a COB that looks like
        # it never ran. Rendered most-urgent first, each growing content_bottom.
        def banner_line(row, text, font, per, tint, accent):   # one wrapped line; height grows to fit
            self._merge(row, 2, 12, "  " + text, font, bg=tint, al="left")
            cell = self.ws.cell(row, 2)
            cell.border = Border(left=Side(style="thick", color=accent))
            cell.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
            self.ws.row_dimensions[row].height = (max(1, (len(text) + per - 1) // per)) * 14 + 6

        def banner_row(row, left, right, tint, accent):
            """One line of a banner's table: a fixed label column, then its values.

            Two merged ranges rather than one wrapped string. The detail used to be every
            host joined by middots into a single paragraph that re-wrapped at the window
            edge, so nothing lined up and a long list read as prose — you could not scan
            down it to find a system.
            """
            self._merge(row, 2, 5, "  " + left, Theme.font(9, True, Theme.WHITE), bg=tint, al="left")
            self.ws.cell(row, 2).border = Border(left=Side(style="thick", color=accent))
            self.ws.cell(row, 2).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
            self._merge(row, 6, 12, right, Theme.font(9, False, Theme.GREY), bg=tint, al="left")
            self.ws.cell(row, 6).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
            self.ws.row_dimensions[row].height = (max(1, (len(right) + 63) // 64)) * 13 + 5

        def render_banner(top, severity, title, rows, expl):
            spec = SEVERITY[severity]
            accent, tint = Theme.CHIP[spec["chip"]]
            banner_line(top, f"{spec['label']}  —  {title}", Theme.font(10, True, accent), 72, tint, accent)
            r = top
            for left, right in rows:
                r += 1
                banner_row(r, left, right, tint, accent)
            if expl:
                r += 1; banner_line(r, expl, Theme.font(8, False, Theme.SUB), 95, tint, accent)
            return r

        # (severity, title, rows, explanation) — rows is [(label, values), ...]
        banners: List[Tuple[str, str, List[Tuple[str, str]], str]] = []

        # 0) LDAP / authentication service down — highest priority, listed first. Every dependent
        #    system can't authenticate users while the shared auth service is unreachable.
        ldap_dependents = ldap_alert(store, systems)
        if ldap_dependents:
            banners.append((
                "imminent",
                f"LDAP / AUTH SERVICE DOWN  —  {len(ldap_dependents)} dependent system(s) affected",
                [("Affected systems", "   ".join(ldap_dependents))],
                "The shared LDAP / authentication service is not responding — users cannot sign in to "
                "the systems that depend on it. Restore the auth service urgently."))

        # 1) imminent near-full disk — moved out of the tile band into a worded banner
        nearfull = disk_near_full(store, systems, self.cfg.chip_red)
        if nearfull:
            byhost: Dict[str, List[str]] = {}
            for s, lbl, mp, used in nearfull:
                byhost.setdefault(f"{s} · {lbl}", []).append(f"{mp} {used:.0f}%")
            banners.append((
                "critical",
                f"DISK NEAR-FULL  —  {len(nearfull)} disk(s) on {len(byhost)} host(s) "
                f"at/over {self.cfg.chip_red}%",
                [(h, ", ".join(v)) for h, v in sorted(byhost.items())],
                "These volumes are almost full — an imminent outage that can take the service down. "
                "Free space or extend the disk now."))

        # 1b) tracked hosts with no fresh backup — a data-loss risk, not a metric out of
        #     range: if the host is lost today, there is nothing recent to restore from.
        #     UNTRACKED hosts never appear here (see backup_missing's own docstring) — this
        #     is only hosts the backup check actually watches and found nothing fresh for.
        if miss:
            bysys: Dict[str, List[str]] = {}
            for s, lbl, reason in miss:
                bysys.setdefault(s, []).append(f"{lbl} ({reason})")
            banners.append((
                "critical",
                f"MISSING BACKUPS  —  {len(miss)} host(s) with no fresh backup",
                [(s, "   ".join(v)) for s, v in sorted(bysys.items())],
                "These hosts run the backup check but have nothing fresh within policy — if the host "
                "is lost today, there is no recent backup to restore from. Confirm the backup job and "
                "re-run it."))

        # 1c) systems where NOT ONE host runs the backup check at all — a monitoring blind
        #     spot, not an active failure (nothing here is judged as missing, because
        #     nothing is being watched to judge). Warning, not critical: this is "we can't
        #     tell" rather than "it's broken" — but it still needs an answer, since a blind
        #     spot is exactly the condition under which a real gap goes unnoticed.
        #     BACKUP_UNTRACKED_EXEMPT systems are excluded here (a stated reason, not an
        #     unexplained gap) -- see their own automatic comment on the system's card.
        untracked = backup_untracked_unexplained(store, systems)
        if untracked:
            banners.append((
                "warning",
                f"BACKUPS UNTRACKED  —  {len(untracked)} system(s) with no backup check at all",
                # one row per system, matching every other banner -- not all names crammed
                # into a single "Systems" row. Same wording flagged_for_system() already
                # uses for this exact condition on a system's own Notes card.
                [(s, "no backup check on any host") for s in sorted(untracked)],
                "No host on these systems reports the backup check, so nothing here can be judged "
                "missing or fresh — it simply isn't being watched. Add the check before this becomes "
                "a real gap nobody caught."))

        # 2) components Prometheus can no longer reach — the highest-severity finding on
        #    this report: every other red banner is at least still being measured, this one
        #    means we've lost visibility entirely. "critical" band + an explicit label (not
        #    just a different accent) so the escalation reads even in black-and-white print.
        if ur:
            bysys: Dict[str, List[str]] = {}
            for s, lbl, _ in ur:
                bysys.setdefault(s, []).append(lbl)
            banners.append((
                "imminent",
                f"UNREACHABLE  —  {len(ur)} component(s) across {len(bysys)} system(s)",
                [(s, ", ".join(lbls)) for s, lbls in sorted(bysys.items())],
                "Prometheus can no longer scrape these targets — the host is down, the exporter has "
                "stopped, or there are network / connectivity issues. Treat as urgent."))

        # 2b) services / links currently reporting DOWN — the named list behind the
        #     overview SERVICES DOWN tile, which until now only ever showed a bare count.
        down_detail = services_down_detail(store, systems)
        if down_detail:
            bysys: Dict[str, List[str]] = {}
            for s, name in down_detail:
                bysys.setdefault(s, []).append(name)
            banners.append((
                "critical",
                f"SERVICES DOWN  —  {len(down_detail)} service(s)/link(s) across {len(bysys)} system(s)",
                [(s, ", ".join(sorted(names))) for s, names in sorted(bysys.items())],
                "These checks or web links are currently reporting down. Confirm whether the outage "
                "is real or the check itself needs attention, then restore service."))

        # 3) SSL certificates expired or expiring within 30 days — a classic silent-failure
        #    risk. Red if any cert has already lapsed (the site is effectively down), else
        #    amber for those merely due to renew. Headline carries the aggregate; detail names
        #    each host with its days-to-expiry.
        if cert_expired or cert_expiring:
            bits = ([f"{len(cert_expired)} expired"] if cert_expired else []) + \
                   ([f"{len(cert_expiring)} expiring within 30 days"] if cert_expiring else [])
            rows = ([("Expired", "   ".join(f"{h} ({abs(cd):.0f}d ago)" for h, cd in cert_expired))]
                    if cert_expired else []) +                    ([("Expiring ≤30d", "   ".join(f"{h} ({cd:.0f}d)" for h, cd in cert_expiring))]
                    if cert_expiring else [])
            banners.append((
                "critical" if cert_expired else "warning",
                f"SSL CERTS  —  {', '.join(bits)}",
                rows,
                "Renew these certificates before they lapse — an expired certificate makes browsers "
                "reject the site, a silent outage until the certificate is replaced."))

        # 3b) monitored web links still on plain HTTP — the named list behind the WEB
        #     ENCRYPTION tile's http count. Warning, not critical: an unencrypted link isn't
        #     down, it's a standing exposure (credentials/session data readable in transit).
        http_links = http_links_detail(store, systems)
        if http_links:
            bysys: Dict[str, List[str]] = {}
            for s, name in http_links:
                bysys.setdefault(s, []).append(name)
            banners.append((
                "warning",
                f"PLAIN HTTP  —  {len(http_links)} link(s) not using HTTPS",
                [(s, ", ".join(sorted(names))) for s, names in sorted(bysys.items())],
                "These web links are reachable over plain HTTP — anything sent to them (including "
                "credentials) travels unencrypted. Move them to HTTPS."))

        # 3c) watched folders (e.g. T24 Log File) over their expected size — see the Folders
        #     table on the owning system's card. Always warning, never critical, however far
        #     over expected the folder grows (see FOLDER_EXPECTED_PCT's docstring) — this is
        #     "keep an eye on it", not an outage.
        over_folders = folder_over_expected_detail(store, systems)
        if over_folders:
            bysys: Dict[str, List[str]] = {}
            for s, name, expected, actual in over_folders:
                bysys.setdefault(s, []).append(f"{name} ({actual:.1f} GB, expected {expected:.1f} GB)")
            banners.append((
                "warning",
                f"FOLDER OVER EXPECTED SIZE  —  {len(over_folders)} folder(s) on "
                f"{len(bysys)} system(s)",
                [(s, "   ".join(v)) for s, v in sorted(bysys.items())],
                "These watched folders have grown past their expected size — worth a look (e.g. "
                "confirm rotation/archival is running), but not itself an outage."))

        # 4) COB looks like it never ran — flagged EVERY day EXCEPT Monday. A Monday
        #    reading covers Sunday (a non-work day with no COB), so an absent/abnormally
        #    high value then is expected, not a fault, and is left unflagged.
        #    EXCEPTION: if the T24 database component is itself unreachable, an abnormal COB
        #    reading isn't evidence COB failed to run — it means we can't tell, because the
        #    exporter that would report it can't be reached. Say that, not "may not have run".
        if cob_missing and datetime.datetime.now().weekday() != 0:   # 0 = Monday
            db_unreachable = any(s == "Temenos" and "DB" in lbl for s, lbl, _ in ur)
            if db_unreachable:
                banners.append((
                    "warning",
                    "COB  —  could not be calculated, T24 database is unreachable",
                    [("Why", "The T24 database component is unreachable, so COB time could not be "
                             "calculated for the previous day — this is not evidence that COB "
                             "itself failed to run.")],
                    "Restore connectivity to the T24 database first, then re-check COB."))
            else:
                banners.append((
                    "warning",
                    "COB  —  close-of-business may not have run yesterday",
                    [("Why", "COB time is out of range (abnormally high), so no completed "
                             "close-of-business was detected for the previous day.")],
                    "Confirm the T24 COB ran and completed. (On Mondays this is expected — Sunday has no "
                    "COB — and is not flagged.)"))

        # 5) SWIFT transaction count missing, WHILE the T24 application component is down —
        #    that's not evidence no SWIFT transactions occurred, it means we can't tell,
        #    because the exporter that would report it can't be reached. Only flagged in this
        #    specific case; a blank SWIFT count while T24 App is up is left unflagged, same as
        #    today, since the app being reachable makes the missing count a different question.
        if swift_missing and any(s == "Temenos" and "App" in lbl for s, lbl, _ in ur):
            banners.append((
                "warning",
                "SWIFT  —  could not be calculated, T24 application is down",
                [("Why", "The T24 application component is down, so SWIFT transaction count could "
                         "not be calculated for the current period — this is not evidence that no "
                         "SWIFT transactions occurred.")],
                "Restore the T24 application first, then re-check SWIFT."))

        if banners:
            r = content_bottom + 2                # one gap row below the tile bands
            banners.sort(key=lambda b: SEVERITY[b[0]]["rank"])   # imminent first, warning last
            for i, (severity, title, rows, expl) in enumerate(banners):
                if i:
                    r += 1                        # blank spacer row between stacked banners
                r = render_banner(r, severity, title, rows, expl)
            content_bottom = r

        # ---- Summary Notes: RHS panel beside the AT A GLANCE / tile bands (explain anything,
        #      incl. the alert) ----
        # O:W (15-23), rows 9-18 by default -- a box beside the tile bands specifically, not
        # one running the full height of however many banners render below. Grows past 18 when
        # its own content needs it: wrap_text alone does NOT grow a row's height in Excel, so
        # long content would otherwise clip instead of visibly wrapping. notes_bottom is the
        # box's own visual bottom; content_bottom (the banners' true bottom, already updated
        # above) still governs where the author line and the NEXT section start, so a tall
        # banner stack is never overlapped just because this box happens to be shorter.
        nl, nr = 15, 23
        field = Border(left=self._thin, right=self._thin, top=self._thin, bottom=self._thin)
        # title sits LOW — level with the cards (row 9), mirroring the per-system notes titles
        tt = 9
        self._merge(tt, nl, nr, "Summary Notes", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)

        # Per-system findings, compiled HERE from live store/systems data via
        # system_comment_text -- the SAME thing each system's own Comment box shows (see
        # _system_card) -- rather than depending on whatever the web form's summary box
        # happened to be submitted with. That's what makes this show up in a CLI/scheduled
        # report too (no web form step, self.annotations is always {} there) instead of only
        # after an admin reviews and submits interactively.
        #
        # Rendered as a table (# | Systems | Comment), grouped by IDENTICAL comment text --
        # several systems very often share the exact same sentence verbatim (most commonly
        # NO_ISSUES_COMMENT, but also a shared policy explanation), and repeating it once per
        # system just made the box longer without saying anything new. One row per DISTINCT
        # comment; the Systems column lists everyone it applies to.
        groups: List[Tuple[str, List[str]]] = []
        seen: Dict[str, int] = {}
        for sysm in systems:
            flagged_s = flagged_for_system(store, sysm, self.cfg)
            text = system_comment_text(store, sysm, flagged_s, self.annotations)
            if not text:
                continue
            if text in seen:
                groups[seen[text]][1].append(sysm.name)
            else:
                seen[text] = len(groups)
                groups.append((text, [sysm.name]))

        # Hard ceiling on the number of table rows. Grouping identical text already does most
        # of the work of keeping this short, but on an unusually bad day with many DIFFERENT
        # findings an unbounded table could still grow tall enough to distort the "AT A GLANCE"
        # section it sits beside. Nothing is actually lost when the cap bites -- every system's
        # own card still carries its own comment in full (see _system_card); this only limits
        # the compiled copy here.
        MAX_TABLE_ROWS = 20
        overflow = 0
        if len(groups) > MAX_TABLE_ROWS:
            overflow = sum(len(names) for _, names in groups[MAX_TABLE_ROWS:])
            groups = groups[:MAX_TABLE_ROWS]

        SYS_CHARS, CMT_CHARS = 20, 50   # rough fit for the Systems / Comment columns' own widths

        def _lines(text: str, chars: int) -> int:
            return max(1, -(-len(text) // chars))          # ceil division

        # Tall content is given more ROWS (vertically merged), never a taller row via
        # row_dimensions[r].height -- these rows are shared with the "AT A GLANCE" tile bands
        # in columns B-N (Excel row height is whole-row, not per-column), so setting an
        # explicit height here previously stretched every tile in that row apart too. Merging
        # more rows at their own existing height achieves the same visible space without
        # touching a property the tiles also depend on.
        def _span(top: int, lines: int, c1: int, c2: int, value, font, al: str) -> None:
            bottom = top + lines - 1
            for rr in range(top, bottom + 1):
                for c in range(c1, c2 + 1):
                    self._cell(rr, c, bg=Theme.CARD).border = field
            self.ws.cell(top, c1).value = value
            self.ws.cell(top, c1).font = font
            self.ws.cell(top, c1).alignment = Alignment(horizontal=al, vertical="top", wrap_text=True)
            if c2 > c1 or bottom > top:
                self.ws.merge_cells(start_row=top, start_column=c1, end_row=bottom, end_column=c2)

        r = tt + 1

        # Admin's own freeform overall remark (web form or CLI --summary), if any -- kept as a
        # plain wrapped line ABOVE the table since it isn't tied to specific systems, so it
        # doesn't force an artificial "Systems" value into the table's own structure.
        if self.summary_comment:
            lines = _lines(self.summary_comment, 100)
            _span(r, lines, nl, nr, self.summary_comment, Theme.font(9, False, Theme.WHITE), "left")
            r += lines

        if groups or overflow:
            # column layout within nl..nr: # (col O alone, centered -- unavoidably wide since O
            # is shared with the per-system Backups panel's own filename column elsewhere on
            # this sheet, but its content is always just 1-2 digits) | Systems (P-Q) | Comment
            # (R-W, the widest share -- comments run longer than most system-name lists).
            num_c, sys1, sys2, cmt1, cmt2 = nl, nl + 1, nl + 2, nl + 3, nr
            self._cell(r, num_c, "#", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
            self._merge(r, sys1, sys2, "Systems", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="left")
            self._merge(r, cmt1, cmt2, "Comment", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="left")
            for cc in (sys1, sys2, cmt1, cmt2):
                self.ws.cell(r, cc).border = field
            r += 1

            for i, (text, names) in enumerate(groups, start=1):
                sys_text = ", ".join(names)
                lines = max(_lines(sys_text, SYS_CHARS), _lines(text, CMT_CHARS))
                _span(r, lines, num_c, num_c, str(i), Theme.font(9, False, Theme.WHITE), "center")
                _span(r, lines, sys1, sys2, sys_text, Theme.font(9, False, Theme.WHITE), "left")
                _span(r, lines, cmt1, cmt2, text, Theme.font(9, False, Theme.SUB), "left")
                r += lines

            if overflow:
                note = f"…and {overflow} more system(s) — see each system's own Comment box."
                _span(r, 1, nl, nr, note, Theme.font(9, False, Theme.SUB), "left")
                r += 1

        notes_bottom = max(18, r - 1)
        # author line — this is the MASTER name cell (drawn first), every system's "By" mirrors it.
        # Below whichever is taller: the banners or this now-short box.
        by = max(content_bottom, notes_bottom) + 1
        self._cell(by, nl, "By  ", Theme.font(8, False, Theme.SUB), bg=Theme.CARD, al="right")
        for c in range(nl + 1, nr + 1):
            self._cell(by, c, bg=Theme.CARD).border = field
        anchor = self.ws.cell(by, nl + 1)
        anchor.alignment = Alignment(horizontal="left", vertical="center")
        if self.author:                                # master author name; every card mirrors it
            anchor.value = self.author
        self._first_by = f"${get_column_letter(nl + 1)}${by}"
        self.ws.merge_cells(start_row=by, start_column=nl + 1, end_row=by, end_column=nr)
        # Everything the purple box no longer reaches (rows below it, alongside a tall banner
        # stack) still needs the page background explicitly -- nothing else touches these
        # cells, and an untouched cell renders WHITE, a stark hole in an otherwise all-dark
        # sheet (the same class of bug the title-bar gap column had earlier).
        for r in range(notes_bottom + 1, content_bottom + 1):
            for c in range(13, nr + 1):
                self._cell(r, c, bg=Theme.BG)
        return by + 1   # next free row (one gap line)

    def _system_card(self, y: int, sysm: System, store: Store) -> int:
        svcs = store.services.get(sysm.name, [])      # [(name, up, kind, component)], sorted kind→component
        # interleave a sub-header whenever the service class changes (SYSTEM SERVICES /
        # OFFERED SERVICES), and — within SYSTEM SERVICES — a lighter component sub-header
        # whenever the host/component changes, so each service sits under the box it runs on.
        svc_rows = []                                 # ("hdr", caption) | ("sub", component) | ("svc", name, up) | ("link", ...)
        last_kind = last_group = None
        for name, up, kind, group in svcs:
            if kind != last_kind:
                svc_rows.append(("hdr", SERVICE_KIND_LABELS.get(kind, kind.upper())))
                last_kind, last_group = kind, None
            if kind == "system" and group and group != last_group:
                svc_rows.append(("sub", group))
                last_group = group
            svc_rows.append(("svc", name, up))
        # web links as a third service class — reachability + SSL cert urgency.
        # links auto-attributed to this system by name (see assign_link)
        nrm = _norm(sysm.name)
        matched = [u for u in sorted(store.links) if self._link_owner.get(u) == nrm]
        if matched:
            svc_rows.append(("hdr", "WEB LINKS"))
            for url in matched:
                svc_rows.append(("link", _link_display(url), store.links[url], url))
        # SSL certificate expiry as its own service sub-class (it's just another health check):
        # one row per HTTPS cert showing days-to-expiry, coloured by the cert band, soonest first
        ssl_certs = [(u, store.links[u].get("cert_days")) for u in matched if u.lower().startswith("https")]
        ssl_certs.sort(key=lambda t: (t[1] is None, t[1] if t[1] is not None else 0.0))
        if ssl_certs:
            svc_rows.append(("hdr", "SSL CERTS"))
            for url, cd in ssl_certs:
                svc_rows.append(("cert", _link_display(url), cd))
        # one Memory row per host, carrying its reachability:  ("down" | "ok" | "nodata", value)
        # a parallel CPU row per host (same order) feeds the Memory · CPU table's CPU % column
        mems, cpus = [], []
        for c in sysm.components:
            if is_unreachable(store, c.instance):
                mems.append((c.label, "down", None))
                cpus.append((c.label, "down", None))
            else:
                mems.append((c.label, "ok", store.ram[c.instance]) if c.instance in store.ram
                            else (c.label, "nodata", None))
                cpus.append((c.label, "ok", store.cpu[c.instance]) if c.instance in store.cpu
                            else (c.label, "nodata", None))
        disks = [(c.label, mp, dd)
                 for c in sysm.components
                 for mp, dd in sorted(store.disk.get(c.instance, {}).items(),
                                      key=lambda kv: -kv[1].get("used", 0))]
        # watched folders (see Store.log_files / FOLDER_EXPECTED_PCT) get their own Folders
        # table, directly under Disk -- never store.disk itself, so they can't be mistaken
        # for a real volume by total_disks()/disk_high()/disk_near_full(). Keyed by SYSTEM
        # (see Store.log_files), not per-component -- attributed to the component whose OWN
        # instance shares the folder_exporter's IP (source_ip), i.e. the host the watched
        # folder actually lives on. T24's log folder turned out to be on T24 DB, not T24 App
        # -- a name-based guess ("whichever looks like App") would have gotten that wrong,
        # so this matches by address instead. Falls back to the first component only if
        # nothing on this system shares that IP.
        folders = []
        for name, gb, source_ip in store.log_files.get(sysm.name.lower(), []):
            owner = next((c for c in sysm.components
                         if c.instance.split(":")[0] == source_ip),
                        sysm.components[0] if sysm.components else None)
            host = owner.label if owner else sysm.name
            folders.append((host, name, gb, owner.instance if owner else None))
        nd = sum(1 for _, st, _ in mems if st == "down")           # hosts Prometheus can't reach
        nc = sum(1 for *_, dd in disks if dd.get("used", 0) >= self.cfg.chip_red) + \
             sum(1 for _, st, v in mems if st == "ok" and v >= self.cfg.chip_red) + \
             sum(1 for _, st, v in cpus if st == "ok" and v >= self.cfg.chip_red)
        nw = sum(1 for *_, dd in disks if self.cfg.chip_amber <= dd.get("used", 0) < self.cfg.chip_red)

        # backups: re-judge each file's freshness by its mtime AT REPORT TIME. The `day` label is
        # baked when the check runs, so it goes STALE if the check stops running (a frozen metric
        # would otherwise still read "yesterday" days later). Anything past the host's backup
        # policy window is dropped; a host left with no fresh file = critical "NO BACKUP".
        _now  = datetime.datetime.now()
        _tmid = _now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        _ymid = _tmid - 86400
        bk_files, bk_missing, bk_expected_off = [], [], []   # (filename, day, mtime) / (host, reason) / (host, reason)
        for c in sysm.components:
            d = store.backups.get(c.instance)
            if d is None:
                continue                         # host doesn't run the backup check -> no row
            _cutoff = backup_cutoff(c.instance, _now)   # daily for most hosts; wider where policy says so
            fresh = []
            for name, _day, mtime in (d.get("files") or []):
                if mtime and mtime >= _tmid:
                    fresh.append((name, "today", mtime))
                elif mtime and mtime >= _ymid:
                    fresh.append((name, "yesterday", mtime))
                elif mtime and mtime >= _cutoff:
                    # still current under a slower-than-daily policy: name the weekday rather
                    # than calling it "yesterday", which it isn't (renders as PRESENT)
                    fresh.append((name, datetime.datetime.fromtimestamp(mtime).strftime("%A").lower(), mtime))
                # else: past the policy window -> stale, does NOT count as a fresh backup
            if fresh:
                bk_files.extend(fresh)
            elif backup_gap_expected_any(c.instance, d.get("ok"), _now):
                # policy says this host isn't expected to have a fresh file today -- either a
                # single off-day (RTGS/CSD, Sundays) or a fixed weekly cadence (FRS, Fridays
                # only) -- an expected gap, not a fault (see backup_gap_expected/
                # backup_weekly_gap_expected's own docstrings for why this can't just be a
                # wider backup_cutoff window). A distinct row, not silence, so the panel still
                # says something rather than looking like the host was never checked at all.
                bk_expected_off.append((c.label, backup_gap_comment(c.instance, _now)))
            else:
                bk_missing.append((c.label, "FOLDER UNREADABLE" if d.get("ok") is False else "NO BACKUP"))
        bk_files.sort(key=lambda ft: (0 if ft[1] == "today" else 1, ft[0]))   # today first
        bk_rows = ([("file", fname, fday, mtime) for fname, fday, mtime in bk_files]
                  + [("missing", host, reason) for host, reason in bk_missing]
                  + [("expected_off", host, reason) for host, reason in bk_expected_off])
        nbk_missing = len(bk_missing)
        # system-wide backup blind spot: NOT ONE host reports the backup check (matches the
        # overview BACKUP TRACKING tile). Distinct from NO BACKUP — a host that DOES run the
        # check but produced nothing fresh. Untracked means the check itself is absent, so the
        # loop above judged nothing; the admin must still answer for it in the notes table.
        bk_untracked = not any(c.instance in store.backups for c in sysm.components)

        y += 1
        # band: system name (left) + one-line health summary (right)
        self._merge(y, 2, 7, f"▌  {sysm.name}", Theme.font(13, True, Theme.CYAN), bg=Theme.CARD)
        # health summary, one colour for the whole line rather than per segment (rich text):
        # openpyxl/Excel's horizontal alignment is NOT reliably honoured on a merged cell
        # holding rich text (multiple runs) -- confirmed by screenshot, the line rendered
        # flush LEFT despite al="right" and the correct 9-23 merge, leaving a visible gap
        # before Notes' own right edge. Plain text's alignment is ordinary, well-supported
        # behaviour, so this line now takes the WORST band present (red > amber > green),
        # same rank order the per-system chips already use, rather than colouring segments
        # individually.
        red, amber, green = Theme.CHIP["red"][0], Theme.CHIP["amber"][0], Theme.CHIP["green"][0]
        segs = []                                            # plain text pieces, worst-first order
        if nd:          segs.append(f"{nd} unreachable")
        if nbk_missing: segs.append(f"{nbk_missing} no-backup")
        if bk_untracked: segs.append("backups untracked")
        segs.append(f"{nc} critical")
        segs.append(f"{nw} warning")
        segs.append(f"{len(svcs)} services")
        summary_color = red if (nd or nbk_missing or nc) else (amber if (bk_untracked or nw) else green)
        # col 8 is the real gap column before Disk (see WIDTHS) -- blanked here TOO, in the
        # CARD background matching the rest of this bar, not just in the rows below, so the
        # name/summary bar reads as one solid strip rather than showing a hole the wrong
        # colour where the gap column crosses it (the bug in the first attempt at this).
        self._cell(y, 8, bg=Theme.CARD)
        # Right-aligned at 23 -- Notes' own right edge, always (see nl/nr below), not
        # Disk's -- so the summary sits flush with where the whole card actually ends,
        # the same edge the name panel's own bar now reaches.
        self._merge(y, 9, 23, "  ·  ".join(segs), Theme.font(9, False, summary_color),
                    bg=Theme.CARD, al="right")
        y += 1
        for c in range(2, 14):           # spacer between the name and the tables
            self._cell(y, c, bg=Theme.BG)
        y += 1
        # table-name row
        self._merge(y, 2, 3, "Services", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        self._cell(y, 4, bg=Theme.BG)
        self._merge(y, 5, 7, "Memory · CPU", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        self._cell(y, 8, bg=Theme.BG)                 # real gap column, matching col 4's -- see WIDTHS
        self._merge(y, 9, 13, "Disk", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        if bk_rows:                                   # Backups panel title, to the right of Disk
            self._cell(y, 14, bg=Theme.BG)
            self._merge(y, 15, 17, "Backups", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
            self._cell(y, 18, bg=Theme.BG)
        else:                                          # nothing tracked here -- a plain gap,
            for c in range(14, 19):                     # not Notes creeping in to fill it
                self._cell(y, c, bg=Theme.BG)
        y += 1
        # column headers
        self._cell(y, 2, "Service Name", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, border=True)
        self._cell(y, 3, "Status", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
        self._cell(y, 4, bg=Theme.BG)
        self._cell(y, 5, "Host", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, border=True)
        self._cell(y, 6, "RAM %", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
        self._cell(y, 7, "CPU %", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
        self._cell(y, 8, bg=Theme.BG)
        for c, t in zip((9, 10, 11, 12, 13), ("Host", "Mount", "Used %", "Free GB", "Size GB")):
            self._cell(y, c, t, Theme.font(8, True, Theme.GREY), bg=Theme.HDR,
                       al=("left" if c <= 10 else "center"), border=True)
        if bk_rows:                                   # Backups headers: File (O) + Generated (P) + Status (Q)
            self._cell(y, 14, bg=Theme.BG)
            self._cell(y, 15, "Backup File", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, border=True)
            self._cell(y, 16, "Generated", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
            self._cell(y, 17, "Status", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
            self._cell(y, 18, bg=Theme.BG)
        else:                                          # plain gap, not Notes creeping in
            for c in range(14, 19):
                self._cell(y, c, bg=Theme.BG)

        top = y + 1
        rows = max(len(svc_rows), len(mems), len(disks), len(bk_rows), 1)
        for k in range(rows):
            r = top + k
            # services (grouped, with a SYSTEM / OFFERED sub-header before each class)
            if k < len(svc_rows):
                item = svc_rows[k]
                if item[0] == "hdr":
                    self._merge(r, 2, 3, "  " + item[1], Theme.font(8, True, Theme.CYAN),
                                bg=Theme.HDR, al="left")
                elif item[0] == "sub":                     # component sub-header (which host these run on)
                    self._merge(r, 2, 3, "    " + item[1], Theme.font(8, False, Theme.SUB),
                                bg=Theme.CARD, al="left")
                elif item[0] == "link":
                    _, name, d, url = item
                    live = d.get("up", False)
                    self._cell(r, 2, name, Theme.font(9, False, Theme.WHITE if live else Theme.SUB), border=True)
                    self.ws.cell(r, 2).hyperlink = url
                    text, band = self._link_status(d, url)
                    if band:
                        self._chip(r, 3, text, band, sz=8)
                    else:
                        self._cell(r, 3, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
                elif item[0] == "cert":                    # SSL cert expiry countdown (a service subtype)
                    _, name, cd = item
                    self._cell(r, 2, name, Theme.font(9, False, Theme.WHITE), border=True)
                    if cd is None:
                        self._cell(r, 3, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
                    else:
                        self._chip(r, 3, "EXPIRED" if cd < 0 else f"{cd:.0f}d",
                                   self._cert_band(cd) or "green", sz=8)
                else:
                    _, name, up = item
                    self._cell(r, 2, name, Theme.font(9, False, Theme.WHITE), border=True)
                    self._chip(r, 3, "RUNNING" if up else "DOWN", "green" if up else "red", sz=8)
            else:
                self._cell(r, 2, bg=Theme.BG); self._cell(r, 3, bg=Theme.BG)
            self._cell(r, 4, bg=Theme.BG)
            # memory (one row per host; flags hosts Prometheus can't reach)
            if k < len(mems):
                label, st, val = mems[k]
                self._cell(r, 5, label, Theme.font(9, False, Theme.WHITE), border=True)
                if st == "down":
                    self._chip(r, 6, "DOWN", "red", sz=8)
                elif st == "ok":
                    self._chip(r, 6, f"{val:.0f}%", self._band(val), sz=9)
                else:
                    self._cell(r, 6, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
            else:
                self._cell(r, 5, bg=Theme.BG); self._cell(r, 6, bg=Theme.BG)
            # cpu % (same host row as Memory; DOWN when Prometheus can't reach the host)
            if k < len(cpus):
                _, cst, cval = cpus[k]
                if cst == "down":
                    self._chip(r, 7, "DOWN", "red", sz=8)
                elif cst == "ok":
                    self._chip(r, 7, f"{cval:.0f}%", self._band(cval), sz=9)
                else:
                    self._cell(r, 7, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
            else:
                self._cell(r, 7, bg=Theme.BG)
            self._cell(r, 8, bg=Theme.BG)               # real gap column, every row -- see WIDTHS
            # disk
            if k < len(disks):
                label, mount, dd = disks[k]
                used, free, size = dd.get("used"), dd.get("free"), dd.get("size")
                self._cell(r, 9, label, Theme.font(9, False, Theme.GREY), border=True)
                self._cell(r, 10, mount, Theme.font(9, False, Theme.GREY), border=True)
                if used is None:            # a log file: sized, not banded -- no % of anything
                    self._cell(r, 11, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
                else:
                    self._chip(r, 11, f"{used:.0f}%", self._band(used), sz=9)
                self._cell(r, 12, f"{free:.1f}" if free is not None else "—",
                           Theme.font(9, False, Theme.WHITE), al="center", border=True)
                self._cell(r, 13, f"{size:.0f}" if size is not None else "—",
                           Theme.font(9, False, Theme.SUB), al="center", border=True)
            else:
                for c in range(9, 14):
                    self._cell(r, c, bg=Theme.BG)
            # backups (4th panel, right of Disk): the Status chip classifies each file by
            # day (TODAY / YESTERDAY, like Services' RUNNING); a red NO BACKUP row per
            # reporting host with none (0 = critical, >0 = acceptable)
            if bk_rows:
                self._cell(r, 14, bg=Theme.BG)
                if k < len(bk_rows):
                    brow = bk_rows[k]
                    if brow[0] == "file":
                        _, fname, fday, mtime = brow
                        gen = (datetime.datetime.fromtimestamp(mtime).strftime("%d %b %H:%M")
                               if mtime and mtime > 1e8 else "—")   # value = mtime = when generated
                        self._cell(r, 15, fname, Theme.font(9, False, Theme.WHITE), border=True)
                        self._cell(r, 16, gen, Theme.font(9, False, Theme.GREY), al="center", border=True)
                        self._chip(r, 17, {"today": "TODAY", "yesterday": "YESTERDAY"}.get(fday, "PRESENT"),
                                   "green", sz=8)
                    elif brow[0] == "expected_off":
                        # reason is now a full sentence (backup_policy_comment) rather than a
                        # short phrase, so it gets the Generated column too (merged O:P) instead
                        # of being clipped behind that column's own "—" -- host leads so the
                        # row still reads host-first at a glance, sentence explains why.
                        _, host, reason = brow
                        self._cell(r, 15, f"{host} — {reason}",
                                   Theme.font(9, False, Theme.SUB), border=True)
                        self._cell(r, 16, "", Theme.font(9, False, Theme.SUB), al="center", border=True)
                        self.ws.merge_cells(start_row=r, start_column=15, end_row=r, end_column=16)
                        self._chip(r, 17, "OFF-DAY", "green", sz=8)
                    else:
                        _, host, reason = brow
                        self._cell(r, 15, f"{reason}  ·  {host}",
                                   Theme.font(9, False, Theme.CHIP["red"][0]), border=True)
                        self._cell(r, 16, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
                        self._chip(r, 17, "NO BACKUP", "red", sz=8)
                else:
                    for c in range(15, 18):
                        self._cell(r, c, bg=Theme.BG)
                self._cell(r, 18, bg=Theme.BG)
            else:                                        # plain gap, not Notes creeping in
                for c in range(14, 19):
                    self._cell(r, c, bg=Theme.BG)

        # ---- Folders table: watched folders (e.g. T24 Log File), directly under Disk,
        #      same columns (9-13) so it reads as part of the same block. Only rendered when
        #      this system actually has an entry -- most systems have none. A gap row first
        #      (same "small gap" spacing used between every other pair of tables on this
        #      card), then title + header rows matching Disk's own styling exactly, then one
        #      data row per folder. Actual GB and the % of Expected column are banded the SAME
        #      way as the Disk usage table (self._band -- green/amber/red at chip_amber/
        #      chip_red, just against % of Expected instead of % of drive) rather than a flat
        #      amber, so a folder that's crept close to its threshold reads as a warning
        #      before it actually crosses it, not just the moment it does. ----
        folders_bottom = top + rows - 1
        if folders:
            fy = top + rows
            for c in range(2, 19):                     # gap row, full card width
                self._cell(fy, c, bg=Theme.BG)
            fy += 1
            for c in range(2, 9):
                self._cell(fy, c, bg=Theme.BG)
            self._merge(fy, 9, 13, "Folders", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
            for c in range(14, 19):
                self._cell(fy, c, bg=Theme.BG)
            fy += 1
            for c in range(2, 9):
                self._cell(fy, c, bg=Theme.BG)
            for c, t in zip((9, 10, 11, 12, 13), ("Host", "Name", "Expected GB", "Actual GB", "% of Expected")):
                self._cell(fy, c, t, Theme.font(8, True, Theme.GREY), bg=Theme.HDR,
                           al=("left" if c <= 10 else "center"), border=True)
            for c in range(14, 19):
                self._cell(fy, c, bg=Theme.BG)
            ftop = fy + 1
            for i, (host, name, gb, instance) in enumerate(folders):
                r = ftop + i
                for c in range(2, 9):
                    self._cell(r, c, bg=Theme.BG)
                expected = folder_expected_gb(store, instance, name)
                self._cell(r, 9, host, Theme.font(9, False, Theme.GREY), border=True)
                self._cell(r, 10, name, Theme.font(9, False, Theme.GREY), border=True)
                self._cell(r, 11, f"{expected:.1f}" if expected is not None else "—",
                           Theme.font(9, False, Theme.WHITE), al="center", border=True)
                # banded like the Disk usage table (self._band): green/amber/red against
                # % of EXPECTED rather than % of the drive itself, so "Actual GB" and the new
                # "% of Expected" column always agree on colour with each other.
                pct = (gb / expected * 100) if expected else None
                if pct is not None:
                    band = self._band(pct)
                    self._chip(r, 12, f"{gb:.1f}", band, sz=9)
                    self._chip(r, 13, f"{pct:.0f}%", band, sz=9)
                else:
                    self._cell(r, 12, f"{gb:.1f}", Theme.font(9, False, Theme.WHITE), al="center", border=True)
                    self._cell(r, 13, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
                for c in range(14, 19):
                    self._cell(r, c, bg=Theme.BG)
            folders_bottom = ftop + len(folders) - 1

        # ---- notes panel to the far right (cols S-W, 19-23) -- ALWAYS this width, backups
        #      or not, so Notes doesn't stretch wider just because there's nothing tracked to
        #      show in 14-18. An untracked system leaves that as a plain gap instead (see the
        #      title/header/data rows above), the same shape as "no backups" reads everywhere
        #      else in this report -- an absence, not free real estate for the next table.
        #      Three stacked parts: a table of THIS RUN's flagged metrics (critical +
        #      warning) for the admin to triage, a free-text comment box, then the author
        #      line. Regenerated fresh each run. ----
        nl, nr = 19, 23
        tn_row, last_data = top - 2, max(top + rows - 1, folders_bottom)
        field = Border(left=self._thin, right=self._thin, top=self._thin, bottom=self._thin)
        self._merge(tn_row, nl, nr, f"{sysm.name} Notes", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)

        # flagged metrics — the SAME list the web form asks about (shared source of truth),
        # so an admin's answers marry back to these exact rows by their stable `key`.
        flagged = flagged_for_system(store, sysm, self.cfg)
        ann = self.annotations.get(sysm.name, {}) if self.annotations else {}
        ann_flags = ann.get("flags", {}) if isinstance(ann, dict) else {}

        mcol = nr - 2                                        # metric spans nl..mcol; fix=nr-1; resolved=nr
        fixL = get_column_letter(nr - 1)
        r = tn_row + 1
        if flagged:
            # header
            self._merge(r, nl, mcol, "  Flagged metric", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="left")
            self._cell(r, nr - 1, "Fix needed?", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
            self._cell(r, nr, "Resolved", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
            for c in (nr - 1, nr):
                self.ws.cell(r, c).alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            self.ws.row_dimensions[r].height = 22
            # one Yes/No dropdown reused for every "Fix needed?" cell in this table
            dv = DataValidation(type="list", formula1='"Yes,No"', allow_blank=True)
            self.ws.add_data_validation(dv)
            for flag in flagged:
                r += 1
                accent = Theme.CHIP[flag.band][0]
                self._merge(r, nl, mcol, "  " + flag.text, Theme.font(9, False, accent), bg=Theme.CARD, al="left")
                for c in range(nl, mcol + 1):
                    self.ws.cell(r, c).border = field
                fix = self._cell(r, nr - 1, "", Theme.font(9), bg=Theme.CARD, al="center", border=True)
                dv.add(fix)
                answer = ann_flags.get(flag.key)             # pre-filled from the web form, if given
                if answer in ("Yes", "No"):
                    fix.value = answer
                # Resolved is derived: no fix needed -> resolved; fix needed -> still open;
                # blank until the admin picks. (Per-snapshot: a flagged item is open when sent.)
                res = self._cell(r, nr, "", Theme.font(9), bg=Theme.CARD, al="center", border=True)
                res.value = f'=IF({fixL}{r}="No","Yes",IF({fixL}{r}="Yes","No",""))'
            table_bottom = r
        else:
            self._merge(r, nl, nr, "  No critical or warning metrics this run.",
                        Theme.font(9, False, Theme.SUB), bg=Theme.CARD, al="left")
            for c in range(nl, nr + 1):
                self.ws.cell(r, c).border = field
            table_bottom = r

        # free-text comment box -- always shown, never removed: a card with nothing to
        # report falls back to NO_ISSUES_COMMENT rather than an empty or missing box, so
        # every card visibly says something and the admin never has to type the same
        # "nothing to report" note by hand.
        cmt_title = table_bottom + 1
        self._merge(cmt_title, nl, nr, "  Comment", Theme.font(8, True, Theme.SUB), bg=Theme.CARD, al="left")
        cmt_top = cmt_title + 1
        cmt_bottom = max(cmt_top + 2, last_data)
        for rr in range(cmt_top, cmt_bottom + 1):
            for c in range(nl, nr + 1):
                self._cell(rr, c, bg=Theme.CARD).border = field
        self.ws.cell(cmt_top, nl).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        self.ws.merge_cells(start_row=cmt_top, start_column=nl, end_row=cmt_bottom, end_column=nr)
        comment_text = system_comment_text(store, sysm, flagged, self.annotations, _now)
        if comment_text:
            self.ws.cell(cmt_top, nl).value = comment_text

        # author line beneath everything:  By [____ name ____]
        by = cmt_bottom + 1
        self._cell(by, nl, "By  ", Theme.font(8, False, Theme.SUB), bg=Theme.CARD, al="right")
        for c in range(nl + 1, nr + 1):
            self._cell(by, c, bg=Theme.CARD).border = field
        anchor = self.ws.cell(by, nl + 1)
        anchor.alignment = Alignment(horizontal="left", vertical="center")
        ref = f"${get_column_letter(nl + 1)}${by}"
        if self.author:                     # auto-filled name -> write it literally in EVERY card
            anchor.value = self.author       # (robust: no formula/recalc dependency in any viewer)
        elif self._first_by is None:
            self._first_by = ref            # no author supplied: type once here, other cards mirror
        else:                               # every other system mirrors the master cell
            anchor.value = f'=IF({self._first_by}="","",{self._first_by})'
        self.ws.merge_cells(start_row=by, start_column=nl + 1, end_row=by, end_column=nr)
        # keep the left/backups area background solid for any rows the taller notes add
        for rr in range(last_data + 1, by + 1):
            for c in range(2, nl):
                self._cell(rr, c, bg=Theme.BG)
        return by + 1   # next free row (one gap line)

    def _links_section(self, y: int, store: Store, systems: List[System]) -> int:
        """A standalone table of monitored web endpoints: reachability + SSL/TLS,
           sourced from the blackbox HTTP prober (mirrors the 'links' dashboard).
           Only links NOT attributed to a system's table appear here."""
        links = {u: d for u, d in store.links.items() if self._link_owner.get(u) is None}
        if not links:
            return y

        # order: down first, then soonest cert expiry, then URL
        def key(item):
            url, d = item
            cd = d.get("cert_days")
            return (0 if not d.get("up", True) else 1,
                    cd if cd is not None else float("inf"), url)
        data = sorted(links.items(), key=key)

        down = sum(1 for _, d in data if not d.get("up", True))
        expired = sum(1 for _, d in data if (d.get("cert_days") is not None and d["cert_days"] < 0))
        soon = sum(1 for _, d in data if (d.get("cert_days") is not None and 0 <= d["cert_days"] < 24))

        y += 1
        # section band: title (left) + one-line health summary (right)
        self._merge(y, 2, 7, "▌  Web Links & SSL", Theme.font(13, True, Theme.CYAN), bg=Theme.CARD)
        bits = ([f"{down} down"] if down else []) + \
               ([f"{expired} cert(s) expired"] if expired else []) + \
               ([f"{soon} cert(s) expiring"] if soon else []) + \
               [f"{len(data)} links"]
        hc = Theme.CHIP["red"][0] if (down or expired) else (Theme.CHIP["amber"][0] if soon else Theme.CHIP["green"][0])
        self._merge(y, 8, 12, " · ".join(bits), Theme.font(9, False, hc), bg=Theme.CARD, al="right")
        y += 1
        for c in range(2, 13):                 # spacer between the band and the table
            self._cell(y, c, bg=Theme.BG)
        y += 1
        # table-name row
        self._merge(y, 2, 5, "Endpoint", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        self._merge(y, 6, 12, "Reachability  ·  SSL / TLS", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        y += 1
        # column headers (Link | Status | Code | SSL | Cert (days) | TLS)
        HEADERS = [((2, 5), "Link", "left"), ((6, 7), "Status", "center"), ((8, 8), "Code", "center"),
                   ((9, 9), "SSL", "center"), ((10, 11), "Cert (days)", "center"), ((12, 12), "TLS", "center")]
        for (c1, c2), text, al in HEADERS:
            for c in range(c1, c2 + 1):
                self._cell(y, c, text if c == c1 else "", Theme.font(8, True, Theme.GREY),
                           bg=Theme.HDR, al=al, border=True)
            if c2 > c1:
                self.ws.merge_cells(start_row=y, start_column=c1, end_row=y, end_column=c2)

        top = y + 1
        for k, (url, d) in enumerate(data):
            r = top + k
            up = d.get("up", False)
            https = url.lower().startswith("https")
            # Link (merged 2-5), clickable, dimmed when down
            for c in range(2, 6):
                self._cell(r, c, url if c == 2 else "",
                           Theme.font(9, False, Theme.WHITE if up else Theme.SUB), border=True)
            self.ws.merge_cells(start_row=r, start_column=2, end_row=r, end_column=5)
            self.ws.cell(r, 2).hyperlink = url
            # Status (6-7)
            self._chip_span(r, 6, 7, "UP" if up else "DOWN", "green" if up else "red", sz=8)
            # Code (8)
            code = d.get("code")
            if code:
                self._chip(r, 8, str(code), self._code_band(code), sz=9)
            else:
                self._cell(r, 8, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
            # SSL (9)
            if not https:
                self._cell(r, 9, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
            else:
                ok = d.get("ssl", False)
                self._chip(r, 9, "OK" if ok else "NO", "green" if ok else "red", sz=8)
            # Cert days (10-11)
            cd = d.get("cert_days")
            if not https or cd is None:
                self._chip_span(r, 10, 11, "—", None, sz=9)
            else:
                self._chip_span(r, 10, 11, f"{cd:.0f}", self._cert_band(cd), sz=9)
            # TLS (12)
            tls = d.get("tls") if https else None
            self._cell(r, 12, tls or "—", Theme.font(9, False, Theme.WHITE if tls else Theme.SUB),
                       al="center", border=True)

        rows = len(data)
        # ---- notes panel BESIDE the table (cols R-V), same pattern as the system cards ----
        nl, nr = 14, 22       # no Backups panel here -> notes span the full right-hand width
        tn_row, hdr_row, last_data = top - 2, top - 1, top + rows - 1
        field = Border(left=self._thin, right=self._thin, top=self._thin, bottom=self._thin)
        self._merge(tn_row, nl, nr, "Links Notes", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        for r in range(hdr_row, last_data + 1):
            for c in range(nl, nr + 1):
                self._cell(r, c, bg=Theme.CARD).border = field
        self.ws.cell(hdr_row, nl).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        self.ws.merge_cells(start_row=hdr_row, start_column=nl, end_row=last_data, end_column=nr)
        by = last_data + 1
        self._cell(by, nl, "By  ", Theme.font(8, False, Theme.SUB), bg=Theme.CARD, al="right")
        for c in range(nl + 1, nr + 1):
            self._cell(by, c, bg=Theme.CARD).border = field
        anchor = self.ws.cell(by, nl + 1)
        anchor.alignment = Alignment(horizontal="left", vertical="center")
        if self.author:                     # auto-filled name -> write it literally
            anchor.value = self.author
        elif self._first_by is None:
            self._first_by = f"${get_column_letter(nl + 1)}${by}"
        else:
            anchor.value = f'=IF({self._first_by}="","",{self._first_by})'
        self.ws.merge_cells(start_row=by, start_column=nl + 1, end_row=by, end_column=nr)
        return by + 1

    def _footer(self, y: int):
        self._merge(y, 2, 12,
                    "chip key:  green under 75%   ·   amber 75-90%   ·   red 90% and over"
                    "      |      services RUNNING / DOWN      |      live from Prometheus",
                    Theme.font(8, False, Theme.SUB))
        self._merge(y + 1, 2, 12,
                    "services:  SYSTEM = infrastructure that keeps the platform running"
                    "   ·   OFFERED = business endpoints delivered to users",
                    Theme.font(8, False, Theme.SUB))
        self._merge(y + 2, 2, 12,
                    "web links:  status UP / DOWN   ·   SSL cert (days) green ≥24 · amber <24 · red <7"
                    "   ·   blackbox HTTP prober",
                    Theme.font(8, False, Theme.SUB))

    def _paint_canvas(self, last_row: int):
        for r in range(1, last_row + 40):
            for c in range(1, 46):
                x = self.ws.cell(r, c)
                if x.fill is None or x.fill.patternType is None:
                    x.fill = Theme.fill(Theme.BG)
        self.ws.sheet_view.showGridLines = False

    # -- public API -----------------------------------------------------------
    def build(self, store: Store, systems: List[System]) -> openpyxl.Workbook:
        self._link_owner = {u: assign_link(u, systems) for u in store.links}
        self._header(store)
        y = self._overview(store, systems)
        for sysm in systems:
            y = self._system_card(y, sysm, store)
        y = self._links_section(y, store, systems)
        y += 1
        self._footer(y)
        self._paint_canvas(y)
        return self.wb

    def save(self, path: str) -> str:
        candidates = [path] + [path.replace(".xlsx", f" (v{n}).xlsx") for n in range(2, 6)]
        for cand in candidates:
            try:
                self.wb.save(cand)
                return cand
            except PermissionError:
                continue
        raise PermissionError(f"could not write {path} (all candidates locked)")


# ============================================================================ #
#  PUBLIC BUILD HELPER  (used by the Django webapp and any other in-process caller)
# ============================================================================ #
def build_report_bytes(store: "Store", systems: List[System], cfg: Config, *,
                       theme: str = "dark", author: Optional[str] = None,
                       annotations: Optional[dict] = None,
                       summary_comment: Optional[str] = None) -> bytes:
    """Render the report in the chosen theme ('dark'|'light') with the admin's inputs baked
       in, and return the .xlsx as bytes (nothing touches disk). `store`/`systems` come from
       capture(); `annotations` marries the form's answers to each card's flagged rows."""
    with palette(theme):
        builder = ReportBuilder(cfg, author=author, annotations=annotations,
                                summary_comment=summary_comment)
        workbook = builder.build(store, systems)
    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def scope_links_to_systems(store: "Store", systems: List[System]) -> None:
    """Web links (blackbox HTTP probes) are captured GLOBALLY, independent of the systems
       list. When a report is scoped to a subset, drop every link not owned by one of those
       systems (per assign_link — the same attribution the report itself uses) so the
       link-derived KPIs (Web encryption, SSL certs) and the link sections don't leak other
       systems' endpoints. Mutates store.links in place."""
    store.links = {u: d for u, d in store.links.items() if assign_link(u, systems) is not None}


def default_report_filename(theme: str = "dark", when: Optional[datetime.datetime] = None) -> str:
    """The webapp's download name — date/time-stamped and theme-tagged, so a scheduled run
       leaves a dated history instead of overwriting one file."""
    when = when or datetime.datetime.now()
    return f"System Admin Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


# ============================================================================ #
#  ENTRY POINT
# ============================================================================ #
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the System Admin Report from Prometheus.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="path to config.ini")
    parser.add_argument("--prom", default=None, help="override Prometheus base URL")
    parser.add_argument("--grafana", default=None, help="override Grafana dashboard URL")
    parser.add_argument("--out", default=None, help="override output xlsx path")
    # --- parity with the Report Generator webapp (reports/services.py) --------------------
    parser.add_argument("--theme", default="dark", choices=sorted(PALETTES),
                        help="report palette (default: dark)")
    parser.add_argument("--author", default=None,
                        help="name written into the master 'By' field, mirrored across every card")
    parser.add_argument("--summary", default=None, help="free text for the Summary Notes box")
    parser.add_argument("--systems", default=None,
                        help="scope the report to these systems (comma-separated); default = all")
    parser.add_argument("--stamp", action="store_true",
                        help="write a date/time-stamped filename instead of overwriting --out")
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    if args.prom:
        cfg.prom = args.prom
    if args.grafana:
        cfg.grafana = args.grafana
    if args.out:
        cfg.out = args.out if Path(args.out).is_absolute() else str(HERE / args.out)
    if args.stamp:
        cfg.out = str(Path(cfg.out).parent / default_report_filename(args.theme))

    print(f"[*] reading topology from {cfg.prometheus_yml} ...")
    try:
        systems = load_topology(cfg.prometheus_yml)
    except Exception as exc:
        print(f"[!] could not read topology from {cfg.prometheus_yml}: {exc}", file=sys.stderr)
        return 2

    only = {n.strip() for n in (args.systems or "").split(",") if n.strip()}
    if only:
        known = {s.name for s in systems}
        unknown = sorted(only - known)
        if unknown:
            print(f"[!] unknown system(s): {', '.join(unknown)}. Known: {', '.join(sorted(known))}",
                  file=sys.stderr)
            return 2
        systems = [s for s in systems if s.name in only]
    print(f"    {len(systems)} systems: {', '.join(s.name for s in systems)}"
          + (" (scoped)" if only else ""))

    prom = Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    print(f"[*] connecting to Prometheus at {cfg.prom} ...")
    try:
        prom.ping()
    except Exception as exc:
        print(f"[!] Prometheus unreachable at {cfg.prom}: {exc}", file=sys.stderr)
        return 2

    print("[*] capturing metrics (disk, memory, services, COB, SWIFT) ...")
    store = capture(prom, systems, cfg)
    if only:
        scope_links_to_systems(store, systems)   # don't leak other systems' endpoints/certs
    hosts = sum(len(s.components) for s in systems)
    nsvc = total_services(store)   # matches the SERVICES tile the report itself will show
    nbk = sum(len(d.get("files") or []) for d in store.backups.values())
    print(f"    systems={len(systems)} hosts={hosts} services={nsvc} "
          f"disk_instances={len(store.disk)} ram_instances={len(store.ram)} cpu_instances={len(store.cpu)} "
          f"cob={store.cob} swift={store.swift} "
          f"backup_hosts={len(store.backups)} backup_files={nbk}")

    print(f"[*] rendering report ({args.theme} theme) ...")
    # same code path the webapp uses (build_report_bytes) — palette swap + admin inputs — but
    # saved to disk rather than streamed, so CLI and webapp output are identical.
    with palette(args.theme):
        builder = ReportBuilder(cfg, author=args.author, summary_comment=args.summary)
        builder.build(store, systems)
        out = builder.save(cfg.out)
    print(f"[+] saved -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
