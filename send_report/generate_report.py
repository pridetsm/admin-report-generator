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
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont
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
    }
    INFO = ("005BC0D4", "001B2836")            # neutral overview accent

    @staticmethod
    def font(size: int = 9, bold: bool = False, color: Optional[str] = None) -> Font:
        return Font(name="Consolas", size=size, bold=bold, color=Color(rgb=color or Theme.WHITE))

    @staticmethod
    def fill(color: str) -> PatternFill:
        return PatternFill(patternType="solid", fgColor=color)


# -- selectable palettes (dark is the default; light is the same layout, re-coloured).
#    Values are swapped onto the Theme class for the duration of a build (see `palette`),
#    so the whole builder re-themes without touching its ~80 Theme.* references. --------
_THEME_KEYS = ("BG", "CARD", "HDR", "BORDER", "WHITE", "GREY", "CYAN", "SUB", "CHIP", "INFO")

PALETTES: Dict[str, Dict[str, object]] = {
    "dark": {   # the original, unchanged palette (kept identical so dark output never shifts)
        "BG": "000E1620", "CARD": "00121E2B", "HDR": "001B2836", "BORDER": "0026323F",
        "WHITE": "00E7EEF5", "GREY": "00AFBBC7", "CYAN": "005BC0D4", "SUB": "007F93A6",
        "CHIP": {"green": ("004CC9A4", "0014322B"), "amber": ("00E8B04B", "003A2F14"),
                 "red": ("00EF6A5A", "003A1A16")},
        "INFO": ("005BC0D4", "001B2836"),
    },
    "light": {  # matched to the approved reference (webapp/System_Admin_Report_Light.xlsx):
                # white canvas, dark slate text, vivid chips — higher contrast than a soft theme
        "BG": "00FFFFFF", "CARD": "00F2F5F8", "HDR": "00F5F7FA", "BORDER": "00E1E6EA",
        "WHITE": "0016232E", "GREY": "005B6B78", "CYAN": "000E7C93", "SUB": "0051707F",
        "CHIP": {"green": ("000E9C74", "00E8F6F0"), "amber": ("00B8790A", "00FFF6E0"),
                 "red": ("00D14A3A", "00FDEBEA")},
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
}

# preferred display order (known systems first); anything else is appended A-Z
SYSTEM_ORDER = ["RTGS", "RTGSTEST", "Temenos", "Efin", "CMS", "CSD", "ESF",
                "ESFEXEC", "RBZ Website", "Intranet", "FRS", "SmartHR", "Eagle", "CEPECS", "CEBAS", "BDTRS", "LMS", "CRB", "Paytyme", "GCMS", "GMS", "BSA", "Collateral Registry", "EDMS", "EBIS"]

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


def backup_cutoff(instance: str, now: datetime.datetime | None = None) -> float:
    """Oldest mtime that still counts as a CURRENT backup for `instance` (unix seconds).

    Midnight-based, matching how the backup_monitor scripts judge age, so the verdict
    doesn't drift with the time of day the report happens to run. Hosts absent from
    BACKUP_MAX_AGE_DAYS get the daily default = yesterday-midnight, exactly as before.
    """
    now = now or datetime.datetime.now()
    tmid = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    return tmid - 86400 * BACKUP_MAX_AGE_DAYS.get(instance, DEFAULT_BACKUP_MAX_AGE_DAYS)


# Systems that depend on the shared LDAP / authentication service — if LDAP is down these
# systems can't authenticate users. Source of truth for the "LDAP dependency" banner; extend
# as more dependents are identified. (Names must match the `system` labels in prometheus.yml.)
LDAP_DEPENDENTS = {"GCMS", "GMS"}
# `system` label values that are not real systems
SKIP_SYSTEMS = {"unassigned", "prometheus", ""}

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


def load_topology(prometheus_yml: str) -> List[System]:
    """Read the system -> hosts topology from prometheus.yml (grouped by the `system` label)."""
    import yaml  # PyYAML — see requirements.txt
    with open(prometheus_yml, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    grouped: Dict[str, List[Component]] = {}
    for job in doc.get("scrape_configs", []) or []:
        for sc in job.get("static_configs", []) or []:
            labels = sc.get("labels", {}) or {}
            system = (labels.get("system") or "").strip()
            if system.lower() in SKIP_SYSTEMS:
                continue
            role, display = labels.get("role"), labels.get("display")
            for target in sc.get("targets", []) or []:
                grouped.setdefault(system, []).append(
                    Component(_component_label(display, role, system, target), target))
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


# filters reused across every node_filesystem / windows_logical_disk query
_FS = 'fstype=~"ext.*|xfs|btrfs",mountpoint!~".*pod.*|.*container.*|^/snap/|^/var/snap"'
_VOL = 'volume!~"HarddiskVolume.+"'
_HASH = re.compile(r"[0-9a-f]{20,}")


def _shorten(name: str) -> str:
    for suffix in (" Service", " service"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    if len(name) > 17 and "." in name:        # collapse long dotted CI names
        name = name.split(".")[-1]
    return name


def capture(prom: Prometheus, systems: List[System], cfg: Config) -> Store:
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
        rows = prom.query(f'probe_success{{instance="{cfg.ldap_target}"}}')
        if rows:
            ldap_up = max(r["value"] for r in rows) >= 1

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
                result = prom.query(svc.expr)
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

    return Store(disk, ram, cpu, cob, swift, services, up, links, backups, ldap_up=ldap_up)


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
            result = prom.query(expr)
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
        for r in prom.query("probe_tls_version_info"):
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
            result = prom.query(expr)
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
            if not fresh:
                missing.append((s.name, c.label,
                                "FOLDER UNREADABLE" if d.get("ok") is False else "NO BACKUP"))
    return missing


def backup_untracked(store: "Store", systems: List["System"]) -> List[str]:
    """Systems where NO component reports the backup check at all (no instance in
       store.backups) -> [system names]. These are a blind spot: backup_missing skips
       them (nothing to judge), so they never show as MISSING despite being unmonitored."""
    return [s.name for s in systems
            if not any(c.instance in store.backups for c in s.components)]


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
        if not any(mt and mt >= cutoff for _n, _day, mt in (d.get("files") or [])):
            reason = "FOLDER UNREADABLE" if d.get("ok") is False else "NO BACKUP"
            flags.append(Flag(f"backup:{c.label}", f"{c.label} · {reason}", "red", "backup"))
    # untracked: no host on the system runs the backup check at all
    if not any(c.instance in store.backups for c in sysm.components):
        flags.append(Flag(f"untracked:{sysm.name}",
                          f"{sysm.name} · UNTRACKED (no backup check on any host)", "amber", "untracked"))
    flags.sort(key=lambda f: 0 if f.band == "red" else 1)   # critical first (stable)
    return flags


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
    WIDTHS = {"A": 6.43, "B": 22, "C": 9, "D": 2, "E": 14, "F": 8,
              "G": 8, "H": 14, "I": 12, "J": 7, "K": 7, "L": 11,   # G = Memory·CPU's CPU % column
              "M": 2, "N": 30, "O": 13, "P": 11,          # N-P = Backups (File | Generated | Status)
              "Q": 2,                                      # gap before Notes
              "R": 13, "S": 11, "T": 11, "U": 11, "V": 9}  # R-V = notes column
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

    def _band_spans(self, tiles, ncols=11) -> List[int]:
        """Column counts for a row of overview tiles across cols 2..12. Every tile gets a
           readable minimum, then spare columns go first to the panels with the MOST
           sub-columns (a 2-column panel needs more room than a single value) so the row
           stays balanced and nothing is crushed."""
        n = len(tiles)
        spans = [max(1, ncols // n)] * n
        spare = ncols - sum(spans)
        subcols = lambda t: len(t[2]) if t[0] == "panel" else 1
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
        nsvc = sum(len(v) for v in store.services.values()) + len(store.links)
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
        swift = f"{store.swift:.0f}" if store.swift is not None else "—"
        # web-encryption posture: how many monitored endpoints are HTTPS vs plain HTTP
        n_https = sum(1 for u in store.links if u.lower().startswith("https"))
        n_http = sum(1 for u in store.links if u.lower().startswith("http://"))

        palette = {"info": Theme.INFO, "good": Theme.CHIP["green"],
                   "bad": Theme.CHIP["red"], "warn": Theme.CHIP["amber"]}

        def card(rtop, group, label, value, state, vrow=None):
            """Standard card: title (rtop) + big value. vrow lets row 2 bottom-align
               its value so it lines up with the taller disk panel."""
            c1, c2 = group
            accent, tint = palette[state]
            vrow = rtop + 1 if vrow is None else vrow
            bar = Border(left=Side(style="thick", color=accent))   # accent bar on the LEFT
            self._merge(rtop, c1, c2, "  " + label, Theme.font(8, True, Theme.SUB), bg=tint, al="left")
            for r in range(rtop + 1, vrow):                        # keep the card solid if it spans 3 rows
                self._merge(r, c1, c2, "", Theme.font(8), bg=tint, al="left")
            self._merge(vrow, c1, c2, "  " + value, Theme.font(22, True, accent), bg=tint, al="left")
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

        def caption(row, text):
            """Thin label above a band of cards, so the two rows read as one group each."""
            self._merge(row, 2, 12, "  " + text, Theme.font(8, True, Theme.SUB), bg=Theme.BG, al="left")
            self.ws.row_dimensions[row].height = 14

        ur = unreachable(store, systems)           # needed for the Unreachable KPI below

        # ---- ROW 1 · static stats: inventory + point-in-time readings (neutral cyan) ----
        # widths chosen so the wide readings (SWIFT / COB) sit in the wide groups
        caption(8, "AT A GLANCE  ·  inventory & readings")
        static = [((2, 2),   "SYSTEMS",    str(len(systems))),
                  ((3, 4),   "HOSTS",      str(hosts)),
                  ((5, 6),   "SERVICES",   str(nsvc)),
                  ((7, 9),   "SWIFT TXNS", swift),
                  ((10, 12), "COB · T24",  cob)]
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
            ("card", "MISSING BACKUPS", str(nmiss), backup_missing_band(nmiss)),
            ("card", "UNREACHABLE COMPONENTS", str(len(ur)), "good" if not ur else "bad"),
            ("card", "SERVICES DOWN",   str(down), "good" if down == 0 else "bad"),
            ("card", "EXPIRED CERTS", str(len(cert_expired)), "good" if not cert_expired else "bad"),
        ]
        # This tile counts EVERY high disk (>= thr) — elevated and near-full together —
        # so it can never read 0 while the DISK NEAR-FULL banner below lists disks; those
        # near-full disks ARE high disks and are included here. The banner still carries
        # the named per-host detail. State follows the count: red if any disk is near-full,
        # amber if only elevated, green when zero — so 0 is always green (the colour rule).
        disk_high_h, disk_high_d, disk_high_state = disk_high(
            store, systems, thr, self.cfg.chip_red)
        # systems with no backup check at all (a monitoring blind spot) -> amber when any
        n_untracked = len(backup_untracked(store, systems))
        # web-encryption posture: green ONLY when no endpoint is plain HTTP; red when plain
        # HTTP endpoints OUTNUMBER the encrypted ones; amber for anything in between.
        web_state = "good" if n_http == 0 else ("bad" if n_http > n_https else "warn")
        watch_tiles = [
            ("panel", "HIGH CPU USAGE", [("HOSTS", cpu_hosts)], cpu_state),
            ("panel", "HIGH RAM USAGE", [("HOSTS", ram_hosts)], ram_state),
            ("panel", f"HIGH DISK USAGE  ·  ≥{thr}%",
             [("HOSTS", disk_high_h), ("DISKS", disk_high_d)],
             disk_high_state),
            ("panel", "WEB ENCRYPTION", [("HTTPS", n_https), ("HTTP", n_http)], web_state),
            ("panel", "UNTRACKED BACKUPS", [("SYSTEMS", n_untracked)],
             "good" if n_untracked == 0 else "warn"),
        ]

        def band(cap_row, title, tiles):
            """Lay a row of tiles across columns 2..12 under a caption, so the band reads as
               one group however many tiles it holds. Width is shared by _band_spans (wider
               panels get more room). Returns the band's bottom row (value row)."""
            caption(cap_row, title)
            trow = cap_row + 1
            start = 2
            for t, span in zip(tiles, self._band_spans(tiles)):
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

        def render_banner(top, band_name, headline, detail, expl):
            accent, tint = Theme.CHIP[band_name]
            banner_line(top, headline, Theme.font(10, True, accent), 72, tint, accent)
            r = top
            if detail:
                r += 1; banner_line(r, detail, Theme.font(9, False, Theme.WHITE), 82, tint, accent)
            if expl:
                r += 1; banner_line(r, expl, Theme.font(8, False, Theme.SUB), 95, tint, accent)
            return r

        banners: List[Tuple[str, str, str, str]] = []   # (band, headline, detail, explanation)

        # 0) LDAP / authentication service down — highest priority, listed first. Every dependent
        #    system can't authenticate users while the shared auth service is unreachable.
        ldap_dependents = ldap_alert(store, systems)
        if ldap_dependents:
            banners.append((
                "red",
                f"LDAP / AUTH SERVICE DOWN  —  {len(ldap_dependents)} dependent system(s) affected",
                "      ·      ".join(ldap_dependents),
                "The shared LDAP / authentication service is not responding — users cannot sign in to "
                "the systems that depend on it. Restore the auth service urgently."))

        # 1) imminent near-full disk — moved out of the tile band into a worded banner
        nearfull = disk_near_full(store, systems, self.cfg.chip_red)
        if nearfull:
            byhost: Dict[str, List[str]] = {}
            for s, lbl, mp, used in nearfull:
                byhost.setdefault(f"{s} · {lbl}", []).append(f"{mp} {used:.0f}%")
            banners.append((
                "red",
                f"DISK NEAR-FULL  —  {len(nearfull)} disk(s) on {len(byhost)} host(s) "
                f"at/over {self.cfg.chip_red}%",
                "      ·      ".join(f"{h} ({', '.join(v)})" for h, v in byhost.items()),
                "These volumes are almost full — an imminent outage that can take the service down. "
                "Free space or extend the disk now."))

        # 2) components Prometheus can no longer reach
        if ur:
            bysys: Dict[str, List[str]] = {}
            for s, lbl, _ in ur:
                bysys.setdefault(s, []).append(lbl)
            banners.append((
                "red",
                f"UNREACHABLE  —  {len(ur)} component(s) across {len(bysys)} system(s)",
                "      ·      ".join(f"{s} ({', '.join(lbls)})" for s, lbls in bysys.items()),
                "Prometheus can no longer scrape these targets — the host is down, the exporter has "
                "stopped, or there are network / connectivity issues. Treat as urgent."))

        # 3) SSL certificates expired or expiring within 30 days — a classic silent-failure
        #    risk. Red if any cert has already lapsed (the site is effectively down), else
        #    amber for those merely due to renew. Headline carries the aggregate; detail names
        #    each host with its days-to-expiry.
        if cert_expired or cert_expiring:
            bits = ([f"{len(cert_expired)} expired"] if cert_expired else []) + \
                   ([f"{len(cert_expiring)} expiring within 30 days"] if cert_expiring else [])
            detail = "      ·      ".join(
                [f"{h} (EXPIRED {abs(cd):.0f}d ago)" for h, cd in cert_expired] +
                [f"{h} ({cd:.0f}d)" for h, cd in cert_expiring])
            banners.append((
                "red" if cert_expired else "amber",
                f"SSL CERTS  —  {', '.join(bits)}",
                detail,
                "Renew these certificates before they lapse — an expired certificate makes browsers "
                "reject the site, a silent outage until the certificate is replaced."))

        # 4) COB looks like it never ran — flagged EVERY day EXCEPT Monday. A Monday
        #    reading covers Sunday (a non-work day with no COB), so an absent/abnormally
        #    high value then is expected, not a fault, and is left unflagged.
        if cob_missing and datetime.datetime.now().weekday() != 0:   # 0 = Monday
            banners.append((
                "amber",
                "COB  —  close-of-business may not have run yesterday",
                "COB time is out of range (abnormally high), so no completed close-of-business was "
                "detected for the previous day.",
                "Confirm the T24 COB ran and completed. (On Mondays this is expected — Sunday has no "
                "COB — and is not flagged.)"))

        if banners:
            r = content_bottom + 2                # one gap row below the tile bands
            for i, (band_name, headline, detail, expl) in enumerate(banners):
                if i:
                    r += 1                        # blank spacer row between stacked banners
                r = render_banner(r, band_name, headline, detail, expl)
            content_bottom = r

        # ---- Summary Notes: RHS panel spanning the whole summary (explain anything, incl. the alert) ----
        nl, nr = 14, 22       # no Backups panel here -> notes span the full right-hand width
        field = Border(left=self._thin, right=self._thin, top=self._thin, bottom=self._thin)
        # title sits LOW — level with the cards (row 9), mirroring the per-system notes titles
        tt = 9
        self._merge(tt, nl, nr, "Summary Notes", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        for r in range(tt + 1, content_bottom + 1):    # writable box directly beneath the title
            for c in range(nl, nr + 1):
                self._cell(r, c, bg=Theme.CARD).border = field
        self.ws.cell(tt + 1, nl).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        self.ws.merge_cells(start_row=tt + 1, start_column=nl, end_row=content_bottom, end_column=nr)
        if self.summary_comment:                       # pre-fill the summary box from the web form
            self.ws.cell(tt + 1, nl).value = self.summary_comment
        # author line — this is the MASTER name cell (drawn first), every system's "By" mirrors it
        by = content_bottom + 1
        self._cell(by, nl, "By  ", Theme.font(8, False, Theme.SUB), bg=Theme.CARD, al="right")
        for c in range(nl + 1, nr + 1):
            self._cell(by, c, bg=Theme.CARD).border = field
        anchor = self.ws.cell(by, nl + 1)
        anchor.alignment = Alignment(horizontal="left", vertical="center")
        if self.author:                                # master author name; every card mirrors it
            anchor.value = self.author
        self._first_by = f"${get_column_letter(nl + 1)}${by}"
        self.ws.merge_cells(start_row=by, start_column=nl + 1, end_row=by, end_column=nr)
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
        bk_files, bk_missing = [], []            # (filename, day, mtime)  /  (host, reason)
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
            else:
                bk_missing.append((c.label, "FOLDER UNREADABLE" if d.get("ok") is False else "NO BACKUP"))
        bk_files.sort(key=lambda ft: (0 if ft[1] == "today" else 1, ft[0]))   # today first
        bk_rows = [("file", fname, fday, mtime) for fname, fday, mtime in bk_files] + \
                  [("missing", host, reason) for host, reason in bk_missing]   # ("file", name, day, mtime) | ("missing", host, reason)
        nbk_missing = len(bk_missing)
        # system-wide backup blind spot: NOT ONE host reports the backup check (matches the
        # overview UNTRACKED BACKUPS tile). Distinct from NO BACKUP — a host that DOES run the
        # check but produced nothing fresh. Untracked means the check itself is absent, so the
        # loop above judged nothing; the admin must still answer for it in the notes table.
        bk_untracked = not any(c.instance in store.backups for c in sysm.components)

        y += 1
        # band: system name (left) + one-line health summary (right)
        self._merge(y, 2, 7, f"▌  {sysm.name}", Theme.font(13, True, Theme.CYAN), bg=Theme.CARD)
        # health summary: colour each segment by its OWN meaning (rich text), not the whole line.
        # counts that are a state go green when 0 / red|amber when >0; plain counts (services)
        # are constants -> the same blue as the system name (neither good nor bad).
        red, amber, green = Theme.CHIP["red"][0], Theme.CHIP["amber"][0], Theme.CHIP["green"][0]
        segs = []                                            # (text, colour)
        if nd:          segs.append((f"{nd} unreachable", red))
        if nbk_missing: segs.append((f"{nbk_missing} no-backup", red))
        if bk_untracked: segs.append(("backups untracked", amber))
        segs.append((f"{nc} critical", green if nc == 0 else red))
        segs.append((f"{nw} warning",  green if nw == 0 else amber))
        segs.append((f"{len(svcs)} services", Theme.CYAN))   # a constant count, not a health state
        _tb = lambda text, color: TextBlock(InlineFont(rFont="Consolas", sz=9, color=color), text)
        parts = []
        for i, (text, color) in enumerate(segs):
            if i:
                parts.append(_tb("  ·  ", Theme.SUB))        # neutral separator
            parts.append(_tb(text, color))
        self._merge(y, 8, 12, "", Theme.font(9, False, Theme.WHITE), bg=Theme.CARD, al="right")
        self.ws.cell(y, 8).value = CellRichText(parts)
        y += 1
        for c in range(2, 13):           # spacer between the name and the tables
            self._cell(y, c, bg=Theme.BG)
        y += 1
        # table-name row
        self._merge(y, 2, 3, "Services", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        self._cell(y, 4, bg=Theme.BG)
        self._merge(y, 5, 7, "Memory · CPU", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        self._merge(y, 8, 12, "Disk", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        if bk_rows:                                   # Backups panel title, to the right of Disk
            self._cell(y, 13, bg=Theme.BG)
            self._merge(y, 14, 16, "Backups", Theme.font(9, True, Theme.CYAN), bg=Theme.CARD)
        y += 1
        # column headers
        self._cell(y, 2, "Service Name", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, border=True)
        self._cell(y, 3, "Status", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
        self._cell(y, 4, bg=Theme.BG)
        self._cell(y, 5, "Host", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, border=True)
        self._cell(y, 6, "RAM %", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
        self._cell(y, 7, "CPU %", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
        for c, t in zip((8, 9, 10, 11, 12), ("Host", "Mount", "Used %", "Free GB", "Size GB")):
            self._cell(y, c, t, Theme.font(8, True, Theme.GREY), bg=Theme.HDR,
                       al=("left" if c <= 9 else "center"), border=True)
        if bk_rows:                                   # Backups headers: File (N) + Generated (O) + Status (P)
            self._cell(y, 13, bg=Theme.BG)
            self._cell(y, 14, "Backup File", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, border=True)
            self._cell(y, 15, "Generated", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)
            self._cell(y, 16, "Status", Theme.font(8, True, Theme.GREY), bg=Theme.HDR, al="center", border=True)

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
            # disk
            if k < len(disks):
                label, mount, dd = disks[k]
                used, free, size = dd.get("used", 0), dd.get("free"), dd.get("size")
                self._cell(r, 8, label, Theme.font(9, False, Theme.GREY), border=True)
                self._cell(r, 9, mount, Theme.font(9, False, Theme.GREY), border=True)
                self._chip(r, 10, f"{used:.0f}%", self._band(used), sz=9)
                self._cell(r, 11, f"{free:.1f}" if free is not None else "—",
                           Theme.font(9, False, Theme.WHITE), al="center", border=True)
                self._cell(r, 12, f"{size:.0f}" if size is not None else "—",
                           Theme.font(9, False, Theme.SUB), al="center", border=True)
            else:
                for c in range(8, 13):
                    self._cell(r, c, bg=Theme.BG)
            # backups (4th panel, right of Disk): the Status chip classifies each file by
            # day (TODAY / YESTERDAY, like Services' RUNNING); a red NO BACKUP row per
            # reporting host with none (0 = critical, >0 = acceptable)
            if bk_rows:
                self._cell(r, 13, bg=Theme.BG)
                if k < len(bk_rows):
                    brow = bk_rows[k]
                    if brow[0] == "file":
                        _, fname, fday, mtime = brow
                        gen = (datetime.datetime.fromtimestamp(mtime).strftime("%d %b %H:%M")
                               if mtime and mtime > 1e8 else "—")   # value = mtime = when generated
                        self._cell(r, 14, fname, Theme.font(9, False, Theme.WHITE), border=True)
                        self._cell(r, 15, gen, Theme.font(9, False, Theme.GREY), al="center", border=True)
                        self._chip(r, 16, {"today": "TODAY", "yesterday": "YESTERDAY"}.get(fday, "PRESENT"),
                                   "green", sz=8)
                    else:
                        _, host, reason = brow
                        self._cell(r, 14, f"{reason}  ·  {host}",
                                   Theme.font(9, False, Theme.CHIP["red"][0]), border=True)
                        self._cell(r, 15, "—", Theme.font(9, False, Theme.SUB), al="center", border=True)
                        self._chip(r, 16, "NO BACKUP", "red", sz=8)
                else:
                    for c in range(14, 17):
                        self._cell(r, c, bg=Theme.BG)

        # ---- notes panel to the far right (cols R-V; spans 14-22 when there is no
        #      Backups panel). Three stacked parts: a table of THIS RUN's flagged
        #      metrics (critical + warning) for the admin to triage, a free-text
        #      comment box, then the author line. Regenerated fresh each run. ----
        nl, nr = (18, 22) if bk_rows else (14, 22)
        tn_row, last_data = top - 2, top + rows - 1
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

        # free-text comment box, stretched down to at least the tables' height
        cmt_title = table_bottom + 1
        self._merge(cmt_title, nl, nr, "  Comment", Theme.font(8, True, Theme.SUB), bg=Theme.CARD, al="left")
        cmt_top = cmt_title + 1
        cmt_bottom = max(cmt_top + 2, last_data)
        for rr in range(cmt_top, cmt_bottom + 1):
            for c in range(nl, nr + 1):
                self._cell(rr, c, bg=Theme.CARD).border = field
        self.ws.cell(cmt_top, nl).alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        self.ws.merge_cells(start_row=cmt_top, start_column=nl, end_row=cmt_bottom, end_column=nr)
        if isinstance(ann, dict) and ann.get("comment"):     # pre-fill from the web form, if given
            self.ws.cell(cmt_top, nl).value = ann["comment"]

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
    nsvc = sum(len(v) for v in store.services.values())
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
