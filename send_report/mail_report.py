#!/usr/bin/env python3
"""
mail_report.py
==================================================================================
E-mail a brand-styled HTML snapshot of everything that needs attention, captured
LIVE and DIRECTLY from Prometheus — plus a link to the Grafana Report Generator
webapp where an admin can build and download the full report on demand.

The e-mail body is SELF-CONTAINED: the Prometheus client, the system topology, the
service checks and the analysis helpers are all copied in below (lifted from
generate_report.py), so the link-only mode needs nothing but PyYAML.

The XLSX report can also be attached (it is again — see --attach / --report). That
path defers to generate_report.py, the one engine the Report Generator webapp uses,
so the attachment matches what an admin would download from the webapp. When it is
used, the capture is done ONCE through that engine and shared by the e-mail body and
the workbook, so the two can never disagree. The Report Generator link stays in the
e-mail either way — the attachment is the snapshot, the link is where an admin builds
an annotated report on demand.

Pipeline:
    1. read settings from config.ini ([smtp] / [recipients] / [prometheus] / [grafana])
    2. capture live metrics straight from Prometheus
    3. analyse -> unreachable / critical / warning / no-data findings
    4. render a responsive, brand-styled HTML e-mail (KPI strip + findings)
    5. build/attach the XLSX report (--attach or --report), if asked
    6. embed a link to the Grafana Report Generator webapp
    7. send via Office365 SMTP  (only with --send; otherwise DRY-RUN preview)

    Usage:
        python mail_report.py --to ops@rbz.co.zw,dba@rbz.co.zw          # dry-run preview
        python mail_report.py --to ops@rbz.co.zw --send                 # actually send
        python mail_report.py --attach --send                           # + generate & attach the xlsx
        python mail_report.py --attach --theme light --author "P. Moyo" --send
        python mail_report.py --report "System Admin Report.xlsx" --send # attach an existing xlsx

Requires: PyYAML (topology).  openpyxl + Pillow as well when attaching.  Python 3.8+.
==================================================================================
"""
from __future__ import annotations

import argparse
import configparser
import datetime
import html
import json
import math
import os
import re
import smtplib
import ssl
import sys
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.ini"

# Grafana Report Generator webapp — admins open this to build the full report on demand.
REPORT_GENERATOR_URL = "https://monitoring.rbz.co.zw"

# severity thresholds (mirror the report's chip colours)
CRIT = 90      # used % >= CRIT  -> critical
WARN = 75      # WARN <= used %  -> warning

# brand palette for the e-mail (light theme, broadly compatible)
NAVY, GOLD = "#0e2a47", "#c8a24b"
RED, AMBER, GREEN, MUTED = "#c0392b", "#b9770e", "#1e7d4f", "#6b7785"
RED_T, AMBER_T, GREEN_T, NAVY_T = "#fdecea", "#fef6e7", "#e8f5ee", "#f3f5f8"
# reserved for the unreachable-components banner alone: the highest-severity finding, since
# it means Prometheus has lost visibility entirely (every other red finding is at least still
# being measured). Same tint as RED (a slight escalation, not a new visual language); a
# deeper, more serious accent carries it. Always paired with an explicit "CRITICAL" label.
CRITICAL = "#8e1f1f"
# light tint behind a KPI tile, keyed to its value colour (card-like look, mirrors the xlsx)
TINT = {RED: RED_T, AMBER: AMBER_T, GREEN: GREEN_T, NAVY: NAVY_T, MUTED: "#f1f2f4", CRITICAL: RED_T}


# ============================================================================ #
#  CONFIGURATION  (copied from generate_report.py; report-building bits dropped)
# ============================================================================ #
@dataclass
class Config:
    prom: str = "https://10.100.248.249:9090"
    grafana: str = (
        "https://10.100.248.249:3000/d/05e1d489-469b-4557-a0e9-73d782b60e844/"
        "system-admin-dashboard-green?orgId=1&from=now-5m&to=now&timezone=browser"
        "&var-Filters=&refresh=30s"
    )
    prometheus_yml: str = "../prometheus.yml"   # topology source (system labels), just outside this folder
    overview_threshold: int = 85   # headline "disk/ram usage over N%" counters
    chip_amber: int = 75           # per-cell chip thresholds (used % >= amber -> amber)
    chip_red: int = 90             # used % >= red -> red
    http_timeout: int = 20
    # LDAP / auth blackbox probe instance; blank = not monitored (no sign-in banner)
    ldap_target: str = "vault.rbz.co.zw:7272"
    # set false for an internal Prometheus serving a self-signed cert (mirror of generate_report.py)
    verify_tls: bool = True


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
            cfg.overview_threshold = r.getint("overview_threshold", cfg.overview_threshold)
            cfg.chip_amber = r.getint("chip_amber", cfg.chip_amber)
            cfg.chip_red = r.getint("chip_red", cfg.chip_red)
            cfg.ldap_target = r.get("ldap_target", cfg.ldap_target).strip()
    if not Path(cfg.prometheus_yml).is_absolute():
        cfg.prometheus_yml = str((HERE / cfg.prometheus_yml).resolve())
    return cfg


# --------------------------------------------------------------------------- ini
def load_mail_config(ini_path) -> dict:
    cp = configparser.ConfigParser()
    if not cp.read(ini_path):
        raise FileNotFoundError(f"cannot read {ini_path}")
    smtp = cp["smtp"]
    recipients = []
    if cp.has_section("recipients"):
        recipients = [r.strip() for r in cp["recipients"].get("to", "").split(",") if r.strip()]
    return {
        "enabled": smtp.getboolean("enabled", fallback=True),
        "host": smtp.get("host", "").strip(),
        "port": smtp.getint("port", fallback=587),
        "user": smtp.get("user", "").strip(),
        "password": smtp.get("password", ""),                       # never logged
        "from_address": smtp.get("from_address", smtp.get("user", "")).strip(),
        "from_name": smtp.get("from_name", "System Admin Dashboard").strip(),
        "starttls": smtp.getboolean("starttls", fallback=True),
        "skip_verify": smtp.getboolean("skip_verify", fallback=False),
        "ehlo": (smtp.get("ehlo", "") or "").strip() or None,
        "recipients": recipients,                                   # the mailing list
    }


# ============================================================================ #
#  PROMETHEUS CLIENT  (copied from generate_report.py)
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
#  TOPOLOGY  (copied from generate_report.py — what to capture, grouped by system)
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
    prefix: str = ""             # prepended to the per-series name — disambiguates rows
    group: Optional[str] = None  # fixed component sub-group; None -> take it from each series' `display`


SERVICE_KIND_ORDER = {"system": 0, "offered": 1}


@dataclass
class System:
    name: str
    components: List[Component]
    services: List[Service] = field(default_factory=list)


# -- small PromQL builders so the service table stays readable ----------------
def win_service(name: str, inst: str) -> str:
    return f'max by (name, display) (windows_service_state{{name="{name}", instance="{inst}"}})'


def systemd(inst: str, name: str, type_: Optional[str] = None) -> str:
    typ = f', type="{type_}"' if type_ else ""
    return f'node_systemd_unit_state{{instance="{inst}", name="{name}", state="active"{typ}}}'


def probe(inst: str) -> str:
    return f'probe_success{{instance="{inst}"}}'


def host_up(inst: str) -> str:
    return f'up{{job="windows_exporter", instance="{inst}"}}'


def _t24_label(name: str) -> str:
    """Tidy a T24 TSA service path for display: drop the BNK/ product prefix."""
    return name[4:] if name.startswith("BNK/") else name


# -- service-health checks per system (PromQL); host topology is read from prometheus.yml.
#    Keyed by NORMALISED system name (lower-case, alnum only).
SERVICE_CHECKS: Dict[str, List[Service]] = {
    "rtgs": [
        Service(None, "jboss_status", name_label="name"),
        Service(None, "fe_jboss_status", name_label="component"),
        Service(None, "max by (service, display) (oracle_listener_instance_status)", name_label="service"),
        Service("RTGS apache2 Service", systemd("10.100.246.70:9100", "apache2.service", "forking")),
    ],
    "rtgstest": [
        Service("RTGS site", probe("https://rtgs.rbz.co.zw/"), kind="offered"),
        Service("RTGS reverse Proxy", probe("10.100.246.70")),
        Service("Apache2", systemd("10.100.249.67:9100", "apache2")),
    ],
    "temenos": [
        Service("MSSQLSERVER", win_service("MSSQLSERVER", "10.0.212.4:9182")),
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
    "bsa": [Service("MSSQLSERVER",   win_service("MSSQLSERVER", "10.0.206.5:9182")),
            Service("BSAv50Monitor", win_service("BSAv50Monitor", "10.0.206.5:9182")),
            Service("BSAv50Parser",  win_service("BSAv50Parser", "10.0.206.5:9182")),
            Service("Nginx Reverse Proxy", systemd("192.168.25.156:9100", "nginx.service", "forking")),
            Service("Docker",             systemd("10.0.206.6:9100", "docker.service", "notify"))],
}

# preferred display order (known systems first); anything else is appended A-Z
SYSTEM_ORDER = ["RTGS", "RTGSTEST", "Temenos", "Efin", "CMS", "CSD", "ESF",
                "ESFEXEC", "RBZ Website", "Intranet", "FRS", "SmartHR", "Eagle",
                "CEPECS", "CEBAS", "BDTRS", "LMS", "CRB", "Paytyme", "BSA"]
# `system` label values that are not real systems. "rbz network" is the core switch / network
# device estate (see the `snmp` job in prometheus.yml and DEVICES in webapp/reports/network.py)
# — those get their own Network Admin Report and are deliberately excluded here so a switch
# never appears among RTGS and Temenos on the System Admin side.
SKIP_SYSTEMS = {"unassigned", "prometheus", "", "rbz network"}
# systems whose users sign in through the LDAP / auth service (see cfg.ldap_target)
LDAP_DEPENDENTS = {"GCMS", "GMS"}

# BACKUP POLICY — how many calendar days old a host's newest backup may be and still count
# as CURRENT. Default 1 = daily = today or yesterday, so nothing changes for the systems
# that back up every day. A system on a slower cycle needs its interval here, else the days
# between its runs are misreported as NO BACKUP. Keyed by the exporter instance publishing
# backup_file. Mirror of the table in generate_report.py — keep the two in step.
#   BSA: MSSQL full backup every 3rd day (see backup_monitor/check_backup_bsa.ps1 -MaxAgeDays).
BACKUP_MAX_AGE_DAYS = {
    "10.0.206.5:9182": 3,          # BSA Database
}
DEFAULT_BACKUP_MAX_AGE_DAYS = 1    # daily backup = today or yesterday


def backup_cutoff(instance: str, now: datetime.datetime | None = None) -> float:
    """Oldest mtime that still counts as a CURRENT backup for `instance` (unix seconds).
       Midnight-based, matching how the backup_monitor scripts judge age."""
    now = now or datetime.datetime.now()
    tmid = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    return tmid - 86400 * BACKUP_MAX_AGE_DAYS.get(instance, DEFAULT_BACKUP_MAX_AGE_DAYS)


def _link_display(url: str) -> str:
    """Compact label for a link row: host (+path), no scheme or trailing slash."""
    return re.sub(r"^https?://", "", url, flags=re.IGNORECASE).rstrip("/")


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
#  DATA CAPTURE  (copied from generate_report.py)
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
    links: Dict[str, dict]                      # URL -> {up, code, ssl, cert_days, tls, duration}
    backups: Dict[str, dict]                    # instance -> {files, count, ok, ts}
    ldap_up: Optional[bool] = None              # LDAP/auth probe: True up / False down / None not monitored


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
                group = svc.group or r["labels"].get("display") or sysm.name
                if (group, name) in seen:
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
        rows.sort(key=lambda t: (SERVICE_KIND_ORDER.get(t[2], 99),
                                 comp_order.get(t[3], 999), t[3]))
        services[sysm.name] = rows

    # ---- web links (blackbox HTTP probes) -------------------------------------
    links = capture_links(prom)

    # ---- backups (textfile collector: backup_file / _count / _success / _ts) ----
    backups = capture_backups(prom)

    # ---- LDAP / auth blackbox probe (drives the red sign-in banner) ------------
    ldap_up: Optional[bool] = None
    if cfg.ldap_target:
        rows = prom.query(f'probe_success{{instance="{cfg.ldap_target}"}}')
        if rows:
            ldap_up = max(r["value"] for r in rows) >= 1

    return Store(disk, ram, cpu, cob, swift, services, up, links, backups, ldap_up=ldap_up)


def _is_url(inst: Optional[str]) -> bool:
    """A blackbox HTTP target (its `instance` is a URL) — not an ICMP-ping host."""
    return bool(inst) and inst.lower().startswith(("http://", "https://"))


def capture_links(prom: Prometheus) -> Dict[str, dict]:
    """Per-URL reachability + SSL/TLS snapshot from the blackbox exporter."""
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
    try:
        for r in prom.query("probe_tls_version_info"):
            inst, ver = r["labels"].get("instance"), r["labels"].get("version")
            if _is_url(inst) and ver:
                links.setdefault(inst, {})["tls"] = ver
    except Exception:
        pass
    return links


def capture_backups(prom: Prometheus) -> Dict[str, dict]:
    """Per-host backup snapshot from the textfile collector (backup_monitor scripts)."""
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

    scan("backup_file", lambda d, r: d["files"].append(
        (r["labels"].get("file", ""), r["labels"].get("day", ""), r["value"])))
    scan("backup_file_count", lambda d, r: d.__setitem__("count", int(r["value"])))
    scan("backup_check_success", lambda d, r: d.__setitem__("ok", r["value"] >= 1))
    scan("backup_check_timestamp_seconds", lambda d, r: d.__setitem__("ts", r["value"]))

    for d in data.values():
        d["files"] = sorted((ft for ft in d["files"] if ft[0]),
                            key=lambda ft: (0 if ft[1] == "today" else 1, ft[0]))
    return data


# ============================================================================ #
#  PRESSURE / ANALYSIS METRICS  (copied from generate_report.py)
# ============================================================================ #
def disk_high(store: "Store", systems: List["System"], amber: int, red: int
              ) -> Tuple[int, int, str]:
    """EVERY disk over the elevated threshold, counting elevated (amber..red) and
       near-full (>= red) together. Returns (hosts, disks, state)."""
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
    """Every disk AT/OVER red% -> [(system, host, mount, used%)], worst first."""
    out: List[Tuple[str, str, str, float]] = []
    for s in systems:
        for c in s.components:
            for mp, dd in store.disk.get(c.instance, {}).items():
                used = dd.get("used", 0)
                if used >= red:
                    out.append((s.name, c.label, mp, used))
    out.sort(key=lambda t: -t[3])
    return out


def _usage_pressure(values: Dict[str, float], systems: List["System"], amber: int, red: int) -> Tuple[int, str]:
    """Hosts carrying a warning-or-worse marker (>= amber%) and the colour BAND of
       their average usage. Returns (count, state)."""
    vals = [values[c.instance] for s in systems for c in s.components
            if values.get(c.instance, 0) >= amber]
    if not vals:
        return 0, "good"
    return len(vals), ("bad" if (sum(vals) / len(vals)) >= red else "warn")


def ram_pressure(store: "Store", systems: List["System"], amber: int, red: int) -> Tuple[int, str]:
    return _usage_pressure(store.ram, systems, amber, red)


def cpu_pressure(store: "Store", systems: List["System"], amber: int, red: int) -> Tuple[int, str]:
    return _usage_pressure(store.cpu, systems, amber, red)


def cert_rollup(store: "Store", horizon_days: int = 30) -> Tuple[List[Tuple[str, float]], List[Tuple[str, float]]]:
    """SSL certificate expiry rollup across ALL monitored HTTPS endpoints.
       Returns (expired, expiring), each a [(host, days)] list, soonest first."""
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
       Expired certs tile, same filter cert_rollup uses."""
    return sum(1 for url, d in store.links.items()
               if url.lower().startswith("https") and d.get("cert_days") is not None)


def is_unreachable(store: "Store", instance: str) -> bool:
    """True when a configured target isn't reporting: up==0 OR no up series at all
       (only trusted when up data exists for OTHER targets)."""
    u = store.up.get(instance)
    if u is not None:
        return u < 1
    return bool(store.up)


def backup_missing(store: "Store", systems: List["System"]) -> List[Tuple[str, str, str]]:
    """Reporting hosts with NO fresh backup -> [(system, host, reason)].
       Freshness is judged against each host's own backup policy (see backup_cutoff)."""
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


def backup_tracked_hosts(store: "Store", systems: List["System"]) -> int:
    """Total HOST components with a backup check reporting at all — the denominator for the
       Missing backups tile."""
    return sum(1 for s in systems for c in s.components if c.instance in store.backups)


def backup_untracked(store: "Store", systems: List["System"]) -> List[str]:
    """Systems where NO component reports the backup check at all -> [system names]."""
    return [s.name for s in systems
            if not any(c.instance in store.backups for c in s.components)]


def backup_missing_band(count: int) -> str:
    """Card state for the MISSING BACKUPS tile. No misses -> good. Yesterday Sunday
       (today Monday) -> warn (pair straddles the non-work day). Else -> bad."""
    if count == 0:
        return "good"
    yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
    return "warn" if yesterday.weekday() == 6 else "bad"


# ---------------------------------------------------------------------- analysis
Finding = Tuple[str, str, str, str]   # (system, component, item, detail)


def analyse(store: Store, systems, cfg: Optional["Config"] = None):
    """Bucket every reading into unreachable / critical / warning / no-data.
       `cfg` is optional: when supplied (the webapp passes it) the chip thresholds from
       config.ini are used, otherwise the module CRIT/WARN defaults — which config.ini
       mirrors, so both routes agree unless someone deliberately retunes them."""
    crit_at = getattr(cfg, "chip_red", CRIT)
    warn_at = getattr(cfg, "chip_amber", WARN)
    unreach: List[Finding] = []     # exporter not responding -> host/network down
    critical: List[Finding] = []
    warning: List[Finding] = []
    nodata: List[Finding] = []
    for sysm in systems:
        for name, up, kind, group in store.services.get(sysm.name, []):
            if not up:
                cls = "Offered service" if kind == "offered" else "System service"
                where = f"{group} · {name}" if group and group != sysm.name else name
                critical.append((sysm.name, cls, where, "DOWN"))
        for comp in sysm.components:
            if is_unreachable(store, comp.instance):
                unreach.append((sysm.name, comp.label, "host",
                                "exporter unreachable — host down / network?"))
                continue            # host is down: skip its metric-level "no data"
            ram = store.ram.get(comp.instance)
            if ram is None:
                nodata.append((sysm.name, comp.label, "memory", "no data — exporter up, metric missing"))
            elif ram >= crit_at:
                critical.append((sysm.name, comp.label, "RAM", f"{ram:.0f}% used"))
            elif ram >= warn_at:
                warning.append((sysm.name, comp.label, "RAM", f"{ram:.0f}% used"))
            cpu = store.cpu.get(comp.instance)
            if cpu is None:
                nodata.append((sysm.name, comp.label, "cpu", "no data — exporter up, metric missing"))
            elif cpu >= crit_at:
                critical.append((sysm.name, comp.label, "CPU", f"{cpu:.0f}% busy"))
            elif cpu >= warn_at:
                warning.append((sysm.name, comp.label, "CPU", f"{cpu:.0f}% busy"))
            disks = store.disk.get(comp.instance, {})
            if not disks:
                nodata.append((sysm.name, comp.label, "disk", "no data — exporter up, metric missing"))
            for mount, dd in sorted(disks.items(), key=lambda kv: -kv[1].get("used", 0)):
                used, free = dd.get("used", 0), dd.get("free")
                detail = f"{used:.0f}% used" + (f", {free:.0f} GB free" if free is not None else "")
                if used >= crit_at:
                    critical.append((sysm.name, comp.label, mount, detail))
                elif used >= warn_at:
                    warning.append((sysm.name, comp.label, mount, detail))
    # ---- web links (blackbox HTTP probes): reachability + SSL cert expiry ----
    for url, d in getattr(store, "links", {}).items():
        host = url.split("://", 1)[-1].rstrip("/")
        if not d.get("up", True):
            code = d.get("code")
            critical.append(("Web Link", host, "reachability", "DOWN" + (f" (HTTP {code})" if code else "")))
        cd = d.get("cert_days")
        if cd is not None:
            if cd < 0:
                critical.append(("Web Link", host, "SSL cert", f"EXPIRED {abs(cd):.0f} day(s) ago"))
            elif cd < 7:
                critical.append(("Web Link", host, "SSL cert", f"expires in {cd:.0f} day(s)"))
            elif cd < 24:
                warning.append(("Web Link", host, "SSL cert", f"expires in {cd:.0f} day(s)"))
    # ---- backups: hosts with no fresh backup file (same day logic as the report tile) ----
    miss = backup_missing(store, systems)
    bucket = warning if backup_missing_band(len(miss)) == "warn" else critical
    for sysn, host, reason in miss:
        bucket.append((sysn, host, "backup", reason))
    return unreach, critical, warning, nodata


# -------------------------------------------------------------------- rendering
def _rows(items: List[Finding], color: str) -> str:
    out = ""
    for sysn, comp, item, detail in items:
        out += (
            "<tr>"
            f'<td style="padding:7px 12px;border-bottom:1px solid #eef0f2;font-weight:600;color:{NAVY};">{html.escape(sysn)}</td>'
            f'<td style="padding:7px 12px;border-bottom:1px solid #eef0f2;color:#1f2733;">{html.escape(comp)}</td>'
            f'<td style="padding:7px 12px;border-bottom:1px solid #eef0f2;color:#1f2733;font-family:Consolas,monospace;">{html.escape(item)}</td>'
            f'<td style="padding:7px 12px;border-bottom:1px solid #eef0f2;color:{color};font-weight:600;white-space:nowrap;">{html.escape(detail)}</td>'
            "</tr>"
        )
    return out


def _section(title: str, items: List[Finding], color: str, tint: str) -> str:
    if not items:
        return ""
    head = "".join(
        f'<th align="left" style="padding:7px 12px;font-size:11px;letter-spacing:.4px;'
        f'color:{MUTED};text-transform:uppercase;background:{tint};">{c}</th>'
        for c in ("System", "Component", "Item", "Reading")
    )
    return (
        f'<tr><td style="padding:20px 24px 8px;"><span style="font-size:15px;font-weight:700;color:{color};">'
        f'&#9632; {title}</span> <span style="color:{MUTED};font-size:13px;">({len(items)})</span></td></tr>'
        f'<tr><td style="padding:0 24px;"><table width="100%" cellspacing="0" cellpadding="0" '
        f'style="border-collapse:collapse;border-left:3px solid {color};border-radius:2px;overflow:hidden;">'
        f"<tr>{head}</tr>{_rows(items, color)}</table></td></tr>"
    )


def _kpi(label: str, value: str, color: str) -> str:
    tint = TINT.get(color, NAVY_T)
    return (
        '<td align="center" valign="top" style="padding:4px;">'
        f'<div style="background:{tint};border-radius:8px;padding:13px 6px;">'
        f'<div style="font-size:22px;font-weight:700;color:{color};line-height:1;">{html.escape(value)}</div>'
        f'<div style="font-size:10px;letter-spacing:.4px;color:{MUTED};text-transform:uppercase;margin-top:6px;">{label}</div>'
        "</div></td>"
    )


def _kpi_panel(title: str, cols, color: str) -> str:
    """A titled KPI tile split into sub-columns: cols = [(sublabel, value), ...]."""
    tint = TINT.get(color, NAVY_T)
    def half(v: int, lbl: str, border: str) -> str:
        return (
            f'<td align="center" valign="top" style="padding:0 8px;{border}">'
            f'<div style="font-size:22px;font-weight:700;color:{color};line-height:1;">{v}</div>'
            f'<div style="font-size:9px;letter-spacing:.3px;color:{MUTED};text-transform:uppercase;margin-top:3px;">{lbl}</div>'
            "</td>"
        )
    cells = "".join(half(v, lbl, "border-left:1px solid rgba(0,0,0,.12);" if i else "")
                    for i, (lbl, v) in enumerate(cols))
    return (
        '<td align="center" valign="top" style="padding:4px;">'
        f'<div style="background:{tint};border-radius:8px;padding:13px 4px;">'
        '<table cellspacing="0" cellpadding="0" style="margin:0 auto;"><tr>'
        + cells +
        "</tr></table>"
        f'<div style="font-size:10px;letter-spacing:.4px;color:{MUTED};text-transform:uppercase;margin-top:7px;">{title}</div>'
        "</div></td>"
    )


def _unreachable_block(unreach: List[Finding]) -> str:
    """A prominent callout listing the systems/components Prometheus can no longer reach."""
    if not unreach:
        return ""
    bysys: dict = {}
    for sysn, comp, *_ in unreach:
        bysys.setdefault(sysn, []).append(comp)
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(s)}</b>'
        f'<span style="color:#555;"> &mdash; {html.escape(", ".join(lbls))}</span></div>'
        for s, lbls in bysys.items()
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{RED_T};border-left:4px solid {CRITICAL};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{CRITICAL};">&#9888;&nbsp; CRITICAL &mdash; {len(unreach)} component(s) unreachable</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">Prometheus can no longer scrape these targets &mdash; '
        "the host is down, the exporter has stopped, or there is a network / connectivity issue. "
        "<b>Treat as urgent.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _disk_nearfull_block(store, systems) -> str:
    """A prominent callout listing the volumes that are almost full (>= CRIT%)."""
    nearfull = disk_near_full(store, systems, CRIT)
    if not nearfull:
        return ""
    byhost: dict = {}
    for s, lbl, mount, used in nearfull:
        byhost.setdefault(f"{s} · {lbl}", []).append(f"{mount} {used:.0f}%")
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(h)}</b>'
        f'<span style="color:#555;"> &mdash; {html.escape(", ".join(v))}</span></div>'
        for h, v in byhost.items()
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{RED_T};border-left:4px solid {RED};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{RED};">&#9888;&nbsp; '
        f'{len(nearfull)} disk(s) near-full on {len(byhost)} host(s)</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">These volumes are almost full '
        f'(&#8805;{CRIT}%) &mdash; an imminent outage that can take the service down. '
        "<b>Free space or extend the disk now.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _cob_block(store, unreach) -> str:
    """A callout when COB looks like it never ran — flagged every day EXCEPT Monday.

    If the T24 database component is itself unreachable, an abnormally-high/absent COB
    reading doesn't mean COB failed to run — it means we can't tell, because the exporter
    that would report it can't be reached. Say that plainly rather than implying a T24
    process failure when the real fault may just be connectivity to the DB host."""
    cob_missing = store.cob is None or (isinstance(store.cob, float) and math.isnan(store.cob))
    if not cob_missing or datetime.date.today().weekday() == 0:   # 0 = Monday
        return ""
    db_unreachable = any(sysn == "Temenos" and "DB" in comp for sysn, comp, *_ in unreach)
    if db_unreachable:
        headline = "COB &mdash; could not be calculated, T24 database is unreachable"
        detail = ("The T24 database component is unreachable, so COB time could not be "
                   "calculated for the previous day &mdash; this is not evidence that COB "
                   "itself failed to run. <b>Restore connectivity to the T24 database first, "
                   "then re-check COB.</b>")
    else:
        headline = "COB &mdash; close-of-business may not have run yesterday"
        detail = ("COB time is out of range (abnormally high), so no completed close-of-business "
                   "was detected for the previous day. <b>Confirm the T24 COB ran and completed.</b> "
                   "(On Mondays this is expected &mdash; Sunday has no COB &mdash; and is not flagged.)")
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{AMBER_T};border-left:4px solid {AMBER};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; {headline}</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 0;">{detail}</div>'
        "</div></td></tr>"
    )


def _swift_block(store, unreach) -> str:
    """A callout when SWIFT transaction count is missing WHILE the T24 application component
    is down. Only fires in that specific case — a blank SWIFT count while T24 App is up is
    left unflagged, since the app being reachable makes the missing count a different
    question. That's not evidence no SWIFT transactions occurred — it means we can't tell,
    because the exporter that would report it can't be reached."""
    swift_missing = store.swift is None or (isinstance(store.swift, float) and math.isnan(store.swift))
    if not swift_missing:
        return ""
    if not any(sysn == "Temenos" and "App" in comp for sysn, comp, *_ in unreach):
        return ""
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{AMBER_T};border-left:4px solid {AMBER};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; '
        "SWIFT &mdash; could not be calculated, T24 application is down</div>"
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 0;">The T24 application component '
        "is down, so SWIFT transaction count could not be calculated for the current period "
        "&mdash; this is not evidence that no SWIFT transactions occurred. "
        "<b>Restore the T24 application first, then re-check SWIFT.</b></div>"
        "</div></td></tr>"
    )


def _ldap_block(store, systems) -> str:
    """RED callout when the LDAP / auth service is down — users can't sign in to the
       dependent systems. Mirrors the xlsx + the webapp's highest-priority banner.
       Only fires on a positive 'down' reading; an absent probe is never alarmed on."""
    if getattr(store, "ldap_up", None) is not False:      # True (up) or None (not monitored)
        return ""
    present = [s.name for s in systems if s.name in LDAP_DEPENDENTS] or sorted(LDAP_DEPENDENTS)
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{RED_T};border-left:4px solid {RED};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{RED};">&#9888;&nbsp; '
        f"LDAP / auth service down &mdash; {len(present)} dependent system(s) affected</div>"
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 0;">Users cannot sign in to: '
        f'<b>{html.escape(", ".join(present))}</b>. <b>Treat as urgent.</b></div>'
        "</div></td></tr>"
    )


def _cert_block(store) -> str:
    """SSL certificate rollup callout — RED when anything has already expired, AMBER when
       certs are inside the 30-day horizon. This is the banner the webapp shows and the
       e-mail was missing, which is why an amber banner never appeared while only certs
       were in trouble (the individual certs still list under Critical/Warning below)."""
    expired, expiring = cert_rollup(store)
    if not (expired or expiring):
        return ""
    red = bool(expired)
    fg, bg = (RED, RED_T) if red else (AMBER, AMBER_T)
    bits = ([f"{len(expired)} expired"] if expired else []) + \
           ([f"{len(expiring)} expiring &#8804;30d"] if expiring else [])
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(h)}</b>'
        f'<span style="color:#555;"> &mdash; {label}</span></div>'
        for h, label in ([(h, "<b>EXPIRED</b>") for h, _ in expired] +
                         [(h, f"{d:.0f} day(s) left") for h, d in expiring])
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{bg};border-left:4px solid {fg};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{fg};">&#9888;&nbsp; '
        f'SSL certs &mdash; {", ".join(bits)}</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">'
        + ("An expired certificate breaks HTTPS for users. <b>Renew now.</b>" if red else
           "These certificates renew soon. <b>Schedule the renewal before they lapse.</b>")
        + f"</div>{lines}</div></td></tr>"
    )


def _attachment_block(mail) -> str:
    """Callout naming the XLSX report attached to this e-mail. Only rendered when one is
       actually attached — it sits ABOVE the Report Generator call-to-action, which stays
       either way (the attachment is today's snapshot, the link builds one on demand)."""
    name = mail.get("attachment_name")
    if not name:
        return ""
    theme = mail.get("attachment_theme")
    tag = f" &nbsp;&middot;&nbsp; {html.escape(theme)} theme" if theme else ""
    return (
        '<tr><td style="padding:20px 24px 0;">'
        f'<div style="background:{GREEN_T};border-left:4px solid {GREEN};border-radius:4px;padding:13px 16px;">'
        f'<div style="font-size:14px;font-weight:700;color:{GREEN};margin-bottom:5px;">'
        "&#128206;&nbsp; The full report is attached</div>"
        f'<div style="font-size:13px;color:#1f2733;line-height:1.6;">'
        f'<b>{html.escape(name)}</b>{tag} &mdash; the complete System Admin Report '
        "(Services / Memory / Disk / Backups per system, plus web links and SSL certs) "
        "for the same snapshot summarised above.</div>"
        "</div></td></tr>"
    )


def _report_generator_cta(mail) -> str:
    """Call-to-action block: link admins to the Grafana Report Generator webapp to build a
       report on demand — annotated, themed and scoped to the systems they pick. Always
       shown, attachment or not: the attachment is the unannotated daily snapshot."""
    url = html.escape(mail.get("report_url") or REPORT_GENERATOR_URL, quote=True)
    link = (f'<a href="{url}" style="color:{NAVY};font-weight:700;text-decoration:underline;">'
            "Grafana Report Generator</a>")
    if mail.get("attachment_name"):
        heading = "Need to annotate or re-scope it?"
        blurb = ("The attached report is an automated snapshot. To build one with your own "
                 "sign-off &mdash; per-system answers, notes, an author and only the systems you "
                 f"pick &mdash; go to the {link} and generate it on demand. "
                 "Click the link below to open it.")
    else:
        heading = "Need the full report?"
        blurb = ("This e-mail is a live snapshot preview. To build and download the complete "
                 "System Admin Report (Services / Memory / Disk per system), go to the "
                 f"{link} and generate it on demand. Click the link below to open it.")
    return (
        '<tr><td style="padding:20px 24px 4px;">'
        f'<div style="background:{NAVY_T};border-radius:8px;padding:16px 18px;">'
        f'<div style="font-size:14px;font-weight:700;color:{NAVY};margin-bottom:6px;">{heading}</div>'
        f'<div style="font-size:13px;color:#1f2733;line-height:1.6;">{blurb}</div>'
        f'<div style="margin-top:12px;"><a href="{url}" style="background:{NAVY};color:{GOLD};text-decoration:none;'
        f'font-weight:700;font-size:14px;padding:11px 20px;border-radius:6px;display:inline-block;">'
        "&#9658;&nbsp; Grafana Report Generator</a></div>"
        f'<div style="font-size:12px;color:{MUTED};margin-top:9px;">Or paste this address into your browser: {url}</div>'
        "</div></td></tr>"
    )


def render_html(store, systems, unreach, crit, warn, nodata, mail) -> str:
    today = datetime.date.today().strftime("%d %B %Y")
    prepared_by = (f" &nbsp;&middot;&nbsp; prepared by {html.escape(mail['author'])}"
                   if mail.get("author") else "")
    hosts = sum(len(s.components) for s in systems)
    nsvc = sum(len(v) for v in store.services.values())
    down = sum(1 for v in store.services.values() for row in v if not row[1])
    thr = int(mail.get("elevated", 85))                       # shared "over N%" level (config.ini)
    ram_hosts, _ = ram_pressure(store, systems, thr, thr)
    cpu_hosts, _ = cpu_pressure(store, systems, thr, thr)
    nmiss = len(backup_missing(store, systems))
    miss_band = backup_missing_band(nmiss)
    miss_color = GREEN if miss_band == "good" else (AMBER if miss_band == "warn" else RED)
    cob_missing = store.cob is None or (isinstance(store.cob, float) and math.isnan(store.cob))
    cob = "N/A" if cob_missing else f"{store.cob/60:.1f} min"
    cob_alert = cob_missing and datetime.date.today().weekday() != 0   # 0 = Monday (Sunday: no COB)
    swift = f"{store.swift:.0f}" if store.swift is not None else "N/A"
    cert_expired, _cert_expiring = cert_rollup(store)
    n_https = sum(1 for u in store.links if u.lower().startswith("https"))
    n_http = sum(1 for u in store.links if u.lower().startswith("http://"))
    web_color = GREEN if n_http == 0 else (RED if n_http > n_https else AMBER)

    # the closing note points at whichever full breakdown this e-mail actually carries
    full_breakdown = ("see the attached report" if mail.get("attachment_name")
                      else "generate the report from the Grafana Report Generator above")

    if unreach:
        banner_bg, banner_fg = RED_T, CRITICAL
        headline = f"CRITICAL — {len(unreach)} component(s) UNREACHABLE — possible host / network outage"
    elif crit:
        banner_bg, banner_fg, headline = RED_T, RED, f"{len(crit)} item(s) need immediate attention"
    elif warn or cob_alert:
        banner_bg, banner_fg = AMBER_T, AMBER
        headline = (f"{len(warn)} item(s) to keep an eye on" if warn
                    else "COB may not have run yesterday — check T24")
    else:
        banner_bg, banner_fg, headline = GREEN_T, GREEN, "All monitored systems are healthy"

    static_kpis = "".join([
        _kpi("Systems", str(len(systems)), NAVY),
        _kpi("Hosts", str(hosts), NAVY),
        _kpi("Services", str(nsvc), NAVY),
        _kpi("SWIFT txns", swift, NAVY),
        _kpi("COB &middot; T24", cob, NAVY),
    ])
    immediate_kpis = [
        # missing out of TRACKED hosts (an untracked host isn't judged either way — see the
        # separate Backup tracking tile for those).
        _kpi_panel("Missing backups", [("Missing", nmiss), ("Tracked", backup_tracked_hosts(store, systems))],
                   miss_color),
        # unreachable/down out of the TOTAL we monitor, so the count never reads as if fewer
        # components/services exist just because some are currently failing.
        _kpi_panel("Unreachable components", [("Unreachable", len(unreach)), ("Total", hosts)],
                   CRITICAL if unreach else GREEN),
        _kpi_panel("Services down", [("Down", down), ("Total", nsvc)],
                   RED if down else GREEN),
        _kpi_panel("Expired certs", [("Expired", len(cert_expired)), ("Total", cert_monitored(store))],
                   RED if cert_expired else GREEN),
    ]
    disk_high_h, disk_high_d, disk_high_state = disk_high(store, systems, thr, CRIT)
    disk_high_color = {"good": GREEN, "warn": AMBER, "bad": RED}[disk_high_state]
    n_untracked = len(backup_untracked(store, systems))
    n_tracked = len(systems) - n_untracked
    watch_kpis = [
        _kpi_panel("High CPU usage", [("Hosts", cpu_hosts)], AMBER if cpu_hosts else GREEN),
        _kpi_panel("High RAM usage", [("Hosts", ram_hosts)], AMBER if ram_hosts else GREEN),
        _kpi_panel(f"High disk usage &middot; &#8805;{thr}%",
                   [("Hosts", disk_high_h), ("Disks", disk_high_d)],
                   disk_high_color),
        _kpi_panel("Web encryption", [("HTTPS", n_https), ("HTTP", n_http)], web_color),
        _kpi_panel("Backup tracking", [("Tracked", n_tracked), ("Untracked", n_untracked)],
                   AMBER if n_untracked else GREEN),
    ]
    immediate_kpis = "".join(immediate_kpis)
    watch_kpis = "".join(watch_kpis)
    # banner order mirrors the webapp (services.build_overview): LDAP first, then near-full,
    # unreachable, certs, COB — highest-consequence first.
    body = (_ldap_block(store, systems)
            + _disk_nearfull_block(store, systems)
            + _unreachable_block(unreach)
            + _cert_block(store)
            + _cob_block(store, unreach)
            + _swift_block(store, unreach)
            + _section("Critical", crit, RED, RED_T)
            + _section("Warning", warn, AMBER, AMBER_T)
            + _section("No data (check exporters)", nodata, MUTED, "#f1f2f4"))
    if not body:
        body = (f'<tr><td style="padding:24px;"><div style="background:{GREEN_T};border-left:3px solid {GREEN};'
                f'padding:14px 16px;color:{GREEN};font-weight:600;">No disks, memory or services breached their '
                "thresholds at snapshot time.</div></td></tr>")

    return f"""<!doctype html><html><body style="margin:0;padding:0;background:#eef0f3;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f3;font-family:'Segoe UI',Arial,sans-serif;">
<tr><td align="center" style="padding:24px 12px;">
<table width="660" cellpadding="0" cellspacing="0" style="max-width:660px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.12);">

  <tr><td style="background:{NAVY};padding:22px 24px;">
    <div style="font-size:20px;font-weight:700;color:{GOLD};letter-spacing:.5px;">SYSTEM ADMIN REPORT</div>
    <div style="font-size:12px;color:#aebfd1;margin-top:3px;">Reserve Bank of Zimbabwe &nbsp;&middot;&nbsp; live snapshot &nbsp;&middot;&nbsp; {today}{prepared_by}</div>
  </td></tr>

  <tr><td style="background:{banner_bg};border-bottom:1px solid #e6e8ec;padding:12px 24px;">
    <span style="color:{banner_fg};font-weight:700;font-size:14px;">&#9679; {headline}</span>
  </td></tr>

  <tr><td style="padding:12px 24px 0;">
    <div style="font-size:11px;font-weight:700;letter-spacing:.5px;color:{MUTED};text-transform:uppercase;">At a glance</div>
  </td></tr>
  <tr><td style="padding:2px 12px 4px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>{static_kpis}</tr></table>
  </td></tr>
  <tr><td style="padding:8px 24px 0;border-top:1px solid #eef0f2;">
    <div style="font-size:11px;font-weight:700;letter-spacing:.5px;color:{RED};text-transform:uppercase;">&#9679;&nbsp; Needs immediate attention</div>
  </td></tr>
  <tr><td style="padding:2px 12px 6px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>{immediate_kpis}</tr></table>
  </td></tr>
  <tr><td style="padding:8px 24px 0;">
    <div style="font-size:11px;font-weight:700;letter-spacing:.5px;color:{AMBER};text-transform:uppercase;">&#9679;&nbsp; Needs attention</div>
  </td></tr>
  <tr><td style="padding:2px 12px 6px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>{watch_kpis}</tr></table>
  </td></tr>

  {body}

  {_attachment_block(mail)}

  {_report_generator_cta(mail)}

  <tr><td style="padding:14px 24px 22px;">
    <a href="{mail['grafana']}" style="background:{NAVY};color:{GOLD};text-decoration:none;font-weight:700;
       font-size:14px;padding:11px 20px;border-radius:6px;display:inline-block;">&#9658;&nbsp; Open the live Grafana dashboard</a>
  </td></tr>

  <tr><td style="background:#f7f8fa;border-top:1px solid #e6e8ec;padding:14px 24px;">
    <div style="font-size:11px;color:{MUTED};line-height:1.6;">
      This is an automated, point-in-time snapshot captured live from Prometheus ({html.escape(mail.get('prom', '').split('//')[-1])}).
      Thresholds: warning &#8805;{WARN}% &middot; critical &#8805;{CRIT}%. For the full breakdown (Services / Memory / Disk per system),
      {full_breakdown}. For live, auto-refreshing data use the Grafana dashboard.
    </div>
  </td></tr>

</table></td></tr></table></body></html>"""


def plain_summary(unreach, crit, warn, nodata, report_url=None, attachment_name=None) -> str:
    """The text/plain alternative. `report_url` and `attachment_name` are optional so
       in-process callers (the webapp) can ask for the findings alone."""
    lines = ["System Admin Report — summary", ""]
    for title, items in (("UNREACHABLE", unreach), ("CRITICAL", crit),
                         ("WARNING", warn), ("NO DATA", nodata)):
        if items:
            lines.append(f"{title} ({len(items)}):")
            lines += [f"  - {s} / {c} / {i}: {d}" for s, c, i, d in items]
            lines.append("")
    if not (unreach or crit or warn or nodata):
        lines.append("All systems healthy.")
    if attachment_name:
        lines.append(f"Full report attached: {attachment_name}")
    if report_url:
        lines.append(f"Build an annotated report at the Grafana Report Generator: {report_url}")
    return "\n".join(lines)


# -------------------------------------------------------------------------- send
XLSX_MIME = ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")


def send_email(mail: dict, recipients: List[str], subject: str, html_body: str,
               text_body: str, attachment: Optional[Path] = None) -> None:
    """Send the multipart/alternative e-mail, optionally with the XLSX report attached.
       `attachment` is a path — its file NAME becomes the attachment name."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f'{mail["from_name"]} <{mail["from_address"]}>'
    msg["To"] = ", ".join(recipients)
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    if attachment is not None:
        path = Path(attachment)
        maintype, subtype = XLSX_MIME if path.suffix.lower() == ".xlsx" else ("application", "octet-stream")
        msg.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=path.name)
    ctx = ssl.create_default_context()
    if mail["skip_verify"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with smtplib.SMTP(mail["host"], mail["port"], timeout=30) as srv:
        srv.ehlo(mail["ehlo"])
        if mail["starttls"]:
            srv.starttls(context=ctx)
            srv.ehlo(mail["ehlo"])
        if mail["user"]:
            srv.login(mail["user"], mail["password"])
        srv.send_message(msg)


# ----------------------------------------------------------------- report engine
def load_engine():
    """Import generate_report.py — the XLSX engine the Report Generator webapp also uses.
       Returns the module, or None when it can't be loaded (missing openpyxl/Pillow, a
       broken engine): the e-mail is the important part, so we degrade to link-only
       rather than skip the send entirely."""
    try:
        sys.path.insert(0, str(HERE))          # works no matter where this is invoked from
        import generate_report as engine
        return engine
    except Exception as exc:                   # noqa: BLE001 — any import failure degrades gracefully
        print(f"[!] report engine unavailable ({exc.__class__.__name__}: {exc})", file=sys.stderr)
        print("[!] sending WITHOUT the xlsx attachment — 'pip install -r requirements.txt' to fix.",
              file=sys.stderr)
        return None


def capture_via_engine(engine, args) -> tuple:
    """One capture through the engine, shared by the e-mail body and the workbook, so the
       attachment and the summary above it describe the exact same instant. Returns
       (cfg, systems, store) using the ENGINE's Config/System/Store — a superset of this
       module's copies (it also carries ldap_up), so every helper here accepts them."""
    cfg = engine.load_config(args.config)
    if args.prom:
        cfg.prom = args.prom
    if args.grafana:
        cfg.grafana = args.grafana
    systems = engine.load_topology(cfg.prometheus_yml)
    only = {n.strip() for n in (args.systems or "").split(",") if n.strip()}
    if only:
        systems = [s for s in systems if s.name in only]
        if not systems:
            raise SystemExit(f"[!] --systems matched nothing: {args.systems}")
    prom = engine.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    prom.ping()
    store = engine.capture(prom, systems, cfg)
    if only:
        engine.scope_links_to_systems(store, systems)
    return cfg, systems, store


# -------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="E-mail a live Prometheus snapshot + a link to the Report Generator.")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG), help="path to config.ini")
    ap.add_argument("--to", default="", help="override recipients (comma-separated)")
    ap.add_argument("--from-name", default=None, help="override the From display name")
    ap.add_argument("--grafana", default=None, help="override the Grafana dashboard URL")
    ap.add_argument("--prom", default=None, help="override the Prometheus base URL")
    ap.add_argument("--report-url", default=None, help="override the report-generator webapp URL")
    ap.add_argument("--html-out", default=str(HERE / "email_preview.html"), help="dry-run preview path")
    ap.add_argument("--send", action="store_true", help="actually send (otherwise DRY-RUN preview only)")
    # --- XLSX report attachment (generate_report.py — the engine the webapp uses) ---------
    ap.add_argument("--attach", action="store_true",
                    help="generate the XLSX report from this same snapshot and attach it")
    ap.add_argument("--report", default=None, metavar="PATH",
                    help="attach an EXISTING xlsx instead of generating one (e.g. from run.bat)")
    ap.add_argument("--theme", default="dark", choices=("dark", "light"),
                    help="palette for the generated report (default: dark)")
    ap.add_argument("--author", default=None,
                    help="name stamped into the report's 'By' field and the e-mail header")
    ap.add_argument("--summary", default=None,
                    help="free text for the report's Summary Notes box")
    ap.add_argument("--systems", default=None,
                    help="scope the snapshot to these systems (comma-separated); requires --attach")
    ap.add_argument("--keep-report", default=None, metavar="PATH",
                    help="also save the generated xlsx here (default: kept in dry-run, temporary when sending)")
    args = ap.parse_args(argv)

    # everything is sourced from config.ini; CLI flags only override
    cfg = load_config(args.config)
    if args.prom:
        cfg.prom = args.prom
    if args.grafana:
        cfg.grafana = args.grafana

    mail = load_mail_config(args.config)
    if args.from_name:
        mail["from_name"] = args.from_name
    if args.author:
        mail["author"] = args.author
    mail["grafana"] = cfg.grafana
    mail["prom"] = cfg.prom
    mail["elevated"] = cfg.overview_threshold
    mail["report_url"] = args.report_url or REPORT_GENERATOR_URL
    recipients = [r.strip() for r in (args.to or "").split(",") if r.strip()] or mail["recipients"]
    print(f"[*] SMTP {mail['host']}:{mail['port']} as {mail['user']} (starttls={mail['starttls']})")  # no password
    print(f"[*] From: {mail['from_name']} <{mail['from_address']}>")
    print(f"[*] Report generator link: {mail['report_url']}")

    # ---- capture -----------------------------------------------------------------------
    # --attach routes the capture through the report engine so ONE snapshot feeds both the
    # e-mail and the workbook; without it we stay on this module's self-contained copy,
    # which needs nothing but PyYAML.
    engine = load_engine() if args.attach else None
    if engine is not None:
        print(f"[*] capturing live metrics from {cfg.prom} via generate_report.py ...")
        cfg, systems, store = capture_via_engine(engine, args)
        mail["grafana"], mail["prom"] = cfg.grafana, cfg.prom
        mail["elevated"] = cfg.overview_threshold
    else:
        if args.systems:
            print("[!] --systems needs --attach (the report engine) — ignoring it.", file=sys.stderr)
        print(f"[*] reading topology from {cfg.prometheus_yml} ...")
        systems = load_topology(cfg.prometheus_yml)
        prom = Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
        print(f"[*] capturing live metrics from {cfg.prom} ...")
        prom.ping()
        store = capture(prom, systems, cfg)

    unreach, crit, warn, nodata = analyse(store, systems, cfg)
    print(f"[*] findings: {len(unreach)} unreachable, {len(crit)} critical, "
          f"{len(warn)} warning, {len(nodata)} no-data")

    # ---- the attachment ----------------------------------------------------------------
    # Resolved BEFORE rendering: the body names the attachment, so it has to know.
    attachment: Optional[Path] = None
    tmpdir: Optional[str] = None
    if args.report:
        attachment = Path(args.report)
        if not attachment.is_absolute():
            attachment = HERE / attachment
        if not attachment.is_file():
            print(f"[!] --report not found: {attachment}", file=sys.stderr)
            return 2
        print(f"[*] attaching existing report: {attachment.name}")
        mail["attachment_name"] = attachment.name
    elif engine is not None:
        print(f"[*] rendering report ({args.theme} theme) ...")
        data = engine.build_report_bytes(store, systems, cfg, theme=args.theme,
                                         author=args.author, summary_comment=args.summary)
        name = engine.default_report_filename(args.theme)
        if args.keep_report:
            target = Path(args.keep_report)
            attachment = target if target.is_absolute() else HERE / target
            if attachment.is_dir():
                attachment = attachment / name
        elif not args.send:
            attachment = HERE / name          # dry-run: leave it on disk so it can be inspected
        else:
            tmpdir = tempfile.mkdtemp(prefix="report_")
            attachment = Path(tmpdir) / name
        attachment.parent.mkdir(parents=True, exist_ok=True)
        attachment.write_bytes(data)
        print(f"[+] report -> {attachment}  ({len(data)/1024:.0f} KB)")
        mail["attachment_name"] = attachment.name
        mail["attachment_theme"] = args.theme

    try:
        sev = (f"{len(unreach)} unreachable" if unreach else
               (f"{len(crit)} critical" if crit else (f"{len(warn)} warnings" if warn else "all healthy")))
        subject = f"System Admin Report — {datetime.date.today():%d %b %Y} — {sev}"
        html_body = render_html(store, systems, unreach, crit, warn, nodata, mail)
        text_body = plain_summary(unreach, crit, warn, nodata, mail["report_url"],
                                  mail.get("attachment_name"))

        if not args.send:
            Path(args.html_out).write_text(html_body, encoding="utf-8")
            print(f"[DRY-RUN] no e-mail sent. preview -> {args.html_out}")
            print(f"[DRY-RUN] would send '{subject}'")
            print(f"[DRY-RUN] to: {recipients or '(none set — use --to)'}")
            print(f"[DRY-RUN] attachment: {attachment if attachment else '(none)'}")
            print("\n" + text_body)
            return 0

        if not recipients:
            print("[!] no recipients — set [recipients] to=... in config.ini, or pass --to", file=sys.stderr)
            return 2
        if not mail["enabled"]:
            print("[!] smtp.enabled is false in the ini", file=sys.stderr)
            return 2
        print(f"[*] sending to {recipients} ...")
        send_email(mail, recipients, subject, html_body, text_body, attachment)
        print("[+] sent." + (f" (attached {attachment.name})" if attachment else ""))
        return 0
    finally:
        if tmpdir:                            # only the temp copy we made ourselves
            try:
                attachment.unlink()
                os.rmdir(tmpdir)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
