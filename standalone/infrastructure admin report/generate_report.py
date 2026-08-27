#!/usr/bin/env python3
"""
generate_report.py
==================================================================================
Infrastructure Report generator — Active Directory root domain controllers and the
HCI Cluster.

Captures live metrics straight from Prometheus and renders the tree-nested,
dark-themed XLSX dashboard (via report_generator.py, this folder's sibling — the
pure rendering engine, ported from the approved template) that mirrors the webapp's
Infrastructure Admin report (webapp/reports/network.py's build_infrastructure_report
— same live PromQL, same thresholds, different presentation layer: that one maps an
already-annotated Snapshot the admin reviewed on screen, this captures fresh each run).

The device topology below (root-dc-1, root-dc-2, hci-cluster) is a small, fixed set,
not read from prometheus.yml — there is no per-system topology for this estate, the
same reasoning webapp/reports/network.py's own DEVICES list already follows. Keep
these three entries IN STEP BY HAND with that module's DEVICES list: it is the
canonical source (Django-coupled, can't be imported from a standalone script), this
is its self-contained twin — the same duplication convention this repo already
accepts between generate_report.py and network.py sharing PromQL without sharing code.

NOT onboarded yet, so NOT reported on here (see report_generator.py's own docstring
on never fabricating a metric that isn't collected):
  * Standalone DB Hosts / "oracle hosts" — no Prometheus scrape config exists for
    this estate anywhere yet. Add a DEVICES-shaped entry below once it does; the
    report picks it up automatically, no other code change needed.
  * Cluster Storage (a vSAN-style pool used%/size) — no metric source for it exists
    in this codebase yet. Every group's cluster_storage stays empty on purpose; the
    renderer already omits that panel whenever the list is empty.
  * Root DC CPU/RAM/disk — per webapp/reports/network.py's own DEVICES comment,
    only the SERVICE collector is currently enabled on both root DCs (confirmed
    2026-08-25); CPU/RAM/disk read no data. This script reports that honestly (a
    note saying so) rather than showing a fabricated 0%.

    Usage:
        python generate_report.py
        python generate_report.py --theme light --author "P. Moyo" --stamp
        python generate_report.py --prom http://10.100.248.249:9090 --out report.xlsx

    Requirements:
        Python 3.8+   and   openpyxl   (pip install openpyxl)
==================================================================================
"""
from __future__ import annotations

import argparse
import configparser
import datetime
import json
import ssl
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import report_generator as rg


# ============================================================================ #
#  CONFIGURATION
# ============================================================================ #
@dataclass
class Config:
    prom: str = "https://10.100.248.249:9090"
    out: str = "Infrastructure Report.xlsx"
    http_timeout: int = 20
    # set false for an internal Prometheus serving a self-signed cert (matches the
    # verify_tls pattern the System Admin Report's own config.ini already uses)
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
            cfg.verify_tls = cp["prometheus"].getboolean("verify_tls", cfg.verify_tls)
        if cp.has_section("report"):
            cfg.out = cp["report"].get("output", cfg.out)
    if not Path(cfg.out).is_absolute():
        cfg.out = str(HERE / cfg.out)
    return cfg


# ============================================================================ #
#  PROMETHEUS CLIENT  (identical to send_report/generate_report.py's)
# ============================================================================ #
class Prometheus:
    """Minimal read-only client for the Prometheus HTTP API (instant queries)."""

    def __init__(self, base: str, timeout: int = 20, verify_tls: bool = True):
        self.base = base.rstrip("/")
        self.timeout = timeout
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

    def ping(self) -> None:
        self.query("vector(1)")


# ============================================================================ #
#  TOPOLOGY  — kept in step by hand with webapp/reports/network.py's DEVICES
# ============================================================================ #
ROOT_DCS = [
    {"key": "root-dc-1", "name": "RBZHQ-ROOT-01", "target": "10.100.249.200:9182"},
    {"key": "root-dc-2", "name": "RBZ-HQ-ROOT-02", "target": "10.100.249.201:9182"},
]
ROOT_DC_JOB = "root_domain_controllers"

HCI_JOB = "hci_cluster"
HCI_PRIMARY_TARGET = "10.100.246.3:9182"   # network.py's own DEVICES entry for this device

# The two DCs' confirmed-enabled windows_exporter service collector (see module docstring).
# (service short name, display name) — short names are the real Windows service names the
# `name` label carries; verify against a live scrape before trusting these if they ever
# read empty (no Prometheus is reachable from this dev environment to confirm against).
ROOT_DC_SERVICES = [
    ("ADWS", "Active Directory Web Services"),
    ("DNS", "DNS Server"),
    ("Netlogon", "Netlogon"),
    ("kdc", "Kerberos Key Distribution Center"),
]

# volume filter for windows_logical_disk queries — mirrors network.py's own _WIN_VOL
_WIN_VOL = 'volume!~"HarddiskVolume.+"'

# same 80%/90% amber/red thresholds webapp/reports/network.py's _windows_device_flags uses,
# so a device reads the same way here as it would on the webapp's own report
AMBER, RED = 80, 90


def _q(prom: Prometheus, expr: str) -> List[dict]:
    try:
        return prom.query(expr)
    except Exception as exc:                # noqa: BLE001 — one bad query must not sink the run
        print(f"[!] query failed: {expr!r}: {exc}", file=sys.stderr)
        return []


def _windows_host_metrics(prom: Prometheus, job: str, targets: List[str]) -> Dict[str, dict]:
    """CPU/RAM/disk for a set of windows_exporter targets under one scrape job — the exact
    PromQL webapp/reports/network.py's _windows_metrics() uses, so a host reads the same way
    here as it would on the webapp's own report.

    Returns {target: {"known":, "reachable":, "cpu_pct":, "mem_pct":, "mem_total_gb":,
                       "disks": [...]}}.
    """
    up = {r["labels"].get("instance", ""): r["value"] for r in _q(prom, f'up{{job="{job}"}}')}
    cpu = {r["labels"]["instance"]: r["value"]
          for r in _q(prom, '100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[5m])) * 100)')
          if r["labels"].get("instance") in targets}
    mem = {r["labels"]["instance"]: r["value"]
          for r in _q(prom, "100*(1-windows_memory_physical_free_bytes/windows_memory_physical_total_bytes)")
          if r["labels"].get("instance") in targets}
    mem_total = {r["labels"]["instance"]: r["value"]
                for r in _q(prom, "windows_memory_physical_total_bytes/1024/1024/1024")
                if r["labels"].get("instance") in targets}
    used, free, size = {}, {}, {}
    for r in _q(prom, f"100*(1-windows_logical_disk_free_bytes{{{_WIN_VOL}}}/windows_logical_disk_size_bytes{{{_WIN_VOL}}})"):
        if r["labels"].get("instance") in targets:
            used.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]
    for r in _q(prom, f"windows_logical_disk_free_bytes{{{_WIN_VOL}}}/1024/1024/1024"):
        if r["labels"].get("instance") in targets:
            free.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]
    for r in _q(prom, f"windows_logical_disk_size_bytes{{{_WIN_VOL}}}/1024/1024/1024"):
        if r["labels"].get("instance") in targets:
            size.setdefault(r["labels"]["instance"], {})[r["labels"].get("volume")] = r["value"]

    out = {}
    for t in targets:
        scraped = up.get(t)
        disks = [{"volume": vol, "used": u,
                  "free": free.get(t, {}).get(vol), "size": size.get(t, {}).get(vol)}
                 for vol, u in used.get(t, {}).items()]
        out[t] = {
            "known": scraped is not None,
            "reachable": scraped == 1.0,
            "cpu_pct": cpu.get(t),
            "mem_pct": mem.get(t),
            "mem_total_gb": mem_total.get(t),
            "disks": disks,
        }
    return out


def _hci_cluster_nodes(prom: Prometheus) -> Dict[str, dict]:
    """Every instance currently configured under job="hci_cluster" — job-scoped, not a fixed
    target list, so this naturally covers however many HCI nodes are actually onboarded
    (today: one). Mirrors network.py's _hci_node_metrics() exactly."""
    up: Dict[str, float] = {}
    display: Dict[str, str] = {}
    for r in _q(prom, 'up{job="hci_cluster"}'):
        inst = r["labels"].get("instance")
        if inst:
            up[inst] = r["value"]
            display[inst] = r["labels"].get("display", inst)
    if not up:
        return {}
    m = _windows_host_metrics(prom, HCI_JOB, list(up.keys()))
    out = {}
    for inst, scraped in up.items():
        row = m.get(inst, {"known": True, "reachable": scraped == 1.0, "cpu_pct": None,
                           "mem_pct": None, "mem_total_gb": None, "disks": []})
        row = dict(row, display=display.get(inst, inst))
        out[inst] = row
    return out


_CLUSTER_NODE_STATE = {-1: "unknown", 0: "up", 1: "down", 2: "paused", 3: "joining"}
_CLUSTER_RESOURCE_STATE = {-1: "unknown", 0: "inherited", 1: "initializing", 2: "online",
                          3: "offline", 4: "failed", 128: "pending", 129: "online pending",
                          130: "offline pending"}


def _hci_cluster_state(prom: Prometheus, target: str) -> Optional[dict]:
    """WSFC node/resource state for the HCI Cluster target, mirroring network.py's
    _windows_cluster_metrics(). None if this target has no mscluster collector data at all
    (e.g. the cluster role isn't reachable) — absence, not a fabricated empty cluster."""
    nodes = []
    for r in _q(prom, "windows_mscluster_node_state"):
        if r["labels"].get("instance") != target:
            continue
        state = int(r["value"])
        nodes.append((r["labels"].get("node", "?"), _CLUSTER_NODE_STATE.get(state, f"state {state}"),
                     state == 0))
    resources = {"online": 0, "offline": 0, "failed": 0, "other": 0, "failed_names": []}
    seen_resource = False
    for r in _q(prom, "windows_mscluster_resource_state"):
        if r["labels"].get("instance") != target:
            continue
        seen_resource = True
        state = int(r["value"])
        name = r["labels"].get("name", "?")
        if state == 2:
            resources["online"] += 1
        elif state == 3:
            resources["offline"] += 1
        elif state == 4:
            resources["failed"] += 1
            resources["failed_names"].append(name)
        else:
            resources["other"] += 1
    if not nodes and not seen_resource:
        return None
    return {"nodes": nodes, "resources": resources}


def _service_rows(prom: Prometheus, target: str) -> List[rg.ServiceRow]:
    """RUNNING/STOPPED for the confirmed-enabled service collector on a root DC (see module
    docstring) — windows_service_state{name=..., instance=..., state="running"} == 1 means
    that service's current state is Running."""
    rows = []
    for short, display in ROOT_DC_SERVICES:
        res = _q(prom, f'windows_service_state{{name="{short}", instance="{target}", state="running"}}')
        running = bool(res) and res[0]["value"] == 1.0
        rows.append(rg.ServiceRow(display, "RUNNING" if running else "STOPPED"))
    return rows


# ============================================================================ #
#  ReportData ASSEMBLY
# ============================================================================ #
def _flag_note(label: str, pct: float) -> rg.NoteRow:
    return rg.NoteRow(f"{label} at {pct:.0f}%")


def _host_notes(name: str, m: dict) -> tuple:
    """(notes, critical, warning) for one host — the band counts come from the SAME
    threshold checks that build each note, in the same pass, rather than being re-derived
    later by parsing the note text back apart (fragile, and can drift from the text itself)."""
    if not m.get("known"):
        return [rg.NoteRow(f"{name} has never been scraped by Prometheus")], 1, 0
    if not m.get("reachable"):
        return [rg.NoteRow(f"{name} is not answering")], 1, 0
    notes = []
    critical = warning = 0
    cpu = m.get("cpu_pct")
    if cpu is not None and cpu >= AMBER:
        notes.append(_flag_note(f"{name} · CPU", cpu))
        critical += cpu >= RED
        warning += cpu < RED
    mem = m.get("mem_pct")
    if mem is not None and mem >= AMBER:
        notes.append(_flag_note(f"{name} · Memory", mem))
        critical += mem >= RED
        warning += mem < RED
    for d in m.get("disks", []):
        used = d.get("used")
        if used is not None and used >= AMBER:
            notes.append(_flag_note(f"{name} · {d['volume']}", used))
            critical += used >= RED
            warning += used < RED
    return notes, critical, warning


def _active_directory_group(prom: Prometheus, metrics: Dict[str, dict]) -> rg.DeviceGroup:
    cpu_ram, disks, notes, services = [], [], [], []
    critical = warning = 0
    no_host_metrics = True
    for d in ROOT_DCS:
        m = metrics.get(d["target"], {"known": False, "reachable": False})
        if m.get("cpu_pct") is not None and m.get("mem_pct") is not None:
            no_host_metrics = False
            ram_size = f"{m['mem_total_gb']:.0f}GB" if m.get("mem_total_gb") is not None else None
            cpu_ram.append(rg.CpuRam(d["name"], m["cpu_pct"], m["mem_pct"], ram_size))
            for disk in m.get("disks", []):
                if disk.get("used") is not None and disk.get("size") is not None:
                    disks.append(rg.DiskRow(d["name"], disk["used"], round(disk["size"]),
                                            disk.get("volume") or "C:"))
        host_notes, c, w = _host_notes(d["name"], m)
        notes.extend(host_notes)
        critical += c
        warning += w
        services.extend(_service_rows(prom, d["target"]))

    if no_host_metrics:
        notes.append(rg.NoteRow(
            "CPU / RAM / Disk are not collected for these hosts",
            comment="Only the windows_exporter service collector is currently enabled on the "
                    "root domain controllers (confirmed 2026-08-25) — host-resource metrics "
                    "will appear here automatically once that collector is turned on."))
    if not notes:
        notes = [rg.NoteRow(rg.SENTINEL_NOTE)]

    return rg.DeviceGroup(
        title="Active Directory", services=services, cpu_ram=cpu_ram, disks=disks,
        notes=notes, critical=critical, warning=warning,
        count=len(ROOT_DCS), count_label="devices",
    )


def _node_cpu_ram_disk(label: str, m: dict) -> tuple:
    """(cpu_ram_row_or_None, disk_rows) for one HCI instance — no notes here, callers get
    those from _host_notes directly so the note text and the band counts can't drift apart."""
    if m.get("cpu_pct") is None or m.get("mem_pct") is None:
        return None, []
    ram_size = f"{m['mem_total_gb']:.0f}GB" if m.get("mem_total_gb") is not None else None
    cr = rg.CpuRam(label, m["cpu_pct"], m["mem_pct"], ram_size)
    disk_rows = [rg.DiskRow(label, d["used"], round(d["size"]), d.get("volume") or "C:")
                for d in m.get("disks", []) if d.get("used") is not None and d.get("size") is not None]
    return cr, disk_rows


def _hci_cluster_group(nodes: Dict[str, dict], cluster_state: Optional[dict]) -> rg.DeviceGroup:
    cluster_notes = []
    if cluster_state:
        for name, state_text, up in cluster_state["nodes"]:
            if not up:
                cluster_notes.append(rg.NoteRow(f"Cluster node {name} is {state_text}"))
        for name in cluster_state["resources"]["failed_names"]:
            cluster_notes.append(rg.NoteRow(f"Cluster resource '{name}' is in a Failed state"))
    # node-down / resource-failed are always genuine faults when present.
    cluster_critical = len(cluster_notes)

    if len(nodes) <= 1:
        target, m = next(iter(nodes.items())) if nodes else (
            HCI_PRIMARY_TARGET, {"known": False, "reachable": False})
        label = m.get("display", target)
        cr, disk_rows = _node_cpu_ram_disk(label, m)
        host_notes, critical, warning = _host_notes(label, m)
        notes = host_notes + cluster_notes
        if not notes:
            notes = [rg.NoteRow(rg.SENTINEL_NOTE)]
        return rg.DeviceGroup(
            title="HCI Cluster",
            cpu_ram=[cr] if cr else [], disks=disk_rows, notes=notes,
            critical=critical + cluster_critical, warning=warning, count=1, count_label="host",
        )

    # More than one HCI instance is configured — nest each as a child, same shape a Node
    # takes in the reference template (sample_data.json), not hardcoded to any fixed count.
    children = []
    for target, m in sorted(nodes.items(), key=lambda kv: kv[1].get("display", kv[0])):
        label = m.get("display", target)
        cr, disk_rows = _node_cpu_ram_disk(label, m)
        host_notes, c, w = _host_notes(label, m)
        notes = host_notes or [rg.NoteRow(rg.SENTINEL_NOTE)]
        children.append(rg.DeviceGroup(
            title=f"Node ({label})",
            cpu_ram=[cr] if cr else [], disks=disk_rows, notes=notes,
            critical=c, warning=w, count=1, count_label="node",
        ))
    top_notes = cluster_notes or [rg.NoteRow(rg.SENTINEL_NOTE)]
    return rg.DeviceGroup(
        title="HCI Cluster", notes=top_notes, critical=cluster_critical, warning=0,
        count=len(nodes), count_label="hosts", children=children,
    )


def capture(cfg: Config) -> rg.ReportData:
    prom = Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)

    # Fetch each series exactly once and hand the same dicts to every consumer below — the
    # group builders, the dashboard tiles, and the down-count all describe the SAME snapshot
    # this way, rather than each re-querying Prometheus and risking a different instant.
    root_dc_metrics = _windows_host_metrics(prom, ROOT_DC_JOB, [d["target"] for d in ROOT_DCS])
    hci_nodes = _hci_cluster_nodes(prom)
    cluster_state = _hci_cluster_state(prom, HCI_PRIMARY_TARGET)

    ad = _active_directory_group(prom, root_dc_metrics)
    hci = _hci_cluster_group(hci_nodes, cluster_state)
    groups = [ad, hci]

    now = datetime.datetime.now()

    devices_total = len(ROOT_DCS) + max(1, len(hci_nodes))
    all_host_metrics = list(root_dc_metrics.values()) + list(hci_nodes.values())
    devices_down = sum(1 for m in all_host_metrics if not m.get("reachable"))
    mem_known = [m for m in all_host_metrics if m.get("mem_pct") is not None]
    all_disks = [d for m in all_host_metrics for d in m.get("disks", []) if d.get("used") is not None]

    cluster_nodes_down = sum(1 for _n, _s, up in (cluster_state["nodes"] if cluster_state else ()) if not up)
    cluster_nodes_total = len(cluster_state["nodes"]) if cluster_state else 0
    if cluster_state:
        r = cluster_state["resources"]
        resources_offline = r["offline"]
        resources_total = r["online"] + r["offline"] + r["failed"] + r["other"]
    else:
        resources_offline = resources_total = 0

    needs_attention = [
        rg.SummaryMetric("DEVICES DOWN", devices_down, f"down | {devices_total} total",
                         "red" if devices_down else "green"),
        rg.SummaryMetric("NODES DOWN", cluster_nodes_down, f"down | {cluster_nodes_total} total",
                         "red" if cluster_nodes_down else "green"),
        rg.SummaryMetric("STORAGE CRITICAL >=95%",
                         sum(1 for d in all_disks if d["used"] >= 95),
                         f"nodes | {len(all_disks)} total",
                         "red" if any(d["used"] >= 95 for d in all_disks) else "green"),
        rg.SummaryMetric("MEMORY CRITICAL >=95%",
                         sum(1 for m in mem_known if m["mem_pct"] >= 95),
                         f"nodes | {len(mem_known)} total",
                         "red" if any(m["mem_pct"] >= 95 for m in mem_known) else "green"),
    ]
    high_cpu = [m for m in all_host_metrics if m.get("cpu_pct") is not None and m["cpu_pct"] >= AMBER]
    high_mem = [m for m in mem_known if m["mem_pct"] >= AMBER]
    storage_capacity = [d for d in all_disks if d["used"] >= 85]
    watch_list = [
        rg.SummaryMetric("HIGH CPU", len(high_cpu), f"nodes | {len(all_host_metrics)} total",
                         "red" if any(m["cpu_pct"] >= RED for m in high_cpu) else "amber" if high_cpu else "green"),
        rg.SummaryMetric("HIGH MEMORY", len(high_mem), f"nodes | {len(mem_known)} total",
                         "red" if any(m["mem_pct"] >= RED for m in high_mem) else "amber" if high_mem else "green"),
        rg.SummaryMetric("STORAGE AT CAPACITY >=85%", len(storage_capacity), f"nodes | {len(all_disks)} total",
                         "red" if any(d["used"] >= 95 for d in storage_capacity) else "amber" if storage_capacity else "green"),
        rg.SummaryMetric("CLUSTER RESOURCES OFFLINE", resources_offline, f"resources | {resources_total} total",
                         "amber" if resources_offline else "green"),
    ]

    summary_notes = []
    if devices_down:
        summary_notes.append(rg.SummaryNote(
            "Devices", f"{devices_down} of {devices_total} monitored device(s) are not answering."))

    return rg.ReportData(
        generated_at=now.strftime("%d %b %Y  ·  %H:%M"),
        nodes_total=devices_total,
        cluster_count=1 if cluster_state else 0,
        cluster_nodes=max(1, len(hci_nodes)),
        cluster_resources_tb="—",     # no real cluster-storage-capacity metric exists yet
        last_checked=now.strftime("%H:%M"),
        needs_attention=needs_attention,
        watch_list=watch_list,
        summary_notes=summary_notes,
        groups=groups,
    )


def default_report_filename(theme: str = "dark", when: Optional[datetime.datetime] = None) -> str:
    """Named like the Network Admin Report's own Infrastructure Report download, so the two
    sit together in a folder (see webapp/reports/network.py's network_report_filename)."""
    when = when or datetime.datetime.now()
    return f"Infrastructure Report - {when:%Y-%m-%d %H%M} ({theme}).xlsx"


# ============================================================================ #
#  CLI
# ============================================================================ #
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the Infrastructure Report (Active Directory root domain "
                    "controllers + HCI Cluster) from Prometheus.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="path to config.ini")
    parser.add_argument("--prom", default=None, help="override Prometheus base URL")
    parser.add_argument("--out", default=None, help="override output xlsx path")
    parser.add_argument("--theme", default="dark", choices=("dark", "light"),
                        help="report palette (default: dark) — NOTE: the current renderer "
                             "ships one dark theme only; kept for CLI parity with the other "
                             "reports, has no effect until report_generator.py grows a light "
                             "palette")
    parser.add_argument("--author", default="Pride Moyo",
                        help="name written into each group's 'By' field")
    parser.add_argument("--summary", default=None, help="free text noted alongside Summary Notes")
    parser.add_argument("--stamp", action="store_true",
                        help="write a date/time-stamped filename instead of overwriting --out")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    if args.prom:
        cfg.prom = args.prom
    if args.out:
        cfg.out = args.out if Path(args.out).is_absolute() else str(HERE / args.out)
    if args.stamp:
        cfg.out = str(Path(cfg.out).parent / default_report_filename(args.theme))

    prom = Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    print(f"[*] connecting to Prometheus at {cfg.prom} ...")
    try:
        prom.ping()
    except Exception as exc:
        print(f"[!] Prometheus unreachable at {cfg.prom}: {exc}", file=sys.stderr)
        return 2

    print("[*] capturing metrics (Active Directory, HCI Cluster) ...")
    data = capture(cfg)

    def _sign(group: rg.DeviceGroup) -> None:
        group.signed_by = args.author
        for child in group.children:
            _sign(child)

    for g in data.groups:
        _sign(g)
    data.summary_signed_by = args.author
    if args.summary:
        data.summary_notes.append(rg.SummaryNote("Summary", args.summary))
    print(f"    devices={data.nodes_total} cluster_nodes={data.cluster_nodes} "
          f"groups={', '.join(g.title for g in data.groups)}")

    print(f"[*] rendering report -> {cfg.out} ...")
    rg.build_report(data, cfg.out)
    print(f"[+] saved -> {cfg.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
