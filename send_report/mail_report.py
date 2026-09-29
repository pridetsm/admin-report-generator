#!/usr/bin/env python3
"""
mail_report.py
==================================================================================
E-mail a brand-styled HTML snapshot of everything that needs attention, captured
LIVE and DIRECTLY from Prometheus — plus a link to the RBZ Monitoring Console webapp
where an admin can build and download the full report on demand.

The capture AND the analysis both go through generate_report.py (the same engine the
webapp and the xlsx use — same SERVICE_CHECKS, same topology loader, same Store, same
threshold/rollup functions), so the e-mail can never disagree with the report. Earlier
versions kept a self-contained duplicate of all of that "for a lightweight link-only
mode" and it quietly drifted more than once (missing systems, a different services
total, stale severity labels) — generate_report.py is now the ONLY place this logic
lives; mail_report.py is presentation (HTML/text templating + SMTP) on top of it.
--attach controls whether the xlsx itself gets built and attached — independent of
this, since the capture/analysis happens either way.

Pipeline:
    1. read settings from config.ini ([smtp] / [recipients] / [prometheus] / [grafana])
    2. capture live metrics via generate_report.py
    3. analyse -> unreachable / critical / warning / no-data findings (same engine helpers)
    4. render a responsive, brand-styled HTML e-mail (KPI strip + findings)
    5. build/attach the XLSX report (--attach or --report), if asked
    6. embed a link to the RBZ Monitoring Console webapp
    7. send via Office365 SMTP  (only with --send; otherwise DRY-RUN preview)

    Usage:
        python mail_report.py --to ops@rbz.co.zw,dba@rbz.co.zw          # dry-run preview
        python mail_report.py --to ops@rbz.co.zw --send                 # actually send
        python mail_report.py --attach --send                           # + generate & attach the xlsx
        python mail_report.py --attach --theme light --author "P. Moyo" --send
        python mail_report.py --report "System Admin Report.xlsx" --send # attach an existing xlsx

Requires: openpyxl, PyYAML, Pillow — generate_report.py is a hard dependency now, not an
optional extra (see requirements.txt).  Python 3.8+.
==================================================================================
"""
from __future__ import annotations

import argparse
import configparser
import datetime
import html
import math
import os
import smtplib
import ssl
import sys
import tempfile
import time
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path
from typing import List, Optional, Tuple, Union

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.ini"

sys.path.insert(0, str(HERE))          # works no matter where this is invoked from
import generate_report as engine       # the ONLY capture/analysis engine — see module docstring

# RBZ Monitoring Console webapp — admins open this to build the full report on demand.
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
#  CONFIGURATION  (SMTP/recipients only — Prometheus/topology config is engine.load_config)
# ============================================================================ #
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


# Store/Component/Service/System are generate_report.py's own dataclasses — every function
# below takes/returns those (via `engine.load_topology`, `engine.capture`, etc.), there is no
# local copy to keep in step anymore.


# ============================================================================ #
#  ANALYSIS  — all pressure/rollup/reachability metrics come from generate_report.py
#  (engine.disk_high, engine.disk_near_full, engine.ram_pressure, engine.cpu_pressure,
#  engine.cert_rollup, engine.cert_monitored, engine.is_unreachable, engine.backup_missing,
#  engine.backup_tracked_hosts, engine.backup_untracked, engine.backup_untracked_unexplained,
#  engine.backup_missing_band,
#  engine.total_services, engine.services_down) — this module only buckets them into the
#  four e-mail finding lists below.
# ============================================================================ #
Finding = Tuple[str, str, str, str]   # (system, component, item, detail)


def analyse(store, systems, cfg=None):
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
            if engine.is_unreachable(store, comp.instance):
                unreach.append((sysm.name, comp.label, "device",
                                "exporter unreachable — device down / network?"))
                continue            # device is down: skip its metric-level "no data"
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
    miss = engine.backup_missing(store, systems)
    bucket = warning if engine.backup_missing_band(len(miss)) == "warn" else critical
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
            f'<td style="padding:7px 12px;border-bottom:1px solid #eef0f2;color:#1f2733;">{html.escape(item)}</td>'
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


def _kpi(label: str, value: str, color: str, font_family: str = "") -> str:
    """`font_family` (2026-09-14, on request: "return the smoth font that you had in your
    original design but only the font") -- empty (every existing caller since 2026-09-17,
    when the whole template's base font became Times New Roman on request) means inherit the
    surrounding table's own font, byte-identical to before; a caller wanting a DIFFERENT font
    just for the KPI numbers passes its own font_family -- see render_html's own `number_font`
    param, which threads this through without touching any of its many _kpi()/_kpi_panel() call
    sites individually."""
    tint = TINT.get(color, NAVY_T)
    font_style = f"font-family:{font_family};" if font_family else ""
    return (
        '<td align="center" valign="top" style="padding:4px;">'
        f'<div style="background:{tint};border-radius:8px;padding:13px 6px;">'
        f'<div style="font-size:17px;font-weight:700;color:{color};line-height:1;{font_style}">{html.escape(value)}</div>'
        f'<div style="font-size:10px;letter-spacing:.4px;color:{MUTED};text-transform:uppercase;margin-top:6px;">{label}</div>'
        "</div></td>"
    )


def _kpi_panel(title: str, cols, color: str, font_family: str = "") -> str:
    """A titled KPI tile split into sub-columns: cols = [(sublabel, value), ...].
    `font_family` -- same as _kpi's own, see that function's own docstring."""
    tint = TINT.get(color, NAVY_T)
    font_style = f"font-family:{font_family};" if font_family else ""
    def half(v: int, lbl: str, border: str) -> str:
        return (
            f'<td align="center" valign="top" style="padding:0 8px;{border}">'
            f'<div style="font-size:17px;font-weight:700;color:{color};line-height:1;{font_style}">{v}</div>'
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
        f'<div style="font-size:15px;font-weight:700;color:{CRITICAL};">&#9888;&nbsp; IMMINENT &mdash; {len(unreach)} component(s) unreachable</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">Prometheus can no longer scrape these targets &mdash; '
        "the device is down, the exporter has stopped, or there is a network / connectivity issue. "
        "<b>Treat as urgent.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _services_down_block(store, systems) -> str:
    """A prominent callout listing every DOWN service/link -- the named list behind the
    overview SERVICES DOWN tile, which until now only ever showed a bare count."""
    down = engine.services_down_detail(store, systems)
    if not down:
        return ""
    bysys: dict = {}
    for s, name in down:
        bysys.setdefault(s, []).append(name)
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(s)}</b>'
        f'<span style="color:#555;"> &mdash; {html.escape(", ".join(sorted(names)))}</span></div>'
        for s, names in sorted(bysys.items())
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{RED_T};border-left:4px solid {RED};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{RED};">&#9888;&nbsp; CRITICAL &mdash; '
        f'{len(down)} service(s)/link(s) down across {len(bysys)} system(s)</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">These checks or web links are '
        "currently reporting down. <b>Confirm whether the outage is real or the check itself needs "
        "attention, then restore service.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _nearfull_disks_render(nearfull, threshold: int) -> str:
    """The actual banner markup for "volumes almost full" -- pulled out of
    _disk_nearfull_block (2026-09-17, on request: "copy and reuse one of the banner templates
    from the system admin report's mailing template") so a SECOND estate (Cluster Health, a
    completely different engine/shape from generate_report.py's own Store/System) can reuse
    the exact same banner instead of a hand-copied duplicate -- one template, two callers, see
    _cluster_storage_critical_block below. `nearfull` is the same (system, host, mount, used%)
    shape engine.disk_near_full returns; `threshold` is just for the headline/body wording,
    since the two callers filter at different %'s (AD/System Admin's own CRIT=90 vs Cluster
    Health's own Storage Critical tile at >=95 -- see that caller's own comment)."""
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
        f'<div style="font-size:15px;font-weight:700;color:{RED};">&#9888;&nbsp; CRITICAL &mdash; '
        f'{len(nearfull)} disk(s) near-full on {len(byhost)} device(s)</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">These volumes are almost full '
        f'(&#8805;{threshold}%) &mdash; an imminent outage that can take the service down. '
        "<b>Free space or extend the disk now.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _disk_nearfull_block(store, systems) -> str:
    """A prominent callout listing the volumes that are almost full (>= CRIT%)."""
    return _nearfull_disks_render(engine.disk_near_full(store, systems, CRIT), CRIT)


def _cluster_storage_critical_block(nearfull) -> str:
    """Cluster Health's own equivalent of _disk_nearfull_block, same banner template
    (2026-09-17, on request: the "Storage critical" tile had a count but no banner naming
    which disk/node it actually was -- "copy and reuse one of the banner templates from the
    system admin report's mailing template"). `nearfull` is built by the caller from
    network.py's own FlagVM disk-high flags (category="disk", text ending "at N% used"),
    filtered to >=95% to match the Storage critical tile's OWN threshold exactly -- reusing
    AD/System Admin's own CRIT=90 here would list MORE disks than that tile claims, a mismatch
    between the banner and the number it's meant to explain, not a fix for one."""
    return _nearfull_disks_render(nearfull, 95)


def _backup_missing_block(store, systems) -> str:
    """A prominent callout listing tracked hosts with no fresh backup — a data-loss risk,
    not a metric out of range: if the host is lost today, there is nothing recent to restore
    from. Untracked hosts never appear here (see engine.backup_missing's own docstring)."""
    miss = engine.backup_missing(store, systems)
    if not miss:
        return ""
    bysys: dict = {}
    for s, lbl, reason in miss:
        bysys.setdefault(s, []).append(f"{lbl} ({reason})")
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(s)}</b>'
        f'<span style="color:#555;"> &mdash; {html.escape(", ".join(v))}</span></div>'
        for s, v in bysys.items()
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{RED_T};border-left:4px solid {RED};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{RED};">&#9888;&nbsp; CRITICAL &mdash; '
        f'{len(miss)} device(s) missing a fresh backup</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">These devices run the backup check '
        "but have nothing fresh within policy &mdash; if the device is lost today, there is no recent "
        "backup to restore from. <b>Confirm the backup job and re-run it.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _backups_untracked_block(store, systems) -> str:
    """A callout listing systems where NOT ONE host runs the backup check at all -- a
    monitoring blind spot, not an active failure: nothing here is judged missing, since
    nothing is being watched to judge. Excludes engine.BACKUP_UNTRACKED_EXEMPT systems (a
    stated reason, not an unexplained gap) -- matches the xlsx's own banner."""
    untracked = engine.backup_untracked_unexplained(store, systems)
    if not untracked:
        return ""
    # one row per system, matching every other banner -- not all names crammed into a
    # single "Systems" row.
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(s)}</b>'
        f'<span style="color:#555;"> &mdash; no backup check on any device</span></div>'
        for s in sorted(untracked)
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{AMBER_T};border-left:4px solid {AMBER};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; WARNING &mdash; '
        f'{len(untracked)} system(s) with no backup check at all</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">No device on these systems reports '
        "the backup check, so nothing here can be judged missing or fresh &mdash; it simply isn't being "
        "watched. <b>Add the check before this becomes a real gap nobody caught.</b></div>"
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
        headline = "WARNING &mdash; COB &mdash; could not be calculated, T24 database is unreachable"
        detail = ("The T24 database component is unreachable, so COB time could not be "
                   "calculated for the previous day &mdash; this is not evidence that COB "
                   "itself failed to run. <b>Restore connectivity to the T24 database first, "
                   "then re-check COB.</b>")
    else:
        headline = "WARNING &mdash; COB &mdash; close-of-business may not have run yesterday"
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
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; WARNING '
        "&mdash; SWIFT &mdash; could not be calculated, T24 application is down</div>"
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 0;">The T24 application component '
        "is down, so SWIFT transaction count could not be calculated for the current period "
        "&mdash; this is not evidence that no SWIFT transactions occurred. "
        "<b>Restore the T24 application first, then re-check SWIFT.</b></div>"
        "</div></td></tr>"
    )


def _ldap_block(store, systems) -> str:
    """IMMINENT callout when the LDAP / auth service is down — users can't sign in to the
       dependent systems. Mirrors the xlsx + the webapp's highest-priority banner.
       Only fires on a positive 'down' reading; an absent probe is never alarmed on."""
    if getattr(store, "ldap_up", None) is not False:      # True (up) or None (not monitored)
        return ""
    present = ([s.name for s in systems if s.name in engine.LDAP_DEPENDENTS]
               or sorted(engine.LDAP_DEPENDENTS))
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{RED_T};border-left:4px solid {CRITICAL};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{CRITICAL};">&#9888;&nbsp; IMMINENT &mdash; '
        f"LDAP / auth service down &mdash; {len(present)} dependent system(s) affected</div>"
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 0;">Users cannot sign in to: '
        f'<b>{html.escape(", ".join(present))}</b>. <b>Treat as urgent.</b></div>'
        "</div></td></tr>"
    )


def _stale_metrics_block(stale: list) -> str:
    """WARNING callout when one or more of the data sources this report's own estate depends
    on have gone stale (2026-09-21, on request: "stale metrics warning not showing up in a
    warning banner in mailing template") -- reports.system_alerts' FreshnessCheck/
    SystemAlertFinding is a COMPLETELY SEPARATE notification family (its own e-mail, own
    purple styling, own reminder schedule -- see that module's own docstring) that never fed
    into this report before; a reader here had no way to know a number they were looking at
    might be frozen at an old reading unless they separately noticed and read that other
    e-mail too. This surfaces the SAME underlying finding here as well, not a second
    computation of it -- the caller queries SystemAlertFinding directly and passes through
    already-open findings scoped to whatever systems THIS report covers.

    `stale`: [(label, detail), ...] -- label is "system · check name" (or a device name for a
    network.py-sourced relay staleness flag, see below), detail is an already-human-readable
    line the CALLER formats (2026-09-21, broadened on request: an identical-shaped
    win_stale_but_pinging flag -- "RBZHQ-DC-204 is reachable (ping OK), but its own metrics-
    collection script has not reported in 3.8d via RBZHQ-DC-203" -- turned out to be the SAME
    "a data source has gone stale, and this report never said so" gap for a SECOND, unrelated
    staleness mechanism: network.py's own relay-based reachability for DC-204-shaped devices
    with no windows_exporter of their own (see that module's own _windows_device_flags), a
    completely different code path from FreshnessCheck/SystemAlertFinding but the identical
    complaint from a reader's perspective. Pushing formatting to the caller, rather than this
    function assuming every entry is a raw FreshnessCheck age in seconds, is what lets both
    sources share one banner without one of them needing to be shoehorned into the other's
    shape). Amber, not red -- this says "some of what follows may be out of date", not
    "something is confirmed broken"; the underlying stale checker/exporter is its own,
    separately-notified (or, for the relay case, separately-flagged) problem."""
    if not stale:
        return ""
    rows = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(label)}</b>'
        f'<span style="color:#555;"> &mdash; {html.escape(detail)}</span></div>'
        for label, detail in stale
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{AMBER_T};border-left:4px solid {AMBER};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; WARNING &mdash; '
        f'{len(stale)} metrics source(s) reporting stale data</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">Some readings in this report may '
        "be frozen at an old value rather than current until the checker/exporter behind them is "
        "restored. <b>See System Alerts for detail.</b></div>"
        f"{rows}</div></td></tr>"
    )


def _cert_block(store) -> str:
    """SSL certificate rollup callout — RED when anything has already expired, AMBER when
       certs are inside the 30-day horizon. This is the banner the webapp shows and the
       e-mail was missing, which is why an amber banner never appeared while only certs
       were in trouble (the individual certs still list under Critical/Warning below)."""
    expired, expiring = engine.cert_rollup(store)
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
        f'{"CRITICAL" if red else "WARNING"} &mdash; SSL certs &mdash; {", ".join(bits)}</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">'
        + ("An expired certificate breaks HTTPS for users. <b>Renew now.</b>" if red else
           "These certificates renew soon. <b>Schedule the renewal before they lapse.</b>")
        + f"</div>{lines}</div></td></tr>"
    )


def _http_links_block(store, systems) -> str:
    """A callout listing monitored web links still on plain HTTP -- the named list behind
    the WEB ENCRYPTION tile's http count. Warning, not critical: an unencrypted link isn't
    down, it's a standing exposure (credentials/session data readable in transit)."""
    http_links = engine.http_links_detail(store, systems)
    if not http_links:
        return ""
    bysys: dict = {}
    for s, name in http_links:
        bysys.setdefault(s, []).append(name)
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(s)}</b>'
        f'<span style="color:#555;"> &mdash; {html.escape(", ".join(sorted(names)))}</span></div>'
        for s, names in sorted(bysys.items())
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{AMBER_T};border-left:4px solid {AMBER};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; WARNING &mdash; '
        f'{len(http_links)} link(s) not using HTTPS</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">These web links are reachable '
        "over plain HTTP &mdash; anything sent to them (including credentials) travels unencrypted. "
        "<b>Move them to HTTPS.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _folder_over_expected_block(store, systems) -> str:
    """A callout listing watched folders (e.g. T24 Log File) over their expected size --
    see the Folders table on the owning system's card. Always warning, never critical, no
    matter how far over expected the folder grows (see FOLDER_EXPECTED_GB's docstring):
    this is "keep an eye on it", not an outage."""
    over_folders = engine.folder_over_expected_detail(store, systems)
    if not over_folders:
        return ""
    bysys: dict = {}
    for s, name, expected, actual in over_folders:
        bysys.setdefault(s, []).append(f"{name} ({actual:.1f} GB, expected {expected:.1f} GB)")
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(s)}</b>'
        f'<span style="color:#555;"> &mdash; {html.escape(", ".join(names))}</span></div>'
        for s, names in sorted(bysys.items())
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{AMBER_T};border-left:4px solid {AMBER};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; WARNING &mdash; '
        f'{len(over_folders)} folder(s) on {len(bysys)} system(s) over expected size</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">These watched folders have grown '
        "past their expected size &mdash; worth a look (e.g. confirm rotation/archival is running), "
        "but not itself an outage.</div>"
        f"{lines}</div></td></tr>"
    )


def _attachment_block(mail) -> str:
    """Callout naming the XLSX report(s) attached to this e-mail. Only rendered when at least
       one is actually attached — it sits ABOVE the Report Generator call-to-action, which
       stays either way (the attachment is today's snapshot, the link builds one on demand).

       `mail["attachments"]` (2026-09-17, on request: the scheduled Active Directory Report
       send now attaches a fresh Cluster Health Report alongside it) is the general shape --
       a list of {"name", "theme", "label", "detail"} dicts, one callout per attached file, so
       a second (or third) report describes itself instead of inheriting the first one's text.
       Falls back to the original single `attachment_name`/`attachment_theme` keys, describing
       it as the System Admin Report exactly as before -- every existing caller (System Admin
       Report, the Reporting test-fire tools) sets only those two keys and never `attachments`,
       so this produces byte-identical HTML for all of them."""
    attachments = mail.get("attachments")
    if not attachments:
        name = mail.get("attachment_name")
        if not name:
            return ""
        attachments = [{
            "name": name, "theme": mail.get("attachment_theme"),
            "label": "the complete System Admin Report",
            "detail": ("(Services / Memory / Disk / Backups per system, plus web links "
                      "and SSL certs)"),
        }]
    blocks = []
    for a in attachments:
        theme = a.get("theme")
        tag = f" &nbsp;&middot;&nbsp; {html.escape(theme)} theme" if theme else ""
        blocks.append(
            f'<div style="background:{GREEN_T};border-left:4px solid {GREEN};border-radius:4px;'
            f'padding:13px 16px;{"margin-top:10px;" if blocks else ""}">'
            f'<div style="font-size:14px;font-weight:700;color:{GREEN};margin-bottom:5px;">'
            "&#128206;&nbsp; The full report is attached</div>"
            f'<div style="font-size:13px;color:#1f2733;line-height:1.6;">'
            f'<b>{html.escape(a["name"])}</b>{tag} &mdash; {a.get("label", "the full report")} '
            f'{a.get("detail", "")} for the same snapshot summarised above.</div>'
            "</div>")
    return f'<tr><td style="padding:20px 24px 0;">{"".join(blocks)}</td></tr>'


def _report_generator_cta(mail) -> str:
    """Call-to-action block: link admins to the RBZ Monitoring Console webapp to build a
       report on demand — annotated, themed and scoped to the systems they pick. Always
       shown, attachment or not: the attachment is the unannotated daily snapshot."""
    url = html.escape(mail.get("report_url") or REPORT_GENERATOR_URL, quote=True)
    link = (f'<a href="{url}" style="color:{NAVY};font-weight:700;text-decoration:underline;">'
            "RBZ Monitoring Console</a>")
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
        "&#9658;&nbsp; RBZ Monitoring Console</a></div>"
        f'<div style="font-size:12px;color:{MUTED};margin-top:9px;">Or paste this address into your browser: {url}</div>'
        "</div></td></tr>"
    )


def render_html(store, systems, unreach, crit, warn, nodata, mail,
                title: str = "SYSTEM ADMIN REPORT", system_label: str = "Systems",
                show_backups: bool = True, show_web_links: bool = True,
                show_swift: bool = True, show_cob: bool = True, show_certs: bool = True,
                show_queues: bool = True, number_font: str = "",
                extra_estate: Optional[dict] = None,
                stale_metrics: Optional[list] = None) -> str:
    """`title` (2026-09-14, on request: "create the data model for domain controllers and
    model it after the systems domain" -- once the AD estate became a real, capturable
    System list via load_topology(scope="ad"), this became the ONE hardcoded thing left
    stopping this exact function from also rendering the Active Directory Report's own
    e-mail unmodified) -- same "one parameter, default unchanged" fix build_infrastructure_
    report's own report_title already used for the identical problem (network.py sharing one
    renderer between the Infrastructure Admin and Active Directory Reports). Every existing
    caller keeps getting "SYSTEM ADMIN REPORT" with zero code changes; a new caller passes
    its own.

    The five params below are the SAME "default preserves every existing caller exactly, new
    caller opts in" shape as `title`, added the same day once the Active Directory Report's
    own e-mail (built from this same function, see generate_active_directory_report) turned
    out to carry several tiles/callouts that only ever mean something for the business
    estate -- none of these are things the System Admin Report itself should ever lose:
      system_label   -- "Systems" (unchanged) vs. "Devices" (on request: "rename systems to
          devices") for the glance tile only; nothing else in this function says "system".
      show_backups   -- gates "Missing backups"/"Backup tracking" KPIs and both backup
          finding blocks (on request: "remove... backups, not checked for these systems" --
          AD/DC hosts have no backup_file textfile check configured, so these always render
          a meaningless zero rather than a real finding).
      show_web_links -- gates "Web encryption" KPI and the HTTP/HTTPS finding block (on
          request: "no https or http check either" -- same reasoning, no web links are
          monitored on domain controllers).
      show_swift     -- gates the "SWIFT txns" glance KPI and its own finding block (on
          request: "swift transactions also useless in this report, deactivate and remove
          that tile" -- SWIFT throughput has nothing to do with Active Directory).
      show_cob       -- gates the "COB &middot; T24" glance KPI, its own finding block, and
          the "COB may not have run" banner headline (2026-09-17, on request: "cob time panel
          should also be removed from this mailing report" -- same reasoning as show_swift,
          T24 close-of-business has nothing to do with Active Directory either).
      show_certs     -- gates the "Expired certs" KPI and its own finding block (2026-09-17,
          on request: "remove expired certs tile" -- same reasoning again: SSL certificate
          expiry is a web-endpoint concept, domain controllers don't serve any of the sites
          this tracks).
      show_queues    -- gates the "Queue folders drained" KPI (2026-09-17, on request:
          "remove folder drainage tile" -- T24's payment/interface message queues are a
          business-system concept, meaningless for Active Directory or an HCI/S2D cluster).
      number_font    -- CSS font-family for every KPI tile's own big number, overriding the
          template's own base font just for those (originally added on request: "return the
          smoth font that you had in your original design but only the font" -- the AD
          e-mail's own first draft used Georgia for these; restored as JUST the font, not the
          rest of that draft's now-rejected reinterpretation. No longer used by any caller as
          of 2026-09-17, when the base font itself became Times New Roman on request -- kept
          as a hook, not removed, in case a future caller wants one tile's numbers to differ
          from the rest again). Empty (every existing caller) inherits the surrounding base
          font, unchanged.
      stale_metrics  -- [(label, detail), ...], see _stale_metrics_block's own docstring for
          the full shape and history (2026-09-21, on request: "stale metrics warning not
          showing up in a warning banner in mailing template", then broadened the same day for
          a second, unrelated staleness mechanism). None (every existing caller) renders
          nothing new, same as every other opt-in parameter here.
      extra_estate   -- {"cluster_count", "cluster_nodes", "total_devices"} (2026-09-17, on
          request: "we have 8 nodes which essentially are devices from the cluster health
          report" -- once the scheduled Active Directory Report started attaching a fresh
          Cluster Health Report alongside itself, this e-mail's own AT A GLANCE tiles still
          only ever counted the AD estate, silently leaving the second report's 8 nodes out of
          every device/host count). None (every existing caller) leaves the glance row and
          every "Total" exactly as before -- a caller covering a second estate passes:
          cluster_count/cluster_nodes = CLUSTER devices/nodes only (network.py
          len(snapshot._hci_nodes) for cluster_nodes, a count of `cluster: True` devices for
          cluster_count -- NOT len(snapshot.systems)/snapshot.hosts_count, which also count
          any non-cluster device the same estate might carry, see total_devices' own note
          below for why that distinction turned out to matter), matching exactly what the
          Cluster Health Report's own "Cluster count"/"Cluster nodes" glance tiles show, so the
          two reports can never disagree on their own numbers; total_devices = EVERY device in
          that estate regardless of shape (snapshot.hosts_count, cluster nodes AND any
          standalone device both), for combined_hosts below. Swaps the "Hosts" glance tile for
          two new ones ("Cluster count", "Cluster nodes") rather than just adding them --
          "Hosts" on its own would undercount once a second estate exists, and a bare rename
          would misdescribe the AD side's own real hosts -- and folds total_devices into the
          `system_label` glance tile's own value and the "Total" of every other glance-level
          tile whose Total is a device/host count (Unreachable components, High CPU usage,
          High RAM usage) so those genuinely reflect the WHOLE estate this e-mail now
          represents, not only the AD half of it.

          cluster_count/cluster_nodes vs. total_devices were the SAME number until 2026-09-17,
          when Standalone Servers joined the same infra estate as the clusters ("are you sure
          device count and component count are not the same thing here[,] last i checked these
          arnt systems that have multiple hosts or devices each") -- each standalone server is
          one device with no sub-nodes, so it was never a cluster NODE, but len(snapshot.
          systems)/snapshot.hosts_count (what cluster_count/cluster_nodes used to be computed
          from directly) count it anyway, inflating "Cluster count"/"Cluster nodes" past their
          own true numbers (was showing 6/13 once 3 standalone servers existed alongside 3
          real clusters/10 real nodes) while total_devices genuinely needed the same 3 counted.
          Two separate keys now, computed separately by the caller, so a future non-cluster
          addition to this estate can't silently reintroduce the same conflation.

          Tiles keyed to a different concept entirely (Services down, Expired certs, Queue folders, High
          disk usage) are untouched -- their totals were never a host count to begin with.

          A third optional key, "extra_down" (2026-09-17, "unreachable components and
          components down can also be combined into a single tile... the philosophy is
          simple[:] if one tile can represent both reports' findings then have one tile") --
          the Cluster Health estate's own "Components down" count, folded straight into this
          function's "Unreachable components" numerator (its Total was already combined_hosts
          above, i.e. already the LARGER, whole-estate total -- "the number with the highest
          total... gives more coverage" is what combined_hosts already is, so merging the
          numerator into that same tile rather than keeping "Components down" as a second,
          narrower-Total tile follows through on the same idea). The caller drops "Components
          down" out of its own immediate_tiles list when passing extra_down, so it isn't shown
          twice under two different names.

          Two more, "extra_cpu"/"extra_ram" (2026-09-17, corrected the same day: "cpu and ram
          are different metrics they still need different tiles i meant one tile for each
          metric[,] remember there where multiple ram tiles" -- the actual duplication was the
          Cluster Health estate's own "High CPU"/"High memory" watch tiles restating the SAME
          metric this function's "High CPU usage"/"High RAM usage" tiles already track, just
          over a different slice of the estate -- fold into THOSE tiles' own numerators
          exactly like extra_down does for Unreachable components, one tile per metric, never
          combining two different metrics into one). The caller drops "High CPU"/"High memory"
          out of its own watch_tiles list the same way it drops "Components down".

          Two more still, "extra_disk"/"extra_disk_total" (2026-09-17, "what about high disk
          usage and storage critical tiles[,] can't they be merged" -- originally merged
          Cluster Health's own WATCH-tier "Storage at capacity" tile (>=85%) into this
          function's own "High disk usage" tile, into BOTH the numerator and the Total this
          time since disk counts -- unlike device counts -- were never folded into
          combined_hosts. That source tile is GONE as of 2026-09-18 though (on request:
          "storage capacity and storage critical are the same metric... combine every
          occurrence and remove this redundancy" -- it was computed as storage_amber +
          storage_critical, i.e. ALWAYS including whatever Cluster Health's own separate
          IMMEDIATE-band "Storage critical" tile (>=95%) already counted, unlike every other
          watch/immediate pair here which stays mutually exclusive -- see network._infra_
          overview's own comment on the removal). extra_disk/extra_disk_total now read
          "Storage critical" directly instead -- so "High disk usage" here reflects the
          stricter >=95% threshold, not the old >=85% one. "Storage critical" ALSO still gets
          its own dedicated red banner (storage_critical_items, below) and is dropped from
          immediate_tiles' own generic "others" list for the same reason -- it would otherwise
          render a third time.

          One more, "storage_critical_items" (2026-09-17, on request: "the report says there
          is critical storage usage out of 31 disks[,] but no critical banner to tell us
          exactly whats going on[,] copy and reuse one of the banner templates from the system
          admin report's mailing template" -- the "Storage critical" tile had a count with no
          detail anywhere naming which disk). A list of (system, host, mount, used%) tuples,
          the SAME shape engine.disk_near_full returns, rendered through
          _cluster_storage_critical_block -- literally the same banner template
          _disk_nearfull_block already uses (_nearfull_disks_render, factored out for this),
          not a hand-copied second one. Filtered by the caller to >=95% specifically, to match
          the Storage critical tile's own threshold exactly (AD/System Admin's own CRIT=90
          would list more disks than that tile claims).

          Also takes two optional keys, "immediate_tiles" and "watch_tiles" (2026-09-17, on
          request: "try to add tiles more useful to these two reports[,] storage critical for
          example, they may be others" -- once Queue folders drained was removed as the last
          AD-irrelevant tile, this e-mail's immediate/watch bands had room, and the Cluster
          Health estate already computes several genuinely relevant ones of its own that
          simply weren't surfaced here). Each is a list of {"label", "value", "sub", "state"}
          dicts in EXACTLY the shape network.py's own _infra_overview/_network_overview
          already build for their "immediate"/"watch" bands -- "value" and "sub" are each a
          "X | Y" pair (e.g. value="3 | 8", sub="down | total"), "state" one of bad/warn/good/
          info -- so a caller passes those overview dicts' own tiles straight through with no
          reshaping, the same "can never disagree with the Cluster Health Report's own
          numbers" guarantee cluster_count/cluster_nodes above already gives. Rendered as
          ADDITIONAL two-column panels appended after this function's own AD-side tiles, not a
          replacement for them -- the two estates' findings are both worth showing, not a
          choice between them.
    Commented out, not deleted, wherever a block simply isn't called under these flags -- "we
    may need them as the report grows" (on request) once AD backup checks/web links exist."""
    today = datetime.date.today().strftime("%d %B %Y")
    prepared_by = (f" &nbsp;&middot;&nbsp; prepared by {html.escape(mail['author'])}"
                   if mail.get("author") else "")
    hosts = sum(len(s.components) for s in systems)
    # total + down both span BOTH service classes (PromQL checks + web links) — single source
    # of truth in generate_report.py, so this KPI never disagrees with the xlsx or the webapp.
    nsvc = engine.total_services(store)
    down = engine.services_down(store)
    thr = int(mail.get("elevated", 85))                       # shared "over N%" level (config.ini)
    ram_hosts, _ = engine.ram_pressure(store, systems, thr, thr)
    cpu_hosts, _ = engine.cpu_pressure(store, systems, thr, thr)
    nmiss = len(engine.backup_missing(store, systems))
    miss_band = engine.backup_missing_band(nmiss)
    miss_color = GREEN if miss_band == "good" else (AMBER if miss_band == "warn" else RED)
    cob_missing = store.cob is None or (isinstance(store.cob, float) and math.isnan(store.cob))
    cob = "N/A" if cob_missing else f"{store.cob/60:.1f} min"
    cob_alert = show_cob and cob_missing and datetime.date.today().weekday() != 0   # 0 = Monday (Sunday: no COB)
    swift = f"{store.swift:.0f}" if store.swift is not None else "N/A"
    cert_expired, _cert_expiring = engine.cert_rollup(store)
    n_https = sum(1 for u in store.links if u.lower().startswith("https"))
    n_http = sum(1 for u in store.links if u.lower().startswith("http://"))
    web_color = GREEN if n_http == 0 else (RED if n_http > n_https else AMBER)

    # the closing note points at whichever full breakdown this e-mail actually carries --
    # pluralized once there's a real second one to name (see _attachment_block's own docstring)
    _n_attached = len(mail.get("attachments") or ([1] if mail.get("attachment_name") else []))
    full_breakdown = ("see the attached reports" if _n_attached > 1 else
                      "see the attached report" if _n_attached == 1 else
                      "generate the report from the RBZ Monitoring Console above")

    if unreach:
        banner_bg, banner_fg = RED_T, CRITICAL
        headline = f"IMMINENT — {len(unreach)} component(s) UNREACHABLE — possible device / network outage"
    elif crit:
        banner_bg, banner_fg, headline = RED_T, RED, f"CRITICAL — {len(crit)} item(s) need immediate attention"
    elif warn or cob_alert:
        banner_bg, banner_fg = AMBER_T, AMBER
        headline = (f"WARNING — {len(warn)} item(s) to keep an eye on" if warn
                    else "WARNING — COB may not have run yesterday — check T24")
    else:
        banner_bg, banner_fg, headline = GREEN_T, GREEN, "All monitored systems are healthy"

    # Local wrappers baking number_font into every _kpi()/_kpi_panel() call below without
    # touching each one's own arguments -- see render_html's own docstring on number_font.
    def _kpi_(label, value, color):
        return _kpi(label, value, color, font_family=number_font)
    def _kpi_panel_(panel_title, cols, color):
        return _kpi_panel(panel_title, cols, color, font_family=number_font)

    linux_pct, win_pct = engine.platform_host_pcts(systems)
    # See render_html's own docstring on extra_estate for why combined_hosts folds
    # total_devices into every device/host-count Total below, INCLUDING the system_label
    # glance tile itself (2026-09-17, on request: "the device tile currently says 3 devices
    # which is wrong considering there are 8 cluster nodes which are devices" -- len(systems)
    # was counting AD's own TIER groups, not devices at all, so it undercounted the instant a
    # second estate existed; combined_hosts is the real, whole-estate device count).
    #
    # total_devices, NOT cluster_nodes, for combined_hosts (fixed 2026-09-17, on request: "are
    # you sure device count and component count are not the same thing here[,] last i checked
    # these arnt systems that have multiple hosts or devices each" -- confirmed live: once
    # Standalone Servers joined the same infra estate as the clusters, cluster_nodes (meant to
    # be CLUSTER nodes only, for the "Cluster nodes" glance tile below) and total_devices
    # (meant to be EVERY device regardless of shape, for combined_hosts/Devices) had been the
    # exact same number by accident -- correct only while every infra device happened to be a
    # cluster. Standalone servers each stayed one device but were getting counted as if they
    # were cluster nodes too, inflating "Cluster count"/"Cluster nodes" past their own real
    # numbers (was showing 6/13, really 3/10) while total_devices needed them counted
    # regardless. Two separate keys now -- see render_html's own docstring.
    combined_hosts = hosts + (extra_estate["total_devices"] if extra_estate else 0)
    static_kpis_list = [_kpi_(system_label, str(combined_hosts if extra_estate else len(systems)), NAVY)]
    if extra_estate:
        static_kpis_list.append(_kpi_("Cluster count", str(extra_estate["cluster_count"]), NAVY))
        static_kpis_list.append(_kpi_("Cluster nodes", str(extra_estate["cluster_nodes"]), NAVY))
    else:
        static_kpis_list.append(_kpi_("Devices", str(hosts), NAVY))
    static_kpis_list += [
        _kpi_("Linux | Windows", f"{linux_pct}% | {win_pct}%", NAVY),
        _kpi_("Services", str(nsvc), NAVY),
    ]
    if show_swift:
        static_kpis_list.append(_kpi_("SWIFT txns", swift, NAVY))
    if show_cob:
        static_kpis_list.append(_kpi_("COB &middot; T24", cob, NAVY))
    static_kpis = "".join(static_kpis_list)
    # Queue folders drained (2026-09-08, on request) -- T24's payment/interface message queues
    # (see engine.Store.queue_folders' own docstring), scoped to whichever systems THIS e-mail
    # actually covers, the same "don't leak systems outside the scope" discipline every other
    # KPI here already follows -- store.queue_folders itself is captured unconditionally from
    # Prometheus, so this filters it down here rather than showing e.g. Temenos's own queues on
    # an RTGS-only run.
    sysnames_lower = {s.name.lower() for s in systems}
    queue_entries = [e for sn, entries in store.queue_folders.items()
                    if sn in sysnames_lower for e in entries]
    n_queue_folders = len(queue_entries)
    n_queue_drained = sum(1 for (_, _, waiting, _) in queue_entries if waiting <= 0)

    immediate_kpis = []
    if show_backups:
        # missing out of TRACKED hosts (an untracked host isn't judged either way — see the
        # separate Backup tracking tile for those).
        immediate_kpis.append(_kpi_panel_(
            "Missing backups", [("Missing", nmiss), ("Tracked", engine.backup_tracked_hosts(store, systems))],
            miss_color))
    # "Components down" folded in here, not shown as its own tile -- see render_html's own
    # docstring on extra_estate's "extra_down".
    total_unreachable = len(unreach) + (extra_estate.get("extra_down", 0) if extra_estate else 0)
    immediate_kpis += [
        # unreachable/down out of the TOTAL we monitor, so the count never reads as if fewer
        # components/services exist just because some are currently failing.
        _kpi_panel_("Unreachable components", [("Unreachable", total_unreachable), ("Total", combined_hosts)],
                    CRITICAL if total_unreachable else GREEN),
        _kpi_panel_("Services down", [("Down", down), ("Total", nsvc)],
                    RED if down else GREEN),
    ]
    if show_certs:
        immediate_kpis.append(
            _kpi_panel_("Expired certs", [("Expired", len(cert_expired)), ("Total", engine.cert_monitored(store))],
                       RED if cert_expired else GREEN))
    if show_queues:
        immediate_kpis.append(
            # "Drained", not "Stuck", out of Total -- the positive framing every affected-out-
            # of-total tile here already uses. AMBER, not RED: the finer verdict already
            # happens once, correctly, via the flagged-metric mechanism (reports.alerting.
            # undrained_folder_flags_by_system) -- this tile is a glance-level count, not a
            # second independently-computed severity judgement.
            _kpi_panel_("Queue folders drained", [("Drained", n_queue_drained), ("Total", n_queue_folders)],
                       GREEN if n_queue_drained == n_queue_folders else AMBER))
    _disk_high_h, disk_high_d, disk_high_state = engine.disk_high(store, systems, thr, CRIT)
    disk_high_color = {"good": GREEN, "warn": AMBER, "bad": RED}[disk_high_state]
    # extra_disk/extra_disk_total (2026-09-17, on request: "what about high disk usage and
    # storage critical tiles[,] can't they be merged" -- originally merged Cluster Health's
    # own WATCH-tier "Storage at capacity" tile, the SAME 85% `thr` AD's own disk_high()
    # already uses. That source tile is GONE as of 2026-09-18 though ("storage capacity and
    # storage critical are the same metric... combine every occurrence" -- it double-counted
    # against Cluster Health's own separate "Storage critical" tile, see network._infra_
    # overview's own comment on the removal), so extra_disk/extra_disk_total now come from
    # "Storage critical" (>=95%) instead. This tile's own numerator is therefore now AD's own
    # 85%+ count PLUS Cluster Health's stricter 95%+ count -- two different thresholds folded
    # into one number, a real change from the "same metric, same threshold" merge this used to
    # be -- accepted deliberately rather than dropping disk coverage from this combined tile
    # entirely. "Storage critical" ALSO still gets its own dedicated banner (storage_critical_
    # items, below), unlike Components down/High CPU/High memory above which are ONLY ever
    # folded in, never shown a second way.
    total_disk_count = disk_high_d + (extra_estate.get("extra_disk", 0) if extra_estate else 0)
    disk_high_color = (AMBER if (disk_high_d == 0 and extra_estate and extra_estate.get("extra_disk", 0))
                       else disk_high_color)
    n_untracked = len(engine.backup_untracked_unexplained(store, systems))
    n_tracked = len(systems) - n_untracked
    # Every tile reads affected-out-of-TOTAL, matching the xlsx and the webapp: a bare count
    # can't be judged (3 is alarming out of 5 hosts, unremarkable out of 56).
    # CPU and RAM stay as TWO tiles -- different metrics (2026-09-17, corrected on request:
    # "cpu and ram are different metrics they still need different tiles i meant one tile for
    # each metric"). What actually needed merging was the DUPLICATION within each metric --
    # the AD side's own "High CPU usage"/"High RAM usage" and the Cluster Health estate's own
    # "High CPU"/"High memory" watch tiles were two separate tiles measuring the SAME metric
    # over two different slices of the one estate ("remember there where multiple ram tiles
    # etc"). extra_cpu/extra_ram fold the Cluster Health estate's own affected-node counts
    # into these SAME two tiles' numerators instead, same pattern as extra_down above -- one
    # CPU tile, one RAM tile, each covering every device in both reports.
    total_cpu = cpu_hosts + (extra_estate.get("extra_cpu", 0) if extra_estate else 0)
    total_ram = ram_hosts + (extra_estate.get("extra_ram", 0) if extra_estate else 0)
    watch_kpis = [
        _kpi_panel_("High CPU usage", [("CPU", total_cpu), ("Total", combined_hosts)],
                    AMBER if total_cpu else GREEN),
        _kpi_panel_("High RAM usage", [("RAM", total_ram), ("Total", combined_hosts)],
                    AMBER if total_ram else GREEN),
        # Disks/Total only — matches the xlsx (see generate_report.py's HIGH DISK USAGE tile),
        # which dropped the separate Hosts/Total pair so Backup tracking below could keep its
        # own Total instead of every tile in the row fighting over the same fixed column budget.
        _kpi_panel_(f"High disk usage &middot; &#8805;{thr}%",
                    [("Disks", total_disk_count),
                     ("Total", engine.total_disks(store, systems)
                              + (extra_estate.get("extra_disk_total", 0) if extra_estate else 0))],
                    disk_high_color),
    ]
    if show_web_links:
        # https out of ALL monitored endpoints, not https vs http — the old pair made a fully
        # encrypted estate read "12 | 0", which looks like half a number rather than a pass.
        watch_kpis.append(_kpi_panel_("Web encryption", [("HTTPS", n_https), ("Total", n_https + n_http)], web_color))
    if show_backups:
        watch_kpis.append(_kpi_panel_("Backup tracking", [("Tracked", n_tracked), ("Total", len(systems))],
                                      AMBER if n_untracked else GREEN))
    if extra_estate:
        # See render_html's own docstring on extra_estate's "immediate_tiles"/"watch_tiles".
        _tile_state_color = {"bad": RED, "warn": AMBER, "good": GREEN, "info": NAVY}
        def _extra_tile_panel(tile: dict) -> str:
            vparts = str(tile.get("value", "")).split(" | ")
            sparts = str(tile.get("sub", "")).split(" | ")
            cols = (list(zip(sparts, vparts)) if len(vparts) == 2 and len(sparts) == 2
                   else [("", tile.get("value", ""))])
            return _kpi_panel_(tile.get("label", ""), cols,
                               _tile_state_color.get(tile.get("state", "info"), NAVY))
        immediate_kpis += [_extra_tile_panel(t) for t in extra_estate.get("immediate_tiles", [])]
        watch_kpis += [_extra_tile_panel(t) for t in extra_estate.get("watch_tiles", [])]
    immediate_kpis = "".join(immediate_kpis)
    watch_kpis = "".join(watch_kpis)
    # banner order mirrors generate_report.py's SEVERITY rank: IMMINENT (LDAP, unreachable)
    # first, then CRITICAL (near-full disks, expired certs), then WARNING (expiring certs,
    # COB, SWIFT, stale metrics) -- highest-consequence first. Stale metrics sits LAST of the
    # named warnings, right before the generic tables -- "some data here may be stale" is
    # useful context once you've already seen what's actually being reported, not something
    # that should bury the real findings underneath it.
    body = (_ldap_block(store, systems)
            + _unreachable_block(unreach)
            + _services_down_block(store, systems)
            + _disk_nearfull_block(store, systems)
            + (_cluster_storage_critical_block(extra_estate.get("storage_critical_items", []))
              if extra_estate else "")
            # Backup/web-link findings -- commented out via show_backups/show_web_links, not
            # deleted, "we may need them as the report grows" (on request) once AD backup
            # checks/web links exist; see render_html's own docstring.
            + (_backup_missing_block(store, systems) if show_backups else "")
            + (_backups_untracked_block(store, systems) if show_backups else "")
            + (_cert_block(store) if show_certs else "")
            + (_http_links_block(store, systems) if show_web_links else "")
            + _folder_over_expected_block(store, systems)
            + (_cob_block(store, unreach) if show_cob else "")
            + (_swift_block(store, unreach) if show_swift else "")
            + _stale_metrics_block(stale_metrics or [])
            + _section("Critical", crit, RED, RED_T)
            + _section("Warning", warn, AMBER, AMBER_T)
            + _section("No data (check exporters)", nodata, MUTED, "#f1f2f4"))
    if not body:
        body = (f'<tr><td style="padding:24px;"><div style="background:{GREEN_T};border-left:3px solid {GREEN};'
                f'padding:14px 16px;color:{GREEN};font-weight:600;">No disks, memory or services breached their '
                "thresholds at snapshot time.</div></td></tr>")

    return f"""<!doctype html><html><body style="margin:0;padding:0;background:#eef0f3;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f3;font-family:'Times New Roman',Times,serif;">
<tr><td align="center" style="padding:24px 12px;">
<table width="660" cellpadding="0" cellspacing="0" style="max-width:660px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.12);">

  <tr><td style="background:{NAVY};padding:22px 24px;">
    <div style="font-size:20px;font-weight:700;color:{GOLD};letter-spacing:.5px;">{title}</div>
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
       in-process callers (the webapp) can ask for the findings alone.

       `attachment_name` accepts a plain string (unchanged, every existing caller) or a list
       of names (2026-09-17: the scheduled Active Directory Report now attaches a fresh
       Cluster Health Report alongside it) -- one "Full report attached" line per name."""
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
        names = [attachment_name] if isinstance(attachment_name, str) else list(attachment_name)
        for name in names:
            lines.append(f"Full report attached: {name}")
    if report_url:
        lines.append(f"Build an annotated report at the RBZ Monitoring Console: {report_url}")
    return "\n".join(lines)


# -------------------------------------------------------------------------- send
XLSX_MIME = ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")
PDF_MIME = ("application", "pdf")
_ATTACHMENT_MIME = {".xlsx": XLSX_MIME, ".pdf": PDF_MIME}


# Retries for the SMTP conversation itself (connect/STARTTLS/login/send) -- NOT for anything
# upstream (capture, xlsx render), which either works or doesn't and re-running buys nothing.
# Office365 has been observed taking 15s+ just to answer AUTH on an otherwise-healthy
# connection (measured directly against this account), so a single slow morning can outrun a
# tight timeout even with nothing actually wrong -- confirmed 2026-08-21 after an unattended
# run's login read timed out at 30s and the whole report silently never reached anyone, with
# no retry to absorb what looks like ordinary O365 latency/throttling rather than an outage.
_SMTP_ATTEMPTS = 3
_SMTP_RETRY_DELAYS = (5, 20)          # seconds between attempts 1->2 and 2->3
_SMTP_TIMEOUT = 45                    # was 30s; the observed slow-but-working login took 15s


def send_email(mail: dict, recipients: List[str], subject: str, html_body: str,
               text_body: str, attachment: Optional[Union[Path, List[Path]]] = None,
               inline_images: Optional[dict] = None) -> None:
    """Send the multipart/alternative e-mail, optionally with the XLSX report(s) attached.
       `attachment` is a path, or a list of paths (2026-09-17, on request: the scheduled
       Active Directory Report send now attaches a fresh Cluster Health Report alongside it)
       -- each file's own NAME becomes its attachment name.

       `inline_images`, if given, is {cid: png_bytes} for images the HTML references via
       `<img src="cid:...">` or a table `background="cid:..."` attribute (reports/
       alert_email_templates.py's Outlook-safe gauge/ring/header visuals) — attached as
       multipart/related parts scoped to the HTML alternative specifically, the standard MIME
       shape mail clients expect for an inline (not attached-as-a-file) image.

       Retries the whole SMTP conversation (fresh connection each time -- a half-open one
       from a failed attempt is not reused) on a transient network/timeout error, since this
       runs unattended every morning with nobody watching to re-run it by hand. A persistent
       failure (bad credentials, SMTP rejects the message, etc.) still raises after the last
       attempt -- retrying is for "the network/server hiccuped", not a substitute for
       reporting a real, non-transient failure."""
    msg = EmailMessage()
    msg["Subject"] = subject
    # formataddr(), not a raw f-string (fixed 2026-09-22, confirmed live: a from_name
    # containing "[" / "]" -- e.g. author="[SYNTHETIC TEST]" -- produces a From header Outlook
    # cannot parse at all (square brackets are RFC 5322 domain-literal syntax outside quotes);
    # combined with this from_name's own "·" forcing RFC 2047 encoding, the encoded word
    # SWALLOWED the trailing "<from_address>" entirely, leaving no parseable address and
    # Outlook showing the sender as "Unknown"). formataddr quotes/escapes the display name
    # correctly for ANY input, the same way it already would for e.g. an admin's own name
    # containing a comma or parenthesis via --author.
    msg["From"] = formataddr((mail["from_name"], mail["from_address"]))
    msg["To"] = ", ".join(recipients)
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    if inline_images:
        html_part = msg.get_payload()[-1]
        for cid, png_bytes in inline_images.items():
            html_part.add_related(png_bytes, maintype="image", subtype="png", cid=f"<{cid}>")
    if attachment is not None:
        paths = [attachment] if isinstance(attachment, (str, Path)) else list(attachment)
        for a in paths:
            path = Path(a)
            maintype, subtype = _ATTACHMENT_MIME.get(path.suffix.lower(), ("application", "octet-stream"))
            msg.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=path.name)
    ctx = ssl.create_default_context()
    if mail["skip_verify"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    last_exc: Optional[Exception] = None
    for attempt in range(1, _SMTP_ATTEMPTS + 1):
        try:
            with smtplib.SMTP(mail["host"], mail["port"], timeout=_SMTP_TIMEOUT) as srv:
                srv.ehlo(mail["ehlo"])
                if mail["starttls"]:
                    srv.starttls(context=ctx)
                    srv.ehlo(mail["ehlo"])
                if mail["user"]:
                    srv.login(mail["user"], mail["password"])
                srv.send_message(msg)
            return
        except (smtplib.SMTPException, OSError, TimeoutError) as exc:
            last_exc = exc
            if attempt < _SMTP_ATTEMPTS:
                delay = _SMTP_RETRY_DELAYS[attempt - 1]
                print(f"[!] SMTP attempt {attempt}/{_SMTP_ATTEMPTS} failed "
                      f"({type(exc).__name__}: {exc}) -- retrying in {delay}s ...", file=sys.stderr)
                time.sleep(delay)
    raise last_exc


# ----------------------------------------------------------------- report engine
def capture_via_engine(args) -> tuple:
    """One capture through the engine, shared by the e-mail body and the workbook, so the
       attachment and the summary above it describe the exact same instant.
       Returns (cfg, systems, store) — generate_report.py's own Config/System/Store."""
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
                    help="scope the snapshot to these systems (comma-separated)")
    ap.add_argument("--keep-report", default=None, metavar="PATH",
                    help="also save the generated xlsx here (default: kept in dry-run, temporary when sending)")
    args = ap.parse_args(argv)

    # everything is sourced from config.ini; CLI flags only override
    cfg = engine.load_config(args.config)
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
    # Capture and analysis both go through generate_report.py — the same SERVICE_CHECKS/
    # topology/capture/analysis code the webapp and the xlsx use, so the e-mail can never
    # disagree with the report (see module docstring). --attach only controls whether the
    # xlsx itself gets built and attached, independent of where the data came from.
    print(f"[*] capturing live metrics from {cfg.prom} via generate_report.py ...")
    cfg, systems, store = capture_via_engine(args)
    mail["grafana"], mail["prom"] = cfg.grafana, cfg.prom
    mail["elevated"] = cfg.overview_threshold

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
    elif args.attach:
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
