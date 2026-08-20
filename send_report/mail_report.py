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
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional, Tuple

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
#  engine.backup_tracked_hosts, engine.backup_untracked, engine.backup_missing_band,
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
        f'<div style="font-size:15px;font-weight:700;color:{CRITICAL};">&#9888;&nbsp; IMMINENT &mdash; {len(unreach)} component(s) unreachable</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">Prometheus can no longer scrape these targets &mdash; '
        "the host is down, the exporter has stopped, or there is a network / connectivity issue. "
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


def _disk_nearfull_block(store, systems) -> str:
    """A prominent callout listing the volumes that are almost full (>= CRIT%)."""
    nearfull = engine.disk_near_full(store, systems, CRIT)
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
        f'{len(nearfull)} disk(s) near-full on {len(byhost)} host(s)</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">These volumes are almost full '
        f'(&#8805;{CRIT}%) &mdash; an imminent outage that can take the service down. '
        "<b>Free space or extend the disk now.</b></div>"
        f"{lines}</div></td></tr>"
    )


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
        f'{len(miss)} host(s) missing a fresh backup</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">These hosts run the backup check '
        "but have nothing fresh within policy &mdash; if the host is lost today, there is no recent "
        "backup to restore from. <b>Confirm the backup job and re-run it.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _backups_untracked_block(store, systems) -> str:
    """A callout listing systems where NOT ONE host runs the backup check at all -- a
    monitoring blind spot, not an active failure: nothing here is judged missing, since
    nothing is being watched to judge."""
    untracked = engine.backup_untracked(store, systems)
    if not untracked:
        return ""
    # one row per system, matching every other banner -- not all names crammed into a
    # single "Systems" row.
    lines = "".join(
        f'<div style="margin:3px 0;font-size:13px;">'
        f'<b style="color:{NAVY};">{html.escape(s)}</b>'
        f'<span style="color:#555;"> &mdash; no backup check on any host</span></div>'
        for s in sorted(untracked)
    )
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{AMBER_T};border-left:4px solid {AMBER};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; WARNING &mdash; '
        f'{len(untracked)} system(s) with no backup check at all</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">No host on these systems reports '
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


def render_html(store, systems, unreach, crit, warn, nodata, mail) -> str:
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
    cob_alert = cob_missing and datetime.date.today().weekday() != 0   # 0 = Monday (Sunday: no COB)
    swift = f"{store.swift:.0f}" if store.swift is not None else "N/A"
    cert_expired, _cert_expiring = engine.cert_rollup(store)
    n_https = sum(1 for u in store.links if u.lower().startswith("https"))
    n_http = sum(1 for u in store.links if u.lower().startswith("http://"))
    web_color = GREEN if n_http == 0 else (RED if n_http > n_https else AMBER)

    # the closing note points at whichever full breakdown this e-mail actually carries
    full_breakdown = ("see the attached report" if mail.get("attachment_name")
                      else "generate the report from the RBZ Monitoring Console above")

    if unreach:
        banner_bg, banner_fg = RED_T, CRITICAL
        headline = f"IMMINENT — {len(unreach)} component(s) UNREACHABLE — possible host / network outage"
    elif crit:
        banner_bg, banner_fg, headline = RED_T, RED, f"CRITICAL — {len(crit)} item(s) need immediate attention"
    elif warn or cob_alert:
        banner_bg, banner_fg = AMBER_T, AMBER
        headline = (f"WARNING — {len(warn)} item(s) to keep an eye on" if warn
                    else "WARNING — COB may not have run yesterday — check T24")
    else:
        banner_bg, banner_fg, headline = GREEN_T, GREEN, "All monitored systems are healthy"

    linux_pct, win_pct = engine.platform_host_pcts(systems)
    static_kpis = "".join([
        _kpi("Systems", str(len(systems)), NAVY),
        _kpi("Hosts", str(hosts), NAVY),
        _kpi("Linux | Windows", f"{linux_pct}% | {win_pct}%", NAVY),
        _kpi("Services", str(nsvc), NAVY),
        _kpi("SWIFT txns", swift, NAVY),
        _kpi("COB &middot; T24", cob, NAVY),
    ])
    immediate_kpis = [
        # missing out of TRACKED hosts (an untracked host isn't judged either way — see the
        # separate Backup tracking tile for those).
        _kpi_panel("Missing backups", [("Missing", nmiss), ("Tracked", engine.backup_tracked_hosts(store, systems))],
                   miss_color),
        # unreachable/down out of the TOTAL we monitor, so the count never reads as if fewer
        # components/services exist just because some are currently failing.
        _kpi_panel("Unreachable components", [("Unreachable", len(unreach)), ("Total", hosts)],
                   CRITICAL if unreach else GREEN),
        _kpi_panel("Services down", [("Down", down), ("Total", nsvc)],
                   RED if down else GREEN),
        _kpi_panel("Expired certs", [("Expired", len(cert_expired)), ("Total", engine.cert_monitored(store))],
                   RED if cert_expired else GREEN),
    ]
    _disk_high_h, disk_high_d, disk_high_state = engine.disk_high(store, systems, thr, CRIT)
    disk_high_color = {"good": GREEN, "warn": AMBER, "bad": RED}[disk_high_state]
    n_untracked = len(engine.backup_untracked(store, systems))
    n_tracked = len(systems) - n_untracked
    # Every tile reads affected-out-of-TOTAL, matching the xlsx and the webapp: a bare count
    # can't be judged (3 is alarming out of 5 hosts, unremarkable out of 56).
    watch_kpis = [
        _kpi_panel("High CPU usage", [("Hosts", cpu_hosts), ("Total", hosts)],
                   AMBER if cpu_hosts else GREEN),
        _kpi_panel("High RAM usage", [("Hosts", ram_hosts), ("Total", hosts)],
                   AMBER if ram_hosts else GREEN),
        # Disks/Total only — matches the xlsx (see generate_report.py's HIGH DISK USAGE tile),
        # which dropped the separate Hosts/Total pair so Backup tracking below could keep its
        # own Total instead of every tile in the row fighting over the same fixed column budget.
        _kpi_panel(f"High disk usage &middot; &#8805;{thr}%",
                   [("Disks", disk_high_d), ("Total", engine.total_disks(store, systems))],
                   disk_high_color),
        # https out of ALL monitored endpoints, not https vs http — the old pair made a fully
        # encrypted estate read "12 | 0", which looks like half a number rather than a pass.
        _kpi_panel("Web encryption", [("HTTPS", n_https), ("Total", n_https + n_http)], web_color),
        _kpi_panel("Backup tracking", [("Tracked", n_tracked), ("Total", len(systems))],
                   AMBER if n_untracked else GREEN),
    ]
    immediate_kpis = "".join(immediate_kpis)
    watch_kpis = "".join(watch_kpis)
    # banner order mirrors generate_report.py's SEVERITY rank: IMMINENT (LDAP, unreachable)
    # first, then CRITICAL (near-full disks, expired certs), then WARNING (expiring certs,
    # COB, SWIFT) -- highest-consequence first.
    body = (_ldap_block(store, systems)
            + _unreachable_block(unreach)
            + _services_down_block(store, systems)
            + _disk_nearfull_block(store, systems)
            + _backup_missing_block(store, systems)
            + _backups_untracked_block(store, systems)
            + _cert_block(store)
            + _http_links_block(store, systems)
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
        lines.append(f"Build an annotated report at the RBZ Monitoring Console: {report_url}")
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
