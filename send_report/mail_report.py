#!/usr/bin/env python3
"""
mail_report.py
==================================================================================
Analyse the System Admin Report and e-mail a well-styled HTML summary of
everything that needs attention, with the .xlsx report attached.

Pipeline:
    1. read settings from config.ini ([smtp] / [recipients] / [prometheus] / [grafana])
    2. capture live metrics (reuses generate_report.py)
    3. (re)build the xlsx report for the attachment
    4. analyse -> critical / warning / no-data findings
    5. render a responsive, brand-styled HTML e-mail
    6. send via Office365 SMTP  (only with --send; otherwise DRY-RUN preview)

    Usage:
        python mail_report.py --to ops@rbz.co.zw,dba@rbz.co.zw          # dry-run preview
        python mail_report.py --to ops@rbz.co.zw --send                 # actually send

Requires: openpyxl + generate_report.py in the same folder.  Python 3.8+.
==================================================================================
"""
from __future__ import annotations

import argparse
import configparser
import datetime
import html
import math
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import List, Tuple

import generate_report as gr   # Prometheus client, topology, capture(), ReportBuilder

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.ini"

# severity thresholds (mirror the report's chip colours)
CRIT = 90      # used % >= CRIT  -> critical
WARN = 75      # WARN <= used %  -> warning

# brand palette for the e-mail (light theme, broadly compatible)
NAVY, GOLD = "#0e2a47", "#c8a24b"
RED, AMBER, GREEN, MUTED = "#c0392b", "#b9770e", "#1e7d4f", "#6b7785"
RED_T, AMBER_T, GREEN_T, NAVY_T = "#fdecea", "#fef6e7", "#e8f5ee", "#f3f5f8"
# light tint behind a KPI tile, keyed to its value colour (card-like look, mirrors the xlsx)
TINT = {RED: RED_T, AMBER: AMBER_T, GREEN: GREEN_T, NAVY: NAVY_T, MUTED: "#f1f2f4"}


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


# ---------------------------------------------------------------------- analysis
Finding = Tuple[str, str, str, str]   # (system, component, item, detail)


def analyse(store: gr.Store, systems):
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
            if gr.is_unreachable(store, comp.instance):
                unreach.append((sysm.name, comp.label, "host",
                                "exporter unreachable — host down / network?"))
                continue            # host is down: skip its metric-level "no data"
            ram = store.ram.get(comp.instance)
            if ram is None:
                nodata.append((sysm.name, comp.label, "memory", "no data — exporter up, metric missing"))
            elif ram >= CRIT:
                critical.append((sysm.name, comp.label, "RAM", f"{ram:.0f}% used"))
            elif ram >= WARN:
                warning.append((sysm.name, comp.label, "RAM", f"{ram:.0f}% used"))
            cpu = store.cpu.get(comp.instance)
            if cpu is None:
                nodata.append((sysm.name, comp.label, "cpu", "no data — exporter up, metric missing"))
            elif cpu >= CRIT:
                critical.append((sysm.name, comp.label, "CPU", f"{cpu:.0f}% busy"))
            elif cpu >= WARN:
                warning.append((sysm.name, comp.label, "CPU", f"{cpu:.0f}% busy"))
            disks = store.disk.get(comp.instance, {})
            if not disks:
                nodata.append((sysm.name, comp.label, "disk", "no data — exporter up, metric missing"))
            for mount, dd in sorted(disks.items(), key=lambda kv: -kv[1].get("used", 0)):
                used, free = dd.get("used", 0), dd.get("free")
                detail = f"{used:.0f}% used" + (f", {free:.0f} GB free" if free is not None else "")
                if used >= CRIT:
                    critical.append((sysm.name, comp.label, mount, detail))
                elif used >= WARN:
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
    # ---- backups: hosts with no fresh backup file. Severity follows the same
    #      day logic as the report's tile (backup_missing_band): while yesterday
    #      is Sunday (i.e. today is Monday) a miss is a WARNING; on every other
    #      day both days of the pair are work days, so a miss is CRITICAL. ----
    miss = gr.backup_missing(store, systems)
    bucket = warning if gr.backup_missing_band(len(miss)) == "warn" else critical
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
    """A titled KPI tile split into sub-columns: cols = [(sublabel, value), ...]
       (one column for RAM/CPU, two — hosts | disks, https | http — for the split tiles)."""
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
        f'<div style="background:{RED_T};border-left:4px solid {RED};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{RED};">&#9888;&nbsp; {len(unreach)} component(s) unreachable</div>'
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 9px;">Prometheus can no longer scrape these targets &mdash; '
        "the host is down, the exporter has stopped, or there is a network / connectivity issue. "
        "<b>Treat as urgent.</b></div>"
        f"{lines}</div></td></tr>"
    )


def _disk_nearfull_block(store, systems) -> str:
    """A prominent callout listing the volumes that are almost full (>= CRIT%),
       mirroring the report's DISK NEAR-FULL banner. These are imminent outages —
       replaces the old 'Disk near-full' immediate KPI tile."""
    nearfull = gr.disk_near_full(store, systems, CRIT)
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


def _cob_block(store) -> str:
    """A callout when COB looks like it never ran — flagged every day EXCEPT Monday.
       A Monday reading covers Sunday (a non-work day with no COB), so an absent /
       abnormally-high value then is expected and is left unflagged."""
    cob_missing = store.cob is None or (isinstance(store.cob, float) and math.isnan(store.cob))
    if not cob_missing or datetime.date.today().weekday() == 0:   # 0 = Monday
        return ""
    return (
        '<tr><td style="padding:18px 24px 2px;">'
        f'<div style="background:{AMBER_T};border-left:4px solid {AMBER};border-radius:4px;padding:12px 16px;">'
        f'<div style="font-size:15px;font-weight:700;color:{AMBER};">&#9888;&nbsp; '
        "COB &mdash; close-of-business may not have run yesterday</div>"
        f'<div style="font-size:12px;color:{MUTED};margin:5px 0 0;">COB time is out of range '
        "(abnormally high), so no completed close-of-business was detected for the previous day. "
        "<b>Confirm the T24 COB ran and completed.</b> "
        "(On Mondays this is expected &mdash; Sunday has no COB &mdash; and is not flagged.)</div>"
        "</div></td></tr>"
    )


def render_html(store, systems, unreach, crit, warn, nodata, mail) -> str:
    today = datetime.date.today().strftime("%d %B %Y")
    # optional "prepared by" credit (set by the webapp so the e-mail shows who authored it)
    prepared_by = (f" &nbsp;&middot;&nbsp; prepared by {html.escape(mail['author'])}"
                   if mail.get("author") else "")
    hosts = sum(len(s.components) for s in systems)
    nsvc = sum(len(v) for v in store.services.values())
    down = sum(1 for v in store.services.values() for row in v if not row[1])
    thr = int(mail.get("elevated", 85))                       # shared "over N%" level (config.ini)
    ram_hosts, _ = gr.ram_pressure(store, systems, thr, thr)   # (count, state); email uses the count
    cpu_hosts, _ = gr.cpu_pressure(store, systems, thr, thr)   # hosts pegged at/over the elevated level
    nmiss = len(gr.backup_missing(store, systems))             # hosts with no fresh backup file
    miss_band = gr.backup_missing_band(nmiss)                  # good / warn (Sun-straddle) / bad
    miss_color = GREEN if miss_band == "good" else (AMBER if miss_band == "warn" else RED)
    # COB reads N/A when the metric is absent OR NaN (the collector writes NaN when the
    # value is out of range — abnormally high — i.e. COB most likely did not run yesterday).
    cob_missing = store.cob is None or (isinstance(store.cob, float) and math.isnan(store.cob))
    cob = "N/A" if cob_missing else f"{store.cob/60:.1f} min"
    cob_alert = cob_missing and datetime.date.today().weekday() != 0   # 0 = Monday (Sunday: no COB)
    swift = f"{store.swift:.0f}" if store.swift is not None else "n/a"
    # SSL rollup: expired certs are failing now; web-encryption posture (HTTPS vs plain HTTP)
    cert_expired, _cert_expiring = gr.cert_rollup(store)
    n_https = sum(1 for u in store.links if u.lower().startswith("https"))
    n_http = sum(1 for u in store.links if u.lower().startswith("http://"))
    # green only when no endpoint is plain HTTP; red when HTTP endpoints OUTNUMBER HTTPS; else amber
    web_color = GREEN if n_http == 0 else (RED if n_http > n_https else AMBER)

    if unreach:
        banner_bg, banner_fg = RED_T, RED
        headline = f"{len(unreach)} component(s) UNREACHABLE — possible host / network outage"
    elif crit:
        banner_bg, banner_fg, headline = RED_T, RED, f"{len(crit)} item(s) need immediate attention"
    elif warn or cob_alert:
        banner_bg, banner_fg = AMBER_T, AMBER
        headline = (f"{len(warn)} item(s) to keep an eye on" if warn
                    else "COB may not have run yesterday — check T24")
    else:
        banner_bg, banner_fg, headline = GREEN_T, GREEN, "All monitored systems are healthy"

    # static stats (inventory + point-in-time readings) live on their own row ...
    static_kpis = "".join([
        _kpi("Systems", str(len(systems)), NAVY),
        _kpi("Hosts", str(hosts), NAVY),
        _kpi("Services", str(nsvc), NAVY),
        _kpi("SWIFT txns", swift, NAVY),
        _kpi("COB &middot; T24", cob, NAVY),
    ])
    # ... and live health signals below, SPLIT BY URGENCY into two rows:
    #   immediate — something is failing now (act immediately)
    #   watch     — degrading, not yet failing (keep an eye on it)
    immediate_kpis = [
        _kpi("Missing backups", str(nmiss), miss_color),
        _kpi("Unreachable", str(len(unreach)), RED if unreach else GREEN),
        _kpi("Services down", str(down), RED if down else GREEN),
        _kpi("Expired certs", str(len(cert_expired)), RED if cert_expired else GREEN),
    ]
    # This tile counts EVERY high disk (>= thr) — elevated and near-full together — so it
    # can never read 0 while the DISK NEAR-FULL block above lists disks; those near-full
    # disks ARE high disks and are counted here. The block still carries the named per-host
    # detail. Colour follows the count: red if any disk is near-full, amber if only
    # elevated, green when zero — so 0 is always green (the colour rule holds).
    disk_high_h, disk_high_d, disk_high_state = gr.disk_high(store, systems, thr, CRIT)
    disk_high_color = {"good": GREEN, "warn": AMBER, "bad": RED}[disk_high_state]
    n_untracked = len(gr.backup_untracked(store, systems))   # systems with no backup check at all
    watch_kpis = [
        _kpi_panel("High CPU usage", [("Hosts", cpu_hosts)], AMBER if cpu_hosts else GREEN),
        _kpi_panel("High RAM usage", [("Hosts", ram_hosts)], AMBER if ram_hosts else GREEN),
        _kpi_panel(f"High disk usage &middot; &#8805;{thr}%",
                   [("Hosts", disk_high_h), ("Disks", disk_high_d)],
                   disk_high_color),
        _kpi_panel("Web encryption", [("HTTPS", n_https), ("HTTP", n_http)], web_color),
        _kpi_panel("Untracked backups", [("Systems", n_untracked)],
                   AMBER if n_untracked else GREEN),
    ]
    immediate_kpis = "".join(immediate_kpis)
    watch_kpis = "".join(watch_kpis)
    body = (_disk_nearfull_block(store, systems)
            + _unreachable_block(unreach)
            + _cob_block(store)
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
    <div style="font-size:12px;color:#aebfd1;margin-top:3px;">Reserve Bank of Zimbabwe &nbsp;&middot;&nbsp; static snapshot &nbsp;&middot;&nbsp; {today}{prepared_by}</div>
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

  <tr><td style="padding:22px 24px;">
    <a href="{mail['grafana']}" style="background:{NAVY};color:{GOLD};text-decoration:none;font-weight:700;
       font-size:14px;padding:11px 20px;border-radius:6px;display:inline-block;">&#9658;&nbsp; Open the live Grafana dashboard</a>
  </td></tr>

  <tr><td style="background:#f7f8fa;border-top:1px solid #e6e8ec;padding:14px 24px;">
    <div style="font-size:11px;color:{MUTED};line-height:1.6;">
      This is an automated, point-in-time snapshot from Prometheus ({html.escape(mail.get('prom', '').split('//')[-1])}).
      Thresholds: warning &#8805;{WARN}% &middot; critical &#8805;{CRIT}%. The full breakdown (Services / Memory / Disk per system)
      is attached as an Excel report. For live, auto-refreshing data use the Grafana dashboard above.
    </div>
  </td></tr>

</table></td></tr></table></body></html>"""


def plain_summary(unreach, crit, warn, nodata) -> str:
    lines = ["System Admin Report — summary", ""]
    for title, items in (("UNREACHABLE", unreach), ("CRITICAL", crit),
                         ("WARNING", warn), ("NO DATA", nodata)):
        if items:
            lines.append(f"{title} ({len(items)}):")
            lines += [f"  - {s} / {c} / {i}: {d}" for s, c, i, d in items]
            lines.append("")
    if not (unreach or crit or warn or nodata):
        lines.append("All systems healthy.")
    lines.append("See the attached Excel report for the full breakdown.")
    return "\n".join(lines)


# -------------------------------------------------------------------------- send
def send_email(mail: dict, recipients: List[str], subject: str, html_body: str,
               text_body: str, attachment: Path) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f'{mail["from_name"]} <{mail["from_address"]}>'
    msg["To"] = ", ".join(recipients)
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    if attachment and attachment.exists():
        msg.add_attachment(attachment.read_bytes(),
                           maintype="application",
                           subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                           filename=attachment.name)
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


# -------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="E-mail a styled summary of the System Admin Report.")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG), help="path to config.ini")
    ap.add_argument("--to", default="", help="override recipients (comma-separated)")
    ap.add_argument("--from-name", default=None, help="override the From display name")
    ap.add_argument("--grafana", default=None, help="override the Grafana dashboard URL")
    ap.add_argument("--prom", default=None, help="override the Prometheus base URL")
    ap.add_argument("--report", default=None, help="attach this xlsx instead of regenerating")
    ap.add_argument("--html-out", default=str(HERE / "email_preview.html"), help="dry-run preview path")
    ap.add_argument("--send", action="store_true", help="actually send (otherwise DRY-RUN preview only)")
    args = ap.parse_args(argv)

    # everything is sourced from config.ini; CLI flags only override
    cfg = gr.load_config(args.config)
    if args.prom:
        cfg.prom = args.prom
    if args.grafana:
        cfg.grafana = args.grafana

    mail = load_mail_config(args.config)
    if args.from_name:
        mail["from_name"] = args.from_name
    mail["grafana"] = cfg.grafana              # keep e-mail + report links in sync
    mail["prom"] = cfg.prom
    mail["elevated"] = cfg.overview_threshold  # same "over N%" level as the xlsx report
    recipients = [r.strip() for r in (args.to or "").split(",") if r.strip()] or mail["recipients"]
    print(f"[*] SMTP {mail['host']}:{mail['port']} as {mail['user']} (starttls={mail['starttls']})")  # no password
    print(f"[*] From: {mail['from_name']} <{mail['from_address']}>")

    print(f"[*] reading topology from {cfg.prometheus_yml} ...")
    systems = gr.load_topology(cfg.prometheus_yml)

    prom = gr.Prometheus(cfg.prom, cfg.http_timeout)
    print(f"[*] capturing live metrics from {cfg.prom} ...")
    prom.ping()
    store = gr.capture(prom, systems, cfg)

    if args.report:
        report_path = Path(args.report)
    else:
        print("[*] building xlsx report for attachment ...")
        builder = gr.ReportBuilder(cfg); builder.build(store, systems)
        report_path = Path(builder.save(cfg.out))

    unreach, crit, warn, nodata = analyse(store, systems)
    print(f"[*] findings: {len(unreach)} unreachable, {len(crit)} critical, "
          f"{len(warn)} warning, {len(nodata)} no-data")

    sev = (f"{len(unreach)} unreachable" if unreach else
           (f"{len(crit)} critical" if crit else (f"{len(warn)} warnings" if warn else "all healthy")))
    subject = f"System Admin Report — {datetime.date.today():%d %b %Y} — {sev}"
    html_body = render_html(store, systems, unreach, crit, warn, nodata, mail)
    text_body = plain_summary(unreach, crit, warn, nodata)

    if not args.send:
        Path(args.html_out).write_text(html_body, encoding="utf-8")
        print(f"[DRY-RUN] no e-mail sent. preview -> {args.html_out}")
        print(f"[DRY-RUN] would send '{subject}'")
        print(f"[DRY-RUN] to: {recipients or '(none set — use --to)'}  | attach: {report_path.name}")
        print("\n" + text_body)
        return 0

    if not recipients:
        print("[!] no recipients — set [recipients] to=... in config.ini, or pass --to", file=sys.stderr)
        return 2
    if not mail["enabled"]:
        print("[!] smtp.enabled is false in the ini", file=sys.stderr)
        return 2
    print(f"[*] sending to {recipients} ...")
    send_email(mail, recipients, subject, html_body, text_body, report_path)
    print("[+] sent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
