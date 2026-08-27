#!/usr/bin/env python3
"""
mail_report.py
==================================================================================
E-mail a brand-styled HTML snapshot of the Infrastructure Report (Active Directory
root domain controllers + HCI Cluster), captured LIVE and DIRECTLY from Prometheus —
plus the XLSX itself as an attachment (--attach) or an existing one (--report).

The capture goes through generate_report.py (this folder's sibling engine — same
DEVICES, same PromQL, same thresholds the xlsx uses), so the e-mail can never
disagree with the report. This module is presentation only: HTML/text templating +
SMTP on top of generate_report.capture(). Same split System Admin Report's own
mail_report.py already makes against ITS engine, for the same reason (see its
module docstring): a duplicated analysis path drifts, a shared one can't.

    Usage:
        python mail_report.py --to ops@rbz.co.zw                    # dry-run preview
        python mail_report.py --to ops@rbz.co.zw --send             # actually send
        python mail_report.py --attach --send                       # + attach the xlsx
        python mail_report.py --report "Infrastructure Report.xlsx" --send

Requires: openpyxl (generate_report.py is a hard dependency — see requirements.txt).
Python 3.8+.
==================================================================================
"""
from __future__ import annotations

import argparse
import configparser
import smtplib
import ssl
import sys
import tempfile
import time
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.ini"

sys.path.insert(0, str(HERE))          # works no matter where this is invoked from
import generate_report as engine       # the ONLY capture/analysis engine — see module docstring
import report_generator as rg

# brand palette for the e-mail (light theme, broadly compatible) — same values the System
# Admin Report's own mail_report.py uses, so the two mailings look like one family.
NAVY, GOLD = "#0e2a47", "#c8a24b"
RED, AMBER, GREEN, MUTED = "#c0392b", "#b9770e", "#1e7d4f", "#6b7785"
RED_T, AMBER_T, GREEN_T, NAVY_T = "#fdecea", "#fef6e7", "#e8f5ee", "#f3f5f8"
TONE_COLOR = {"red": RED, "amber": AMBER, "green": GREEN}
TONE_TINT = {"red": RED_T, "amber": AMBER_T, "green": GREEN_T}

XLSX_MIME = ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")
_SMTP_ATTEMPTS = 3
_SMTP_RETRY_DELAYS = (5, 15)      # seconds between attempts 1->2, 2->3
_SMTP_TIMEOUT = 30


# ============================================================================ #
#  CONFIGURATION  (SMTP/recipients only — Prometheus config is engine.load_config)
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
        "from_name": smtp.get("from_name", "Infrastructure Report").strip(),
        "starttls": smtp.getboolean("starttls", fallback=True),
        "skip_verify": smtp.getboolean("skip_verify", fallback=False),
        "ehlo": (smtp.get("ehlo", "") or "").strip() or None,
        "recipients": recipients,
    }


# ============================================================================ #
#  HTML RENDERING — a KPI strip + the needs-attention/watch-list tiles + any
#  flagged notes per group, straight off the SAME ReportData the xlsx renders from.
# ============================================================================ #
def _esc(text) -> str:
    import html
    return html.escape(str(text))


def _kpi(label: str, value, tone: Optional[str] = None) -> str:
    color = TONE_COLOR.get(tone, NAVY)
    tint = TONE_TINT.get(tone, NAVY_T)
    return (f'<td style="padding:10px 14px;background:{tint};border-radius:6px;text-align:center;">'
           f'<div style="font-size:11px;color:{MUTED};letter-spacing:.04em;">{_esc(label)}</div>'
           f'<div style="font-size:20px;font-weight:700;color:{color};">{_esc(value)}</div></td>')


def _kpi_row(metrics: List[rg.SummaryMetric]) -> str:
    cells = "".join(_kpi(m.label, f"{m.value} / {m.sublabel.split(chr(124))[-1].strip()}"
                        if "|" in m.sublabel else m.value, m.tone) for m in metrics)
    return f'<table role="presentation" style="width:100%;border-spacing:8px 0;"><tr>{cells}</tr></table>'


def _group_block(group: rg.DeviceGroup, depth: int = 0) -> str:
    tone = "red" if group.critical else "amber" if group.warning else "green"
    color = TONE_COLOR[tone]
    rows = "".join(
        f'<li style="margin:2px 0;color:{"#333" if n.flagged_metric != rg.SENTINEL_NOTE else MUTED};">'
        f'{_esc(n.flagged_metric)}</li>'
        for n in group.notes)
    indent = 18 * depth
    html = (f'<div style="margin:{6 if depth else 12}px 0 0 {indent}px;">'
           f'<div style="font-weight:600;color:{NAVY};">{_esc(group.title)} '
           f'<span style="font-weight:400;color:{color};font-size:12px;">'
           f'({group.critical} critical &middot; {group.warning} warning)</span></div>'
           f'<ul style="margin:4px 0 0 18px;padding:0;font-size:13px;">{rows}</ul></div>')
    for child in group.children:
        html += _group_block(child, depth + 1)
    return html


def render_html(data: rg.ReportData, mail: dict, attachment_name: Optional[str] = None) -> str:
    kpis = (f'<table role="presentation" style="width:100%;border-spacing:8px 0;margin-top:6px;"><tr>'
           f'{_kpi("DEVICES", data.nodes_total)}{_kpi("CLUSTERS", data.cluster_count)}'
           f'{_kpi("CLUSTER NODES", data.cluster_nodes)}</tr></table>')
    needs_attention = _kpi_row(data.needs_attention)
    watch_list = _kpi_row(data.watch_list)
    groups_html = "".join(_group_block(g) for g in data.groups)
    attach_note = (f'<p style="font-size:12px;color:{MUTED};">The full workbook is attached '
                   f'({_esc(attachment_name)}).</p>' if attachment_name else "")
    return f"""<!doctype html><html><body style="font-family:Segoe UI,Arial,sans-serif;
color:#1a1a1a;background:#f5f6f8;padding:24px;">
<div style="max-width:640px;margin:0 auto;background:#fff;border-radius:8px;
overflow:hidden;border:1px solid #e1e6ea;">
  <div style="background:{NAVY};color:#fff;padding:18px 24px;">
    <div style="font-size:18px;font-weight:700;">Infrastructure Report</div>
    <div style="font-size:12px;color:#c9d4de;">snapshot generated {_esc(data.generated_at)}</div>
  </div>
  <div style="padding:20px 24px;">
    {kpis}
    <h3 style="margin:18px 0 6px;color:{NAVY};font-size:13px;">NEEDS ATTENTION</h3>
    {needs_attention}
    <h3 style="margin:18px 0 6px;color:{NAVY};font-size:13px;">WATCH LIST</h3>
    {watch_list}
    <h3 style="margin:18px 0 6px;color:{NAVY};font-size:13px;">DEVICE GROUPS</h3>
    {groups_html}
    {attach_note}
  </div>
</div>
</body></html>"""


def plain_summary(data: rg.ReportData) -> str:
    lines = [f"Infrastructure Report — snapshot generated {data.generated_at}", ""]
    lines.append("Needs attention:")
    for m in data.needs_attention:
        lines.append(f"  {m.label}: {m.value} ({m.sublabel})")
    lines.append("")
    lines.append("Watch list:")
    for m in data.watch_list:
        lines.append(f"  {m.label}: {m.value} ({m.sublabel})")
    lines.append("")
    for g in data.groups:
        lines.append(f"{g.title}: {g.critical} critical, {g.warning} warning")
    return "\n".join(lines)


# ============================================================================ #
#  SMTP  (identical mechanics to the System Admin Report's own mail_report.py)
# ============================================================================ #
def send_email(mail: dict, recipients: List[str], subject: str, html_body: str,
               text_body: str, attachment: Optional[Path] = None) -> None:
    """Send the multipart/alternative e-mail, optionally with the XLSX report attached.
       Retries the whole SMTP conversation on a transient network/timeout error, since this
       runs unattended with nobody watching to re-run it by hand."""
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
       Returns (cfg, data) — generate_report.py's own Config/ReportData."""
    cfg = engine.load_config(args.config)
    if args.prom:
        cfg.prom = args.prom
    prom = engine.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    prom.ping()
    data = engine.capture(cfg)
    if args.author:
        data.summary_signed_by = args.author
        for g in data.groups:
            g.signed_by = args.author
    if args.summary:
        data.summary_notes.append(rg.SummaryNote("Summary", args.summary))
    return cfg, data


def subject_for(data: rg.ReportData) -> str:
    total_critical = sum(g.critical for g in data.groups)
    total_warning = sum(g.warning for g in data.groups)
    if total_critical:
        return f"[CRITICAL] Infrastructure Report — {total_critical} critical finding(s)"
    if total_warning:
        return f"[Warning] Infrastructure Report — {total_warning} finding(s) to watch"
    return "Infrastructure Report — all clear"


# -------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="E-mail a live Infrastructure Report snapshot.")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG), help="path to config.ini")
    ap.add_argument("--to", default="", help="override recipients (comma-separated)")
    ap.add_argument("--from-name", default=None, help="override the From display name")
    ap.add_argument("--prom", default=None, help="override the Prometheus base URL")
    ap.add_argument("--html-out", default=str(HERE / "email_preview.html"), help="dry-run preview path")
    ap.add_argument("--send", action="store_true", help="actually send (otherwise DRY-RUN preview only)")
    ap.add_argument("--attach", action="store_true",
                    help="generate the XLSX report from this same snapshot and attach it")
    ap.add_argument("--report", default=None, metavar="PATH",
                    help="attach an EXISTING xlsx instead of generating one")
    ap.add_argument("--author", default=None, help="name stamped into the report's 'By' fields")
    ap.add_argument("--summary", default=None, help="free text noted alongside Summary Notes")
    ap.add_argument("--keep-report", default=None, metavar="PATH",
                    help="also save the generated xlsx here (default: kept in dry-run, temporary when sending)")
    args = ap.parse_args(argv)

    mail = load_mail_config(args.config)
    if args.from_name:
        mail["from_name"] = args.from_name
    recipients = [r.strip() for r in (args.to or "").split(",") if r.strip()] or mail["recipients"]
    print(f"[*] SMTP {mail['host']}:{mail['port']} as {mail['user']} (starttls={mail['starttls']})")
    print(f"[*] From: {mail['from_name']} <{mail['from_address']}>")

    print(f"[*] capturing live metrics via generate_report.py ...")
    cfg, data = capture_via_engine(args)
    print(f"    devices={data.nodes_total} cluster_nodes={data.cluster_nodes} "
          f"critical={sum(g.critical for g in data.groups)} warning={sum(g.warning for g in data.groups)}")

    attachment_path: Optional[Path] = None
    tmp_dir: Optional[tempfile.TemporaryDirectory] = None
    if args.report:
        attachment_path = Path(args.report)
        if not attachment_path.is_file():
            print(f"[!] --report file not found: {attachment_path}", file=sys.stderr)
            return 2
    elif args.attach:
        filename = engine.default_report_filename("dark")
        if args.keep_report:
            attachment_path = Path(args.keep_report)
        elif args.send:
            tmp_dir = tempfile.TemporaryDirectory()
            attachment_path = Path(tmp_dir.name) / filename
        else:
            attachment_path = HERE / filename
        print(f"[*] rendering xlsx -> {attachment_path} ...")
        rg.build_report(data, str(attachment_path))

    subject = subject_for(data)
    html_body = render_html(data, mail, attachment_path.name if attachment_path else None)
    text_body = plain_summary(data)

    if not args.send:
        Path(args.html_out).write_text(html_body, encoding="utf-8")
        print(f"[*] DRY RUN — preview written to {args.html_out}")
        print(f"    subject: {subject}")
        print(f"    recipients: {', '.join(recipients) or '(none configured — use --to)'}")
        if tmp_dir:
            tmp_dir.cleanup()
        return 0

    if not recipients:
        print("[!] no recipients (config.ini [recipients] is empty and --to was not given)", file=sys.stderr)
        return 2

    print(f"[*] sending to {', '.join(recipients)} ...")
    try:
        send_email(mail, recipients, subject, html_body, text_body, attachment_path)
    finally:
        if tmp_dir:
            tmp_dir.cleanup()
    print("[+] sent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
