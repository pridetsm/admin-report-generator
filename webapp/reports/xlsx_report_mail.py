"""E-mail delivery for the XLSX-report family (Active Directory today; more xlsx report types
join the SAME bundle e-mail later -- see `reports`' own list shape below). Parallel to
automated_reports_mail.py (which is narrative-report-specific: PDF attachment, chart CIDs,
AutomatedReportInstance) -- kept as a separate module rather than merged into it because the
two report families have nothing in common except both ultimately calling
mail_report.send_email.

Reuses mail_report.send_email for ALL SMTP (same as automated_reports_mail/alerting/services)
-- no second mail implementation.

MULTI-ATTACHMENT NOTE (future work, not done here): mail_report.send_email(...) takes a single
`attachment: Optional[Path]` -- today's only caller of this module ever passes exactly one
xlsx (Active Directory), so this is not yet a limitation. The day a second xlsx type joins the
SAME bundle e-mail (2026-09-12: "as we attach different xlsx reports we will need to show
their dashboard in the mailing template"), send_email's signature will need to grow to accept
more than one attachment -- deliberately not done now, since send_email is also used,
unmodified, by the standalone System Admin Report mailer, and changing a shared primitive for
a use case that doesn't exist yet is unwarranted churn.
"""
from __future__ import annotations

import os
import pathlib
import tempfile

from django.template.loader import render_to_string

import generate_report as gr
import mail_report as mr


def _text_body(reports: list) -> str:
    lines = ["Scheduled report(s) attached.", ""]
    for r in reports:
        lines.append(r["title"])
        ov = r.get("overview") or {}
        for kpi in ov.get("glance", []):
            lines.append(f"  {kpi['label']}: {kpi['value']}")
        if ov.get("immediate"):
            lines.append(f"  Immediate attention: {len(ov['immediate'])} item(s)")
        if ov.get("watch"):
            lines.append(f"  Watch list: {len(ov['watch'])} item(s)")
        lines.append(f"  Attached: {r['filename']}")
        lines.append("")
    return "\n".join(lines)


def send_xlsx_report_bundle(recipients: list, reports: list) -> None:
    """`reports`: list of {type, title, filename, overview, systems, xlsx_bytes} dicts --
    today always length 1 (active_directory). Raises RuntimeError / the underlying SMTP error
    on failure -- callers (e.g. generate_active_directory_report) decide whether that stops
    the run or is just logged, same contract as automated_reports_mail.send_automated_report.

    Only reports[0]'s xlsx_bytes is attached -- see module docstring's MULTI-ATTACHMENT NOTE;
    a caller must never pass more than one report's worth of xlsx_bytes today.
    """
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        raise RuntimeError("No SMTP host configured in send_report/config.ini ([smtp]).")
    mailcfg["from_name"] = "RBZ Monitoring Console · Reporting"

    subject = "Scheduled Report: " + ", ".join(r["title"] for r in reports)
    html_body = render_to_string("reports/xlsx_report_bundle_email.html", {"reports": reports})
    text_body = _text_body(reports)

    primary = reports[0]
    tmpdir = tempfile.mkdtemp(prefix="xlsx_report_bundle_")
    path = pathlib.Path(tmpdir) / primary["filename"]
    try:
        path.write_bytes(primary["xlsx_bytes"])
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, path)
    finally:
        try:
            path.unlink()
            os.rmdir(tmpdir)
        except OSError:
            pass
