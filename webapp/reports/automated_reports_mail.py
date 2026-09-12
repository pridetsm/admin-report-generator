"""E-mail delivery for a finished AutomatedReportInstance (Phase 5 item 12/Phase 7 item 16).

Reuses mail_report.send_email for ALL SMTP, same as reports.alerting and reports.services do
-- no second mail implementation.

The PDF (views.build_automated_report_pdf, the SAME renderer "Download PDF" uses) is
attached, not just linked -- 2026-09-08, on request, after a real test send arrived with
"zero graphs": the HTML body (automated_report_email.html) is deliberately chart-free, since
it exists purely so Outlook's limited renderer doesn't mangle the console's own CSS -- see
that template's own docstring. Attaching the real PDF, which already renders every chart
correctly (xhtml2pdf, not a browser, but a purpose-built renderer, not a mail-client
compromise), remains the primary way to see every chart at full detail.

The HTML body embeds TWO headline visuals as CID-referenced inline images (multipart/related,
via mail_report.send_email's own `inline_images` param, the SAME mechanism alert_email_
templates.py already uses for its Outlook-safe gauge/ring visuals), NOT a base64 data: URI --
Outlook's renderer famously can't display a data: URI at all; a CID image is the one embedding
method Outlook DOES support natively (it's how Outlook embeds its own inline images).

RE-SCOPED 2026-09-10 (spec item 5) from an earlier version that embedded all six of the
report's own summary charts (both heatmaps, estate health, attention bar, theme bar, plus
SWIFT): "The email is not a smaller PDF... a digest, plus the PDF attached for the full thing."
The approved structure is masthead / KPI row / ONE Pareto-stat callout / top 3-5 findings as a
plain list / the Pareto chart + classification donut as the two headline visuals / two CTAs
(view full report, PDF attachment) / footer -- a genuinely condensed document, not an attempt
to squeeze all 13 report sections into an inbox. The full chart set (and the per-component
Hourly Activity spike-line charts, which have never been embedded here -- 20+ per report,
would balloon this message) remains one click away via the PDF attachment or the "View full
report" link, both always included together (never one without the other).
"""
from __future__ import annotations

import base64

from django.template.loader import render_to_string
from django.urls import reverse

from .ai_narrative import narrative_sections
from .models import AutomatedReportGroup


class EmailNotConfigured(RuntimeError):
    """Raised when SMTP settings are missing/incomplete in config.ini -- mirrors
    reports.services.EmailNotConfigured."""


def automated_report_recipients(report_type: str) -> list:
    """Every de-duplicated, validated e-mail address any ACTIVE AutomatedReportGroup that
    covers `report_type` resolves to (2026-09-08: Automated Reports now goes through the same
    Group-based notification-engine pattern AlertGroup/EventGroup already established, rather
    than the old flat EmailRecipient.receives_automated_reports boolean, which had no way to
    say "only send me the quarterly one"). Filtered in Python (`g.covers_report_type(...)`),
    the same "fetch active rows, then filter by coverage in Python" shape run_alert_cycle/
    run_event_cycle already use for their own groups' systems/categories -- not a DB-side JSON
    query, for the identical portability reasons those call sites already settled on."""
    emails: set = set()
    for g in AutomatedReportGroup.objects.filter(active=True):
        if g.covers_report_type(report_type):
            emails.update(g.recipient_emails())
    return sorted(emails)


def _summary_chart_images(content: dict) -> dict:
    """{cid: png_bytes} for this e-mail's own headline visuals -- 2026-09-10, item 5's own
    approved structure: "Two headline visuals as static raster images: the Pareto chart (bars +
    cumulative-% line) and the classification donut... rendered server-side from the same chart
    components the web page uses, then screenshotted/rasterized, not redrawn independently."
    Deliberately just these two (+ the masthead logo) -- NOT the full six-chart set this e-mail
    used to embed (both heatmaps, estate health, attention bar, theme bar, SWIFT): item 5's own
    guiding distinction is "the email is not a smaller PDF... a digest, plus the PDF attached
    for the full thing" -- the full chart set already lives one click away in that PDF
    attachment, and duplicating it here fought that design rather than serving it. Reuses the
    EXACT same report_charts calls build_automated_report_pdf/pareto_chart use, so this e-mail's
    own two images never disagree with the PDF's or the web view's."""
    from . import report_charts, views

    def _png_bytes(data_uri):
        if not data_uri:
            return None
        return base64.b64decode(data_uri.split(",", 1)[1])

    persistent_count, recurring_count = views._persistent_recurring_counts(content)

    data_uris = {
        "donut": report_charts.issue_breakdown_donut(
            persistent_count, recurring_count,
            len(content.get("anomalies", [])), len(content.get("one_off_issues", []))),
        "pareto": report_charts.pareto_chart(content.get("system_attention", [])),
        # The masthead logo (item 32) -- same base64-data-URI-in/PNG-bytes-out pipeline as the
        # two charts above, then embedded the SAME CID way (never a base64 <img src> directly,
        # and never a live https:// fetch either -- this app already treats "no external fetch
        # at render time" as a rule). report_charts.logo_data_uri() is what actually reads
        # static/img/brand-mark.png, cached module-level after the first read.
        "logo": report_charts.logo_data_uri(),
    }
    return {key: png for key, uri in data_uris.items() if (png := _png_bytes(uri)) is not None}


def _pareto_stat(content: dict) -> tuple | None:
    """(top_systems, share) for the ONE highlighted callout box (item 5's own approved
    structure: "the Pareto stat") -- the identical computation report_charts.pareto_chart's own
    cumulative line and ai_narrative.py's own exec_bits already use (same >=80%-of-active-
    issues definition), so the e-mail's own callout number can never quietly disagree with
    either of those. Returns None if there are fewer than 2 systems with an active issue
    (nothing to concentrate)."""
    rows = content.get("system_attention", [])
    if len(rows) < 2:
        return None
    ranked = sorted(rows, key=lambda r: r["persistent_count"] + r["recurring_count"], reverse=True)
    total = sum(r["persistent_count"] + r["recurring_count"] for r in ranked)
    if not total:
        return None
    target = total * 0.8
    running = 0
    top = []
    for r in ranked:
        top.append(r["system"])
        running += r["persistent_count"] + r["recurring_count"]
        if running >= target:
            break
    return top, running / total


def render_report_html(instance, chart_cids: dict | None = None) -> str:
    """`chart_cids` (see _summary_chart_images) is the set of cids actually available THIS
    render -- e.g. pareto is None for a window with fewer than 2 affected systems -- so the
    template can skip an <img> tag for a chart that was never generated rather than showing a
    broken-image icon."""
    from . import views

    content = instance.content
    pareto = _pareto_stat(content)
    persistent_count, recurring_count = views._persistent_recurring_counts(content)
    return render_to_string("reports/automated_report_email.html", {
        "instance": instance, "report": content,
        "sections": narrative_sections(content.get("narrative", {})),
        "chart_cids": chart_cids or {},
        "persistent_count": persistent_count, "recurring_count": recurring_count,
        # Top 3-5 highest-significance findings, plain bulleted list (item 5's own approved
        # structure) -- recurring_issues is already ranked by significance (classify_all's own
        # ordering, preserved through every filter since), so this is just a slice, not a
        # re-derivation.
        "top_findings": content.get("recurring_issues", [])[:5],
        "pareto_systems": pareto[0] if pareto else [],
        "pareto_share_pct": round(pareto[1] * 100) if pareto else None,
        "report_url": (f"https://monitoring.rbz.co.zw"
                      f"{reverse('automated_report_detail', args=[instance.report_type, instance.pk])}"),
    })


def send_automated_report(instance) -> str:
    """E-mails one AutomatedReportInstance to every AutomatedReportGroup that covers its own
    report_type (see automated_report_recipients), with the full PDF attached (see module
    docstring). Returns the subject. Raises EmailNotConfigured / views.PdfRenderError / the
    underlying SMTP error on failure -- callers (the generate_automated_report management
    command) decide whether that should stop the run or just be logged."""
    import os
    import pathlib
    import tempfile

    import generate_report as gr
    import mail_report as mr

    from . import views

    recipients = automated_report_recipients(instance.report_type)
    if not recipients:
        raise EmailNotConfigured(
            f"No active AutomatedReportGroup covers report type {instance.report_type!r}.")

    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        raise EmailNotConfigured("No SMTP host configured in send_report/config.ini ([smtp]).")
    mailcfg["from_name"] = "RBZ Monitoring Console · Automated Reports"

    content = instance.content
    subject = f"{content.get('label', 'Automated Report')} — {instance.generated_at:%d %b %Y}"
    chart_images = _summary_chart_images(content)          # {cid: png_bytes}
    chart_cids = {key: key for key in chart_images}         # template only needs the cid names
    html_body = render_report_html(instance, chart_cids)
    report_url = (f"https://monitoring.rbz.co.zw"
                 f"{reverse('automated_report_detail', args=[instance.report_type, instance.pk])}")
    # Item 29's own plain-text companion, matching the condensed HTML body's own structure --
    # KPI counts + the Pareto stat + top findings + both CTAs, not the fuller executive-summary
    # excerpt this used to carry (that belongs in the full report, one click/attachment away).
    pareto = _pareto_stat(content)
    persistent, recurring = views._persistent_recurring_counts(content)
    lines = [
        content.get("label", "Automated Report"),
        f"Window: {content.get('window_start', '')} to {content.get('window_end', '')}",
        "",
        f"Persistent: {persistent}  ·  Recurring: {recurring}  ·  "
        f"Potential flukes: {len(content.get('anomalies', []))}  ·  "
        f"One-off: {len(content.get('one_off_issues', []))}",
    ]
    if pareto:
        top_systems, share = pareto
        lines += ["", f"{len(top_systems)} systems ({', '.join(top_systems[:5])}) account for "
                      f"{share * 100:.0f}% of active issues this window."]
    top_findings = content.get("recurring_issues", [])[:5]
    if top_findings:
        lines += ["", "Top findings:"]
        lines += [f"  - {i['system']} {i['flag_key']} ({i['label']})" for i in top_findings]
    lines += ["", f"View full report: {report_url}",
             "The full report, with every chart, is also attached as a PDF."]
    text_body = "\n".join(lines)

    pdf_bytes = views.build_automated_report_pdf(instance)
    filename = views.automated_report_pdf_filename(instance)
    # Same "write to a temp dir with its proper name" pattern services.email_report already
    # uses -- mail_report.send_email's `attachment` param is a Path (it reads path.name for
    # the filename Outlook shows), not raw bytes, so the in-memory PDF needs a real file on
    # disk just long enough to hand off to smtplib.
    tmpdir = tempfile.mkdtemp(prefix="automated_report_")
    path = pathlib.Path(tmpdir) / filename
    try:
        path.write_bytes(pdf_bytes)
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, path,
                      inline_images=chart_images)
    finally:
        try:
            path.unlink()
            os.rmdir(tmpdir)
        except OSError:
            pass
    return subject
