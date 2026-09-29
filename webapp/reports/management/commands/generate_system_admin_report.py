"""Unattended, scheduled twin of reports.views.generate (the interactive Report Generator
picker -> review -> generate flow) for the estate-wide System Admin Report -- same shape as
generate_active_directory_report.py (generate -> store ReportSubmission -> resolve recipients
-> conditionally e-mail -> distinguish "generated but not e-mailed" from a hard failure), but
simpler: one report, no second attachment, no per-system scoping (the interactive flow lets an
admin narrow to specific systems; this unattended run always covers the whole estate, same as
the standalone fork it replaces).

Replaces the OLD automation entirely: folder_exporter.yml's `system_admin_report` job used to
shell out to standalone/systems admin report/run_and_mail.bat, a disconnected fork of this same
engine with its own config.ini mailing list and no Django history -- see this command's own
2026-09-22 migration (reports.scheduled_xlsx_reports.XLSX_REPORT_TYPES["system_admin"]'s own
comment for the full reasoning). This command calls the SAME reports.services functions
(capture_snapshot/build_report/email_report) the in-app Report Generator screen already uses,
so the unattended run and a human-generated one can never quietly disagree.

No CLI arguments (folder_exporter.yml's job runner launches `command:` as one literal process
path with no argv splitting -- see run_system_admin_report.bat's own header, and
run_active_directory_report.bat's for the same lesson).
"""
from __future__ import annotations

import uuid

from django.core.management.base import BaseCommand
from django.utils import timezone

from reports.automated_reports_mail import automated_report_recipients
from reports.models import ReportSubmission
from reports.services import (
    EmailNotConfigured,
    PrometheusUnavailable,
    build_report,
    capture_snapshot,
    default_report_filename,
    email_report,
)

REPORT_TYPE = "system_admin"


class Command(BaseCommand):
    help = ("Generate the System Admin Report headlessly, store it (ReportSubmission, the "
           "same History table the interactive Report Generator writes to), and e-mail it to "
           "every active Reporting group covering 'system_admin'.")

    def handle(self, *args, **options):
        theme = "dark"                 # unattended: no user profile to read a preference from
        author = "Automated"           # unattended: no request.user
        annotations: dict = {}         # unattended: nobody reviewing flags/writing comments
        summary_comment = ""

        token = uuid.uuid4().hex
        try:
            snapshot = capture_snapshot(token)   # no `only` -- whole estate, same as the fork it replaces
        except PrometheusUnavailable as exc:
            # Prometheus down at 07:30 is an operational hiccup, not a code failure -- exit
            # cleanly so folder_exporter's own job log shows a clean, expected skip rather
            # than a crash trace; tomorrow's run is unaffected.
            self.stderr.write(self.style.WARNING(f"Skipped: Prometheus unavailable ({exc})."))
            return

        data = build_report(snapshot, theme=theme, author=author,
                            annotations=annotations, summary_comment=summary_comment)
        filename = default_report_filename(theme, timezone.localtime())

        # Same "kind" tag reports.views.generate already writes (2026-09-12) so the Executive
        # Dashboard/History find this run the same way they find an admin-generated one.
        report_content = {
            "kind": "system_admin",
            "overview": snapshot.overview,
            "systems": [{
                "name": s.name, "hosts": s.hosts,
                "flags": [{"key": f.key, "text": f.text, "band": f.band,
                          "category": f.category, "answer": ""} for f in s.flags],
                "comment": "",
            } for s in snapshot.systems],
        }

        recipients = automated_report_recipients(REPORT_TYPE)
        delivery = "email" if recipients else "download"

        submission = ReportSubmission.objects.create(
            generated_by=None, author=author, theme=theme, delivery=delivery,
            recipients=", ".join(recipients), prom_url=snapshot.prom_url,
            systems_count=len(snapshot.systems),
            hosts_count=sum(s.hosts for s in snapshot.systems),
            immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
            summary_comment=summary_comment, annotations=annotations,
            report_content=report_content, filename=filename,
        )
        self.stdout.write(self.style.SUCCESS(
            f"Generated {filename} (id={submission.pk}) "
            f"systems={submission.systems_count} hosts={submission.hosts_count}"))

        if not recipients:
            self.stdout.write("No active Reporting group covers 'system_admin' -- "
                              "stored only, not e-mailed.")
            return

        try:
            subject = email_report(snapshot, data, recipients=recipients,
                                   author=author, filename=filename)
        except EmailNotConfigured as exc:
            self.stderr.write(self.style.WARNING(f"Generated but NOT e-mailed: {exc}"))
            return
        except Exception as exc:   # noqa: BLE001 -- a failed send must not look like a failed run
            self.stderr.write(self.style.WARNING(f"Generated but NOT e-mailed: {exc}"))
            return
        self.stdout.write(self.style.SUCCESS(
            f"E-mailed to {len(recipients)} recipient(s): {subject}"))
