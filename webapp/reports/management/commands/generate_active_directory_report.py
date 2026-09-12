"""Unattended, scheduled twin of reports.views.active_directory_generate (the interactive
picker -> review -> generate flow) -- mirrors generate_automated_report.py's own shape
(generate -> store ReportSubmission -> resolve recipients -> conditionally e-mail ->
distinguish "generated but not e-mailed" from a hard failure), but for the XLSX Active
Directory Report, not a narrative Automated Report.

No CLI arguments (folder_exporter.yml's job runner launches `command:` as one literal process
path with no argv splitting -- see run_active_directory_report.bat's own header), and no
--force-distribute switch: unlike the narrative Automated Reports, there is no shadow-mode
flag gating this at all. SystemConfig.automated_reports_distribution_enabled is a rollout
switch specifically for the six narrative report types (currently off) -- gating this
explicitly-requested job behind an unrelated, off-by-default flag would silently defeat the
point of scheduling it (2026-09-12: "schedule the active directory report to run at 07:30
hrs, put me as the only recipient of that report group").
"""
from __future__ import annotations

import uuid

from django.core.management.base import BaseCommand
from django.utils import timezone

from reports import network
from reports.automated_reports_mail import automated_report_recipients
from reports.models import ReportSubmission
from reports.scheduled_xlsx_reports import XLSX_REPORT_TYPES
from reports.xlsx_report_mail import send_xlsx_report_bundle

REPORT_TYPE = "active_directory"


class Command(BaseCommand):
    help = ("Generate the Active Directory Report headlessly, store it (ReportSubmission, "
           "the same History table the interactive picker writes to), and e-mail it to "
           "every active Reporting group covering 'active_directory'.")

    def handle(self, *args, **options):
        theme = "dark"                 # unattended: no user profile to read a preference from
        author = "Automated"           # unattended: no request.user
        annotations: dict = {}         # unattended: nobody reviewing flags/writing comments
        summary_comment = ""

        only = {d["key"] for d in network.DEVICES if d.get("system") in network.AD_SYSTEMS}
        token = uuid.uuid4().hex
        try:
            snapshot = network.capture_snapshot(token, only=only, infra=True)
        except network.NetworkUnavailable as exc:
            # Prometheus down at 07:30 is an operational hiccup, not a code failure -- exit
            # cleanly so folder_exporter's own job log shows a clean, expected skip rather
            # than a crash trace; tomorrow's run is unaffected.
            self.stderr.write(self.style.WARNING(f"Skipped: Prometheus unavailable ({exc})."))
            return

        data = network.build_infrastructure_report(
            snapshot, theme=theme, author=author, annotations=annotations,
            summary_comment=summary_comment, report_title="ACTIVE DIRECTORY REPORT")
        filename = network.active_directory_report_filename(theme, timezone.localtime())

        report_content = {
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
            self.stdout.write("No active Reporting group covers 'active_directory' -- "
                              "stored only, not e-mailed.")
            return

        try:
            send_xlsx_report_bundle(recipients, reports=[{
                "type": REPORT_TYPE,
                "title": XLSX_REPORT_TYPES[REPORT_TYPE]["label"],
                "filename": filename,
                "overview": snapshot.overview,
                "systems": report_content["systems"],
                "xlsx_bytes": data,
            }])
        except Exception as exc:   # noqa: BLE001 -- a failed send must not look like a failed run
            self.stderr.write(self.style.WARNING(f"Generated but NOT e-mailed: {exc}"))
            return
        self.stdout.write(self.style.SUCCESS(f"E-mailed to {len(recipients)} recipient(s)."))
