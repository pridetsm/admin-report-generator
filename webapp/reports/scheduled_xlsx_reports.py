"""Registry of XLSX-report types that can be scheduled/e-mailed unattended via a Reporting
group (reports.models.AutomatedReportGroup), PARALLEL to reports.automated_reports.REPORT_TYPES
but never merged into it: that dict is narrative-engine-specific --
reports/management/commands/generate_automated_report.py's own CLI
(`choices=sorted(REPORT_TYPES)`) routes any key found there into narrative generation, so an
xlsx type must never appear there.

AutomatedReportGroup.report_types/.covers_report_type() and
automated_reports_mail.automated_report_recipients() are already fully generic (a bare
JSONField with no coupling to REPORT_TYPES' own shape) -- a key from THIS dict works with all
of them unmodified. This registry exists only to widen the Reporting screen's own choice list
(reports.views.config_automated_reports / config_automated_report_group_edit) so an admin can
tick "Active Directory Report" as a group's report_types entry, without touching the narrative
command's CLI choices (2026-09-12, on request: "schedule the active directory report to run at
07:30 hrs, put me as the only recipient of that report group").
"""
from __future__ import annotations

XLSX_REPORT_TYPES = {
    "active_directory": {
        "label": "Active Directory Report",
        "purpose": "Root/Child Domain Controllers and AD Sync & Authentication -- the same "
                  "xlsx a human can already generate on demand from the Active Directory "
                  "Report picker, run unattended on a fixed daily schedule.",
        "cadence": "Daily",
        "cron": "30 7 * * *",
    },
}
