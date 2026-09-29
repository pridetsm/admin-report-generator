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
    # Key stays "active_directory" (2026-09-17: label/purpose updated, key untouched) --
    # existing AutomatedReportGroup rows store this literal string in their report_types
    # JSONField, so renaming the key would silently drop it from every group already
    # covering it. Label/purpose changed because the actual send now fires TWO reports on
    # one shared e-mail (on request: "so in reporting has the group been updated to
    # infrastructure reports firing multple reports on a shared email template" -- the
    # SENDING code already had been, since generate_active_directory_report.py/
    # _send_xlsx_report_test both attach a fresh Cluster Health Report alongside the AD one
    # and title the e-mail "INFRASTRUCTURE REPORTS" when both succeed; this registry entry
    # -- what admins actually see on the Reporting screen and in report history -- had not,
    # and was still describing the old AD-only single-attachment behavior).
    "active_directory": {
        "label": "Active Directory & Cluster Health Reports",
        "purpose": "Root/Child Domain Controllers and AD Sync & Authentication, PLUS a fresh "
                  "Cluster Health Report (HCI/DR/Bulawayo clusters, Standalone Servers) "
                  "attached to the same e-mail -- the same two xlsx files a human can already "
                  "generate on demand from the Active Directory and Cluster Health Report "
                  "pickers, run unattended together on a fixed daily schedule. Falls back to "
                  "the Active Directory Report alone if the Cluster Health half fails to "
                  "capture that run.",
        "cadence": "Daily",
        "cron": "30 7 * * *",
    },
    # Migrated off the old, disconnected standalone/systems admin report/ fork (2026-09-22, on
    # request: "migrate the automated system admin report generation to be within the app as we
    # did for infrastructure reports... generate and send reports such as we did for infra") --
    # that fork ran outside Django entirely, read its own config.ini for the mailing list, and
    # had drifted from send_report/generate_report.py (missing the win_service() case-
    # insensitivity fix and the AD/DC SKIP_SYSTEMS exclusion). This entry routes the SAME
    # estate-wide System Admin Report through generate_system_admin_report.py, which calls the
    # exact same services.capture_snapshot/build_report/email_report the in-app "Report
    # Generator" screen already uses -- one engine, one recipients source (this group), instead
    # of two.
    "system_admin": {
        "label": "System Admin Report",
        "purpose": "Estate-wide Prometheus snapshot -- Services/Memory/Disk/web links/SSL "
                  "certs/backups per business system -- the same xlsx+e-mail summary a human "
                  "can already generate on demand from the Report Generator screen, run "
                  "unattended on a fixed daily schedule.",
        "cadence": "Daily",
        "cron": "30 7 * * *",
    },
    # The four Networks Report pickers (Core Switches, Routers, Wireless Controller, Access
    # Switches -- 2026-09-23) as ONE scheduled job, ONE bundled e-mail (2026-09-24, on
    # request: "wire them in in reporting config to send to the same people that recieve the
    # infrastructure networks report at around the same time" -- shares 07:30 with
    # active_directory/system_admin above intentionally, same "folder_exporter fires every
    # due job independently" reasoning folder_exporter.yml's own active_directory_report
    # entry documents). generate_network_reports.py runs all four CONCURRENTLY
    # (concurrent.futures.ThreadPoolExecutor -- see that command's own module docstring for
    # why threads, not asyncio or multiprocessing) and isolates each one's failure from the
    # other three, then sends whichever succeeded as one bundle via
    # network.email_network_reports_bundle.
    "network_reports": {
        "label": "Network Reports (Core Switches, Routers, Wireless Controller, Access Switches)",
        "purpose": "All four Networks Report pickers, generated concurrently and e-mailed "
                  "together on one bundle -- the same four xlsx files a human can already "
                  "generate on demand from their own pickers, run unattended on a fixed "
                  "daily schedule. A failure in one does not stop the other three from "
                  "generating or sending.",
        "cadence": "Daily",
        "cron": "30 7 * * *",
    },
}
