from django.db import migrations


REPORT_TYPES = [
    "weekly_trend", "monthly_recurring", "quarterly_summary",
    "system_attention", "admin_observations", "anomaly_log",
]


def migrate_recipients(apps, schema_editor):
    """One-time carry-over (2026-09-08) so switching Automated Reports over to
    AutomatedReportGroup doesn't silently stop delivery to whoever was already opted in via
    the old flat EmailRecipient.receives_automated_reports boolean. Creates ONE group covering
    every report type (the old boolean's own behaviour -- it could not distinguish report
    types either), with these recipients as plain e-mails rather than User accounts: robust
    regardless of whether any of these addresses happens to match a real login, and an admin
    can always split them into finer-grained groups afterward from the new config screen.
    No-op (creates an empty-but-inactive placeholder) if nobody was opted in."""
    EmailRecipient = apps.get_model("reports", "EmailRecipient")
    AutomatedReportGroup = apps.get_model("reports", "AutomatedReportGroup")

    emails = list(EmailRecipient.objects
                 .filter(active=True, receives_automated_reports=True)
                 .values_list("email", flat=True))

    AutomatedReportGroup.objects.get_or_create(
        name="Migrated Automated Report Recipients",
        defaults={
            "report_types": REPORT_TYPES,
            "emails": emails,
            "active": bool(emails),
        },
    )


def noop_reverse(apps, schema_editor):
    AutomatedReportGroup = apps.get_model("reports", "AutomatedReportGroup")
    AutomatedReportGroup.objects.filter(name="Migrated Automated Report Recipients").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0045_automatedreportgroup"),
    ]

    operations = [
        migrations.RunPython(migrate_recipients, noop_reverse),
    ]
