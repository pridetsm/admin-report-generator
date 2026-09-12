from django.db import migrations


# Seeds the ONE FreshnessCheck row confirmed genuinely dead during the 2026-09-05
# investigation that motivated this whole feature: t24_services.prom (feeds
# t24_tsa_service_running -> t24_service_up), a windows_exporter textfile-collector source
# on the T24 app server (10.0.212.3:9182) found 12.2 days stale while its own Prometheus
# scrape stayed perfectly healthy throughout.
#
# transactions.prom on the SAME host also read stale (18.1 days) during that first
# investigation pass, but a follow-up read minutes later (while building this feature) found
# it freshly rewritten again -- its own update cadence is evidently irregular/long by design
# (a SWIFT transaction-volume file plausibly only rewritten when there's something to
# report, not on a fixed clock), not a dead task like t24_services.prom. Deliberately NOT
# seeded here without knowing its real expected interval -- guessing one would risk a
# FreshnessCheck that itself false-alerts on every normal quiet period. Add it properly from
# Configuration > System Alerts once its real cadence is known.
#
# max_age_seconds=7200 (2h) is a safe starting point for t24_services.prom specifically --
# TSA business services should be checked far more often than every 2 hours regardless of
# the checker's exact real interval -- editable any time from Configuration > System Alerts
# without a further migration.
def seed_checks(apps, schema_editor):
    FreshnessCheck = apps.get_model("reports", "FreshnessCheck")
    FreshnessCheck.objects.get_or_create(
        instance="10.0.212.3:9182", file="t24_services.prom",
        defaults={"name": "T24 TSA Services Checker", "system": "Temenos",
                  "max_age_seconds": 7200, "active": True},
    )


def unseed_checks(apps, schema_editor):
    FreshnessCheck = apps.get_model("reports", "FreshnessCheck")
    FreshnessCheck.objects.filter(
        instance="10.0.212.3:9182", file="t24_services.prom",
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0033_alter_seenbackupfile_options_freshnesscheck_and_more"),
    ]

    operations = [
        migrations.RunPython(seed_checks, unseed_checks),
    ]
