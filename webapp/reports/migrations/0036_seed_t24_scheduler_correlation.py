from django.db import migrations


# Sets scheduler_instance/scheduler_job on the T24 TSA Services Checker FreshnessCheck seeded
# in 0034 -- found 2026-09-05 in a follow-up investigation: folder_exporter's own job
# scheduler (10.0.212.3:9847, job "folder_exporter") reports its "t24_service_checker" job as
# 100% successful (exit_code=0, "ok" on every one of 3518 runs, most recent success SECONDS
# before this migration was written) while the file that job is supposed to produce
# (t24_services.prom) had gone stale for 12+ days. Naming the job here makes the alert e-mail
# show that job's own last-success timestamp next to the file's staleness -- see
# reports.system_alerts._scheduler_last_success's own docstring.
def seed_correlation(apps, schema_editor):
    FreshnessCheck = apps.get_model("reports", "FreshnessCheck")
    FreshnessCheck.objects.filter(
        instance="10.0.212.3:9182", file="t24_services.prom",
    ).update(scheduler_instance="10.0.212.3:9847", scheduler_job="t24_service_checker")


def unseed_correlation(apps, schema_editor):
    FreshnessCheck = apps.get_model("reports", "FreshnessCheck")
    FreshnessCheck.objects.filter(
        instance="10.0.212.3:9182", file="t24_services.prom",
    ).update(scheduler_instance="", scheduler_job="")


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0035_freshnesscheck_scheduler_instance_and_more"),
    ]

    operations = [
        migrations.RunPython(seed_correlation, unseed_correlation),
    ]
