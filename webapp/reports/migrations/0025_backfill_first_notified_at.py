# Generated manually 2026-09-04

from django.db import migrations


def _backfill(apps, schema_editor):
    """Rows that predate the 3-stage reminder schedule (0024) have last_notified_at set but
    first_notified_at NULL -- without this backfill, _decide() would see a row with
    last_notified_at set (so never "new" again) but no first_notified_at to anchor the new
    schedule against, and it would sit skipping every reminder forever. Their most recent
    notification becomes the schedule's new anchor point -- the honest available answer, since
    the OLD system never recorded a true "first" notification time separately."""
    from django.db.models import F

    AlertFinding = apps.get_model("reports", "AlertFinding")
    AlertFinding.objects.filter(
        last_notified_at__isnull=False, first_notified_at__isnull=True
    ).update(first_notified_at=F("last_notified_at"))


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0024_remove_alertgroup_renotify_interval_minutes_and_more'),
    ]

    operations = [
        migrations.RunPython(_backfill, migrations.RunPython.noop),
    ]
