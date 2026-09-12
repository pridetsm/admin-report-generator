from django.conf import settings
from django.db import migrations


# Merges SystemAlertGroup into AlertGroup (2026-09-05, on request: "alert groups must be for
# all alerts even if there are system alerts... we just want everything to make sense and be
# solid") -- ONE group model classified by alert_type/alert_subtype, replacing two
# structurally-separate-but-otherwise-identical stakeholder models. Preserves each
# SystemAlertGroup row's OWN primary key on its new AlertGroup row so SystemAlertFinding.group
# (still pointing at the old table's ID column at this point in the migration sequence) needs
# no rewriting at all -- the very next migration retargets that FK's constraint once these
# rows already exist under the same IDs. Only safe because there is exactly one
# SystemAlertGroup row in production at merge time (asserted below rather than silently
# working around a collision) -- a second one, or a second run of this app's history with
# more rows, would need actual ID remapping instead.
def merge_forward(apps, schema_editor):
    SystemAlertGroup = apps.get_model("reports", "SystemAlertGroup")
    AlertGroup = apps.get_model("reports", "AlertGroup")

    for sag in SystemAlertGroup.objects.all():
        if AlertGroup.objects.filter(pk=sag.pk).exists():
            raise RuntimeError(
                f"Cannot merge SystemAlertGroup {sag.pk} ({sag.name!r}): an AlertGroup with "
                f"that same primary key already exists. This migration only handles the "
                f"pk-preserving case; extend it with real ID remapping (and a "
                f"SystemAlertFinding.group_id rewrite) if this ever fires.")
        name = sag.name
        if AlertGroup.objects.filter(name=name).exists():
            name = f"{name} (System)"
        ag = AlertGroup.objects.create(
            pk=sag.pk, name=name, alert_type="system", alert_subtype="staleness",
            systems=sag.systems, categories={}, emails=sag.emails, min_severity="red",
            reminder_minutes=[sag.reminder_minutes] if sag.reminder_minutes else [],
            imminent_reminder_minutes=None, active=sag.active,
            updated_by_id=sag.updated_by_id,
        )
        ag.users.set(sag.users.all())


def merge_backward(apps, schema_editor):
    AlertGroup = apps.get_model("reports", "AlertGroup")
    AlertGroup.objects.filter(alert_type="system", alert_subtype="staleness").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0038_alertgroup_alert_subtype_alertgroup_alert_type"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RunPython(merge_forward, merge_backward),
    ]
