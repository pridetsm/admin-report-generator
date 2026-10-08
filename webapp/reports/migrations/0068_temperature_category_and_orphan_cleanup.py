"""Two related fixes, same request (2026-10-01: "core switch high temp reading issue still
reads as an unreachable component error under systems create a new issue type called
temperature... also this is a network component not a systems component"):

1. Backfill every existing `temp_high` IssueOccurrence onto the new "temperature" category
   (see AlertGroup.CATEGORY_CHOICES' own comment) by the row's own stored `band` -- red stays
   the finding's own current-truth band, just relabeled off "degraded"/"degrading"/
   "unreachable" onto "temperature". Already-open rows would also self-heal on their next poll
   touch (alerting.record_occurrences diffs category), but this keeps history and any
   currently-open row consistent immediately.

2. Resolve the two genuinely ORPHANED "Core Switch" (no "(HQ)" suffix) rows -- confirmed
   (not assumed) that "Core Switch" exists in NEITHER the current business-system topology
   NOR network.DEVICES; the device was renamed to "Core Switch (HQ)" and moved into the
   Network domain around 2026-09-18, the exact day these two rows' own `started_at` shows.
   record_occurrences() only ever revisits a system it's asked to capture again -- since
   nothing in any current topology still answers to the old name, these two rows (temp_high,
   metrics_missing) were never going to self-heal or resolve on their own, open forever. Zero
   AlertFinding rows reference "Core Switch" either (confirmed), so resolving them notifies
   nobody and loses no real incident history -- this is cleanup of dead data, not a live
   finding being silenced."""
from django.db import migrations

_TEMPERATURE_OLD_CATEGORIES = {"degraded", "degrading", "unreachable"}


def backfill_and_cleanup(apps, schema_editor):
    IssueOccurrence = apps.get_model("reports", "IssueOccurrence")

    IssueOccurrence.objects.filter(
        flag_key="temp_high", category__in=_TEMPERATURE_OLD_CATEGORIES
    ).update(category="temperature")

    from django.utils import timezone
    IssueOccurrence.objects.filter(
        system="Core Switch", resolved_at__isnull=True
    ).update(resolved_at=timezone.now())


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0067_alter_alertsilence_category"),
    ]

    operations = [
        migrations.RunPython(backfill_and_cleanup, noop_reverse),
    ]
