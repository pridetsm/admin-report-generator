"""One-time backfill for IssueOccurrence.category on rows written while "degraded" was still
a single bucket for every severity (2026-10-01) -- see AlertGroup.CATEGORY_CHOICES' own
comment for the full history: "degraded" was split into "degraded" (red/Critical),
"degrading" (amber/Warning), and "potentially_degrading" (note/Note) on the same date, on
request ("some of these discards are too severe to lump all together").

Every row going FORWARD self-heals on its own (alerting.record_occurrences' refresh branch
already diffs `category`, added in the earlier 2026-10-01 fix for exactly this kind of
reclassification), so this migration only matters for rows record_occurrences will never
revisit again: already-RESOLVED occurrences. Already-open rows matching this filter would
also self-heal on their next poll touch regardless, but fixing them now keeps the dashboard
consistent immediately rather than waiting up to one poll cycle (~5 minutes).

Classification is by the row's OWN `band` field, already correct and already stored -- not a
guess: red stays "degraded" (untouched, not in this migration's filter), amber becomes
"degrading", note becomes "potentially_degrading". This mirrors exactly how network.py's own
FlagVM call sites decide the same split at the source."""
from django.db import migrations


def backfill(apps, schema_editor):
    IssueOccurrence = apps.get_model("reports", "IssueOccurrence")

    IssueOccurrence.objects.filter(category="degraded", band="amber").update(category="degrading")
    IssueOccurrence.objects.filter(category="degraded", band="note").update(category="potentially_degrading")


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0063_alter_alertsilence_category"),
    ]

    operations = [
        migrations.RunPython(backfill, noop_reverse),
    ]
