"""One-time backfill for IssueOccurrence.category on rows written before "untracked_metrics"
existed (2026-10-01) -- see AlertGroup.CATEGORY_CHOICES' own comment for the full history:
"untracked" originally meant exactly one thing -- generate_report.py's "no backup check on any
host" Flag -- but network.py's metrics_missing (SNMP coverage gap) and counter_width (32-bit
counter wrap) findings had been reusing the same category, which meant the Network/
Infrastructure "no backups tracked" blanket AlertSilence (see
0062_backfill_issueoccurrence_degraded_category's sibling migration for that history) was
ALSO silently suppressing these, purely because they shared a category by coincidence, not by
design.

Every row going FORWARD self-heals (alerting.record_occurrences' refresh branch already diffs
`category`), so this migration only matters for rows it will never revisit: already-RESOLVED
occurrences. Classification is by flag_key, exactly the two network.py now writes under
"untracked_metrics": "metrics_missing" and "counter_width"."""
from django.db import migrations

_UNTRACKED_METRICS_KEYS = {"metrics_missing", "counter_width"}


def backfill(apps, schema_editor):
    IssueOccurrence = apps.get_model("reports", "IssueOccurrence")
    IssueOccurrence.objects.filter(
        category="untracked", flag_key__in=_UNTRACKED_METRICS_KEYS
    ).update(category="untracked_metrics")


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0065_alter_alertsilence_category"),
    ]

    operations = [
        migrations.RunPython(backfill, noop_reverse),
    ]
