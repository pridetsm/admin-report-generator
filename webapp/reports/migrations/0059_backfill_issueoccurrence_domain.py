"""One-time backfill for IssueOccurrence.domain on rows written before that field existed
(2026-09-30) -- see IssueOccurrence.domain's own comment for why this is a bootstrap only,
not the ongoing source of truth: every row going forward gets its domain set directly by
record_occurrences' own caller, and even pre-existing OPEN rows self-heal on their next touch
(next alert-poller cycle, ~5 minutes) since a blank domain never matches a real one. This
migration exists only to give ALREADY-RESOLVED historical rows (which record_occurrences never
revisits) a real domain, so the Alert Dashboard's trend charts have accurate history from day
one instead of a wall of blanks.

Classification is by `system` name, matched against the SAME name sets the live capture paths
already define -- generate_report.INFRA_SYSTEMS/AD_SYSTEMS (lowercased) for Infrastructure,
network.py's own DEVICES list (kind in Switch/Router/WLC/Firewall) for Network -- not a new,
separately-maintained list. Anything matching neither defaults to Systems, the correct call
for this table's oldest data (written before the other three capture paths existed)."""
from django.db import migrations


def backfill_domain(apps, schema_editor):
    IssueOccurrence = apps.get_model("reports", "IssueOccurrence")

    import generate_report as gr
    from reports import network

    infra_names = {s.lower() for s in (gr.INFRA_SYSTEMS | gr.AD_SYSTEMS)}
    network_names = {d["name"].lower() for d in network.DEVICES
                     if d.get("kind") in ("Switch", "Router", "WLC", "Firewall")}

    for row in IssueOccurrence.objects.filter(domain="").iterator():
        name = row.system.lower()
        if name in infra_names:
            row.domain = "Infrastructure"
        elif name in network_names:
            row.domain = "Network"
        else:
            row.domain = "Systems"
        row.save(update_fields=["domain"])


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0058_issueoccurrence_domain"),
    ]

    operations = [
        migrations.RunPython(backfill_domain, noop_reverse),
    ]
