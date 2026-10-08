"""One-time backfill for IssueOccurrence.category on rows written before the "degraded"
category existed (2026-10-01) -- see AlertGroup.CATEGORY_CHOICES' own comment for why
category="service" was split: "service" now means a NAMED service/process/listener/cluster-
resource is down; "degraded" is everything else read FROM a reachable device (interface
errors/saturation/discards, OSPF adjacency loss, PSU/fan failure, temperature, recent reboot,
interface/AP down-regressions).

Every row going FORWARD self-heals on its own (alerting.record_occurrences' refresh branch now
diffs `category` too, the same way it already diffs `domain` -- see that fix's own docstring),
so this migration only matters for rows record_occurrences will never revisit again: already-
RESOLVED occurrences. Without this, a finding that closed the day before this fix shipped would
keep showing as "Service down" forever in historical/trend views, while every currently-OPEN
one of the same kind already reads "Degraded" -- the exact same transient-history problem
0059_backfill_issueoccurrence_domain fixed for `domain`, same reasoning, same fix shape.

Classification is by flag_key PREFIX (the part before the first ":", matching generate_report's
own Flag.key convention) against the literal set of flag_keys network.py's FlagVM call sites
use for these findings -- not a guess, read directly from that module. `links_failed` is a
retired flag_key (replaced 2026-09-22 by interface_down_regression) but still appears in old
rows with the same "reachable device, not a named service" reasoning, so it's included too.
`service`/`cluster_resource_failed` are deliberately ABSENT from this set -- those stay
category="service", the two cases that genuinely are a named service/resource down."""
from django.db import migrations

_DEGRADED_PREFIXES = {
    "node_net_err", "node_net_disc", "interface_down_regression", "ap_down_regression",
    "temp_high", "recent_reboot", "psu_fan_failed", "ospf_adjacency_lost",
    "links_saturated_critical", "links_saturated", "iface_errors", "iface_discards_heavy",
    "iface_discards", "links_failed",
}


def backfill_degraded(apps, schema_editor):
    IssueOccurrence = apps.get_model("reports", "IssueOccurrence")

    for row in IssueOccurrence.objects.filter(category="service").iterator():
        prefix = row.flag_key.split(":", 1)[0]
        if prefix in _DEGRADED_PREFIXES:
            row.category = "degraded"
            row.save(update_fields=["category"])


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0061_alter_alertsilence_category"),
    ]

    operations = [
        migrations.RunPython(backfill_degraded, noop_reverse),
    ]
