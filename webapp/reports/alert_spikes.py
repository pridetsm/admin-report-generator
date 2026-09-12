"""Hourly issue-spike chart, built on reports.models.IssueOccurrence -- NOT this app's
IssueClassification/ReportSubmission history (see trend_classification.py's own docstring),
and NOT Prometheus's native ALERTS metric either (an earlier version of this module used that;
see IssueOccurrence's own docstring for why it was replaced, 2026-09-07).

Why not IssueClassification/ReportSubmission: that answers "how persistent/recurring is this
issue" from report-GENERATION events, which happen whenever an admin (or a schedule) chooses to
run a report -- 47 submissions covered only 26 of the last 168 hours, confirmed live. Fine for
day-level recurrence, but an HOURLY chart built on it would mostly show "when did someone click
generate", not "when did the problem actually happen".

Why not Prometheus's ALERTS metric: real hourly resolution (Prometheus evaluates alerting rules
continuously, not on report-generation events), but only for whatever an alerting RULE actually
watches -- 5 rules, all Temenos folder/backup monitoring, confirmed live. No CPU/RAM/Disk/
Service-down coverage at all, and -- the sharper problem, raised directly: alerts are for
HUMANS. Every AlertGroup's own category/severity tick-list decides who gets notified, not
whether the underlying condition is worth recording, so any category nobody has ticked leaves
no trace in ALERTS at all, and a system not covered by any active AlertGroup isn't captured
even once. Neither of those is a Prometheus limitation, both are "we chose not to be told" --
looking exactly like "nothing happened" on a chart that's supposed to show what happened.

IssueOccurrence fixes both: reports.alerting.record_occurrences writes it unconditionally,
every 5-minute alert-poller cycle, for every system in the topology and every category
generate_report.flagged_for_system produces -- independent of any AlertGroup's configuration.
"""
from __future__ import annotations

import datetime
import math
import statistics


def _hour_floor(dt: datetime.datetime) -> datetime.datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def hourly_alert_series(systems: list[str], days: int = 7, now=None,
                        category: str | None = None) -> dict:
    """{"hours": [datetime, ...], "series": {system: [count, ...]}} -- one point per hour,
    `days * 24 + 1` points total, for exactly the given systems (report_charts.
    spike_systems_for_category's own output, when called for one system at a time -- see
    report_charts.issue_spike_line_single/spike_line_data_single).

    `category` (generate_report.Flag.category, e.g. "ram"/"disk") optionally scopes this to
    ONE issue type -- 2026-09-07, on request: "split it per issue... have as many of these as
    there are issues appearing in the heat map" -- a system's total incident count conflates
    every category together, which can't answer "when did THIS system's RAM specifically
    spike" the way a per-category chart can. `None` (the default) keeps the original
    all-categories-combined behaviour.

    Per-hour count = the number of DISTINCT IssueOccurrence incidents open at any point during
    that hour (an incident whose [started_at, resolved_at) overlaps the hour counts once,
    however much or little of the hour it actually covered) -- fetched once for the whole
    window then bucketed in Python, not one query per hour: at this table's real scale (tens of
    open incidents estate-wide at any instant, see IssueOccurrence's own docstring) that is
    comfortably cheaper than 169 separate range-overlap queries.

    A system with no incidents in this window still gets its own all-zero series (built
    upfront below, never conditionally added) -- a flat line in the legend, not a system
    silently missing from the chart."""
    from django.db.models import Q
    from django.utils import timezone as dj_timezone

    from .models import IssueOccurrence

    now = now or dj_timezone.now()
    end = _hour_floor(now)
    start = end - datetime.timedelta(hours=24 * days)
    range_end = end + datetime.timedelta(hours=1)   # exclusive upper bound: the last bucket is
                                                     # [end, end+1h), same width as every other
    hours = [start + datetime.timedelta(hours=h) for h in range(24 * days + 1)]

    series = {s: [0] * len(hours) for s in systems}
    if not systems:
        return {"hours": hours, "series": series}

    rows = (IssueOccurrence.objects
           .filter(system__in=systems, started_at__lt=range_end)
           .filter(Q(resolved_at__isnull=True) | Q(resolved_at__gt=start)))
    if category:
        rows = rows.filter(category=category)
    rows = rows.values("system", "started_at", "resolved_at")

    for r in rows:
        active_from = max(r["started_at"], start)
        active_to = min(r["resolved_at"] or range_end, range_end)
        if active_to <= active_from:
            continue
        i0 = int((active_from - start).total_seconds() // 3600)
        i1 = math.ceil((active_to - start).total_seconds() / 3600)
        for i in range(i0, min(i1, len(hours))):
            series[r["system"]][i] += 1

    return {"hours": hours, "series": series}


def spike_mask(values: list[float], k: float = 2.0) -> list[bool]:
    """Per-point spike flag: value > mean + k*stdev of THIS series' own history -- each
    system's own baseline, not one shared threshold, since systems run at very different
    typical counts (see issue_occurrence_heatmap's own reasoning for the same per-series-
    relative-scale principle). A perfectly flat series (stdev 0, e.g. a system with no incident
    history yet in this window) never flags: nothing to compare a spike against."""
    if len(values) < 2:
        return [False] * len(values)
    mean = statistics.fmean(values)
    stdev = statistics.pstdev(values)
    if stdev == 0:
        return [False] * len(values)
    threshold = mean + k * stdev
    return [v > threshold for v in values]
