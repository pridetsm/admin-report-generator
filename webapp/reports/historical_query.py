"""Stitches the long-term archive (MetricSample / prometheus_snapshot_db) with live
Prometheus into one continuous series for a requested time range -- see
PROMETHEUS-RETENTION-PLAN.md, "Phase 4: the live/archive split: one setting, two consumers".

`live_window_days` (reports.models.PrometheusRetentionRevision) is the single boundary: a
range entirely older than that goes to the archive only; a range entirely within it goes to
live Prometheus only (full scrape-interval resolution, not resampled -- this is the "fresh,
forward-facing" data the retention shrink was FOR); a range spanning the boundary gets both,
concatenated. Reads `.current_days()`, which is always the value genuinely APPLIED to the live
Prometheus service (never a saved-but-unapplied draft) -- see that model's own docstring for
why that distinction is load-bearing here, not decorative.

Callers pass the entry key + instance (+ extra -- mount for disk-shaped entries, target for
folder-monitoring ones) SEPARATELY, not a flat "disk:{instance}:{mount}" string -- both
`instance` (often itself "host:port") and `mount` (a Windows drive letter like "D:" carries its
own trailing colon) can contain colons, so a stored metric_key string cannot be split back
apart unambiguously. Every existing caller (report_charts.py) already has instance/mount
resolved separately before it ever touches a key string, so this costs nothing and sidesteps a
real parsing hazard entirely.
"""
from __future__ import annotations

import datetime

from . import metric_registry


def _entry_for(key: str) -> "metric_registry.MetricRegistryEntry | None":
    return next((e for e in metric_registry.REGISTRY if e.key == key), None)


def _metric_key(entry: "metric_registry.MetricRegistryEntry", instance: str | None,
                extra: str | None) -> str:
    if entry.kind == "scalar":
        return entry.key
    if entry.mount_label or entry.target_label or entry.extra_label:
        return f"{entry.key}:{instance}:{extra}"
    return f"{entry.key}:{instance}"


def _archive_rows(entry, instance, extra, start, end) -> list[tuple[datetime.datetime, float]]:
    from .models import MetricSample

    key = _metric_key(entry, instance, extra)
    return list(MetricSample.objects.filter(metric_key=key, taken_at__gte=start, taken_at__lte=end)
               .order_by("taken_at").values_list("taken_at", "value"))


def _live_rows(entry, instance, extra, start, end) -> list[tuple[datetime.datetime, float]]:
    """Full scrape-interval resolution from live Prometheus -- for a scalar entry, its
    bulk_promql already IS the live query (no per-instance filter to apply); for a "global"
    entry, live_query_template resolves to the one-instance (and, for target_label entries,
    one-target) filtered query (see metric_registry.py's own docstring on why this MUST use
    .replace(), never .format() -- PromQL's own {...} label-matcher syntax collides with
    Python's template mini-languages)."""
    from . import services

    if entry.kind == "scalar":
        expr = entry.bulk_promql
    elif entry.live_query_template:
        expr = entry.live_query_template.replace("{instance}", instance)
        if entry.target_label or entry.extra_label:
            expr = expr.replace("{target}", extra)
    else:
        return []

    try:
        prom, _cfg, _systems = services.live_prom_client()
        rows = prom.query_range(expr, start.timestamp(), end.timestamp(), "1m")
    except Exception:
        return []
    if not rows:
        return []
    # query_range returns one row per label-set; a single-instance filter should leave exactly
    # one, but defensively take the first rather than assume.
    return [(datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc), v)
           for t, v in rows[0]["values"]]


def series(key: str, instance: str | None, extra: str | None,
          start: datetime.datetime, end: datetime.datetime) -> list[tuple[datetime.datetime, float]]:
    """The one entry point report_charts.py (and anything else wanting a historical range)
    should call instead of querying MetricSample directly. `extra` is the mount (disk-shaped
    entries) or target (folder-shaped entries) -- None for everything else. Returns
    [(timestamp, value), ...], oldest first, empty list if the key is unknown or nothing was
    found on either side -- never raises, matching every other chart builder's "one bad run
    doesn't take the estate down" contract.

    Resolution jump at the boundary is DELIBERATE, not a bug: the live portion is full scrape-
    interval resolution, the archive portion is hourly -- recent = detailed, older = trend-
    level. See PROMETHEUS-RETENTION-PLAN.md if this should instead be resampled down to hourly
    for visual consistency across the boundary; not done here, left as an explicit call for
    whoever wires the first chart that visibly spans it."""
    entry = _entry_for(key)
    if entry is None:
        return []

    import django.utils.timezone as dj_timezone
    from .models import PrometheusRetentionRevision

    now = dj_timezone.now()
    boundary = now - datetime.timedelta(days=PrometheusRetentionRevision.current_days())

    if end <= boundary:
        return _archive_rows(entry, instance, extra, start, end)
    if start > boundary:
        return _live_rows(entry, instance, extra, start, end)

    # Spans the boundary: archive for the older part, live for the newer part, concatenated.
    # `instance`/`extra` are irrelevant to the archive-vs-live SPLIT decision (only the time
    # range matters for that) but still needed to build each half's own query.
    older = _archive_rows(entry, instance, extra, start, boundary)
    newer = _live_rows(entry, instance, extra, boundary, end)
    return older + newer
