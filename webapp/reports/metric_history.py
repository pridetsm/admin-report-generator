"""Captures a fresh reading of every metric_registry.REGISTRY entry into MetricSample (now
routed to its own database, "prometheus_snapshot_db" -- see reports.db_router and
PROMETHEUS-RETENTION-PLAN.md), so the app's own charts/analytics are no longer bounded by
Prometheus's own (now deliberately short, see reports.historical_query) retention window
(2026-09-18, on request: "store this data in the database... so we can have a much longer
retention window"; widened 2026-09-30 from 5 hardcoded series to the full metric_registry, on
request: "we want the web app to have access to all historical data").

Two entry points:
  capture_now()   -- one fresh reading per registry entry, across the whole estate, scheduled
                     via deploy/gms/folder_exporter.yml (job metric_history_capture) the same
                     way the alert/event/system-alert pollers already are -- see webapp/
                     run_metric_history_capture.bat.
  backfill(days)  -- a ONE-TIME catch-up pull of everything Prometheus still has, meant to be
                     run once by hand right after a new registry entry ships (or after this
                     module itself is deployed), so capture_now doesn't have to build up
                     history one point at a time.

Both loop over metric_registry.REGISTRY uniformly -- adding a new metric family means adding
one entry there, nothing here needs editing. See MetricSample's own docstring for why capture
is unconditional (every instance, every run) rather than scoped to whatever happens to be
"currently flagged" in one report: which components become newsworthy in some FUTURE report
can't be known in advance.
"""
from __future__ import annotations

import datetime
import math

from . import metric_registry


def _mount_of(labels: dict) -> str | None:
    """Linux disk series label their mount `mountpoint`, Windows series label it `volume` --
    the same split generate_report.py's own disk-percent expression has to account for."""
    return labels.get("mountpoint") or labels.get("volume")


def _extra_of(entry: "metric_registry.MetricRegistryEntry", labels: dict) -> str | None:
    """The third key segment for entries that need one beyond bare instance -- disk's mount
    (mount_label), folder monitoring's target (target_label, confirmed live: folder_files
    carries both `instance` AND `target`, since one folder_exporter instance monitors MULTIPLE
    folders -- instance alone is not unique for those), or any other single-named label
    (extra_label, e.g. HCI CSV volumes' own `volume` label). An entry only ever sets one of
    these three, never more than one."""
    if entry.mount_label:
        return _mount_of(labels)
    if entry.target_label:
        return labels.get("target")
    if entry.extra_label:
        return labels.get(entry.extra_label)
    return None


def _metric_key(entry: "metric_registry.MetricRegistryEntry", instance: str,
                extra: str | None = None) -> str:
    """The exact same join key report_charts.py / reports.historical_query build on the READ
    side -- see MetricSample's own docstring for why it's instance-based, not system/label-
    based. Unchanged shape from the pre-registry version (ram:{instance}, disk:{instance}:
    {mount}, swift) so existing archived rows/readers keep working without a rename."""
    if entry.kind == "scalar":
        return entry.key
    if entry.mount_label or entry.target_label or entry.extra_label:
        return f"{entry.key}:{instance}:{extra}"
    return f"{entry.key}:{instance}"


def _needs_extra(entry: "metric_registry.MetricRegistryEntry") -> bool:
    return bool(entry.mount_label or entry.target_label or entry.extra_label)


def _instant_rows_to_samples(rows: list, entry: "metric_registry.MetricRegistryEntry",
                             taken_at: datetime.datetime) -> list:
    from .models import MetricSample

    out = []
    for row in rows:
        instance = row["labels"].get("instance")
        if not instance:
            continue
        extra = _extra_of(entry, row["labels"]) if _needs_extra(entry) else None
        if _needs_extra(entry) and not extra:
            continue
        out.append(MetricSample(metric_key=_metric_key(entry, instance, extra),
                                taken_at=taken_at, value=row["value"]))
    return out


def _range_rows_to_samples(rows: list, entry: "metric_registry.MetricRegistryEntry") -> list:
    from .models import MetricSample

    out = []
    for row in rows:
        instance = row["labels"].get("instance")
        if not instance:
            continue
        extra = _extra_of(entry, row["labels"]) if _needs_extra(entry) else None
        if _needs_extra(entry) and not extra:
            continue
        key = _metric_key(entry, instance, extra)
        for t, v in row["values"]:
            out.append(MetricSample(
                metric_key=key,
                taken_at=datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc),
                value=v))
    return out


def _save(samples: list) -> int:
    from .models import MetricSample

    if not samples:
        return 0
    # ignore_conflicts: capture_now (hourly) and backfill (one-time, same window) can overlap
    # a point for the same series/hour -- the UniqueConstraint on (metric_key, taken_at) makes
    # a re-capture a silent no-op instead of a duplicate row or a failed batch.
    MetricSample.objects.using("metrics").bulk_create(samples, batch_size=1000, ignore_conflicts=True)
    return len(samples)


def capture_now() -> dict:
    """One fresh instant reading per registry entry, across the whole estate, right now.
    Returns {entry.key: n, ..., "error": None} (n = samples written; "error" set instead if
    Prometheus couldn't be reached at all, matching every other chart builder in this app's
    own "never raise, one bad run doesn't take the estate down" pattern)."""
    from . import services

    result = {entry.key: 0 for entry in metric_registry.REGISTRY}
    result["error"] = None
    try:
        prom, cfg, systems = services.live_prom_client()
    except Exception as exc:
        result["error"] = str(exc)
        return result

    import django.utils.timezone as dj_timezone

    now = dj_timezone.now()
    for entry in metric_registry.REGISTRY:
        try:
            rows = prom.query(entry.bulk_promql)
        except Exception:
            continue
        if entry.kind == "scalar":
            # NaN filtered here (cob_time reads NaN once its own checker script itself goes
            # stale -- see generate_report.py's own comment on that) -- a NaN sample would just
            # be an unplottable gap in the chart, and better skipped than stored.
            if rows and not math.isnan(rows[0]["value"]):
                from .models import MetricSample

                value = max(0.0, rows[0]["value"]) if entry.floor_zero else rows[0]["value"]
                result[entry.key] = _save([MetricSample(metric_key=entry.key, taken_at=now, value=value)])
        else:
            result[entry.key] = _save(_instant_rows_to_samples(rows, entry, now))
    return result


def backfill(days: int = 15) -> dict:
    """A ONE-TIME catch-up pull of every registry entry's full history Prometheus still has,
    meant to be run once by hand (`manage.py backfill_metric_history`) after this ships, or
    after a new registry entry is added -- see this module's own docstring. Safe to re-run
    (ignore_conflicts), so re-running it after a gap costs nothing beyond the query time.

    Uses a LONGER Prometheus client timeout than the app's usual live_prom_client() -- a
    heavier registry entry's range query (iface_errors' nested per-ifIndex sum, evaluated at
    every one of ~360 hourly steps across 15 days, confirmed live 2026-09-30: 51 seconds) blows
    straight through the shared 20s cfg.http_timeout every OTHER live query in this app uses,
    and the caller here has no reason to share that budget -- this is a one-time, run-by-hand
    operation, not a page load. The shared timeout stays untouched for every other caller."""
    from . import services

    result = {entry.key: 0 for entry in metric_registry.REGISTRY}
    result["error"] = None
    try:
        prom, cfg, systems = services.live_prom_client()
    except Exception as exc:
        result["error"] = str(exc)
        return result

    import generate_report as gr

    prom = gr.Prometheus(cfg.prom, 120, cfg.verify_tls)

    import time as _time

    end = _time.time()
    start = end - days * 24 * 3600
    for entry in metric_registry.REGISTRY:
        try:
            rows = prom.query_range(entry.bulk_promql, start, end, "1h")
        except Exception:
            continue
        if entry.kind == "scalar":
            if not rows:
                continue
            from .models import MetricSample

            samples = []
            for t, v in rows[0]["values"]:
                if math.isnan(v):
                    continue
                value = max(0.0, v) if entry.floor_zero else v
                samples.append(MetricSample(
                    metric_key=entry.key,
                    taken_at=datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc),
                    value=value))
            result[entry.key] = _save(samples)
        else:
            result[entry.key] = _save(_range_rows_to_samples(rows, entry))
    return result
