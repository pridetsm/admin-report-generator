"""Captures hourly RAM/CPU/Disk %, SWIFT throughput, and COB duration readings into
MetricSample, so the Hourly Activity / SWIFT / COB charts (report_charts.resource_percent_
series / swift_transaction_series / cob_time_series) are no longer bounded by Prometheus's
own retention window (2026-09-18, on request: "store this data in the database... so we can
have a much longer retention window").

Two entry points:
  capture_now()   -- one hourly reading per series (RAM/CPU/Disk for every instance in the
                     business topology, plus SWIFT and COB), scheduled via deploy/gms/
                     folder_exporter.yml (job metric_history_capture) the same way the alert/
                     event/system-alert pollers already are -- see webapp/run_metric_history_
                     capture.bat.
  backfill(days)  -- a ONE-TIME catch-up pull of everything Prometheus still has (confirmed
                     live 2026-09-18: its own retention reaches back 14 days), meant to be run
                     once by hand right after this ships, so capture_now doesn't have to build
                     up two weeks of history one hourly point at a time.

Both walk the WHOLE business topology every run -- every instance's RAM/CPU/every disk mount,
plus SWIFT and COB -- not just whatever happens to be "currently flagged" in one report. See
MetricSample's own docstring for why: which components end up newsworthy in some FUTURE report
can't be known in advance, so capture has to be unconditional to be useful later.
"""
from __future__ import annotations

import datetime
import math

import generate_report as gr

#: Global (no instance filter, one number for the whole estate) scalar metrics -- SWIFT's own
#: daily running total and COB's own last-run duration (seconds). Added to together in one
#: loop (2026-09-18, on request: "add the superimposed one for cob time same style"), since
#: both are captured/backfilled identically: one prom.query()/query_range() call, no per-
#: instance/per-mount splitting the way ram/cpu/disk need.
SCALAR_METRICS = {"swift": "swift_transactions_total", "cob": "cob_time"}


def _metric_key(category: str, instance: str, mount: str | None = None) -> str:
    """The exact same join key report_charts.resource_percent_series/swift_transaction_series/
    cob_time_series build on the READ side -- see MetricSample's own docstring for why it's
    instance-based, not system/label-based."""
    if category in SCALAR_METRICS:
        return category
    if category == "disk":
        return f"disk:{instance}:{mount}"
    return f"{category}:{instance}"


#: One GLOBAL (no instance filter) PromQL expression per percentage category -- linux/windows
#: variants combined with `or`, same style _percent_expr already uses per-instance, so ONE
#: query captures every instance's reading in one call instead of looping per component.
#: Copied from generate_report.capture()'s own disk/ram/cpu expressions (that function issues
#: the linux/windows halves as two separate calls into a shared dict; combining them with `or`
#: here is equivalent -- the two metric families never share an instance -- and halves the
#: number of HTTP round trips this makes per run).
def _global_expressions() -> dict:
    return {
        "ram": ("100*(1-node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes) or "
               "100*(1-windows_memory_physical_free_bytes/windows_memory_physical_total_bytes)"),
        "cpu": ('100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) or '
               '100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"}[5m])) * 100)'),
        "disk": (f"100*(1-node_filesystem_avail_bytes{{{gr._FS}}}/node_filesystem_size_bytes{{{gr._FS}}}) or "
                f"100*(1-windows_logical_disk_free_bytes{{{gr._VOL}}}/windows_logical_disk_size_bytes{{{gr._VOL}}})"),
    }


def _mount_of(labels: dict) -> str | None:
    """Linux disk series label their mount `mountpoint`, Windows series label it `volume` --
    the same split _percent_expr's own disk branch has to account for."""
    return labels.get("mountpoint") or labels.get("volume")


def _instant_rows_to_samples(rows: list, category: str, taken_at: datetime.datetime) -> list:
    from .models import MetricSample

    out = []
    for row in rows:
        instance = row["labels"].get("instance")
        if not instance:
            continue
        mount = _mount_of(row["labels"]) if category == "disk" else None
        if category == "disk" and not mount:
            continue
        out.append(MetricSample(metric_key=_metric_key(category, instance, mount),
                                taken_at=taken_at, value=row["value"]))
    return out


def _range_rows_to_samples(rows: list, category: str) -> list:
    from .models import MetricSample

    out = []
    for row in rows:
        instance = row["labels"].get("instance")
        if not instance:
            continue
        mount = _mount_of(row["labels"]) if category == "disk" else None
        if category == "disk" and not mount:
            continue
        key = _metric_key(category, instance, mount)
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
    MetricSample.objects.bulk_create(samples, batch_size=1000, ignore_conflicts=True)
    return len(samples)


def capture_now() -> dict:
    """One fresh instant reading per series, across the whole business topology, right now.
    Returns {"ram": n, "cpu": n, "disk": n, "swift": n, "cob": n, "error": None} (n = samples
    written; "error" set instead if Prometheus couldn't be reached at all, matching every
    other chart builder in this app's own "never raise, one bad run doesn't take the estate
    down" pattern)."""
    from . import services

    result = {"ram": 0, "cpu": 0, "disk": 0, "swift": 0, "cob": 0, "error": None}
    try:
        prom, cfg, systems = services.live_prom_client()
    except Exception as exc:
        result["error"] = str(exc)
        return result

    import django.utils.timezone as dj_timezone

    now = dj_timezone.now()
    for category, expr in _global_expressions().items():
        try:
            rows = prom.query(expr)
        except Exception:
            continue
        result[category] = _save(_instant_rows_to_samples(rows, category, now))

    from .models import MetricSample

    for key, expr in SCALAR_METRICS.items():
        try:
            rows = prom.query(expr)
        except Exception:
            continue
        # NaN filtered here (cob_time reads NaN once its own checker script itself goes stale
        # -- see generate_report.py's own comment on that) -- a NaN sample would just be an
        # unplottable gap in the chart, and better skipped than stored.
        if rows and not math.isnan(rows[0]["value"]):
            value = max(0.0, rows[0]["value"]) if key == "swift" else rows[0]["value"]
            result[key] = _save([MetricSample(metric_key=key, taken_at=now, value=value)])
    return result


def backfill(days: int = 15) -> dict:
    """A ONE-TIME catch-up pull of every series' full history Prometheus still has, meant to be
    run once by hand (`manage.py backfill_metric_history`) right after this ships -- see this
    module's own docstring. Safe to re-run (ignore_conflicts), so re-running it after a gap
    costs nothing beyond the query time."""
    from . import services

    result = {"ram": 0, "cpu": 0, "disk": 0, "swift": 0, "cob": 0, "error": None}
    try:
        prom, cfg, systems = services.live_prom_client()
    except Exception as exc:
        result["error"] = str(exc)
        return result

    import time as _time

    end = _time.time()
    start = end - days * 24 * 3600
    for category, expr in _global_expressions().items():
        try:
            rows = prom.query_range(expr, start, end, "1h")
        except Exception:
            continue
        result[category] = _save(_range_rows_to_samples(rows, category))

    from .models import MetricSample

    for key, expr in SCALAR_METRICS.items():
        try:
            rows = prom.query_range(expr, start, end, "1h")
        except Exception:
            rows = []
        if not rows:
            continue
        samples = []
        for t, v in rows[0]["values"]:
            if math.isnan(v):
                continue
            value = max(0.0, v) if key == "swift" else v
            samples.append(MetricSample(
                metric_key=key,
                taken_at=datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc),
                value=value))
        result[key] = _save(samples)
    return result
