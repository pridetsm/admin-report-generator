"""Folder Watch: how long the oldest file has been sitting in each watched folder.

The metrics come from folder_exporter, a service on the T24 app server (10.0.212.3)
scraped directly as job `folder_exporter` on :9847. This module is the read side: one
instant query, then a verdict per folder.

WHAT REPLACED WHAT
    This screen used to read `t24_folder_checker_*`, written by a PowerShell script under
    Task Scheduler into a .prom file and re-served by the windows_exporter textfile
    collector. That arrangement had three problems this one does not:

      * a static .prom is re-served unchanged between runs, so an age written at 09:00
        still read as its 09:00 value at 09:05 — a jammed folder appeared to stop ageing,
        and the age had to be reconstructed from the run timestamp to move at all;
      * it published no total file count, only how many files were over the threshold, so
        a tile could say "3 files too old" but never "9 waiting, 3 of them too old";
      * a dead scheduled task published nothing new, yet every folder kept reading as
        drained and healthy until the staleness rule caught it.

    folder_exporter is a long-running service that scans on its own timer and serves the
    result from cache, so a scrape does no disk I/O. It publishes absolute timestamps
    rather than ages, a real file count, and per-folder health.

THE EXPOSITION THIS READS
    folder_files{target}                          files waiting in the folder
    folder_oldest_file_timestamp_seconds{target}  mtime of the oldest file — an ABSOLUTE point
    folder_newest_file_timestamp_seconds{target}  mtime of the newest file
    folder_exists{target}                         1 = the path exists and is readable
    folder_up{target}                             1 = the last scan of this folder completed
    folder_last_scan_timestamp_seconds{target}    when this folder was last walked
    folder_scan_timed_out{target}                 1 = the last scan was cut short (partial data)
    folder_size_bytes{target}                     total bytes waiting
    folder_last_file_added_timestamp_seconds{target}   when a file last appeared
    folder_files_added_total / _removed_total{target}  flow counters, since exporter start
    folder_file_age_seconds_bucket{target,le}     age distribution at the last scan
    folder_file_age_seconds_count{target}         observations in that histogram
    up{job="folder_exporter"}                     is the exporter answering at all

    Every one of these carries a `target` label naming the folder, so unlike the old
    exposition there are no run-wide metrics that have to be applied to every folder.

WHY THE AGE NO LONGER NEEDS RECONSTRUCTING
    The exporter publishes the oldest file's mtime directly, so the fixed point the tiles
    age from is a measured fact rather than `last_run_timestamp - age` arithmetic. This
    module subtracts it from `now`, and the template's script does the same from the same
    field, so the tiles keep ticking between polls and the page and the server cannot
    disagree.

WHERE THE THRESHOLD LIVES NOW — A DELIBERATE CHANGE
    The old exporter applied the operator's age limit on the host and published only the
    RESULT, so this module could honestly say it held no thresholds of its own.

    folder_exporter does not work that way: it publishes facts (ages, counts, a
    distribution) and leaves every judgement to the reader. That is the right shape for an
    exporter — the same numbers now feed Prometheus alert rules and Grafana, which need the
    raw values, not somebody else's verdict. The cost is that the line between "fine" and
    "too old" has to be drawn HERE, and AMBER_SECONDS / RED_SECONDS below are that line.
    They are the only thresholds on this screen; changing one is an edit to this file.

    The defaults match the limits the old folders.csv carried (15 min approaching, 30 min
    fault) so the screen keeps meaning what operators already read it to mean.

WHY THERE IS AN AMBER BAND NOW
    There was none before because the host published one threshold and no way to derive a
    second. With the raw ages in hand an early-warning band is simply a second comparison,
    so a folder that is drifting shows before it is a fault.

WHY A STALE READING IS NOT GREEN
    Unchanged in spirit: if the exporter stops scanning, or Prometheus stops reaching it,
    the last values linger and every folder would read as permanently drained and healthy.
    folder_last_scan_timestamp_seconds is the proof of life, per folder, and `up` is the
    proof the exporter is answering at all. Past STALE_AFTER we report "unknown" and say so
    on the tile. The one thing this screen must never do is show green for a folder nobody
    is looking at.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

import generate_report as gr   # from send_report/ (on sys.path)


# The exporter scans every 10s and Prometheus scrapes every 10s. 120s is many missed
# scans — a stopped service or an unreachable host, not one slow walk. Deliberately
# generous: marking a folder unknown because a single scrape was late would cry wolf,
# and this figure is also what the header clock turns red at.
STALE_AFTER = 120

# The age limits, in seconds. See "WHERE THE THRESHOLD LIVES NOW" above: these are the
# only thresholds this screen has. RED is a fault; AMBER is the early warning that the
# folder is drifting toward one.
#
# These are tight because these are payment queues: a message that has sat for two minutes
# has missed its window, and the consumer that should have taken it is not running. Tight
# limits are only tenable because the exporter scans every 10s and the page ages each tile
# once a second off a published timestamp — a folder crosses into red within a second or
# two of actually doing so, not at the next scrape.
#
# If you loosen these, add matching file_age_buckets_seconds entries in folder_exporter.yml
# or the "N past the limit" counts in the detail dialog quietly stop being answerable.
AMBER_SECONDS = 60      # 1 minute  — drifting
RED_SECONDS = 120       # 2 minutes — a fault

# Per-folder overrides, by the `target` label. An outbound or archive folder that
# legitimately holds files for longer belongs here rather than having the shared limits
# loosened for everybody.
#     "ALLIANCE.OUT_MX": (1800, 7200),
THRESHOLDS: Dict[str, Tuple[int, int]] = {}

# One instant query for the whole screen. Named explicitly rather than folder_.+ so the
# exporter's own self-metrics (folder_exporter_*) are not dragged in, and so adding a
# metric here is a deliberate act.
_WANTED = (
    "folder_files",
    "folder_exists",
    "folder_up",
    "folder_size_bytes",
    "folder_oldest_file_timestamp_seconds",
    "folder_newest_file_timestamp_seconds",
    "folder_last_scan_timestamp_seconds",
    "folder_last_file_added_timestamp_seconds",
    "folder_files_added_total",
    "folder_files_removed_total",
    "folder_scan_timed_out",
    "folder_file_age_seconds_bucket",
    "folder_file_age_seconds_count",
)
_QUERY = '{__name__=~"%s"} or up{job="folder_exporter"}' % "|".join(_WANTED)

# Throughput: files that have LEFT each folder SINCE MIDNIGHT, which for a queue folder is
# what "processed" means — inbound messages consumed by T24, outbound messages collected by
# the interface. The figure resets with the working day, so it reads as "handled today".
#
# Still increase() rather than the raw counter: folder_files_removed_total runs from
# exporter start, so a service restart mid-morning would drop the figure to near zero and a
# payment queue reading "processed 4" at noon is worse than no figure at all. increase()
# spans counter resets, so a restart costs nothing.
#
# The range is computed per query as the time since local midnight, so the count empties at
# 00:00 and fills through the day.
PROCESSED_WINDOW = "today"


def _processed_query(now: Optional[float] = None) -> str:
    """increase() over the window from local midnight to now.

    Floored at 15s so the range is never [0s] — invalid PromQL — in the first moments of a
    day. That floor reaches a few seconds back into yesterday, which can only matter for
    files processed in the final seconds before midnight, and only for the first quarter
    minute of the new day.
    """
    lt = time.localtime(now if now is not None else time.time())
    since_midnight = lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec
    return "increase(folder_files_removed_total[%ds])" % max(15, since_midnight)

_STATE_ORDER = {"red": 0, "amber": 1, "unknown": 2, "green": 3, "idle": 4}


class FolderWatchUnavailable(RuntimeError):
    """Prometheus itself could not be reached."""


def _prometheus():
    """The same Prometheus the rest of the app reads, honouring the Administrator's
    runtime override (Settings › Configuration) over config.ini."""
    cfg = gr.load_config()
    try:
        from .models import SystemConfig
        sc = SystemConfig.get()
        if sc.prometheus_url:
            cfg.prom = sc.prometheus_url
    except Exception:                       # noqa: BLE001 — DB/config optional here
        pass
    return gr.Prometheus(cfg.prom, cfg.http_timeout), cfg.prom


def limits_for(name: str) -> Tuple[int, int]:
    """The (amber, red) limits this folder is judged against."""
    return THRESHOLDS.get(name, (AMBER_SECONDS, RED_SECONDS))


def _fmt_age(seconds: Optional[float]) -> str:
    """A clock-style duration: 0:42 / 2:12 / 1:12:30 / 2d 3:04:11.

    Minutes AND seconds, never a rounded "2m". On an interface folder the difference between
    2:05 and 2:55 is the difference between a slow drain and a stopped consumer, and rounding
    to the minute hides exactly the movement you are watching for — a number that sits on "2m"
    for sixty seconds looks frozen, which is the one impression this screen must not give.
    """
    if seconds is None:
        return "—"
    s = int(max(0, seconds))
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m, sec = divmod(rem, 60)
    if d:
        return f"{d}d {h}:{m:02d}:{sec:02d}"
    if h:
        return f"{h}:{m:02d}:{sec:02d}"
    return f"{m}:{sec:02d}"


def _fmt_clock(epoch: Optional[float]) -> str:
    """Wall-clock time to the second — folders are re-scanned every 30s, so a
    minute-resolution stamp would make two consecutive scans look like the same one."""
    if not epoch:
        return "—"
    return time.strftime("%d %b %H:%M:%S", time.localtime(epoch))


def _fmt_bytes(n: Optional[float]) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def verdict(*, age: Optional[float], files: int, readable: bool, stale: bool,
            scan_ok: bool = True, amber_seconds: int = AMBER_SECONDS,
            red_seconds: int = RED_SECONDS) -> str:
    """The single place a folder's colour is decided.

    Mirrored byte-for-byte by the same function in the template's script so the tile the
    browser repaints each second can never disagree with the one Django rendered.
    Change one, change both.

    The judgement is made on the LIVE age — now minus the oldest file's mtime — not on
    anything precomputed at scan time. A folder therefore turns red the moment it truly
    crosses its limit rather than at the next scrape.
    """
    if stale or not readable or not scan_ok:
        return "unknown"
    if files <= 0:
        return "idle"                       # drained — the healthy steady state
    if age is not None and age >= red_seconds:
        return "red"
    if age is not None and age >= amber_seconds:
        return "amber"
    return "green"                          # files waiting, all of them fresh


def _over(buckets: Dict[float, float], total: Optional[float], limit: int) -> Optional[int]:
    """How many files were older than `limit` at the last scan.

    The histogram is cumulative, so this is total minus the bucket at the limit. It needs a
    bucket boundary at exactly `limit` (configured in folder_exporter.yml); without one
    there is no honest answer and this returns None rather than a number derived from the
    wrong boundary. The verdict never depends on it — only the detail dialog does.
    """
    if total is None or limit not in buckets:
        return None
    return max(0, int(round(total - buckets[limit])))


def _path_of(r: dict) -> List[str]:
    """The hops a message takes through this folder, in order.

    A folder with no `via` gives a two-stop path rather than a three-stop one with an
    empty middle: PAYNET feeds T24 directly, and drawing a hop there would assert a
    translation layer that does not exist. A folder with no source/destination at all
    gives an empty list, and the screen simply shows no path.
    """
    hops = [r.get("source") or "", r.get("via") or "", r.get("destination") or ""]
    return [h for h in hops if h]


def _processed_of(processed: Dict[tuple, float], instance: str, name: str):
    """Files that left this folder over the window, as a whole number.

    increase() extrapolates at the edges of the range, so it returns a float that can sit
    a little under or over the true count and can even be marginally negative on a sparse
    series. Round it, and floor at zero: "processed -0.3" would be nonsense on a tile.
    """
    v = processed.get((instance, name))
    if v is None:
        return None
    return max(0, int(round(v)))


def _collect(series: List[dict]) -> tuple:
    """Fold the flat series list into {(instance, target): {...}}, plus {instance: up}
    and {instance: display name}."""
    folders: Dict[tuple, dict] = {}
    exporter_up: Dict[str, bool] = {}
    hosts: Dict[str, str] = {}

    def row(instance: str, name: str) -> dict:
        return folders.setdefault((instance, name), {
            "name": name, "instance": instance,
            "files": 0, "size_bytes": None, "readable": True, "scan_ok": True,
            "oldest_mtime": None, "newest_mtime": None, "last_scan": None,
            "last_added": None, "added_total": None, "removed_total": None,
            "timed_out": False, "buckets": {}, "hist_total": None,
            "source": "", "via": "", "destination": "", "format": "",
        })

    for s in series:
        lbl = s.get("labels") or {}
        metric = lbl.get("__name__", "")
        instance = lbl.get("instance", "")
        value = s.get("value")

        if lbl.get("display"):
            hosts.setdefault(instance, lbl["display"])

        if metric == "up":
            exporter_up[instance] = value >= 1
            continue

        name = lbl.get("target")
        if not name:
            continue
        r = row(instance, name)

        # The message path, declared per folder in folder_exporter.yml and carried on
        # every series. Read off whichever series arrives first — they all have it.
        for k in ("source", "via", "destination", "format"):
            if not r[k] and lbl.get(k):
                r[k] = lbl[k]

        if metric == "folder_files":
            r["files"] = int(value)
        elif metric == "folder_exists":
            r["readable"] = value >= 1
        elif metric == "folder_up":
            r["scan_ok"] = value >= 1
        elif metric == "folder_size_bytes":
            r["size_bytes"] = value
        elif metric == "folder_oldest_file_timestamp_seconds":
            r["oldest_mtime"] = value
        elif metric == "folder_newest_file_timestamp_seconds":
            r["newest_mtime"] = value
        elif metric == "folder_last_scan_timestamp_seconds":
            r["last_scan"] = value
        elif metric == "folder_last_file_added_timestamp_seconds":
            r["last_added"] = value or None
        elif metric == "folder_files_added_total":
            r["added_total"] = int(value)
        elif metric == "folder_files_removed_total":
            r["removed_total"] = int(value)
        elif metric == "folder_scan_timed_out":
            r["timed_out"] = value >= 1
        elif metric == "folder_file_age_seconds_count":
            r["hist_total"] = value
        elif metric == "folder_file_age_seconds_bucket":
            le = lbl.get("le")
            if le and le != "+Inf":
                try:
                    r["buckets"][float(le)] = value
                except ValueError:
                    pass

    return folders, exporter_up, hosts


def snapshot() -> dict:
    """Every watched folder with its live verdict. One Prometheus query, no capture.

    Raises FolderWatchUnavailable when Prometheus cannot be reached — the caller shows that
    as an error page rather than an empty grid, which would read as "all folders fine".
    """
    prom, prom_url = _prometheus()
    try:
        series = prom.query(_QUERY)
    except Exception as exc:                # noqa: BLE001 — surfaced to the view
        raise FolderWatchUnavailable(f"{prom_url}: {exc}") from exc

    # Throughput is a nice-to-have, not the point of the screen: if this range query fails
    # or the range vector is empty, the grid still renders and the figure is simply absent.
    processed: Dict[tuple, float] = {}
    try:
        for s in prom.query(_processed_query()):
            lbl = s.get("labels") or {}
            name = lbl.get("target")
            if name:
                processed[(lbl.get("instance", ""), name)] = s.get("value")
    except Exception:                       # noqa: BLE001 — deliberately non-fatal
        pass

    now = time.time()
    raw, exporter_up, host_names = _collect(series)

    out: List[dict] = []
    for (instance, name), r in raw.items():
        amber_s, red_s = limits_for(name)

        last_scan = r["last_scan"]
        reachable = exporter_up.get(instance, True)
        stale = (last_scan is None) or ((now - last_scan) > STALE_AFTER) or not reachable

        files = r["files"]
        has_files = files > 0
        oldest_mtime = r["oldest_mtime"] if (r["oldest_mtime"] or 0) > 0 else None
        age = (now - oldest_mtime) if oldest_mtime else None
        scan_ok = r["scan_ok"] and not r["timed_out"]

        state = verdict(age=age, files=files, readable=r["readable"], stale=stale,
                        scan_ok=scan_ok, amber_seconds=amber_s, red_seconds=red_s)

        if not r["readable"]:
            reason = "Path not found on the host"
        elif not reachable:
            reason = "The exporter on this host is not answering — these readings are not live"
        elif r["timed_out"]:
            reason = "The last scan was cut short — this folder's figures may be incomplete"
        elif not r["scan_ok"]:
            reason = "The last scan of this folder reported an error"
        elif stale:
            reason = ("This folder has not been scanned recently — these readings are not live"
                      if last_scan else "No scan timestamp — this folder may never have been scanned")
        else:
            reason = ""

        newest_mtime = r["newest_mtime"] if (r["newest_mtime"] or 0) > 0 else None
        last_added = r["last_added"]

        out.append({
            "key": f"{instance}|{name}",
            "name": name,
            # T24 folder names are dotted (ALLIANCE.IN_MT) and have no spaces, so a browser
            # breaks them mid-token — "ALLIA / NCE". A zero-width space after each dot and
            # underscore gives it the break opportunities the name already implies, without
            # changing what the name reads as or what gets copied out of it.
            "name_wrap": name.replace(".", ".​").replace("_", "_​"),
            "instance": instance,
            "host": host_names.get(instance, instance),

            # the leg of the payment path this folder holds
            "source": r["source"],
            "via": r["via"],
            "destination": r["destination"],
            "format": (r["format"] or "").upper(),
            "path": _path_of(r),
            "path_text": " → ".join(_path_of(r)),

            # what is waiting
            "files": files,
            "has_files": has_files,
            "size_bytes": r["size_bytes"],
            "size_text": _fmt_bytes(r["size_bytes"]),
            "over_amber": _over(r["buckets"], r["hist_total"], amber_s),
            "over_red": _over(r["buckets"], r["hist_total"], red_s),

            # the fixed points the browser ages from
            "oldest_mtime": oldest_mtime,
            "newest_mtime": newest_mtime,
            "age": None if age is None else int(age),
            "age_text": _fmt_age(age),
            "newest_age": None if newest_mtime is None else int(now - newest_mtime),

            # flow
            "last_added": last_added,
            "since_added": None if not last_added else int(now - last_added),
            "added_total": r["added_total"],
            "removed_total": r["removed_total"],
            # files that left this folder since midnight — the throughput figure on the
            # tile. None when the range query gave nothing, so the tile omits it rather
            # than showing a zero it cannot stand behind.
            "processed": _processed_of(processed, instance, name),
            "processed_window": PROCESSED_WINDOW,

            # health
            "readable": r["readable"],
            "scan_ok": scan_ok,
            "timed_out": r["timed_out"],
            "reachable": reachable,
            "checked_at": last_scan,
            "checked_at_text": _fmt_clock(last_scan),
            "since_check": None if last_scan is None else int(now - last_scan),
            "stale": stale,
            "state": state,
            "reason": reason,

            # the limits this folder is judged against, so the tile can explain itself
            "amber_seconds": amber_s,
            "red_seconds": red_s,
            "limit_text": _fmt_age(red_s),
        })

    # Stable alphabetical order, NOT worst-first: tiles that reshuffle every poll destroy the
    # muscle memory of "PAYNET.IN lives there". Severity is carried by colour, which is the
    # whole point of the layout, and the toolbar can filter to problems only.
    out.sort(key=lambda f: (f["host"].lower(), f["name"].lower()))

    counts = {k: 0 for k in ("red", "amber", "green", "idle", "unknown")}
    for f in out:
        counts[f["state"]] += 1

    worst = min((f for f in out), key=lambda f: _STATE_ORDER[f["state"]], default=None)
    breached = [f for f in out if f["state"] == "red"]

    # The NEWEST scan across folders: "how long ago did fresh data last arrive", which is
    # what a reader takes a ticking clock in the header to mean. It resets each time a
    # scrape lands, so it counts 0 -> one scan interval and starts again.
    #
    # This was the oldest scan, on the reasoning that the header should not let one stalled
    # folder hide behind four current ones. It read badly: because a folder's timestamp is
    # already up to one scrape old, the oldest of five never returned to zero and the clock
    # swept a whole interval ABOVE where a reader expects it to start. The safety property
    # is not lost — staleness is evaluated per folder against that folder's own timestamp,
    # so a folder that stops being scanned still turns unknown and dashed on its own tile
    # and is counted in the Unknown pill, whatever this header says.
    scans = [f["checked_at"] for f in out if f["checked_at"]]
    last_run = max(scans) if scans else None

    return {
        "ok": True,
        "now": now,
        "now_text": _fmt_clock(now),
        "prom_url": prom_url,
        "stale_after": STALE_AFTER,
        "amber_seconds": AMBER_SECONDS,
        "red_seconds": RED_SECONDS,
        # Human-readable forms for the prose on the page: "passed 120 seconds" reads worse
        # than "passed 2:00", and worse still once a limit is measured in hours.
        "amber_text": _fmt_age(AMBER_SECONDS),
        "red_text": _fmt_age(RED_SECONDS),
        "processed_window": PROCESSED_WINDOW,
        "processed_total": sum(f["processed"] or 0 for f in out),
        "folders": out,
        "counts": counts,
        "total": len(out),
        "hosts": sorted({f["host"] for f in out}),
        "attention": counts["red"] + counts["amber"] + counts["unknown"],
        "worst_state": worst["state"] if worst else "idle",
        # the single oldest breach — the headline number when something is wrong
        "worst_folder": max(breached, key=lambda f: f["age"] or 0, default=None),
        "files_waiting": sum(f["files"] for f in out),
        # scan facts, surfaced on the page
        "last_run": last_run,
        "last_run_text": _fmt_clock(last_run),
        "since_last_run": None if last_run is None else int(now - last_run),
        "run_ok": all(f["scan_ok"] for f in out) if out else True,
        "exporter_up": all(exporter_up.values()) if exporter_up else True,
    }
