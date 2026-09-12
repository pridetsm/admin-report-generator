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

    The defaults originally matched the limits the old folders.csv carried; revised since (see
    AMBER_SECONDS / RED_SECONDS' own comment, 2026-09-04) once real operation showed the
    original fault line firing on folders that were still legitimately draining, not stuck.

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

# The BACKUP_HOST_INSTANCES exporter (2026-09-04, confirmed via 6h of
# folder_last_scan_timestamp_seconds history) walks its folders roughly once an HOUR, not
# every 10s like the interface host — there is no reason to re-walk a backup drive every
# scrape, and its own scan_interval_seconds is configured accordingly on that host. Judged
# against the payment-queue STALE_AFTER above, every one of its folders would sit "stale" for
# the ~59 minutes between scans and never once read as live — the dashed/faded "not being
# told" treatment this screen reserves for a genuinely stopped exporter, on folders whose
# exporter was never more current (on request, 2026-09-04: "remove the dotted lines for this
# folders"). 3x the observed cadence is the same "many missed scans, not one slow walk"
# margin STALE_AFTER's own 120s already uses (12x its 10s scan interval) — generous enough
# to absorb a late scan without ever being generous enough to hide a truly stopped exporter
# for most of a working day.
STALE_AFTER_BACKUP = 3 * 3600

# The age limits, in seconds. See "WHERE THE THRESHOLD LIVES NOW" above: these are the
# only thresholds this screen has. RED is a fault; AMBER is the early warning that the
# folder is drifting toward one.
#
# Loosened from 60s/120s to 300s/600s (2026-09-04, on request: "currently some folders are
# not draining please set drainage alert at 10 minutes for payment and interface queues") --
# the original 2-minute fault line was firing on folders that were legitimately still
# draining, not stuck; 10 minutes is the point an operator actually wants telling about.
# AMBER stays at half of RED, the same ratio the original 60s/120s pair used, so there is
# still real lead time between "drifting" and "a fault" rather than the two firing together.
#
# These are now just the SHIPPED DEFAULTS -- admin-editable at Configuration > Alerts >
# Drainage thresholds (models.DrainageThresholdConfig, see _queue_limits()), on request
# (2026-09-04: "there needs to be a way to specify per alert type configuration"). Nothing in
# this module reads these two names directly any more except verdict()'s own default kwargs
# (never actually relied on -- every real caller passes explicit amber_seconds/red_seconds).
#
# If you loosen these further (here or via the config screen), add a matching
# file_age_buckets_seconds boundary in the REMOTE folder_exporter.yml (the T24 host, not this
# repo's own deploy/gms/folder_exporter.yml -- this app has no file access to it, see
# BACKUP_HOST_INSTANCES' own comment) or the "N past the limit" counts in the detail dialog
# quietly stop being answerable (_over() returns None when the exact threshold isn't one of
# the exporter's own bucket boundaries) -- the live verdict/colour above is unaffected either
# way, since that's computed straight from age vs. threshold, not from the histogram.
AMBER_SECONDS = 300     # 5 minutes  — drifting
RED_SECONDS = 600       # 10 minutes — a fault

# Per-folder overrides, by the `target` label. An outbound or archive folder that
# legitimately holds files for longer belongs here rather than having the shared limits
# loosened for everybody.
#     "ALLIANCE.OUT_MX": (1800, 7200),
THRESHOLDS: Dict[str, Tuple[int, int]] = {}

# Folder-exporter TARGETS (not individual folders) known to hold BACKUP-type folders -- a
# whole host dedicated to backup/log storage, not a per-folder name list, so a new folder
# added under an already-classified target (e.g. a second archive) is backup-type
# automatically, with no edit needed here. Manually maintained, same spirit as THRESHOLDS
# above. The REMOTE T24 folder_exporter.yml DOES now carry a `role:` label per folder
# (confirmed live, 2026-09-04: `role: backup` on BACKUP/BACKUP.LOGS, `role: logging` on T24
# Log File, `kind: logs` on the two log-shaped ones) -- used below for the
# backup/logs/size-only split WITHIN this set, but this set itself stays the membership test
# for "is this host on the slower backup-style scan cadence at all" (drives
# STALE_AFTER_BACKUP and backup_drain_limits), since a role label says what KIND of folder
# something is, not what CADENCE its host scans on.
BACKUP_HOST_INSTANCES = {"10.0.212.4:9847"}   # "Temenos/T24 Backup & Log Folders" -- confirmed live


def _stale_after_for(instance: str) -> int:
    """How long since the last scan before this folder reads as unknown/stale -- see
    STALE_AFTER_BACKUP's own comment for why a BACKUP_HOST_INSTANCES folder needs a far more
    generous window than the payment-queue default."""
    return STALE_AFTER_BACKUP if instance in BACKUP_HOST_INSTANCES else STALE_AFTER


def _log_file_expected_bytes(prom, instance: str, name: str) -> Optional[float]:
    """Expected size in BYTES for a log-FILE folder (generate_report.FOLDER_EXPECTED_PCT) --
    a fraction of the TOTAL capacity of the volume it lives on, the exact rule
    generate_report.folder_expected_gb applies for the daily/e-mailed report (same source of
    truth -- FOLDER_EXPECTED_PCT -- reused here rather than a second number to keep in sync).

    The volume's size is published by windows_exporter on the HOST itself, a different port
    than folder_exporter's own -- matched by IP rather than exact instance, the same
    source_ip approach generate_report.py's own log_files capture uses (see its comment: "a
    folder_exporter instance label never matches a Component's directly -- just its IP
    does"). One extra lightweight instant query, only ever run for a name actually listed in
    FOLDER_EXPECTED_PCT (today: just one), and only from snapshot() -- never on the
    once-a-second client-side repaint, since a volume's total capacity does not change
    between polls the way a file's age would.

    None on any failure (query error, no matching series) -- the caller reads that as "can't
    judge this one right now" (state "unknown"), never as "must be under its limit"."""
    cfg = gr.FOLDER_EXPECTED_PCT.get(name)
    if cfg is None:
        return None
    mount, pct = cfg
    source_ip = instance.split(":")[0]
    try:
        rows = prom.query(f'windows_logical_disk_size_bytes{{instance=~"{source_ip}:.*",volume="{mount}"}}')
    except Exception:      # noqa: BLE001 -- degrades to "expected size unknown" for the caller
        return None
    if not rows:
        return None
    return rows[0]["value"] * pct

# The dashboard's own grouping (2026-09-04, on request: "grouped according to the type of
# monitoring being done") -- every watched folder is EITHER a payment/interface drop folder,
# drained against the tight fixed AMBER_SECONDS/RED_SECONDS above because a stuck message
# queue is a fault within minutes, OR one of two kinds of folder on a BACKUP_HOST_INSTANCES
# host, still drained against that system's own backup cadence either way
# (backup_drain_limits -- unchanged by this split, see limits_for's own comment) because a
# healthy daily backup is EXPECTED to sit there for the better part of a day.
#
# Backup and log folders were one combined group at first, then split (2026-09-04, on
# request: "backup and log folders should be separate groups as backup folder drainage
# should still be monitored") -- a shared heading was reading as "these get watched the
# same casual way", when the point of keeping them under Drainage Monitoring at all is that
# an actual backup folder going stuck is exactly as real a fault as a payment queue, just on
# a slower clock. There is still no config-side `role:` label to key off (see
# BACKUP_HOST_INSTANCES' own comment on why), so the log/backup split within a backup-host
# instance prefers the exporter's own `kind: logs` label (confirmed live), falling back to a
# NAME heuristic only when that label is absent. "BACKUP.LOGS" is a folder of rotated,
# discrete log files -- genuinely drains, same as a backup; "BACKUP" itself is plain backup.
# A "log FOLDER" like that is NOT the same thing as a "log FILE folder" like "T24 Log File"
# -- ONE continuously-appended file that never drains at all. It still belongs ON this
# dashboard (on request, 2026-09-04: "i no longer see log file folders... t24 log file" --
# it had been excluded outright the first time this was split out), just in its OWN group,
# judged by SIZE against its volume's own capacity rather than by file age (see the
# snapshot() loop's own comment). (key, label, hint) in the fixed order the dashboard always
# presents them.
WATCH_TYPES = [
    ("queue", "Payment & interface queues",
     "Message drop folders drained by an interface or T24 itself -- a stuck one has missed its window within minutes."),
    ("backup", "Backup folders",
     "Backup drop locations on their own backup cadence, not a payment SLA -- a healthy one can sit for the better part of a day."),
    ("logs", "Log folders",
     "Log drop locations on the same backup-host cadence as the backup folders above, watched separately so a stuck log doesn't read as a stuck backup."),
    ("logfiles", "Log file folders",
     "A continuously-written file, never expected to empty -- watched by size against the volume it lives on, not by how long anything has been waiting."),
]

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
    return gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls), cfg.prom


def _queue_limits() -> Tuple[int, int]:
    """(amber, red) for payment/interface queue folders -- admin-editable at
    Configuration > Alerts > Drainage thresholds (models.DrainageThresholdConfig), on request
    (2026-09-04: "there needs to be a way to specify per alert type configuration"). Read
    fresh every call -- a single PK=1 row, cheap -- the same live-read approach
    backup_drain_limits already uses, so a saved change takes effect on the very next
    poll/page load, no restart needed."""
    from .models import DrainageThresholdConfig
    return DrainageThresholdConfig.get().effective_seconds


def limits_for(name: str, *, instance: str = "", system: str = "") -> Tuple[int, int]:
    """The (amber, red) limits this folder is judged against.

    A per-folder THRESHOLDS override wins outright if one exists (an explicit, named
    exception for one folder). Otherwise, if this folder's exporter TARGET is a known
    backup-type host (BACKUP_HOST_INSTANCES), its window is intuited from `system`'s own
    backup policy rather than the admin-configured payment-queue pair -- see
    backup_drain_limits' own docstring for why. Everything else uses _queue_limits()."""
    if name in THRESHOLDS:
        return THRESHOLDS[name]
    if instance in BACKUP_HOST_INSTANCES:
        return backup_drain_limits(system)
    return _queue_limits()


def backup_drain_limits(system_name: str) -> Tuple[int, int]:
    """(amber, red) seconds for a backup-type folder belonging to `system_name`, intuited
    from that system's OWN backup policy (reports/backup_policy_admin.py) rather than the
    generic payment-queue limits -- a daily backup's file is expected to still be sitting
    there right up until tomorrow's lands, so 60s/120s would flag every healthy backup as
    stuck the moment it landed. PUBLIC (no leading underscore) -- reports/views.py's own
    Per Alert Config > Backup drainage monitoring table calls this directly, per system, to
    show what "automatic" currently means for each one (2026-09-04: "show all systems and
    their current values as intuited from backup policy here").

    A watched folder isn't tied to one specific backed-up HOST -- folder_exporter has no such
    label, since the folder is a shared drop location, not one host's own metrics -- only to
    a SYSTEM, via the exporter target's own `system:` label (see limits_for's caller). When
    every instance in that system agrees on the same drain window, that's an honest,
    unambiguous answer; when they disagree (a system mixing daily and every-3rd-day hosts
    sharing one backup folder), or the system has no instances/policy at all, the documented
    fallback -- DEFAULT_FOLDER_DRAIN_HOURS, 24h, "where ambiguous assume the files must be
    cleared within 24 hrs" -- applies rather than guessing which host's cadence the shared
    folder actually follows.

    Amber is 75% of the red deadline -- an early-warning band that scales with the window
    itself (an hour's warning suits a 24h window; it's noise on a week-long one) -- computed
    from whichever red applies, automatic or overridden below.

    `DrainageThresholdConfig.backup_red_seconds_overrides` is a PER-SYSTEM admin override
    (2026-09-04: "these overrides for backup are done at system level" -- each system's own
    cadence already produces a different automatic value, so one flat number for every system
    was the wrong shape) -- `system_name`'s own entry, if present, replaces the auto-computed
    red outright; every other system is unaffected."""
    from . import backup_policy_admin
    from .models import BackupPolicyRevision, DrainageThresholdConfig

    try:
        cfg = gr.load_config()
        topo_systems = gr.load_topology(cfg.prometheus_yml, scope="all")
    except Exception:      # noqa: BLE001 -- topology/config errors already surface on their
        topo_systems = []  # own screens; this degrades to the documented 24h fallback below.

    sysm = next((s for s in topo_systems if s.name == system_name), None)
    if sysm is None or not sysm.components:
        red = backup_policy_admin.DEFAULT_FOLDER_DRAIN_HOURS * 3600
    else:
        rev = BackupPolicyRevision.current()
        policy = rev.policy if rev is not None else backup_policy_admin.parse_live_policy()
        hours = set()
        for c in sysm.components:
            entry = policy.get(c.instance, {})
            days = entry.get(backup_policy_admin.FREQUENCY_FIELD,
                             backup_policy_admin.DEFAULT_FREQUENCY_DAYS)
            hours.add(entry.get(backup_policy_admin.FOLDER_DRAIN_HOURS_FIELD,
                                backup_policy_admin.intuited_drain_hours(days)))
        red = (hours.pop() * 3600) if len(hours) == 1 else backup_policy_admin.DEFAULT_FOLDER_DRAIN_HOURS * 3600

    override = (DrainageThresholdConfig.get().backup_red_seconds_overrides or {}).get(system_name)
    if override:
        red = override
    return round(red * 0.75), red


def backup_drainage_systems() -> set:
    """System names with at least one CURRENTLY LIVE backup/logs-type folder -- used only to
    decide which rows in the per-system backup drainage override table (Per Alert Config)
    render greyed out vs live (2026-09-04: "show all systems... even though the live data not
    there you may gray out these systems but add them"). Never raises -- a Prometheus hiccup
    here greys out the whole table rather than breaking Per Alert Config."""
    try:
        data = snapshot()
    except FolderWatchUnavailable:
        return set()
    return {f["system"] for f in data["folders"]
           if f["watch_type"] in ("backup", "logs") and f.get("system")}


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
    """Fold the flat series list into {(instance, target): {...}}, plus {instance: up},
    {instance: display name}, and {instance: system} -- the exporter TARGET's own `system:`
    static label (same mechanism as `display`), used to intuit a backup-type folder's drain
    window from that system's own backup policy (see backup_drain_limits)."""
    folders: Dict[tuple, dict] = {}
    exporter_up: Dict[str, bool] = {}
    hosts: Dict[str, str] = {}
    systems_by_instance: Dict[str, str] = {}

    def row(instance: str, name: str) -> dict:
        return folders.setdefault((instance, name), {
            "name": name, "instance": instance,
            "files": 0, "size_bytes": None, "readable": True, "scan_ok": True,
            "oldest_mtime": None, "newest_mtime": None, "last_scan": None,
            "last_added": None, "added_total": None, "removed_total": None,
            "timed_out": False, "buckets": {}, "hist_total": None,
            "source": "", "via": "", "destination": "", "format": "",
            "role": "", "kind": "",
        })

    for s in series:
        lbl = s.get("labels") or {}
        metric = lbl.get("__name__", "")
        instance = lbl.get("instance", "")
        value = s.get("value")

        if lbl.get("display"):
            hosts.setdefault(instance, lbl["display"])
        if lbl.get("system"):
            systems_by_instance.setdefault(instance, lbl["system"])

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

        # role/kind: the REMOTE folder_exporter.yml's own declared classification for this
        # folder (confirmed live, 2026-09-04 -- `role: backup`/`role: logging`, `kind: logs`
        # on the two log-shaped ones), used by snapshot() for the backup/logs watch-type
        # split instead of guessing from the folder's NAME.
        for k in ("role", "kind"):
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

    return folders, exporter_up, hosts, systems_by_instance


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
    raw, exporter_up, host_names, systems_by_instance = _collect(series)

    out: List[dict] = []
    for (instance, name), r in raw.items():
        # A "log FILE folder" (generate_report.FOLDER_EXPECTED_PCT -- today just "T24 Log
        # File") holds ONE continuously-appended file, not a batch of discrete files a
        # consumer clears out -- it is never expected to "drain" the way a backup or payment
        # folder does, so judging it by oldest-file AGE is the wrong axis entirely. It gets
        # its OWN watch_type ("logfiles") and its state is judged by SIZE instead (see
        # _log_file_expected_bytes), the same rule generate_report's own Size Monitoring
        # applies -- a "log FOLDER" like BACKUP.LOGS (plural, rotated, genuinely drains) is a
        # completely different thing and is NOT covered by this branch.
        is_log_file = name in gr.FOLDER_EXPECTED_PCT
        amber_s, red_s = limits_for(name, instance=instance,
                                    system=systems_by_instance.get(instance, ""))
        if is_log_file:
            watch_type = "logfiles"
        elif instance not in BACKUP_HOST_INSTANCES:
            watch_type = "queue"
        elif r["kind"] == "logs" or (not r["kind"] and "log" in name.lower()):
            # Prefer the exporter's own `kind: logs` label (confirmed live on BACKUP.LOGS);
            # the name check is only a fallback for a folder with no kind label at all yet.
            watch_type = "logs"
        else:
            watch_type = "backup"

        last_scan = r["last_scan"]
        reachable = exporter_up.get(instance, True)
        stale = (last_scan is None) or ((now - last_scan) > _stale_after_for(instance)) or not reachable

        files = r["files"]
        has_files = files > 0
        oldest_mtime = r["oldest_mtime"] if (r["oldest_mtime"] or 0) > 0 else None
        age = (now - oldest_mtime) if oldest_mtime else None
        scan_ok = r["scan_ok"] and not r["timed_out"]

        size_expected_bytes = None
        size_pct = None
        if is_log_file:
            if not r["readable"] or not reachable or not scan_ok or stale:
                state = "unknown"
            else:
                size_expected_bytes = _log_file_expected_bytes(prom, instance, name)
                if size_expected_bytes is None or r["size_bytes"] is None:
                    state = "unknown"
                else:
                    size_pct = (r["size_bytes"] / size_expected_bytes) * 100 if size_expected_bytes else None
                    # Always a WARNING, never critical, however far over -- matches
                    # generate_report.folder_over_expected_detail's own rule exactly: this is
                    # "keep an eye on it" (a log not being rotated), not an outage.
                    state = "amber" if r["size_bytes"] > size_expected_bytes else "green"
        else:
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
        elif is_log_file and state == "unknown":
            # Every other "why can't we judge this" cause (unreadable/unreachable/timed
            # out/not scanning/stale) was already handled above -- reaching here with
            # state == "unknown" leaves exactly one cause: _log_file_expected_bytes came
            # back empty (the volume-size series wasn't found this poll).
            reason = "Expected size for this file's volume is not currently available"
        elif is_log_file and state == "amber":
            reason = "This file has grown past its expected share of the volume it lives on"
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
            "system": systems_by_instance.get(instance, ""),
            "watch_type": watch_type,

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

            # log-FILE folders only (watch_type == "logfiles") -- size against a fraction of
            # the volume's own total capacity, see _log_file_expected_bytes.
            "size_expected_bytes": size_expected_bytes,
            "size_expected_text": _fmt_bytes(size_expected_bytes),
            "size_pct": None if size_pct is None else round(size_pct),

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
            "stale_after": _stale_after_for(instance),
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

    # Grouped by WATCH_TYPES -- see that constant's own docstring for why "queue" vs "backup"
    # is the grouping and not, say, per-host: a group with no folders in it (today: never,
    # both are live) is simply omitted rather than rendered as an empty heading, the same
    # "don't show what isn't there" stance _config_context's own nav takes.
    groups = [
        {"key": key, "label": label, "hint": hint, "folders": [f for f in out if f["watch_type"] == key]}
        for key, label, hint in WATCH_TYPES
    ]

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

    # The header/help-text prose describes the QUEUE pair specifically (backup/log folders
    # already explain their own, different window inline on each tile) -- read live so a
    # saved Configuration > Alerts > Drainage thresholds change is reflected here too, not
    # just in the live verdict.
    queue_amber, queue_red = _queue_limits()

    return {
        "ok": True,
        "now": now,
        "now_text": _fmt_clock(now),
        "prom_url": prom_url,
        "stale_after": STALE_AFTER,
        "amber_seconds": queue_amber,
        "red_seconds": queue_red,
        # Human-readable forms for the prose on the page: "passed 120 seconds" reads worse
        # than "passed 2:00", and worse still once a limit is measured in hours.
        "amber_text": _fmt_age(queue_amber),
        "red_text": _fmt_age(queue_red),
        "processed_window": PROCESSED_WINDOW,
        "processed_total": sum(f["processed"] or 0 for f in out),
        "folders": out,
        "groups": groups,
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


def folder_watch_systems(prometheus_yml: str) -> set:
    """System names with at least one folder_exporter target -- i.e. systems this screen
    (and reports.alerting's "folder"/"undrained_folders" categories, which read the identical
    job) can actually say anything about at all (today: just Temenos, confirmed live -- the
    folder_exporter job's only two targets are both `system: Temenos`).

    A static, local-file read of prometheus.yml's OWN folder_exporter job, not a live
    Prometheus call: this job's `system:` label is a real, declared fact about the topology
    (unlike a backup check, which has no config-side declaration at all and is only ever
    visible from a live capture) -- it just lives under a job type gr.load_topology's own
    System/Component grouping deliberately excludes (a folder watch isn't a "component"), so
    it needs this small, targeted parse instead of reusing that function.

    Shared by reports.views (per-system category-grid applicability) and reports.alerting
    (which systems an undrained-folder Flag should be attributed to) -- moved here from
    views.py (2026-09-04) so alerting.py isn't reaching into a view module for it.
    """
    import yaml
    try:
        with open(prometheus_yml, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except Exception:      # noqa: BLE001 -- same degrade-to-"can't tell" stance as callers;
        return set()       # a broken topology file already surfaces on Configuration > Topology.
    out = set()
    for job in doc.get("scrape_configs", []) or []:
        if job.get("job_name") != "folder_exporter":
            continue
        for sc in job.get("static_configs", []) or []:
            system = (sc.get("labels", {}) or {}).get("system")
            if system:
                out.add(str(system).strip())
    return out
