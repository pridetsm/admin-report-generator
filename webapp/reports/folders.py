"""Folder Watch: how long the oldest file has been sitting in each watched folder.

The metrics come from the T24 folder checker on the T24 app server (10.0.212.3), via the
windows_exporter textfile collector. This module is the read side: one instant query, then
a verdict per target.

THE EXPOSITION THIS READS
    t24_folder_checker_stale_files_count{target}      files older than the host's threshold
    t24_folder_checker_oldest_file_age_seconds{target} age of the oldest file AT THE LAST RUN
    t24_folder_checker_path_found{target}             1 = path exists, 0 = missing/unreadable
    t24_folder_checker_last_run_success                1 = the run completed without errors
    t24_folder_checker_last_run_timestamp_seconds      when that run happened

    The last two carry NO target label — they describe the run, not a folder, so they apply
    to every target on that instance.

WHY THE AGE IS TURNED BACK INTO A TIMESTAMP
    The exporter publishes an AGE, but a .prom file is static between runs: an age written
    at 09:00 still reads as its 09:00 value at 09:05, so a jammed folder would appear to stop
    ageing. Since the run's own timestamp is published alongside it, the mtime it was measured
    from is recoverable exactly:

        oldest_mtime = last_run_timestamp - oldest_file_age

    Everything downstream then works off that fixed point — this module subtracts it from
    `now`, and app.js in the template does the same arithmetic from the same field, so the
    tiles keep ticking between polls and the page and the server can never disagree.

WHY THE VERDICT TRUSTS stale_files_count
    This exporter applies the operator's age threshold on the host and publishes the RESULT
    (how many files are over it) rather than the threshold itself. So the line between "fine"
    and "too old" is already drawn, on the server, by whoever configured it — and this module
    keeps its long-standing rule of never carrying a second copy of that configuration. There
    is no amber band, because there is no second threshold to derive one from.

WHY A STALE CHECK IS NOT GREEN
    The textfile collector re-serves the last .prom forever, so if the scheduled task dies
    every folder would read as permanently drained and healthy.
    t24_folder_checker_last_run_timestamp_seconds is the proof of life; past STALE_AFTER we
    report "unknown" and say so on the tile. The one thing this screen must never do is show
    green for a folder nobody is looking at.

WHAT THIS EXPORTER CANNOT TELL US
    There is no total file count — only the count of files OVER the threshold. So a tile can
    say "3 files too old", never "9 waiting, 3 of them too old". Presence of any file at all
    is inferred from a non-zero age, which means a file written in the same second as the run
    is indistinguishable from an empty folder until the next run.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

import generate_report as gr   # from send_report/ (on sys.path)


# The check runs about every 2 minutes. 15 minutes is several missed runs — a dead task,
# not a slow one.
STALE_AFTER = 900

# Every series the exporter emits, in one instant query.
_QUERY = '{__name__=~"t24_folder_checker_.+"}'

# Metrics that describe the RUN rather than a folder — they carry no `target` label.
_RUN_METRICS = ("t24_folder_checker_last_run_timestamp_seconds",
                "t24_folder_checker_last_run_success")

_STATE_ORDER = {"red": 0, "unknown": 1, "amber": 2, "green": 3, "idle": 4}


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
    """Wall-clock time of a run, to the second — the cadence here is ~2 minutes, so a
    minute-resolution stamp would make two consecutive runs look like the same one."""
    if not epoch:
        return "—"
    return time.strftime("%d %b %H:%M:%S", time.localtime(epoch))


def verdict(*, stale_files: int, has_files: bool, readable: bool,
            stale: bool, run_ok: bool = True) -> str:
    """The single place a folder's colour is decided.

    Mirrored byte-for-byte by the same function in the template's script so the tile the
    browser repaints each second can never disagree with the one Django rendered.
    Change one, change both.

    There is no amber: the host publishes how many files are already over its threshold,
    not the threshold, so there is nothing to compare against for an early warning.
    """
    if stale or not readable or not run_ok:
        return "unknown"
    if stale_files > 0:
        return "red"                        # past the limit the host itself applies
    if not has_files:
        return "idle"                       # drained — the healthy steady state
    return "green"                          # files waiting, none of them over the line


def _collect(series: List[dict]) -> tuple:
    """Fold the flat series list into {(instance, target): {...}} plus the per-instance run
    facts {instance: checked_at} and {instance: run_ok}.

    Keying by (instance, target) also DEDUPES: 10.0.212.3:9182 is scraped by two jobs
    (`windows_exporter` and the hourly `swift_transactions`), so every textfile series on
    that host arrives twice under different `job` labels. Both copies come from the same
    .prom, so collapsing them on this key is exact, not a guess.
    """
    folders: Dict[tuple, dict] = {}
    checked: Dict[str, float] = {}
    run_ok: Dict[str, bool] = {}
    hosts: Dict[str, str] = {}

    for s in series:
        lbl = s.get("labels") or {}
        metric = lbl.get("__name__", "")
        instance = lbl.get("instance", "")
        value = s.get("value")

        if lbl.get("display"):
            hosts.setdefault(instance, lbl["display"])

        if metric == "t24_folder_checker_last_run_timestamp_seconds":
            # keep the NEWEST across jobs — an hourly job's copy of the file can lag
            checked[instance] = max(checked.get(instance, 0.0), value)
            continue
        if metric == "t24_folder_checker_last_run_success":
            # a failed run anywhere in the pair is a failed run
            run_ok[instance] = run_ok.get(instance, True) and value >= 1
            continue

        name = lbl.get("target")
        if not name:
            continue
        row = folders.setdefault((instance, name), {
            "name": name, "instance": instance,
            "stale_files": 0, "age_at_run": None, "readable": True,
        })

        if metric == "t24_folder_checker_stale_files_count":
            row["stale_files"] = int(value)
        elif metric == "t24_folder_checker_oldest_file_age_seconds":
            row["age_at_run"] = value
        elif metric == "t24_folder_checker_path_found":
            row["readable"] = value >= 1

    return folders, checked, run_ok, hosts


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

    now = time.time()
    raw, checked, run_flags, host_names = _collect(series)

    out: List[dict] = []
    for (instance, name), row in raw.items():
        checked_at = checked.get(instance)
        ok = run_flags.get(instance, True)
        stale = checked_at is None or (now - checked_at) > STALE_AFTER

        # Recover the fixed point the age was measured from, so the browser can go on
        # ageing it between polls (see the module docstring).
        age_at_run = row["age_at_run"]
        has_files = bool(age_at_run and age_at_run > 0)
        oldest_mtime = (checked_at - age_at_run) if (has_files and checked_at) else None
        age = (now - oldest_mtime) if oldest_mtime else None

        state = verdict(stale_files=row["stale_files"], has_files=has_files,
                        readable=row["readable"], stale=stale, run_ok=ok)

        if not row["readable"]:
            reason = "Path not found on the host"
        elif not ok:
            reason = "The last folder check reported an error — these readings may be incomplete"
        elif stale:
            reason = ("The folder check has not run recently — these readings are not live"
                      if checked_at else "No check timestamp — the folder check may never have run")
        else:
            reason = ""

        out.append({
            "key": f"{instance}|{name}",
            "name": name,
            # T24 folder names are dotted (F.DE.O.MSG.ALLIANCE) and have no spaces, so a
            # browser breaks them mid-token — "ALLIA / NCE". A zero-width space after each
            # dot gives it the break opportunities the name already implies, without
            # changing what the name reads as or what gets copied out of it.
            "name_wrap": name.replace(".", ".​"),
            "instance": instance,
            "host": host_names.get(instance, instance),
            "stale_files": row["stale_files"],
            "has_files": has_files,
            "age_at_run": age_at_run,
            "oldest_mtime": oldest_mtime,
            "readable": row["readable"],
            "run_ok": ok,
            "checked_at": checked_at,
            "checked_at_text": _fmt_clock(checked_at),
            "stale": stale,
            "state": state,
            "age": None if age is None else int(age),
            "age_text": _fmt_age(age),
            "since_check": None if checked_at is None else int(now - checked_at),
            "reason": reason,
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
    last_run = max(checked.values(), default=None)

    return {
        "ok": True,
        "now": now,
        "now_text": _fmt_clock(now),
        "prom_url": prom_url,
        "stale_after": STALE_AFTER,
        "folders": out,
        "counts": counts,
        "total": len(out),
        "hosts": sorted({f["host"] for f in out}),
        "attention": counts["red"] + counts["amber"] + counts["unknown"],
        "worst_state": worst["state"] if worst else "idle",
        # the single oldest breach — the headline number when something is wrong
        "worst_folder": max(breached, key=lambda f: f["age"] or 0, default=None),
        # run facts, surfaced on the page: when the host last looked, and whether it worked
        "last_run": last_run,
        "last_run_text": _fmt_clock(last_run),
        "since_last_run": None if last_run is None else int(now - last_run),
        "run_ok": all(run_flags.values()) if run_flags else True,
    }
