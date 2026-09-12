"""SYSTEM ALERT notifications -- a THIRD, separate notification type alongside alerts
(reports.alerting: is a monitored VALUE currently over a threshold) and events
(reports.events: did a discrete thing HAPPEN once). This one answers a different question
again: "is our own monitoring pipeline still telling the truth" (2026-09-05, on request: the
T24 TSA services checker's own textfile source had gone stale for 12+ days -- t24_service_up
kept reporting "all 12 services running" the entire time, because the Prometheus SCRAPE of
windows_exporter's textfile collector never failed, only the checker script actually
rewriting the underlying t24_services.prom file did. Nothing anywhere was watching the
FILE'S OWN age, only the values it last happened to contain, so a dead checker read back as
"everything is fine" for as long as it stayed dead).

A FreshnessCheck (reports.models) names one windows_exporter textfile-collector source --
windows_textfile_mtime_seconds{instance=..., file=...} -- and how old its own last write is
allowed to get before it's considered stale. This is deliberately GENERAL, not a one-off T24
fix: any future checker script that silently stops writing fresh data gets caught the same
way, by adding one more FreshnessCheck row, not by writing a second bespoke watchdog.

OPTIONALLY (2026-09-05, after a follow-up investigation): a FreshnessCheck can also name the
folder_exporter scheduler job responsible for producing it (scheduler_instance/
scheduler_job). That investigation found t24_service_checker's own job-scheduler metrics
(scheduler_job_last_success_timestamp_seconds, scheduler_job_last_exit_code) reporting
PERFECT health -- exit_code=0, "ok" on every one of 3518 runs, most recent success SECONDS
before the alert fired -- while the file that job is supposed to produce hadn't moved in 12+
days. The job scheduler and the file it produces can tell two completely different stories:
a script can run, exit 0, and never reach its own write step. When both scheduler fields are
set, _scheduler_last_success surfaces that job's own last success timestamp alongside the
file's staleness in the alert e-mail itself, so "job says healthy, file says stale" is
visible without a manual cross-query.

There is no severity to escalate here (a checker is either fresh or it isn't) and nothing
like a Monitoring Alert group's capped daily schedule -- staleness reminders are PERSISTENT,
exactly reports.alerting._decide's own imminent branch: every
AlertGroup.effective_system_reminder_minutes, forever, until the file starts updating again.

Groups are plain AlertGroup rows (2026-09-05: "alert groups must be for all alerts even if
there are system alerts... we just want everything to make sense and be solid" -- the
System Alert stakeholder half used to be a separate SystemAlertGroup model, merged into
AlertGroup the same day), filtered here to alert_type=AlertGroup.ALERT_TYPE_SYSTEM,
alert_subtype=AlertGroup.ALERT_SUBTYPE_STALENESS -- "Staleness Alert" is that subtype's own
user-facing name, the same relationship Events' "Backup file dropped" has with EventGroup.

Only the run_system_alerts management command calls run_system_alert_cycle(); nothing else
in the webapp imports this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from django.utils import timezone

import generate_report as gr

from . import alert_email_templates


@dataclass
class SystemAlertRunResult:
    """What one run_system_alert_cycle() call did, mirroring alerting.AlertRunResult's own
    shape for the management command to report and for tests to assert against."""
    groups_evaluated: int = 0
    checks_evaluated: int = 0
    new_count: int = 0
    reminder_count: int = 0
    resolved_count: int = 0
    emails_sent: int = 0
    emails_preview: List[dict] = field(default_factory=list)   # populated only when dry_run


def _duration_str(seconds: float) -> str:
    """Human-readable age -- the same d/h/m shape as alerting._duration_str, but takes a raw
    second count rather than two datetimes: a checker's own staleness is naturally "how old
    is the file" rather than "how long has a row been open"."""
    total_min = max(0, int(seconds // 60))
    if total_min < 60:
        return f"{total_min}m"
    h, m = divmod(total_min, 60)
    if h < 24:
        return f"{h}h {m}m"
    d, h = divmod(h, 24)
    return f"{d}d {h}h"


def _decide(existing, now, reminder_minutes: int):
    """'new' / 'remind' / 'skip' -- the same persistent-until-resolved shape as
    reports.alerting._decide's own imminent branch, simplified: no band to escalate and no
    daily-capped schedule, just "still stale" reminding every reminder_minutes since the
    finding's own last reminder, forever, until it resolves."""
    if existing is None or existing.resolved_at is not None or existing.last_notified_at is None:
        return "new", None
    elapsed_min = (now - existing.last_notified_at).total_seconds() / 60
    if elapsed_min >= reminder_minutes:
        return "remind", existing.reminder_count + 1
    return "skip", None


def _prom_client():
    from .models import SystemConfig

    cfg = gr.load_config()
    sc = SystemConfig.get()
    if sc.prometheus_url:
        cfg.prom = sc.prometheus_url
    prom = gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    prom.ping()
    return prom


def _check_mtimes(prom, checks) -> Dict[int, float]:
    """{FreshnessCheck.pk: unix timestamp of that check's own last-known-good activity} --
    the query branches on `kind` (2026-09-05, on request: "a staleness alert for each and
    every system... intuit what counts as stale, as this value may be different for a
    particular metric"), since not every checker's own freshness is a textfile's mtime:
    KIND_TEXTFILE_MTIME reads windows_textfile_mtime_seconds{instance, file} (a specific
    file's own last write); KIND_BACKUP_CHECK reads backup_check_timestamp_seconds{instance}
    directly (the backup checker SCRIPT's own last-run time, one series per instance, no file
    -- works on Linux node_exporter hosts too, unlike the textfile-collector-only kind). A
    check whose series is missing ENTIRELY (the exporter isn't being scraped, or the source
    has never existed) is a worse problem than a stale one and is treated as stale by
    construction -- "no data at all" can never read as "up to date"."""
    out: Dict[int, float] = {}
    for c in checks:
        if c.kind == c.KIND_BACKUP_CHECK:
            expr = f'backup_check_timestamp_seconds{{instance="{c.instance}"}}'
        else:
            expr = f'windows_textfile_mtime_seconds{{instance="{c.instance}", file="{c.file}"}}'
        rows = prom.query(expr)
        if rows:
            out[c.pk] = rows[0]["value"]
    return out


def _scheduler_last_success(prom, checks) -> Dict[int, float]:
    """{FreshnessCheck.pk: unix timestamp of that job's own last reported success} for every
    check that names a folder_exporter scheduler job (scheduler_instance/scheduler_job both
    set) -- OPTIONAL correlation surfaced alongside the file's own staleness (2026-09-05,
    after a real investigation found folder_exporter's own scheduler reporting 100% success,
    most recent success seconds old, for a job whose OUTPUT FILE had gone 12+ days stale --
    the job scheduler and the file it's supposed to produce were telling two different
    stories, and nothing before this surfaced that mismatch). Checks with either field blank
    are simply absent from the returned dict -- not every FreshnessCheck's source is a
    folder_exporter job."""
    out: Dict[int, float] = {}
    for c in checks:
        if not (c.scheduler_instance and c.scheduler_job):
            continue
        expr = (f'scheduler_job_last_success_timestamp_seconds{{instance="{c.scheduler_instance}", '
               f'exported_job="{c.scheduler_job}"}}')
        rows = prom.query(expr)
        if rows:
            out[c.pk] = rows[0]["value"]
    return out


def run_system_alert_cycle(*, dry_run: bool = False) -> SystemAlertRunResult:
    """One poll: check every active FreshnessCheck's own textfile mtime against its max age,
    decide new/reminder/skip/resolved per (group, check) exactly like an imminent alert
    finding, and send (or, if dry_run, only preview) one digest e-mail per group with
    anything currently stale."""
    from .models import AlertGroup, FreshnessCheck, SystemAlertFinding

    result = SystemAlertRunResult()
    now = timezone.now()
    # AlertGroup, not a separate SystemAlertGroup (2026-09-05: "alert groups must be for all
    # alerts even if there are system alerts... we just want everything to make sense and be
    # solid" -- SystemAlertGroup was merged into AlertGroup, filtered here by classification).
    #
    # A group outside its own schedule (2026-09-07, same feature as reports.alerting's own --
    # see AlertGroup.in_schedule's own docstring) is filtered out here too, reading exactly
    # like `active=False` for this poll.
    groups = [g for g in AlertGroup.objects.filter(
                 active=True, alert_type=AlertGroup.ALERT_TYPE_SYSTEM,
                 alert_subtype=AlertGroup.ALERT_SUBTYPE_STALENESS).prefetch_related("users")
             if g.in_schedule(timezone.localtime(now))]
    result.groups_evaluated = len(groups)

    checks = list(FreshnessCheck.objects.filter(active=True))
    result.checks_evaluated = len(checks)
    if not groups or not checks:
        return result

    prom = _prom_client()
    mtimes = _check_mtimes(prom, checks)
    scheduler_success = _scheduler_last_success(prom, checks)

    per_group_items: Dict[int, list] = {g.pk: [] for g in groups}
    per_group_rows: Dict[int, list] = {g.pk: [] for g in groups}   # (row, action) to stamp on send

    for c in checks:
        mtime = mtimes.get(c.pk)
        age = (now.timestamp() - mtime) if mtime is not None else None
        stale = age is None or age > c.max_age_seconds
        for g in groups:
            if c.system not in (g.systems or []):
                continue
            existing = None if dry_run else SystemAlertFinding.objects.filter(
                group=g, freshness_check=c).first()

            if not stale:
                if not dry_run and existing and existing.resolved_at is None:
                    existing.resolved_at = now
                    existing.save(update_fields=["resolved_at"])
                    result.resolved_count += 1
                continue

            action, reminder_number = _decide(existing, now, g.effective_system_reminder_minutes)
            if action == "skip":
                continue
            per_group_items[g.pk].append((c, age, action, reminder_number))
            if action == "new":
                result.new_count += 1
            else:
                result.reminder_count += 1
            if not dry_run:
                row, created = SystemAlertFinding.objects.get_or_create(
                    group=g, freshness_check=c, defaults={"first_seen_at": now})
                if not created and action == "new":
                    # Reopen (was resolved) or never-yet-notified row going stale again --
                    # reads as a fresh incident, same reasoning as AlertFinding's own reopen.
                    row.first_seen_at = now
                    row.first_notified_at = None
                    row.reminder_count = 0
                row.resolved_at = None
                row.save()
                per_group_rows[g.pk].append((row, action))

    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    mailcfg["from_name"] = "System Alerts"

    for g in groups:
        items = per_group_items[g.pk]
        if not items:
            continue
        recipients = g.recipient_emails()
        if not recipients:
            continue   # misconfigured group: no stakeholders -- skip, don't crash the run

        render_items = []
        # Sorted by system first (2026-09-05, on request: "consolidated and structured as
        # belonging to that system") so a digest spanning several systems reads as grouped
        # rather than in whatever order FreshnessCheck rows happened to be evaluated in.
        for c, age, action, reminder_number in sorted(items, key=lambda t: (t[0].system, t[0].name)):
            label = f"{c.system} · {c.name}"
            max_age_str = _duration_str(c.max_age_seconds)
            detail = (f"Not updated in {_duration_str(age)} (expected within {max_age_str})"
                     if age is not None else
                     f"No data at all from this checker (expected an update within {max_age_str})")
            # OPTIONAL: names the exact "job says healthy, file says stale" signature this
            # feature exists to catch (2026-09-05) -- a folder_exporter job can report
            # exit_code=0/"ok" on every run while never reaching the step that actually
            # rewrites its own output file, which reads as perfectly healthy from the job
            # scheduler's own metrics alone. Only shown when this check names a scheduler job
            # AND that job has a live success timestamp to show.
            success_ts = scheduler_success.get(c.pk)
            if success_ts is not None:
                job_age = now.timestamp() - success_ts
                detail += (f" — but its scheduler job (\"{c.scheduler_job}\") last reported "
                          f"success {_duration_str(job_age)} ago: the job is running, it just "
                          f"isn't writing fresh data")
            render_items.append((label, detail, action, reminder_number))

        # "Staleness Alert" (2026-09-05, on request: "one of the system alerts must be
        # called staleness alert") -- the user-facing NAME of this specific check, the same
        # way Events' first (and so far only) type is user-facing-named "Backup file
        # dropped" without renaming EventGroup/reports.events themselves. System Alerts
        # remains the umbrella notification TYPE (model names, the Configuration tile);
        # "Staleness Alert" is what THIS one is actually called in the subject/banner a
        # recipient sees.
        subject = f"[Staleness Alert] {g.name} — {len(items)} checker(s) stale"
        text_body = "\n".join(f"  {label} — {detail}" for label, detail, _a, _n in render_items)
        html_body, inline_images = alert_email_templates.render_system_alert(
            render_items, group_name=g.name, for_browser=False)

        if dry_run:
            result.emails_preview.append({"group": g.name, "kind": "system_alert",
                                          "to": recipients, "subject": subject,
                                          "text_body": text_body})
            continue
        if not mailcfg.get("host"):
            continue
        try:
            mr.send_email(mailcfg, recipients, subject, html_body, text_body,
                          inline_images=inline_images)
        except Exception:  # noqa: BLE001 -- one group's SMTP failure must not stop the rest
            continue
        result.emails_sent += 1
        # Only stamped once THIS send has actually succeeded -- same reasoning as
        # reports.alerting's own post-send bookkeeping: a transient SMTP failure must leave
        # the row looking exactly like "not yet notified" so the next poll retries immediately.
        for row, action in per_group_rows[g.pk]:
            if action == "new":
                row.first_notified_at = now
            else:
                row.reminder_count += 1
            row.last_notified_at = now
            row.save(update_fields=["first_notified_at", "last_notified_at", "reminder_count"])

    return result
