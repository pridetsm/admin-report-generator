"""EVENT notifications -- deliberately decoupled from ALERT notifications (2026-09-04, on
request: "I want to decouple notifications from alerts... I want to have notification types,
alert notification and event notification"). reports.alerting answers "is something currently
wrong" (a threshold/state, with severity, that can resolve and reminds you while it doesn't).
This module answers a completely different question: "did something happen" -- a single,
discrete occurrence, once, with no severity and nothing to resolve. EventGroup (reports.models)
is the stakeholder half of that, as thin as AlertGroup's own but with none of its alerting
machinery.

The first (and so far only) event type is "backup file dropped": for every system an active
EventGroup covers, a new file appearing in that system's OWN backup-check textfile metric
(backup_file{file="..."} -- see generate_report.capture_backups, the SAME textfile-collector
data reports.alerting already captures for backup-missing/untracked alerts) fires a blue-
themed notification. "Matches the values... we expect from the backup checker textfile
metric" is satisfied by construction, not a second filter here: each host's own check script
already only ever reports a file through its own configured filename glob (see
reports/script_templates/backup_windows.ps1's own $FileName), so any filename backup_file
names AT ALL has already passed that host's own definition of "a backup file".

Only the run_events management command calls run_event_cycle(); nothing else in the webapp
imports this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import generate_report as gr

from . import alert_email_templates


@dataclass
class EventRunResult:
    """What one run_event_cycle() call did, mirroring alerting.AlertRunResult's own shape for
    the management command to report and for tests to assert against."""
    groups_evaluated: int = 0
    new_count: int = 0
    emails_sent: int = 0
    emails_preview: List[dict] = field(default_factory=list)   # populated only when dry_run


def _capture_backups(system_names: set):
    """Just enough of alerting._capture() to reach store.backups -- a real capture (config +
    topology + live Prometheus), scoped to exactly the systems any active EventGroup covers.
    Kept separate from alerting._capture rather than imported from it, since this module has
    no reason to depend on the alerting engine at all (see this module's own docstring on why
    the two stay decoupled)."""
    from .models import SystemConfig

    cfg = gr.load_config()
    sc = SystemConfig.get()
    if sc.prometheus_url:
        cfg.prom = sc.prometheus_url
    if sc.grafana_url:
        cfg.grafana = sc.grafana_url
    systems = [s for s in gr.load_topology(cfg.prometheus_yml, scope="business")
              if s.name in system_names]
    prom = gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
    prom.ping()
    store = gr.capture(prom, systems, cfg)
    return store, systems


def _new_backup_files(store, systems) -> Dict[str, list]:
    """{system name: [(instance, filename), ...]} for every backup_file entry NOT already in
    SeenBackupFile -- the actual "did a new one drop" check. Read-only: callers decide
    whether to record them (dry_run never does, so a preview never consumes the dedup ledger)."""
    from .models import SeenBackupFile

    seen = set(SeenBackupFile.objects.values_list("system", "instance", "filename"))
    out: Dict[str, list] = {}
    for sysm in systems:
        for c in sysm.components:
            d = store.backups.get(c.instance)
            if not d:
                continue
            for filename, _day, _mtime in d["files"]:
                if (sysm.name, c.instance, filename) not in seen:
                    out.setdefault(sysm.name, []).append((c.instance, filename))
    return out


def run_event_cycle(*, dry_run: bool = False) -> EventRunResult:
    """One poll: capture live data, check every active EventGroup's covered systems for new
    backup files, send (or, if dry_run, only preview) one digest e-mail per group with
    anything new, and record what was seen so the next run doesn't re-announce it."""
    from .models import EventGroup, SeenBackupFile

    result = EventRunResult()
    groups = list(EventGroup.objects.filter(active=True).prefetch_related("users"))
    result.groups_evaluated = len(groups)

    covered = {s for g in groups for s in (g.systems or [])}
    if not covered:
        return result

    store, systems = _capture_backups(covered)
    new_files = _new_backup_files(store, systems)
    if not new_files:
        return result

    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    mailcfg["from_name"] = "System Events"

    # A file only enters the ledger once its own SEND has actually succeeded -- never on a
    # transient SMTP failure (same reasoning reports.alerting never advances
    # first_notified_at until its own send succeeds): recording an unsent notification as
    # "seen" would silently and permanently swallow it the moment SMTP is down, the opposite
    # of "we need to be made aware of it, no exceptions" (2026-09-04). NOTE: dedup is still
    # GLOBAL, not per-group (SeenBackupFile carries no group column) -- if two groups cover
    # the same system and only one send succeeds this run, the file is marked seen regardless,
    # so the other group's stakeholders would not be retried next poll. Accepted as a known
    # edge case rather than a full per-group ledger (AlertFinding's own shape), since today no
    # two event groups cover the same system.
    told: Dict[str, set] = {}   # system -> {(instance, filename), ...} successfully notified this run

    for g in groups:
        pairs_by_system = {sysname: new_files.get(sysname, []) for sysname in (g.systems or [])
                           if new_files.get(sysname)}
        items = [(sysname, filename) for sysname, pairs in pairs_by_system.items()
                for _instance, filename in pairs]
        if not items:
            continue
        recipients = g.recipient_emails()
        if not recipients:
            continue   # misconfigured group: no stakeholders -- skip, don't crash the run

        subject = f"[Events] {g.name} — Backup file dropped ({len(items)})"
        text_body = "\n".join(f"  {s} — {f}" for s, f in items)
        html_body, inline_images = alert_email_templates.render_event(
            items, group_name=g.name, event_label="Backup file dropped")

        if dry_run:
            result.emails_preview.append({"group": g.name, "kind": "backup_file_dropped",
                                          "to": recipients, "subject": subject,
                                          "text_body": text_body})
            result.new_count += len(items)
            continue
        if not mailcfg.get("host"):
            continue
        try:
            mr.send_email(mailcfg, recipients, subject, html_body, text_body,
                          inline_images=inline_images)
        except Exception:  # noqa: BLE001 -- one group's SMTP failure must not stop the rest,
            continue       # and must not mark THIS group's own files as told, either.
        result.emails_sent += 1
        result.new_count += len(items)
        for sysname, pairs in pairs_by_system.items():
            told.setdefault(sysname, set()).update(pairs)

    if not dry_run and told:
        to_record = [SeenBackupFile(system=sysname, instance=instance, filename=filename)
                    for sysname, pairs in told.items()
                    for instance, filename in pairs]
        SeenBackupFile.objects.bulk_create(to_record, ignore_conflicts=True)

    return result
