"""Sector-based alerting engine.

Gathers live data the same way services.capture_snapshot does (same config/topology/capture
calls) but works directly with generate_report.flagged_for_system's Flag objects instead of
building the report-builder's SystemVM/FlagVM view-models -- this module has no UI to serve,
only AlertGroup policy to evaluate against the estate's current findings.

Reuses flagged_for_system for ALL per-system policy (RAM_THRESHOLD_OVERRIDES, backup policy
exemptions, etc.) and mail_report.send_email for ALL SMTP -- neither is reimplemented here.
Only the run_alerts management command calls run_alert_cycle(); nothing else in the webapp
imports this module.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List

from django.utils import timezone

import generate_report as gr   # send_report/ is on sys.path, same mechanism services.py uses

# "daily" re-notify reads as a ROLLING 24h window since last_notified_at, not a fixed
# wall-clock time -- simpler to reason about and immune to the poller's own cadence drifting.
REMINDER_INTERVAL = datetime.timedelta(hours=24)


@dataclass
class AlertRunResult:
    """What one run_alert_cycle() call did, for the management command to report and for
    tests to assert against."""
    groups_evaluated: int = 0
    systems_captured: int = 0
    new_count: int = 0
    reminder_count: int = 0
    resolved_count: int = 0
    emails_sent: int = 0
    emails_preview: List[dict] = field(default_factory=list)   # populated only when dry_run


def severity_meets(band: str, min_severity: str) -> bool:
    """Whether a Flag's band clears a group's own configured floor. Red always qualifies;
    amber only qualifies for a group that opted into "Red + Amber"."""
    return band == "red" or (band == "amber" and min_severity == "amber")


def _capture(system_names: set):
    """cfg + topology + a live Prometheus capture, scoped to exactly the systems any active
    group covers. Same three calls services.capture_snapshot makes (gr.load_config, the
    SystemConfig override, gr.load_topology, gr.Prometheus/prom.ping, gr.capture) -- kept
    separate from that function because this module has no Snapshot/view-model to build."""
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
    return store, systems, cfg


def _decide(existing, band: str, group, now) -> str:
    """'new' | 'remind' | 'skip' -- a pure function of the existing AlertFinding row (or None),
    the flag's CURRENT band, and the group's own renotify policy.

    Reopening (resolved_at was set) and a first-ever sighting both read as 'new'. An
    escalation (existing.band was amber, current band is red) also always reads as 'new',
    regardless of renotify_mode -- see AlertFinding's own docstring for why. Otherwise "once"
    groups stay silent once notified; "daily" groups notify again after REMINDER_INTERVAL."""
    if existing is None or existing.resolved_at is not None or existing.last_notified_at is None:
        return "new"
    if existing.band == "amber" and band == "red":
        return "new"
    if group.renotify_mode == "daily" and now - existing.last_notified_at >= REMINDER_INTERVAL:
        return "remind"
    return "skip"


def run_alert_cycle(*, dry_run: bool = False) -> AlertRunResult:
    """One poll: capture live data, evaluate every active group against its own systems, send
    (or, if dry_run, only preview) one digest e-mail per group with anything new/due, and
    record what happened in AlertFinding so the next run knows what's already been said.

    A group with no active systems mapped is skipped entirely (nothing to capture for it); a
    group with findings but no resolvable stakeholder e-mail is skipped at send time (logged
    via the result, not raised -- one misconfigured group must never stop every other group's
    alerts from going out)."""
    from .models import AlertFinding, AlertGroup

    result = AlertRunResult()
    now = timezone.now()
    groups = list(AlertGroup.objects.filter(active=True).prefetch_related("users"))
    result.groups_evaluated = len(groups)

    # A system dropped from a group's OWN scope (edited in Configuration, not just missing
    # from this poll's capture) is resolved here unconditionally, before the capture-scoped
    # loop below even runs -- that loop only ever sees systems that are STILL covered by some
    # active group, so a system removed from every group that used to cover it would otherwise
    # never be captured again and its old findings would dangle open forever.
    if not dry_run:
        for g in groups:
            stale = (AlertFinding.objects
                    .filter(group=g, resolved_at__isnull=True)
                    .exclude(system__in=(g.systems or [])))
            result.resolved_count += stale.update(resolved_at=now)

    covered = {s for g in groups for s in (g.systems or [])}
    if not covered:
        return result

    store, systems, cfg = _capture(covered)
    result.systems_captured = len(systems)

    # Folder-over-expected-size is a real generate_report finding (see
    # folder_over_expected_detail's own docstring), just never routed through
    # flagged_for_system -- it's a report-level banner there, not a per-system Flag. Reused
    # exactly as-is (not reimplemented) and re-packaged into genuine Flag namedtuples here,
    # entirely inside this module, so the rest of this function (severity_meets,
    # category_matches, _decide, the AlertFinding bookkeeping, the digest e-mail) treats a
    # folder finding identically to any other -- no separate code path to keep in sync.
    # Always "amber" (folder_over_expected_detail's own docstring: never escalated, however
    # far over expected a folder grows), category "folder" (see AlertGroup.CATEGORY_CHOICES'
    # own comment on why this category exists only here, not in generate_report.py itself).
    folder_flags_by_system: Dict[str, list] = {}
    for sysname, fname, expected, actual in gr.folder_over_expected_detail(store, systems):
        folder_flags_by_system.setdefault(sysname, []).append(gr.Flag(
            key=f"folder:{fname}",
            text=f"{fname} over expected size: {actual:.1f}GB (expected {expected:.1f}GB)",
            band="amber", category="folder"))

    # [(system, Flag, action)] per group -- collected in the capture pass below, then either
    # previewed (dry_run) or turned into one digest e-mail per group afterward. The rows this
    # loop writes track CURRENT TRUTH (band/text/first_seen_at/last_seen_at) unconditionally,
    # but deliberately do NOT set last_notified_at yet -- that only happens once send_email
    # actually succeeds, below, so a transient SMTP failure leaves the row looking exactly
    # like "not yet notified" and the NEXT cycle tries again immediately rather than waiting
    # out a "daily" group's full 24h window for something nobody was actually told.
    per_group_items: Dict[int, list] = {g.pk: [] for g in groups}
    per_group_rows: Dict[int, list] = {g.pk: [] for g in groups}   # AlertFinding rows to stamp

    for sysm in systems:
        flags = gr.flagged_for_system(store, sysm, cfg) + folder_flags_by_system.get(sysm.name, [])
        for g in groups:
            if sysm.name not in (g.systems or []):
                continue
            eligible = [f for f in flags
                       if severity_meets(f.band, g.min_severity)
                       and g.category_matches(sysm.name, f.category)]
            eligible_keys = {f.key for f in eligible}

            if not dry_run:
                stale = (AlertFinding.objects
                        .filter(group=g, system=sysm.name, resolved_at__isnull=True)
                        .exclude(flag_key__in=eligible_keys))
                result.resolved_count += stale.update(resolved_at=now)

            for f in eligible:
                existing = None if dry_run else AlertFinding.objects.filter(
                    group=g, system=sysm.name, flag_key=f.key).first()
                action = _decide(existing, f.band, g, now)
                if action == "skip":
                    continue
                per_group_items[g.pk].append((sysm.name, f, action))
                if action == "new":
                    result.new_count += 1
                else:
                    result.reminder_count += 1
                if not dry_run:
                    row, created = AlertFinding.objects.get_or_create(
                        group=g, system=sysm.name, flag_key=f.key,
                        defaults={"band": f.band, "text": f.text,
                                  "first_seen_at": now, "last_seen_at": now})
                    if not created and action == "new":
                        row.first_seen_at = now
                    row.band, row.text, row.last_seen_at = f.band, f.text, now
                    row.resolved_at = None
                    row.save()
                    per_group_rows[g.pk].append(row)

    for g in groups:
        items = per_group_items[g.pk]
        if not items:
            continue
        subject, text_body, html_body = _render_alert_email(g, items)
        recipients = g.recipient_emails()
        if not recipients:
            continue   # misconfigured group: no stakeholders -- skip, don't crash the run
        if dry_run:
            result.emails_preview.append({"group": g.name, "to": recipients,
                                          "subject": subject, "text_body": text_body})
            continue
        import mail_report as mr
        mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
        if not mailcfg.get("host"):
            continue
        mailcfg["from_name"] = "System Alerts"
        try:
            mr.send_email(mailcfg, recipients, subject, html_body, text_body)
            result.emails_sent += 1
        except Exception:      # noqa: BLE001 -- one group's SMTP failure must not stop the rest
            continue
        AlertFinding.objects.filter(pk__in=[r.pk for r in per_group_rows[g.pk]]) \
                            .update(last_notified_at=now)
    return result


def _render_alert_email(group, items) -> tuple:
    """items: [(system, Flag, action), ...] for ONE group. Purpose-built digest -- mail_report's
    render_html/analyse/plain_summary are shaped for the full daily report (unreachable/crit/
    warn/nodata buckets + attachment CTA), not a per-group flag digest, so this is new, small
    presentation code; only send_email (SMTP) is reused, never reimplemented."""
    new_items = [(s, f) for s, f, a in items if a == "new"]
    reminders = [(s, f) for s, f, a in items if a == "remind"]
    subject = f"[Alerts] {group.name} — {len(new_items)} new, {len(reminders)} reminder(s)"
    lines = []
    if new_items:
        lines.append("NEW:")
        lines += [f"  [{f.band.upper()}] {s} — {f.text}" for s, f in new_items]
    if reminders:
        lines.append("STILL OPEN (reminder):")
        lines += [f"  [{f.band.upper()}] {s} — {f.text}" for s, f in reminders]
    text_body = "\n".join(lines)
    html_body = "<pre>" + text_body.replace("&", "&amp;").replace("<", "&lt;") + "</pre>"
    return subject, text_body, html_body
