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
import html
from dataclasses import dataclass, field
from typing import Dict, List

from django.utils import timezone

import generate_report as gr   # send_report/ is on sys.path, same mechanism services.py uses

from . import alert_email_templates
from . import folders

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
    resolved_emails_sent: int = 0
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


def _folder_flags_by_system(store, systems) -> Dict[str, list]:
    """Synthetic Flag objects for every currently-over-expected watched folder, grouped by
    owning system. Shared by run_alert_cycle and send_test_alert so the "repackage
    folder_over_expected_detail as a Flag" logic (see run_alert_cycle's own comment on why it
    lives here rather than in generate_report.py) exists in exactly one place."""
    out: Dict[str, list] = {}
    for sysname, fname, expected, actual in gr.folder_over_expected_detail(store, systems):
        out.setdefault(sysname, []).append(gr.Flag(
            key=f"folder:{fname}",
            text=f"{fname} over expected size: {actual:.1f}GB (expected {expected:.1f}GB)",
            band="amber", category="folder"))
    return out


def _undrained_folder_flags_by_system(cfg, covered_systems: set) -> Dict[str, list]:
    """Synthetic Flag objects for every payment-queue folder currently NOT draining --
    files waiting whose oldest has aged past its amber/red limit, per reports.folders'
    own live verdict (folders.verdict: red/amber both imply files>0 and an aged-out oldest
    file; "idle" -- files<=0 -- is the healthy drained state and never flags here).

    A SEPARATE live Prometheus query from _capture's own store (reports.folders.snapshot()
    calls generate_report.Prometheus itself, independently) -- same reasoning as
    _folder_flags_by_system's own comment on why this lives here rather than in
    generate_report.py, just a different underlying screen/exporter reading. Skipped entirely
    (no extra query at all) when no covered system is even eligible to produce this category,
    same T24-only gating as "folder" -- see folders.folder_watch_systems."""
    eligible = folders.folder_watch_systems(cfg.prometheus_yml) & covered_systems
    if not eligible:
        return {}
    try:
        data = folders.snapshot()
    except folders.FolderWatchUnavailable:
        return {}
    out: Dict[str, list] = {}
    for f in data["folders"]:
        if f["state"] not in ("red", "amber"):
            continue
        flag = gr.Flag(
            key=f"undrained:{f['key']}",
            text=f"{f['name']} on {f['host']} not draining: {f['files']} file(s) waiting, oldest {f['age_text']} old",
            band=f["state"], category="undrained_folders")
        for sysname in eligible:
            out.setdefault(sysname, []).append(flag)
    return out


def _decide(existing, band: str, group, now) -> str:
    """'new' | 'remind' | 'skip' -- a pure function of the existing AlertFinding row (or None),
    the flag's CURRENT band, and the group's own renotify_interval_minutes.

    Reopening (resolved_at was set) and a first-ever sighting both read as 'new'. An
    escalation (existing.band was amber, current band is red) also always reads as 'new',
    regardless of the interval -- see AlertFinding's own docstring for why. Otherwise a group
    with no interval set (None/0) stays silent once notified; one WITH an interval fires again
    once at least that many minutes have passed since it last did -- a rolling window since
    last_notified_at, not a fixed wall-clock time, so it's immune to the poller's own cadence
    drifting. "At least", not "exactly": resolution and re-notification are both only ever
    checked when the poller actually runs, so an interval shorter than the poller's own
    schedule can't fire any faster than the poller itself does."""
    if existing is None or existing.resolved_at is not None or existing.last_notified_at is None:
        return "new"
    if existing.band == "amber" and band == "red":
        return "new"
    interval = group.renotify_interval_minutes
    if interval and now - existing.last_notified_at >= datetime.timedelta(minutes=interval):
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

    # (system, band, text, first_seen_at) per group, for the "Resolved" digest below --
    # populated ONLY for rows that were actually notified (last_notified_at is not None): a
    # finding that appeared and cleared between two polls, without anyone ever being told it
    # existed, must not generate a "resolved" e-mail about something nobody knew was wrong.
    per_group_resolved: Dict[int, list] = {g.pk: [] for g in groups}

    def _collect_and_resolve(qs):
        rows = list(qs)
        for row in rows:
            if row.last_notified_at is not None:
                per_group_resolved[row.group_id].append(
                    (row.system, row.band, row.text, row.first_seen_at))
        if rows:
            AlertFinding.objects.filter(pk__in=[r.pk for r in rows]).update(resolved_at=now)
        return len(rows)

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
            result.resolved_count += _collect_and_resolve(stale)

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
    folder_flags_by_system = _folder_flags_by_system(store, systems)
    # A SEPARATE live check (see _undrained_folder_flags_by_system's own docstring on why it
    # queries independently of `store`) for payment-queue folders that have files waiting past
    # their drain-time limit -- category "undrained_folders", distinct from "folder" above
    # (that one is disk-size overflow; this one is a queue backlog, different exporter).
    undrained_flags_by_system = _undrained_folder_flags_by_system(cfg, covered)

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
        flags = (gr.flagged_for_system(store, sysm, cfg) + folder_flags_by_system.get(sysm.name, [])
                 + undrained_flags_by_system.get(sysm.name, []))
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
                result.resolved_count += _collect_and_resolve(stale)

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

    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    mailcfg["from_name"] = "System Alerts"

    for g in groups:
        items = per_group_items[g.pk]
        resolved = per_group_resolved[g.pk]
        if not items and not resolved:
            continue
        recipients = g.recipient_emails()
        if not recipients:
            continue   # misconfigured group: no stakeholders -- skip, don't crash the run

        if items:
            subject, text_body, html_body = _render_fired_email(g, items)
            if dry_run:
                result.emails_preview.append({"group": g.name, "kind": "fired", "to": recipients,
                                              "subject": subject, "text_body": text_body})
            elif mailcfg.get("host"):
                try:
                    mr.send_email(mailcfg, recipients, subject, html_body, text_body)
                    result.emails_sent += 1
                    AlertFinding.objects.filter(pk__in=[r.pk for r in per_group_rows[g.pk]]) \
                                        .update(last_notified_at=now)
                except Exception:  # noqa: BLE001 -- one group's SMTP failure must not stop the rest
                    pass

        if resolved:
            subject, text_body, html_body, inline_images = _render_resolved_email(g, resolved, now)
            if dry_run:
                result.emails_preview.append({"group": g.name, "kind": "resolved", "to": recipients,
                                              "subject": subject, "text_body": text_body})
            elif mailcfg.get("host"):
                try:
                    mr.send_email(mailcfg, recipients, subject, html_body, text_body,
                                  inline_images=inline_images)
                    result.resolved_emails_sent += 1
                except Exception:  # noqa: BLE001 -- one group's SMTP failure must not stop the rest
                    pass
    return result


def send_test_alert(group, *, to: str | None = None) -> tuple[bool, str]:
    """Manually triggered from the group's own edit screen -- always a REAL send, never a dry
    run, because the whole point is to answer "does this actually reach my stakeholders right
    now" (SMTP config, recipient addresses) which a preview can't tell you.

    `to`, if given, MUST already be one of group.recipient_emails() (the caller validates --
    see config_alert_group_test) -- narrows delivery to that one stakeholder instead of the
    whole group, so iterating on a test doesn't re-notify everyone every time. None sends to
    every current stakeholder, same as before this parameter existed.

    Deliberately never touches AlertFinding: a test firing must not consume a group's real
    once-only notify slot or shift its renotify clock, or running one could cause a genuine
    finding to go silently unreported later because the test already "used up" that finding's
    turn. It reads the group's CURRENT saved systems/categories/severity (whatever's actually
    in the database), not any unsaved edits sitting in the form.

    If the group has real eligible findings right now they're included (still marked [TEST]
    throughout) so this doubles as a live check that detection still works; if there are none,
    the e-mail says so explicitly rather than going out empty and unexplained. Exceptions are
    surfaced to the caller as the failure message, not swallowed, since seeing the actual SMTP
    error is the point of clicking this button."""
    recipients = [to] if to else group.recipient_emails()
    if not recipients:
        return False, "This group has no stakeholders yet — add at least one before testing."
    if not group.systems:
        return False, "This group covers no systems yet — add at least one before testing."

    try:
        store, systems, cfg = _capture(set(group.systems))
    except Exception as exc:      # noqa: BLE001 -- shown to the admin, not swallowed
        return False, f"Could not capture live data: {exc}"

    folder_flags_by_system = _folder_flags_by_system(store, systems)
    undrained_flags_by_system = _undrained_folder_flags_by_system(cfg, set(group.systems))
    items = []
    for sysm in systems:
        flags = (gr.flagged_for_system(store, sysm, cfg) + folder_flags_by_system.get(sysm.name, [])
                 + undrained_flags_by_system.get(sysm.name, []))
        eligible = [f for f in flags
                   if severity_meets(f.band, group.min_severity)
                   and group.category_matches(sysm.name, f.category)]
        items += [(sysm.name, f, "new") for f in eligible]

    subject, text_body, html_body = _render_fired_email(group, items)
    subject = f"[TEST] {subject}"
    if items:
        preamble = "This is a manually triggered TEST alert — not a real notification cycle.\n\n"
    else:
        preamble = ("This is a manually triggered TEST alert — not a real notification cycle.\n"
                   "No current findings for this group; sent purely to confirm delivery.\n\n")
    text_body = preamble + text_body
    html_body = "<pre>" + preamble.replace("\n", "<br>") + "</pre>" + html_body

    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        return False, "No SMTP host configured (send_report/config.ini [smtp])."
    mailcfg["from_name"] = "System Alerts (test)"
    try:
        mr.send_email(mailcfg, recipients, subject, html_body, text_body)
    except Exception as exc:      # noqa: BLE001 -- shown to the admin, that's the point of testing
        return False, f"Send failed: {exc}"
    return True, f"Test alert sent to {', '.join(recipients)}."


def _duration_str(start, end) -> str:
    """Human-readable elapsed time for a resolved digest's "open for" column."""
    total_min = max(0, int((end - start).total_seconds() // 60))
    if total_min < 60:
        return f"{total_min}m"
    h, m = divmod(total_min, 60)
    if h < 24:
        return f"{h}h {m}m"
    d, h = divmod(h, 24)
    return f"{d}d {h}h"


def _email_shell(*, kicker: str, banner_bg: str, banner_fg: str, headline: str,
                 col_headers: list, rows_html: str, footer_note: str) -> str:
    """The branded wrapper (navy/gold header, coloured status banner, a table) shared by every
    alert e-mail this module sends -- built from mail_report's own NAVY/GOLD/RED/AMBER/GREEN
    palette so an alert e-mail reads as the same product as the daily report, not a different
    tool with its own look. mail_report's render_html itself is NOT reused (it's shaped for the
    full daily KPI dashboard, not a one-group flag digest) -- only its constants are."""
    import mail_report as mr
    ths = "".join(
        f'<th style="text-align:left;padding:9px 12px;font-size:10px;letter-spacing:.4px;'
        f'color:{mr.MUTED};text-transform:uppercase;background:#f7f8fa;border-bottom:1px solid #e6e8ec;">{html.escape(h)}</th>'
        for h in col_headers)
    return f"""<!doctype html><html><body style="margin:0;padding:0;background:#eef0f3;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f3;font-family:'Segoe UI',Arial,sans-serif;">
<tr><td align="center" style="padding:24px 12px;">
<table width="660" cellpadding="0" cellspacing="0" style="max-width:660px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.12);">
  <tr><td style="background:{mr.NAVY};padding:20px 24px;">
    <div style="font-size:18px;font-weight:700;color:{mr.GOLD};letter-spacing:.5px;">{html.escape(kicker)}</div>
    <div style="font-size:12px;color:#aebfd1;margin-top:3px;">Reserve Bank of Zimbabwe &nbsp;&middot;&nbsp; RBZ Monitoring Console</div>
  </td></tr>
  <tr><td style="background:{banner_bg};border-bottom:1px solid #e6e8ec;padding:12px 24px;">
    <span style="color:{banner_fg};font-weight:700;font-size:14px;">&#9679; {html.escape(headline)}</span>
  </td></tr>
  <tr><td>
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>{ths}</tr>
      {rows_html}
    </table>
  </td></tr>
  <tr><td style="background:#f7f8fa;border-top:1px solid #e6e8ec;padding:14px 24px;">
    <div style="font-size:11px;color:{mr.MUTED};line-height:1.6;">{footer_note}</div>
  </td></tr>
</table></td></tr></table></body></html>"""


def _fired_row(system: str, f) -> str:
    import mail_report as mr
    color = mr.RED if f.band == "red" else mr.AMBER
    return (
        f'<tr><td style="padding:7px 12px;border-bottom:1px solid #eef0f2;font-weight:600;color:{mr.NAVY};">{html.escape(system)}</td>'
        f'<td style="padding:7px 12px;border-bottom:1px solid #eef0f2;color:#1f2733;">{html.escape(f.category)}</td>'
        f'<td style="padding:7px 12px;border-bottom:1px solid #eef0f2;color:#1f2733;">{html.escape(f.text)}</td>'
        f'<td style="padding:7px 12px;border-bottom:1px solid #eef0f2;color:{color};font-weight:700;'
        f'text-transform:uppercase;font-size:11px;white-space:nowrap;">{f.band}</td></tr>')


def _render_fired_email(group, items) -> tuple:
    """items: [(system, Flag, action), ...] for ONE group ('new' or 'remind'). Branded HTML
    (see _email_shell) plus a plain-text alternative; only send_email (SMTP) is reused from
    mail_report, never reimplemented."""
    import mail_report as mr
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

    any_red = any(f.band == "red" for _, f in new_items + reminders)
    banner_bg, banner_fg = (mr.RED_T, mr.RED) if any_red else (mr.AMBER_T, mr.AMBER)
    headline = f"{len(new_items)} new finding(s), {len(reminders)} still open"
    rows_html = "".join(_fired_row(s, f) for s, f in new_items) \
              + "".join(_fired_row(s, f) for s, f in reminders)
    footer = (f'Automated alert from the RBZ Monitoring Console for the &ldquo;{html.escape(group.name)}&rdquo; '
             f'group &mdash; minimum severity: {group.min_severity}. Manage this group\'s systems, metrics '
             f'and stakeholders at {mr.REPORT_GENERATOR_URL}.')
    html_body = _email_shell(kicker="SYSTEM ALERT", banner_bg=banner_bg, banner_fg=banner_fg,
                             headline=headline, col_headers=["System", "Metric", "Finding", "Severity"],
                             rows_html=rows_html, footer_note=footer)
    return subject, text_body, html_body


def _render_resolved_email(group, resolved_items, now, *, for_browser: bool = False) -> tuple:
    """resolved_items: [(system, band, text, first_seen_at), ...] for ONE group -- findings that
    WERE notified and have now cleared (see run_alert_cycle's own filtering: a finding never
    successfully notified never reaches here).

    Uses alert_email_templates.render_resolved for the HTML -- the same branded shell every
    other alert e-mail this feature sends now uses (navy gradient header, white "Alert
    resolved" title matching "Alert notification"'s own styling, green banner) -- not the
    older mail_report-styled digest this used to build via _email_shell, which is what a real
    recipient flagged as visibly mismatched from the rest of the feature (2026-09-04)."""
    subject = f"[Resolved] {group.name} — {len(resolved_items)} finding(s) cleared"
    lines = [f"  {s} — {text} (was {band.upper()}, open for {_duration_str(first_seen, now)})"
            for s, band, text, first_seen in resolved_items]
    text_body = "RESOLVED:\n" + "\n".join(lines)
    items = [(s, band, text, _duration_str(first_seen, now)) for s, band, text, first_seen in resolved_items]
    html_body, inline_images = alert_email_templates.render_resolved(
        items, group_name=group.name, min_severity=group.min_severity, for_browser=for_browser)
    return subject, text_body, html_body, inline_images


def _synthetic_flag(category: str, band: str):
    """A fabricated Flag for test/preview purposes only -- never derived from a live capture,
    so these buttons always produce the same example regardless of what Prometheus actually
    reports right now. Text says so explicitly, so nobody mistakes a test e-mail for a real
    incident or a real resolution."""
    from .models import AlertGroup

    label = dict(AlertGroup.CATEGORY_CHOICES).get(category, category)
    sample = "97%" if band == "red" else "88%"
    text = f"{label} — synthetic test reading {sample} (fabricated for preview, not a real measurement)"
    return gr.Flag(key=f"synthetic:{category}", text=text, band=band, category=category)


def render_test_email(group, *, kind: str, system: str, category: str, band: str,
                      for_browser: bool = False) -> tuple:
    """Builds (subject, text_body, html_body, inline_images) from a FABRICATED example --
    'positive' (a fired finding) or 'resolved' (that finding clearing). Used by both the
    in-browser preview endpoint and send_test_email, so preview and send can never disagree
    about what a recipient would actually see -- the SAME png bytes either way, just addressed
    differently (see alert_email_templates.render's own docstring on for_browser).

    'positive' uses the Outlook-safe per-category rendering (reports/alert_email_templates.py
    -- table-based layout, embedded images instead of inline SVG, no CSS vars/flexbox, see that
    module's own docstring for why) when a shape exists for this category -- today, all nine
    do -- falling back to the plain multi-item digest (inline_images always {}) for any future
    category added without one yet. 'resolved' uses the same module's render_resolved -- the
    same branded shell as 'positive' (white "Alert resolved" title, matching "Alert
    notification"'s own styling), just a green banner and one card per item instead of a
    per-category hero image."""
    flag = _synthetic_flag(category, band)
    inline_images: dict = {}
    if kind == "resolved":
        opened_at = timezone.now() - datetime.timedelta(hours=3, minutes=17)
        subject, text_body, html_body, inline_images = _render_resolved_email(
            group, [(system, band, flag.text, opened_at)], timezone.now(), for_browser=for_browser)
    elif category in alert_email_templates.SHAPE_BY_CATEGORY:
        subject, text_body, _old_html = _render_fired_email(group, [(system, flag, "new")])
        html_body, inline_images = alert_email_templates.render(
            category, system=system, band=band, group_name=group.name,
            min_severity=group.min_severity, for_browser=for_browser)
    else:
        subject, text_body, html_body = _render_fired_email(group, [(system, flag, "new")])
    return f"[SYNTHETIC TEST] {subject}", text_body, html_body, inline_images


def send_test_email(group, *, kind: str, system: str, category: str, band: str,
                    to: str | None = None) -> tuple[bool, str]:
    """Sends the fabricated preview e-mail (see render_test_email) to the group's current
    stakeholders -- a real send, clearly marked [SYNTHETIC TEST] throughout so nobody mistakes
    it for a real incident. Never touches AlertFinding, same reasoning as send_test_alert.

    `to`, if given, MUST already be one of group.recipient_emails() (the caller validates --
    see config_alert_group_test) -- narrows delivery to that one stakeholder instead of the
    whole group. None sends to every current stakeholder."""
    recipients = [to] if to else group.recipient_emails()
    if not recipients:
        return False, "This group has no stakeholders yet — add at least one before testing."

    subject, text_body, html_body, inline_images = render_test_email(
        group, kind=kind, system=system, category=category, band=band, for_browser=False)
    import mail_report as mr
    mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
    if not mailcfg.get("host"):
        return False, "No SMTP host configured (send_report/config.ini [smtp])."
    mailcfg["from_name"] = "System Alerts (test)"
    try:
        mr.send_email(mailcfg, recipients, subject, html_body, text_body, inline_images=inline_images)
    except Exception as exc:      # noqa: BLE001 -- shown to the admin, that's the point of testing
        return False, f"Send failed: {exc}"
    return True, f"Synthetic {kind} test sent to {', '.join(recipients)}."
