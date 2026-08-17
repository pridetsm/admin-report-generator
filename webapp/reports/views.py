"""Report Builder views.

Flow:
    GET  /            -> capture a live snapshot, cache it under a token, render the form
    POST /generate    -> reload the SAME snapshot, bake the admin's answers in, build the
                         .xlsx, save an audit row, and stream it back as a download
    GET  /history     -> past submissions (audit trail)

The snapshot is cached between the two requests so the admin's answers stay married to the
exact numbers they reviewed (Prometheus could drift in the seconds between form and submit).
"""
from __future__ import annotations

import datetime
import uuid

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

import generate_report as gr   # to show the config.ini defaults on the settings page

from . import promconfig
from .directory import search_directory
from .forms import ProfileForm, SystemConfigForm, UserAccountForm
from .models import ReportSubmission, RoleRequest, RoleScope, SystemConfig, UserProfile
from .roles import (
    ALL_ROLES,
    ALL_ROLES_LABEL,
    ALL_ROLES_META,
    ALL_ROLES_TILE_LABEL,
    ROLE_NAMES,
    is_role_admin,
    role_meta,
    user_roles,
)
from .services import (
    EmailNotConfigured,
    PrometheusUnavailable,
    build_report,
    capture_snapshot,
    default_recipients,
    default_report_filename,
    email_report,
    recipient_options,
    topology_systems,
)

_CACHE_PREFIX = "snapshot:"


def _cache_key(token: str) -> str:
    return f"{_CACHE_PREFIX}{token}"


def _active_scope(user, session):
    """(systems_filter, label) for the role this session is working as.

    ``systems_filter`` is None when the workspace is unrestricted — either the active role has
    no Role scope mapped yet, or the user is a superuser holding no groups at all.
    """
    active = session.get("active_role") or ALL_ROLES
    held = user_roles(user)
    if active == ALL_ROLES:
        return (RoleScope.systems_for(held) if held else None), ALL_ROLES_LABEL
    return RoleScope.systems_for([active]), active


def _profile_author(user) -> str:
    """The report's "Signed by / By" name, self-populated from the user's profile.

    We never invent report fields — this only fills an EXISTING field (the master author
    line) so the person who generated the report and stands behind the comments is
    attributed automatically, without the admin having to type it.
    """
    name = (user.get_full_name() or "").strip() or user.get_username()
    prof = getattr(user, "profile", None)
    title = (getattr(prof, "job_title", "") or "").strip() if prof else ""
    return f"{name}, {title}" if title else name


@login_required
def report_form(request):
    """Render the annotation form.

    A plain page refresh REUSES the snapshot captured earlier (kept in the session +
    cache) so the countdown keeps running from the original capture time instead of
    resetting.  A fresh snapshot is only taken when there is none, when the cached one
    has expired, or when the caller explicitly asks (``?fresh=1`` — the "Refresh" action
    and the auto-refresh that fires when the timer hits zero).
    """
    force = request.GET.get("fresh") == "1"
    snapshot = None
    token = request.session.get("snapshot_token", "")
    if not force and token:
        snapshot = cache.get(_cache_key(token))   # None if it lapsed

    if snapshot is None:
        token = uuid.uuid4().hex
        systems_filter, scope_label = _active_scope(request.user, request.session)
        try:
            snapshot = capture_snapshot(token, systems_filter=systems_filter,
                                        scope_label=scope_label)
        except PrometheusUnavailable as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=502)
        cache.set(_cache_key(token), snapshot, timeout=settings.SNAPSHOT_TTL)
        request.session["snapshot_token"] = token

    # Anchor the countdown to the capture time so a refresh continues it (never restarts).
    # captured_at is a naive datetime.now(); compare against the same clock.
    elapsed = (datetime.datetime.now() - snapshot.captured_at).total_seconds()
    remaining = max(0, int(settings.SNAPSHOT_TTL - elapsed))
    return render(request, "reports/form.html", {
        "snapshot": snapshot,
        "token": token,
        "suggested_author": _profile_author(request.user),
        "suggested_recipients": default_recipients(),
        "recipient_options": recipient_options(),
        "default_theme": getattr(getattr(request.user, "profile", None), "default_report_theme", "dark"),
        "ttl_minutes": settings.SNAPSHOT_TTL // 60,
        "ttl_seconds": settings.SNAPSHOT_TTL,
        "remaining_seconds": remaining,   # what the timer starts from on this render
    })


@login_required
@require_POST
def generate(request):
    """Rebuild the report from the cached snapshot + the submitted answers, then download it."""
    token = request.POST.get("token", "")
    snapshot = cache.get(_cache_key(token))
    if snapshot is None:
        # snapshot expired or the process restarted — send the admin back to a fresh capture
        return render(request, "reports/error.html", {
            "detail": "This snapshot expired. Please reload the form to capture fresh metrics.",
            "expired": True,
        }, status=410)

    action = request.POST.get("action", "download")
    if action not in ("download", "email"):
        action = "download"
    # report theme is a user setting (chosen in the Settings menu), not a per-report field
    theme = getattr(getattr(request.user, "profile", None), "default_report_theme", "dark")
    if theme not in ("dark", "light"):
        theme = "dark"
    # Author (the report's master "By" line) self-populates from the profile; only an
    # explicit override in the form replaces it, so it is never blank.
    author = request.POST.get("author", "").strip() or _profile_author(request.user)
    summary_comment = request.POST.get("summary_comment", "").strip()
    recipients_raw = request.POST.get("recipients", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]

    # For an e-mail we need somewhere to send it — validate before doing any work so the
    # snapshot stays intact and the admin can go back and add recipients.
    if action == "email" and not recipients:
        return render(request, "reports/error.html", {
            "detail": "Add at least one recipient to e-mail the report.",
        }, status=400)

    # Rebuild annotations keyed by each flag's stable key. Fields are namespaced by the
    # system index and flag index in the snapshot, so we don't have to encode keys in HTML.
    annotations: dict = {}
    for si, sysvm in enumerate(snapshot.systems):
        flags_ans = {}
        for fi, flag in enumerate(sysvm.flags):
            ans = request.POST.get(f"fix__{si}__{fi}", "")
            if ans in ("Yes", "No"):
                flags_ans[flag.key] = ans
        comment = request.POST.get(f"comment__{si}", "").strip()
        if flags_ans or comment:
            annotations[sysvm.name] = {"flags": flags_ans, "comment": comment}

    data = build_report(
        snapshot, theme=theme, author=author,
        annotations=annotations, summary_comment=summary_comment,
    )
    filename = default_report_filename(theme, timezone.localtime())

    # Freeze exactly what the report presented (overview + per-system flagged items, each
    # married to the admin's answer) so History can replay it without touching Prometheus.
    report_content = {
        "overview": snapshot.overview,
        "systems": [
            {
                "name": sysvm.name,
                "hosts": sysvm.hosts,
                "flags": [
                    {
                        "key": flag.key, "text": flag.text,
                        "band": flag.band, "category": flag.category,
                        "answer": annotations.get(sysvm.name, {}).get("flags", {}).get(flag.key, ""),
                    }
                    for flag in sysvm.flags
                ],
                "comment": annotations.get(sysvm.name, {}).get("comment", ""),
            }
            for sysvm in snapshot.systems
        ],
    }

    # Email path: send first — only record + consume the snapshot if it actually went out,
    # so a transient SMTP failure leaves the form retryable.
    subject = ""
    if action == "email":
        try:
            subject = email_report(snapshot, data, recipients=recipients,
                                   author=author, filename=filename)
        except EmailNotConfigured as exc:
            return render(request, "reports/error.html", {"detail": str(exc)}, status=500)
        except Exception as exc:   # noqa: BLE001 — SMTP/network errors surfaced to the admin
            return render(request, "reports/error.html", {
                "detail": f"Could not send the e-mail: {exc}",
            }, status=502)

    ReportSubmission.objects.create(
        generated_by=request.user,
        author=author,
        theme=theme,
        delivery=action,
        recipients=recipients_raw,
        prom_url=snapshot.prom_url,
        systems_count=len(snapshot.systems),
        hosts_count=snapshot.hosts_count,
        immediate_count=snapshot.immediate_count,
        watch_count=snapshot.watch_count,
        summary_comment=summary_comment,
        annotations=annotations,
        report_content=report_content,
        filename=filename,
    )
    cache.delete(_cache_key(token))   # one-shot: a fresh form gets a fresh snapshot

    if action == "email":
        return render(request, "reports/sent.html", {
            "recipients": recipients, "author": author,
            "filename": filename, "subject": subject,
        })

    response = HttpResponse(
        data,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@never_cache   # always reflect the newest submissions (no stale back/forward-cache copy)
@login_required
def history(request):
    """Recent report submissions (audit trail)."""
    submissions = ReportSubmission.objects.select_related("generated_by")[:100]
    return render(request, "reports/history.html", {"submissions": submissions})


@never_cache
@login_required
def submission_detail(request, pk):
    """Read-only replay of one past report (opened from a History row): the generated
    content + the admin's answers + audit-trail info, laid out as plain tables."""
    sub = get_object_or_404(ReportSubmission.objects.select_related("generated_by"), pk=pk)
    content = sub.report_content or {}
    overview = content.get("overview") or {}
    systems = content.get("systems")
    if not systems:
        # legacy rows saved before report_content existed — reconstruct from annotations
        systems = [
            {
                "name": name,
                "hosts": None,
                "flags": [{"key": k, "text": k, "band": "", "category": "", "answer": v}
                          for k, v in (data.get("flags") or {}).items()],
                "comment": (data.get("comment") or "").strip(),
            }
            for name, data in (sub.annotations or {}).items()
        ]
    systems = sorted(systems, key=lambda s: (s.get("name") or "").lower())
    recipients = [r.strip() for r in (sub.recipients or "").split(",") if r.strip()]
    comments = []
    if sub.summary_comment:
        comments.append({"label": "Overall", "text": sub.summary_comment})
    for s in systems:
        if s.get("comment"):
            comments.append({"label": s["name"], "text": s["comment"]})
    return render(request, "reports/submission_detail.html", {
        "sub": sub, "overview": overview, "systems": systems,
        "recipients": recipients, "comments": comments,
    })


@login_required
def recipient_search(request):
    """Type-ahead recipient lookup against AD/LDAP (empty list if LDAP isn't configured)."""
    return JsonResponse({"results": search_directory(request.GET.get("q", ""))})


@login_required
@require_POST
def mark_notifications_seen(request):
    """Called when the user opens the notifications (in the hamburger) — clears the red dot."""
    prof = getattr(request.user, "profile", None) or UserProfile.objects.create(user=request.user)
    prof.notifications_seen_at = timezone.now()
    prof.save(update_fields=["notifications_seen_at", "updated_at"])
    return JsonResponse({"ok": True})


@login_required
@require_POST
def set_report_theme(request):
    """Report theme is a user setting (lives in the Settings menu) — persist it on the profile."""
    theme = request.POST.get("theme")
    if theme in ("dark", "light"):
        prof = getattr(request.user, "profile", None) or UserProfile.objects.create(user=request.user)
        prof.default_report_theme = theme
        prof.save(update_fields=["default_report_theme", "updated_at"])
    # AJAX (from the Settings menu) -> no page reload, so the admin's form entries survive.
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse({"ok": True, "theme": theme})
    return redirect(request.META.get("HTTP_REFERER") or "report_form")


# ---------------------------------------------------------------------------------------
#  Role selection — which workspace am I in?
# ---------------------------------------------------------------------------------------
@never_cache
@login_required
def role_select(request):
    """The screen a multi-role user meets straight after signing in.

    One tile per role they hold, plus a "Load all my roles" tile that combines them. The
    choice scopes the dashboard (see ``_active_scope``) and is kept in the session, so it
    lasts until they switch roles or sign out.
    """
    held = user_roles(request.user)

    if request.method == "POST":
        choice = request.POST.get("role", "")
        if choice != ALL_ROLES and choice not in held:
            messages.error(request, "That role isn’t assigned to you.")
            return redirect("role_select")
        request.session["active_role"] = choice
        # the cached snapshot belongs to the PREVIOUS scope — drop it so the dashboard
        # re-captures against the systems this role can actually see
        request.session.pop("snapshot_token", None)
        label = ALL_ROLES_LABEL if choice == ALL_ROLES else choice
        messages.success(request, f"Working as {label}.")
        return redirect("report_form")

    scoped = {r: RoleScope.systems_for([r]) for r in held}
    all_systems = topology_systems()
    tiles = []
    for role in held:
        systems = scoped[role]
        tiles.append(dict(role_meta(role),
                          value=role,
                          count=len(all_systems) if systems is None else len(systems),
                          unscoped=systems is None))
    combined = RoleScope.systems_for(held) if held else None
    return render(request, "reports/role_select.html", {
        "tiles": tiles,
        "all_tile": dict(ALL_ROLES_META, name=ALL_ROLES_TILE_LABEL, value=ALL_ROLES,
                         count=len(all_systems) if combined is None else len(combined),
                         unscoped=combined is None),
        "current": request.session.get("active_role", ""),
        "total_systems": len(all_systems),
    })


# ---------------------------------------------------------------------------------------
#  Configuration — every configuration screen lives under here (drawer › Configuration)
# ---------------------------------------------------------------------------------------
#  The default screen is the FORM: a labelled view of prometheus.yml, so the estate is edited
#  through validated fields instead of hand-written YAML. "Live YAML file" shows the same file
#  verbatim; the other tabs configure the app around it.
_CONFIG_TABS = [
    ("configuration", "Configuration form", "Prometheus topology, in labelled fields"),
    ("config_yaml", "Live YAML file", "prometheus.yml exactly as it is on disk"),
    ("system_settings", "Data sources", "Which Prometheus / Grafana to read"),
    ("config_role_scopes", "Role scopes", "Which systems each role sees"),
]


def _config_context(active: str) -> dict:
    return {
        "config_tabs": [{"url_name": n, "label": lbl, "hint": hint, "active": n == active}
                        for n, lbl, hint in _CONFIG_TABS],
        "yaml_file": promconfig.file_info(),
    }


def _require_admin(request):
    """Configuration is Administrator-only; everyone else goes back to the dashboard."""
    return None if is_role_admin(request.user) else redirect("report_form")


@never_cache
@login_required
def configuration(request):
    """DEFAULT configuration screen: prometheus.yml as a labelled form.

    Reads the live file on every request and writes it back on save, so this is a view of the
    file rather than a copy of it. Validation happens before anything is written, and the
    previous file is kept as a timestamped .bak — see reports/promconfig.py.
    """
    denied = _require_admin(request)
    if denied:
        return denied

    try:
        doc = promconfig.load()
        raw = promconfig.read_text()
    except promconfig.ConfigError as exc:
        return render(request, "reports/configuration.html",
                      {**_config_context("configuration"), "load_error": str(exc)}, status=200)

    errors: list = []
    if request.method == "POST":
        new_doc, errors = promconfig.parse_post(request.POST, doc)
        if not errors:
            try:
                backup = promconfig.save(new_doc, header=promconfig.header_comment(raw),
                                         author=request.user.get_full_name() or request.user.get_username())
            except promconfig.ConfigError as exc:
                messages.error(request, str(exc))
                return redirect("configuration")
            messages.success(request, "prometheus.yml saved." + (
                f" Previous version kept as {backup}." if backup else ""))
            return redirect("configuration")
        view = promconfig.view_from_post(request.POST, doc)
    else:
        view = promconfig.to_view(doc)

    return render(request, "reports/configuration.html", {
        **_config_context("configuration"),
        "view": view, "errors": errors,
        "prom_url": SystemConfig.get().prometheus_url or gr.load_config().prom,
        "backups": promconfig.backups(),
    })


@never_cache
@login_required
def config_yaml(request):
    """The live prometheus.yml, verbatim — the source of truth behind the form."""
    denied = _require_admin(request)
    if denied:
        return denied
    try:
        raw, error = promconfig.read_text(), ""
    except promconfig.ConfigError as exc:
        raw, error = "", str(exc)
    if request.GET.get("download") == "1" and raw:
        resp = HttpResponse(raw, content_type="text/yaml; charset=utf-8")
        resp["Content-Disposition"] = 'attachment; filename="prometheus.yml"'
        return resp
    return render(request, "reports/config_yaml.html", {
        **_config_context("config_yaml"),
        "raw": raw, "error": error,
        "line_count": len(raw.splitlines()),
        "backups": promconfig.backups(),
    })


@login_required
@require_POST
def prometheus_reload(request):
    """Ask the running Prometheus to re-read the config we just wrote (POST /-/reload)."""
    denied = _require_admin(request)
    if denied:
        return denied
    url = SystemConfig.get().prometheus_url or gr.load_config().prom
    ok, detail = promconfig.reload_prometheus(url)
    (messages.success if ok else messages.error)(request, detail)
    return redirect(request.POST.get("next") or "configuration")


@never_cache
@login_required
def config_role_scopes(request):
    """Which systems each role's workspace covers — what the role tiles at sign-in select.

    A role with nothing ticked is UNRESTRICTED (it sees the whole estate), so the mapping can
    be filled in one role at a time without hiding systems from anyone in the meantime.
    """
    denied = _require_admin(request)
    if denied:
        return denied

    systems = topology_systems()
    if request.method == "POST":
        for role in ROLE_NAMES:
            chosen = [s for s in request.POST.getlist(f"systems__{role}") if s in systems]
            scope, _ = RoleScope.objects.get_or_create(role=role)
            scope.systems = chosen
            scope.updated_by = request.user
            scope.save()
        messages.success(request, "Role scopes saved — they apply the next time a role is selected.")
        return redirect("config_role_scopes")

    mapped = {s.role: set(s.systems or []) for s in RoleScope.objects.all()}
    rows = [{
        "role": role,
        "meta": role_meta(role),
        "chosen": mapped.get(role, set()),
        "unscoped": not mapped.get(role),
    } for role in ROLE_NAMES]
    return render(request, "reports/config_role_scopes.html", {
        **_config_context("config_role_scopes"),
        "rows": rows, "systems": systems,
    })


@login_required
def system_settings(request):
    """Administrator-only: the Prometheus/Grafana the dashboard fetches from (overrides config.ini)."""
    denied = _require_admin(request)
    if denied:
        return denied
    sc = SystemConfig.get()
    if request.method == "POST":
        form = SystemConfigForm(request.POST, instance=sc)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.updated_by = request.user
            obj.save()
            messages.success(request, "System settings saved — the next capture uses them.")
            return redirect("system_settings")
    else:
        form = SystemConfigForm(instance=sc)
    defaults = gr.load_config()   # the file-based fallbacks, shown for reference
    return render(request, "reports/settings.html", {
        **_config_context("system_settings"),
        "form": form, "sc": sc,
        "config_prom": defaults.prom, "config_grafana": defaults.grafana,
    })


@login_required
def profile(request):
    """View / edit the current user's profile (auth fields + extended profile)."""
    prof, _ = UserProfile.objects.get_or_create(user=request.user)
    if request.method == "POST":
        aform = UserAccountForm(request.POST, instance=request.user)
        pform = ProfileForm(request.POST, instance=prof)
        if aform.is_valid() and pform.is_valid():
            aform.save()
            pform.save()
            messages.success(request, "Profile saved.")
            return redirect("profile")
    else:
        aform = UserAccountForm(instance=request.user)
        pform = ProfileForm(instance=prof)
    roles = list(request.user.groups.values_list("name", flat=True))
    return render(request, "reports/profile.html",
                  {"aform": aform, "pform": pform, "profile": prof, "roles": roles})


@login_required
def no_role(request):
    """Signed-in user with no role: explain, and let them REQUEST one or more roles."""
    my_roles = set(request.user.groups.values_list("name", flat=True))
    pending = set(request.user.role_requests.filter(status="pending").values_list("role", flat=True))

    if request.method == "POST":
        created = 0
        for r in request.POST.getlist("roles"):
            if r in ROLE_NAMES and r not in my_roles and r not in pending:
                RoleRequest.objects.create(user=request.user, role=r)
                created += 1
        if created:
            messages.success(request, f"Requested {created} role(s). An administrator will review it.")
        else:
            messages.error(request, "Select at least one new role to request.")
        return redirect("no_role")

    roles = [{"name": r, "has": r in my_roles, "pending": r in pending} for r in ROLE_NAMES]
    return render(request, "reports/no_role.html", {"roles": roles, "has_any": bool(my_roles)})


def _grant_role(user, role, keycloak):
    """Grant a single role — in Keycloak (the store) when enabled, else the local group mirror."""
    if keycloak.enabled():
        keycloak.add_user_role(user.get_username(), role)
        keycloak.sync_user_roles(user)
    else:
        grp, _ = Group.objects.get_or_create(name=role)
        user.groups.add(grp)


@login_required
def roles_console(request):
    """Administrator view: approve/reject role requests and manage every user's roles."""
    if not is_role_admin(request.user):
        return redirect("report_form")

    if request.method == "POST":
        from . import keycloak
        action = request.POST.get("action")
        if action == "decide":
            req = get_object_or_404(RoleRequest, pk=request.POST.get("request_id"))
            decision = request.POST.get("decision")
            if decision == "approve" and req.role in ROLE_NAMES:
                _grant_role(req.user, req.role, keycloak)
                req.status = "approved"
            elif decision == "reject":
                req.status = "rejected"
            req.decided_at, req.decided_by = timezone.now(), request.user
            req.save()
            messages.success(request, f"{req.user.get_username()} · {req.role}: {req.status}.")
        elif action == "set_roles":
            user = get_object_or_404(get_user_model(), pk=request.POST.get("user_id"))
            selected = {r for r in request.POST.getlist("roles") if r in ROLE_NAMES}
            if keycloak.enabled():
                keycloak.set_user_roles(user.get_username(), selected)   # Keycloak is the store
                keycloak.sync_user_roles(user)                           # mirror back to groups
            else:
                for r in ROLE_NAMES:
                    grp, _ = Group.objects.get_or_create(name=r)
                    user.groups.add(grp) if r in selected else user.groups.remove(grp)
            messages.success(request, f"Updated roles for {user.get_username()}.")
        return redirect("roles_console")

    pending = RoleRequest.objects.filter(status="pending").select_related("user")
    users = get_user_model().objects.all().prefetch_related("groups").order_by("username")
    user_rows = [{"u": u, "roles": set(u.groups.values_list("name", flat=True))} for u in users]
    return render(request, "reports/roles.html", {
        "pending": pending, "user_rows": user_rows, "role_names": ROLE_NAMES,
    })
