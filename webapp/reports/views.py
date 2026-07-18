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

from .directory import search_directory
from .forms import ProfileForm, SystemConfigForm, UserAccountForm
from .models import ReportSubmission, RoleRequest, SystemConfig, UserProfile
from .roles import ROLE_NAMES, is_role_admin
from .services import (
    EmailNotConfigured,
    PrometheusUnavailable,
    build_report,
    capture_snapshot,
    default_recipients,
    default_report_filename,
    email_report,
    recipient_options,
)

_CACHE_PREFIX = "snapshot:"


def _cache_key(token: str) -> str:
    return f"{_CACHE_PREFIX}{token}"


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
        try:
            snapshot = capture_snapshot(token)
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


@login_required
def system_settings(request):
    """Administrator-only: the Prometheus/Grafana the dashboard fetches from (overrides config.ini)."""
    if not is_role_admin(request.user):
        return redirect("report_form")
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
