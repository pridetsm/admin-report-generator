"""Template context shared by every page:
  * role-admin flag  (drives admin-only nav)
  * the user's report-theme setting  (for the Settings menu)
  * notifications  (pending role requests, for Administrators)
  * back-nav target  (the current page's PARENT in the nav hierarchy)
"""
import os

from django.conf import settings
from django.urls import NoReverseMatch, reverse

from .models import RoleRequest
from .roles import is_role_admin


def _asset_version() -> str:
    """Cache-buster for app.js / app.css: the newest mtime among them.

    Without it the browser keeps serving a stale app.js — the files carry only Last-Modified,
    so an edit can sit unseen behind the cache and, worse, an OLD copy can keep running its
    listeners alongside the new page's, producing changes that cancel each other out.
    Recomputed per request: DEBUG edits take effect on a normal reload, and in production the
    value only moves when a file actually changes.
    """
    newest = 0.0
    for rel in ("js/app.js", "css/app.css"):
        for base in list(getattr(settings, "STATICFILES_DIRS", [])) + [getattr(settings, "STATIC_ROOT", "")]:
            if not base:
                continue
            try:
                newest = max(newest, os.path.getmtime(os.path.join(str(base), rel)))
            except OSError:
                continue
    return str(int(newest))

# The navigation hierarchy: each page -> its parent page. The canvas Back button walks ONE
# level up this tree (child -> parent -> ... -> home), rather than jumping straight home.
# report_form (home) has no parent, so it shows no Back button.
_NAV_PARENT = {
    "connect": "report_form",
    "history": "report_form",
    "submission_detail": "history",
    "roles_console": "report_form",
    "system_settings": "report_form",
    "profile": "report_form",
}
_NAV_LABEL = {
    "report_form": "Dashboard",
    "connect": "Connect",
    "history": "History",
    "roles_console": "Roles",
    "system_settings": "Configuration",
    "profile": "Profile",
}


def _back_nav(request):
    """(url, label) of the current page's parent, or (None, None) at the root / unknown page."""
    match = getattr(request, "resolver_match", None)
    name = getattr(match, "url_name", None) if match else None
    parent = _NAV_PARENT.get(name)
    if not parent:
        return None, None
    try:
        return reverse(parent), _NAV_LABEL.get(parent, "Back")
    except NoReverseMatch:
        return None, None


def role_flags(request):
    user = getattr(request, "user", None)
    admin = is_role_admin(user)
    back_url, back_label = _back_nav(request)
    ctx = {
        "is_role_admin": admin,
        "notif_count": 0,
        "notifications": [],
        "notif_unseen": False,   # drives the red dot on the hamburger
        "back_url": back_url,    # parent page for the canvas Back button
        "back_label": back_label,
        "asset_v": _asset_version(),   # ?v= on app.js/app.css so edits are never served stale
    }
    if user is not None and getattr(user, "is_authenticated", False):
        prof = getattr(user, "profile", None)
        ctx["report_theme"] = prof.default_report_theme if prof else "dark"
        ctx["display_name"] = (user.get_full_name() or user.get_username())

        if admin:
            pending_qs = RoleRequest.objects.filter(status="pending")
            pending = list(pending_qs.select_related("user")[:8])
            ctx["notif_count"] = pending_qs.count()
            ctx["notifications"] = [
                {
                    "who": (r.user.get_full_name() or r.user.get_username()),
                    "role": r.role,
                    "when": r.created_at,
                }
                for r in pending
            ]
            seen_at = getattr(prof, "notifications_seen_at", None) if prof else None
            ctx["notif_unseen"] = (
                pending_qs.filter(created_at__gt=seen_at).exists() if seen_at
                else pending_qs.exists()
            )
    return ctx
