"""Template context shared by every page:
  * role-admin flag  (drives admin-only nav)
  * the ACTIVE role  (which workspace the user chose at sign-in; drives the topbar chip)
  * the user's report-theme setting  (for the Settings menu)
  * notifications  (pending role requests, for Administrators)
  * back-nav target  (the current page's PARENT in the nav hierarchy)
"""
from django.urls import NoReverseMatch, reverse

from .models import RoleRequest
from .roles import (
    ALL_ROLES,
    ALL_ROLES_LABEL,
    ALL_ROLES_META,
    is_role_admin,
    role_meta,
    user_roles,
)

# The navigation hierarchy: each page -> its parent page. The canvas Back button walks ONE
# level up this tree (child -> parent -> ... -> home), rather than jumping straight home.
# report_form (home) has no parent, so it shows no Back button.
# Every configuration screen hangs off `configuration`, which is the drawer's entry point —
# so Back from any of them lands on the configuration form, not on the dashboard.
_NAV_PARENT = {
    "history": "report_form",
    "submission_detail": "history",
    "roles_console": "report_form",
    "configuration": "report_form",
    "system_settings": "configuration",
    "config_yaml": "configuration",
    "config_role_scopes": "configuration",
    "profile": "report_form",
}
_NAV_LABEL = {
    "report_form": "Dashboard",
    "history": "History",
    "roles_console": "Roles",
    "configuration": "Configuration",
    "system_settings": "Data sources",
    "config_yaml": "Live YAML",
    "config_role_scopes": "Role scopes",
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
        "active_role": "",
        "active_role_label": "",
        "active_role_icon": "",
        "can_switch_role": False,
    }
    if user is not None and getattr(user, "is_authenticated", False):
        prof = getattr(user, "profile", None)
        ctx["report_theme"] = prof.default_report_theme if prof else "dark"
        ctx["display_name"] = (user.get_full_name() or user.get_username())

        active = request.session.get("active_role", "")
        held = user_roles(user)
        ctx["active_role"] = active
        ctx["active_role_label"] = ALL_ROLES_LABEL if active == ALL_ROLES else active
        if active == ALL_ROLES:
            ctx["active_role_icon"] = ALL_ROLES_META["icon"]
        elif active:
            ctx["active_role_icon"] = role_meta(active)["icon"]
        # only worth offering the switcher to someone who actually has somewhere to switch to
        ctx["can_switch_role"] = len(held) > 1

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
