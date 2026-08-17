"""Role gate: an authenticated user with no role is sent to the 'no role assigned' page.

A "role" is a Django group (superusers/staff always pass). Roles are assigned in the Django
admin today; once Keycloak is wired, its realm/client roles map onto these same groups, so this
gate needs no change — a user Keycloak hasn't granted a role simply arrives with no group.
"""
from django.shortcuts import redirect

# paths reachable without a role (login/logout, the no-role page itself, admin so an admin can
# grant roles, and static/media assets)
_EXEMPT_PREFIXES = ("/no-role", "/accounts/login", "/accounts/logout", "/admin", "/static", "/media")


def user_has_role(user) -> bool:
    return user.is_superuser or user.is_staff or user.groups.exists()


class RoleRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated and not user_has_role(user):
            path = request.path_info
            if not any(path.startswith(p) for p in _EXEMPT_PREFIXES):
                return redirect("no_role")
        return self.get_response(request)


class RoleScopeMiddleware:
    """Keeps a bookmark honest when a role is selected.

    Picking a role narrows the menu, but a bookmark, a browser Back, or a link in an old
    e-mail can still land on a page the current role does not show. Silently 302-ing to the
    dashboard would look like the page had vanished, so this sends the user to the picker
    with a message naming the role that opens it.

    Only ever redirects for a page the user genuinely HOLDS the role for. If they do not
    hold it, nothing happens here and the view's own permission check refuses as before —
    this is a navigation aid, not an access control, and must never be the only thing
    standing between a user and a page.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        # process_view (not __call__) because the URL name is only known after resolution.
        from django.contrib import messages
        from django.shortcuts import redirect

        from .roles import PAGE_OWNER, active_role, held_roles

        user = getattr(request, "user", None)
        if not (user and user.is_authenticated):
            return None
        match = getattr(request, "resolver_match", None)
        name = getattr(match, "url_name", None) if match else None
        if not name:
            return None

        owners = PAGE_OWNER.get(name)
        if not owners:                          # a page common to every role
            return None
        current = active_role(request)
        if not current or current in owners:    # unscoped, or already one of its roles
            return None
        # Name a role they actually hold, where there is one — telling someone to switch to a
        # role they cannot have is worse than saying nothing.
        theirs = owners & set(held_roles(user))
        if not theirs:                          # not theirs at all — let the view refuse
            return None
        owner = sorted(theirs)[0]
        messages.info(request, f"That page belongs to the {owner} role. Switch to it to open it.")
        return redirect("role_select")
