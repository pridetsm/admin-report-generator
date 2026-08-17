"""Two gates that run on every request, in order:

  RoleRequiredMiddleware  — an authenticated user with NO role goes to the 'request a role' page.
  ActiveRoleMiddleware    — a user who holds SEVERAL roles picks which one they are working as
                            before the dashboard loads.

A "role" is a Django group (superusers/staff always pass the first gate). Roles are assigned in
the Django admin / Roles console today; once Keycloak is wired, its realm/client roles map onto
these same groups, so neither gate needs to change — a user Keycloak hasn't granted a role simply
arrives with no group.
"""
from django.shortcuts import redirect

from .roles import ALL_ROLES, user_roles

# paths reachable without a role (login/logout, the no-role page itself, admin so an admin can
# grant roles, and static/media assets)
_EXEMPT_PREFIXES = ("/no-role", "/accounts/login", "/accounts/logout", "/admin", "/static", "/media")

# the role-selection screen is additionally exempt from the *active role* gate — it is the page
# that answers it — as is signing out, so nobody can be trapped on it
_ROLE_SELECT_EXEMPT = _EXEMPT_PREFIXES + ("/roles/select",)


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


class ActiveRoleMiddleware:
    """Establish the session's ACTIVE role before any page that depends on it renders.

    Signing in flushes the session, so this runs fresh on every login:

      * several roles -> redirect to the role-selection screen. The dashboard must never
        silently load every role's systems at once; that choice is the user's to make (and
        "Load all my roles" is one of the tiles there).
      * exactly one role -> select it silently. A single-role user has nothing to choose.
      * no roles (superuser / staff) -> treat as all roles; RoleRequiredMiddleware has already
        turned away everyone else.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if (user is not None and user.is_authenticated
                and not request.session.get("active_role")
                and not any(request.path_info.startswith(p) for p in _ROLE_SELECT_EXEMPT)):
            roles = user_roles(user)
            if len(roles) > 1:
                return redirect("role_select")
            request.session["active_role"] = roles[0] if roles else ALL_ROLES
        return self.get_response(request)
