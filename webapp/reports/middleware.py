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
