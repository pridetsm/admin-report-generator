"""URL configuration for the Report Builder project."""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path, reverse_lazy


class RoleSelectLoginView(auth_views.LoginView):
    """Signing in always lands on Role Select, never on wherever ?next= points.

    Django's LoginView otherwise honours ?next= (set when @login_required or the role
    gate bounces an expired session back here), which meant a session timeout on any deep
    link skipped the picker on the way back in. Role Select is supposed to be the one place
    that always states which hat you are wearing, so login can't have a side door around it.
    """

    def get_success_url(self):
        return str(reverse_lazy("role_select"))


urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/login/",
         RoleSelectLoginView.as_view(template_name="registration/login.html"),
         name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", include("reports.urls")),
]
