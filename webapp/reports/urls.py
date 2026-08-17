from django.urls import path

from . import views

urlpatterns = [
    path("", views.report_form, name="report_form"),
    path("generate/", views.generate, name="generate"),
    path("history/", views.history, name="history"),
    path("history/<int:pk>/", views.submission_detail, name="submission_detail"),
    path("recipients/search/", views.recipient_search, name="recipient_search"),
    path("no-role/", views.no_role, name="no_role"),
    path("roles/", views.roles_console, name="roles_console"),
    path("roles/select/", views.role_select, name="role_select"),
    path("profile/", views.profile, name="profile"),

    # ---- Configuration (drawer › Configuration). The form is the default screen; the other
    # screens are tabs alongside it, so every configuration surface lives under one entry.
    path("configuration/", views.configuration, name="configuration"),
    path("configuration/yaml/", views.config_yaml, name="config_yaml"),
    path("configuration/reload/", views.prometheus_reload, name="prometheus_reload"),
    path("configuration/role-scopes/", views.config_role_scopes, name="config_role_scopes"),
    path("configuration/data-sources/", views.system_settings, name="system_settings"),

    path("settings/report-theme/", views.set_report_theme, name="set_report_theme"),
    path("notifications/seen/", views.mark_notifications_seen, name="mark_notifications_seen"),
]
