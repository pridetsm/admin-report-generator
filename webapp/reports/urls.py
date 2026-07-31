from django.urls import path

from . import views

urlpatterns = [
    path("", views.report_form, name="report_form"),
    path("report/", views.report, name="report"),
    path("generate/", views.generate, name="generate"),
    path("connect/", views.connect_index, name="connect"),
    path("connect/rdp/", views.connect_rdp, name="connect_rdp"),
    path("history/", views.history, name="history"),
    path("history/<int:pk>/", views.submission_detail, name="submission_detail"),
    path("recipients/search/", views.recipient_search, name="recipient_search"),
    path("no-role/", views.no_role, name="no_role"),
    path("roles/", views.roles_console, name="roles_console"),
    path("profile/", views.profile, name="profile"),
    path("settings/", views.system_settings, name="system_settings"),
    path("settings/report-theme/", views.set_report_theme, name="set_report_theme"),
    path("notifications/seen/", views.mark_notifications_seen, name="mark_notifications_seen"),
]
