from django.urls import path

from . import views

urlpatterns = [
    path("reports/", views.reports, name="reports"),
    path("reports/os-inventory/", views.os_inventory, name="os_inventory"),
    path("", views.report_form, name="report_form"),
    path("report/", views.report, name="report"),
    path("generate/", views.generate, name="generate"),
    path("connect/", views.connect_index, name="connect"),
    path("connect/rdp/", views.connect_rdp, name="connect_rdp"),
    path("folders/", views.folder_watch, name="folder_watch"),
    path("folders/temenos/", views.folder_watch_temenos, name="folder_watch_temenos"),
    path("folders/temenos/data/", views.folder_watch_data, name="folder_watch_data"),
    path("network/", views.network_dashboard, name="network_dashboard"),
    path("network/core-switch/", views.network_report, name="network_report"),
    path("network/generate/", views.network_generate, name="network_generate"),
    # The start-of-day checklist. Its own trio of URLs rather than a mode of the report
    # above: that one captures live SNMP for the devices you pick, this one is hand-keyed
    # from four vendor consoles across a fixed estate — but it gets a picker of its own too,
    # to thin the entry screen down to what is actually being checked this morning. Nested
    # the same way network_dashboard/network_report are: the picker owns the parent path.
    path("network/sod/", views.network_sod_select, name="network_sod_select"),
    path("network/sod/checklist/", views.network_sod_form, name="network_sod"),
    path("network/sod/generate/", views.network_sod_generate, name="network_sod_generate"),
    path("infra/", views.infra_form, name="infra_form"),
    path("infra/report/", views.infra_report, name="infra_report"),
    path("infra/generate/", views.infra_generate, name="infra_generate"),
    path("history/", views.history, name="history"),
    path("history/<int:pk>/", views.submission_detail, name="submission_detail"),
    path("recipients/search/", views.recipient_search, name="recipient_search"),
    path("role/", views.role_select, name="role_select"),
    path("role/empty/", views.role_empty, name="role_empty"),
    path("no-role/", views.no_role, name="no_role"),
    path("roles/", views.roles_console, name="roles_console"),
    path("roles/select/", views.role_select, name="role_select"),
    path("profile/", views.profile, name="profile"),
    path("settings/", views.system_settings, name="system_settings"),
    path("settings/grafana/", views.grafana_config, name="grafana_config"),
    path("settings/prometheus/", views.prometheus_config, name="prometheus_config"),
    path("settings/prometheus/rules/<str:filename>/", views.prometheus_rule_file, name="prometheus_rule_file"),

    # ---- The labelled-fields view of the SAME prometheus.yml the raw editor above holds.
    # Separate URLs because they are two ways of editing one thing, not two things: both read
    # the newest PrometheusConfigRevision and both apply through promtool.
    path("configuration/", views.configuration, name="configuration"),
    path("configuration/prometheus/", views.config_prometheus, name="config_prometheus"),
    path("configuration/topology/", views.config_topology, name="config_topology"),
    path("configuration/snmp/", views.config_snmp, name="config_snmp"),
    path("configuration/backup-policy/", views.config_backup_policy, name="config_backup_policy"),
    path("configuration/yaml/", views.config_yaml, name="config_yaml"),
    path("configuration/scripts/", views.config_scripts, name="config_scripts"),
    path("configuration/scripts/<int:pk>/", views.config_script_edit, name="config_script_edit"),
    path("configuration/scripts/<int:pk>/preview/", views.config_script_preview, name="config_script_preview"),
    path("configuration/role-scopes/", views.config_role_scopes, name="config_role_scopes"),
    path("configuration/alert-groups/", views.config_alert_groups, name="config_alert_groups"),
    path("configuration/alert-groups/<int:pk>/", views.config_alert_group_edit, name="config_alert_group_edit"),
    path("users/create/", views.config_create_user, name="config_create_user"),
    path("settings/report-theme/", views.set_report_theme, name="set_report_theme"),
    path("notifications/seen/", views.mark_notifications_seen, name="mark_notifications_seen"),
]
