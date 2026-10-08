from django.urls import path

from . import views

urlpatterns = [
    path("reports/", views.reports, name="reports"),
    path("reports/os-inventory/", views.os_inventory, name="os_inventory"),
    path("reports/backup-history/", views.backup_history_report, name="backup_history_report"),
    path("reports/automated/", views.automated_reports, name="automated_reports"),
    # BOTH of these MUST come before the greedy <str:report_type>/ pattern below -- a single-
    # segment literal path here (e.g. "finding-action") would otherwise match report_type's
    # own single-segment converter FIRST (Django resolves urlpatterns in list order), routing
    # here as if "finding-action" itself were a report type and 404ing inside that view
    # instead (confirmed live 2026-09-10 while building item 10a's editing endpoint -- the
    # existing "distribution/toggle/" entry below never hit this because it has an extra path
    # segment report_type's own single-<str:> converter can't match at all).
    path("reports/automated/finding-action/", views.automated_finding_action,
        name="automated_finding_action"),
    path("reports/automated/<str:report_type>/", views.automated_report_type,
        name="automated_report_type"),
    path("reports/automated/<str:report_type>/<int:pk>/", views.automated_report_detail,
        name="automated_report_detail"),
    path("reports/automated/<str:report_type>/<int:pk>/download/",
        views.automated_report_download, name="automated_report_download"),
    path("reports/automated/distribution/toggle/", views.automated_report_toggle_distribution,
        name="automated_report_toggle_distribution"),
    path("", views.report_form, name="report_form"),
    path("report/", views.report, name="report"),
    path("generate/", views.generate, name="generate"),
    path("my-alert-groups/", views.my_alert_groups, name="my_alert_groups"),
    path("connect/", views.connect_index, name="connect"),
    path("connect/rdp/", views.connect_rdp, name="connect_rdp"),
    path("folders/", views.folder_watch, name="folder_watch"),
    path("folders/temenos/", views.folder_watch_temenos, name="folder_watch_temenos"),
    path("folders/temenos/data/", views.folder_watch_data, name="folder_watch_data"),
    path("management/", views.management_dashboard_pretty, name="management_dashboard_pretty"),
    path("management/pretty-analytical/", views.management_dashboard_pretty_analytical,
        name="management_dashboard_pretty_analytical"),
    path("management/focus/", views.management_dashboard_focus, name="management_dashboard_focus"),
    path("management/full/", views.management_dashboard_full, name="management_dashboard_full"),
    path("management/analytical/", views.management_dashboard_analytical, name="management_dashboard_analytical"),
    path("management/alerts/", views.management_dashboard_alerts, name="management_dashboard_alerts"),
    path("management/alerts/comments/", views.alert_comment_history, name="alert_comment_history"),
    path("management/alerts/mute/", views.alert_mute_from_comment, name="alert_mute_from_comment"),
    path("management/alerts/mute-bulk/", views.alert_mute_bulk, name="alert_mute_bulk"),
    path("management/alerts/unmute/", views.alert_unmute, name="alert_unmute"),
    path("management/alerts/mute-recurring/", views.alert_mute_recurring, name="alert_mute_recurring"),
    # The start-of-day checklist. Its own trio of URLs rather than a mode of a live report:
    # that one would capture live SNMP for the devices you pick, this one is hand-keyed from
    # four vendor consoles across a fixed estate — but it gets a picker of its own too, to
    # thin the entry screen down to what is actually being checked this morning. Nested the
    # same way the four Networks Report pickers below are: the picker owns the parent
    # path. (The old network_dashboard/network_report/network_generate trio this comment used
    # to reference was retired 2026-09-22 -- see network.DEVICES' own comment on the
    # 38-device block -- but "network/sod/" itself is unrelated and stays exactly as it was.)
    path("network/sod/", views.network_sod_select, name="network_sod_select"),
    path("network/sod/checklist/", views.network_sod_form, name="network_sod"),
    path("network/sod/generate/", views.network_sod_generate, name="network_sod_generate"),
    path("infra/", views.infra_form, name="infra_form"),
    path("infra/report/", views.infra_report, name="infra_report"),
    path("infra/generate/", views.infra_generate, name="infra_generate"),
    path("active-directory/", views.active_directory_form, name="active_directory_form"),
    path("active-directory/report/", views.active_directory_report, name="active_directory_report"),
    path("active-directory/generate/", views.active_directory_generate, name="active_directory_generate"),
    # "Networks Report" category (2026-09-22). Deliberately "networks/" (plural), distinct
    # from the existing singular "network/" prefix above (the SOD checklist) -- signals the
    # new category and avoids any path collision. Nested the same way infra/ and
    # active-directory/ are: each picker owns its own parent path.
    #
    # Four reports (2026-09-23, on request: "create a seperate core switches report and a
    # seperate routers report ... this current report rename it to Access switches", then
    # "the one without poe wireless controller... put it in its own report called wireless
    # controller") -- replaces the single combined "networks/switches-routers/" trio this
    # comment used to describe. All four share the same underlying SNMP engine
    # (network.collect()/build_report(), mode="switches_routers") and differ only in which
    # DEVICES keys they're scoped to -- see network.py's own "four report-picker estates"
    # comment just above core_switches_device_keys().
    path("networks/core-switches/", views.core_switches_form, name="core_switches_form"),
    path("networks/core-switches/report/", views.core_switches_report, name="core_switches_report"),
    path("networks/core-switches/generate/", views.core_switches_generate, name="core_switches_generate"),
    path("networks/routers/", views.routers_form, name="routers_form"),
    path("networks/routers/report/", views.routers_report, name="routers_report"),
    path("networks/routers/generate/", views.routers_generate, name="routers_generate"),
    path("networks/wireless-controller/", views.wireless_controller_form, name="wireless_controller_form"),
    path("networks/wireless-controller/report/", views.wireless_controller_report, name="wireless_controller_report"),
    path("networks/wireless-controller/generate/", views.wireless_controller_generate, name="wireless_controller_generate"),
    path("networks/access-switches/", views.access_switches_form, name="access_switches_form"),
    path("networks/access-switches/report/", views.access_switches_report, name="access_switches_report"),
    path("networks/access-switches/generate/", views.access_switches_generate, name="access_switches_generate"),
    # Firewall Report (2026-09-29) -- fifth member of the Networks Report category, see
    # network.firewall_device_keys' own comment on why none of its devices can leak a false
    # "unreachable" into the alert poller or the Executive Dashboard's Network tile.
    path("networks/firewalls/", views.firewalls_form, name="firewalls_form"),
    path("networks/firewalls/report/", views.firewalls_report, name="firewalls_report"),
    path("networks/firewalls/generate/", views.firewalls_generate, name="firewalls_generate"),
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
    path("configuration/roles/", views.config_roles, name="config_roles"),
    path("configuration/users/", views.config_users, name="config_users"),
    path("configuration/prometheus/", views.config_prometheus, name="config_prometheus"),
    path("configuration/topology/", views.config_topology, name="config_topology"),
    path("configuration/snmp/", views.config_snmp, name="config_snmp"),
    path("configuration/folder-exporter/", views.config_folder_exporter, name="config_folder_exporter"),
    path("configuration/backup-policy/", views.config_backup_policy, name="config_backup_policy"),
    path("configuration/yaml/", views.config_yaml, name="config_yaml"),
    path("configuration/scripts/", views.config_scripts, name="config_scripts"),
    path("configuration/scripts/<int:pk>/", views.config_script_edit, name="config_script_edit"),
    path("configuration/scripts/<int:pk>/preview/", views.config_script_preview, name="config_script_preview"),
    path("configuration/role-scopes/", views.config_role_scopes, name="config_role_scopes"),
    path("configuration/alerts/", views.config_alerts, name="config_alerts"),
    path("configuration/alert-groups/<int:pk>/", views.config_alert_group_edit, name="config_alert_group_edit"),
    path("configuration/events/", views.config_events, name="config_events"),
    path("configuration/event-groups/<int:pk>/", views.config_event_group_edit, name="config_event_group_edit"),
    path("configuration/automated-reports/", views.config_automated_reports, name="config_automated_reports"),
    path("configuration/automated-report-groups/<int:pk>/", views.config_automated_report_group_edit, name="config_automated_report_group_edit"),
    path("configuration/freshness-checks/<int:pk>/", views.config_freshness_check_edit, name="config_freshness_check_edit"),
    path("configuration/alert-groups/<int:pk>/test/", views.config_alert_group_test, name="config_alert_group_test"),
    path("configuration/automated-report-groups/<int:pk>/test/", views.config_automated_report_group_test, name="config_automated_report_group_test"),
    path("configuration/alert-groups/<int:pk>/preview/", views.config_alert_group_preview, name="config_alert_group_preview"),
    path("configuration/alert-templates/<str:category>/", views.config_alert_template_preview, name="config_alert_template_preview"),
    path("users/create/", views.config_create_user, name="config_create_user"),
    path("users/<int:pk>/edit/", views.config_edit_user, name="config_edit_user"),
    path("settings/report-theme/", views.set_report_theme, name="set_report_theme"),
    path("notifications/seen/", views.mark_notifications_seen, name="mark_notifications_seen"),
]
