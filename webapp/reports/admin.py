from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import (BackupPolicyRevision, EmailRecipient, GrafanaConfigRevision,
                     PrometheusConfigRevision, PrometheusRuleFileRevision, ReportSubmission,
                     RoleRequest, RoleScope, SnmpConfigRevision, SystemConfig, UserProfile)


@admin.register(SystemConfig)
class SystemConfigAdmin(admin.ModelAdmin):
    list_display = ("__str__", "prometheus_url", "grafana_url", "updated_at", "updated_by")
    readonly_fields = ("updated_at", "updated_by")


@admin.register(GrafanaConfigRevision)
class GrafanaConfigRevisionAdmin(admin.ModelAdmin):
    """Read-only browsing — revisions are only ever created through the grafana_config view
    (which handles password encryption); the admin never shows/edits the encrypted field."""
    list_display = ("__str__", "note", "created_by")
    readonly_fields = tuple(f.name for f in GrafanaConfigRevision._meta.fields
                            if f.name != "smtp_password_encrypted")
    exclude = ("smtp_password_encrypted",)
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(PrometheusConfigRevision)
class PrometheusConfigRevisionAdmin(admin.ModelAdmin):
    """Read-only browsing — revisions are only ever created through the prometheus_config view."""
    list_display = ("__str__", "note", "created_by")
    readonly_fields = tuple(f.name for f in PrometheusConfigRevision._meta.fields)
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(PrometheusRuleFileRevision)
class PrometheusRuleFileRevisionAdmin(admin.ModelAdmin):
    """Read-only browsing — revisions are only ever created through the prometheus_rule_file view."""
    list_display = ("__str__", "filename", "note", "created_by")
    list_filter = ("filename",)
    readonly_fields = tuple(f.name for f in PrometheusRuleFileRevision._meta.fields)
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SnmpConfigRevision)
class SnmpConfigRevisionAdmin(admin.ModelAdmin):
    """Read-only browsing — revisions are only ever created through the config_snmp view
    (which handles secret encryption); the admin never shows/edits secrets_encrypted."""
    list_display = ("__str__", "note", "created_by")
    readonly_fields = tuple(f.name for f in SnmpConfigRevision._meta.fields
                            if f.name != "secrets_encrypted")
    exclude = ("secrets_encrypted",)
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(BackupPolicyRevision)
class BackupPolicyRevisionAdmin(admin.ModelAdmin):
    """Read-only browsing — revisions are only ever created through the config_backup_policy
    view. No secrets in this one, so nothing is excluded."""
    list_display = ("__str__", "note", "created_by")
    readonly_fields = tuple(f.name for f in BackupPolicyRevision._meta.fields)
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    fk_name = "user"
    can_delete = False
    extra = 0
    verbose_name_plural = "Profile"
    fields = ("employee_id", "job_title", "department", "phone", "mobile", "office_location",
              "distinguished_name", "default_report_theme", "page_theme", "source",
              "created_at", "updated_at")
    readonly_fields = ("created_at", "updated_at")


class UserAdmin(BaseUserAdmin):
    inlines = [UserProfileInline]
    list_display = ("username", "email", "first_name", "last_name", "department", "is_staff")

    @admin.display(description="Department")
    def department(self, obj):
        return getattr(getattr(obj, "profile", None), "department", "")


_User = get_user_model()
admin.site.unregister(_User)
admin.site.register(_User, UserAdmin)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "department", "job_title", "source", "updated_at")
    list_filter = ("source", "default_report_theme")
    search_fields = ("user__username", "user__email", "employee_id", "department", "job_title")
    readonly_fields = ("created_at", "updated_at")


@admin.register(RoleRequest)
class RoleRequestAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "status", "created_at", "decided_at", "decided_by")
    list_filter = ("status", "role")
    search_fields = ("user__username", "role")
    autocomplete_fields = ()


@admin.register(RoleScope)
class RoleScopeAdmin(admin.ModelAdmin):
    """Normally edited in-app (Configuration › Role scopes); here for completeness."""
    list_display = ("role", "system_count", "updated_at", "updated_by")
    readonly_fields = ("updated_at", "updated_by")
    search_fields = ("role",)

    @admin.display(description="Systems")
    def system_count(self, obj):
        return len(obj.systems or []) or "all (unrestricted)"


@admin.register(EmailRecipient)
class EmailRecipientAdmin(admin.ModelAdmin):
    list_display = ("email", "name", "default_selected", "active")
    list_editable = ("name", "default_selected", "active")
    list_filter = ("active", "default_selected")
    search_fields = ("email", "name")
    ordering = ("name", "email")


@admin.register(ReportSubmission)
class ReportSubmissionAdmin(admin.ModelAdmin):
    list_display = ("created_at", "author", "theme", "generated_by",
                    "systems_count", "immediate_count", "watch_count", "filename")
    list_filter = ("theme", "created_at")
    search_fields = ("author", "summary_comment", "filename")
    readonly_fields = tuple(f.name for f in ReportSubmission._meta.fields) + ("annotations",)
    date_hierarchy = "created_at"
