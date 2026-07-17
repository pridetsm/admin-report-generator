from django import forms
from django.contrib.auth import get_user_model

from .models import SystemConfig, UserProfile


class SystemConfigForm(forms.ModelForm):
    class Meta:
        model = SystemConfig
        fields = ["prometheus_url", "grafana_url"]
        widgets = {
            "prometheus_url": forms.TextInput(attrs={"placeholder": "http://10.100.248.249:9090"}),
            "grafana_url": forms.TextInput(attrs={"placeholder": "http://…:3000/d/…"}),
        }


class UserAccountForm(forms.ModelForm):
    """Auth-adjacent fields the user may edit. E-mail is OPTIONAL (nullable) — a profile can
    be created by an admin or completed on first LDAP login without one."""

    class Meta:
        model = get_user_model()
        fields = ["first_name", "last_name", "email"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = False
        self.fields["email"].widget.attrs["placeholder"] = "name@rbz.co.zw (optional)"


class ProfileForm(forms.ModelForm):
    """User-editable profile fields (directory-sourced fields like the DN stay admin-managed)."""

    class Meta:
        model = UserProfile
        fields = ["employee_id", "job_title", "department", "phone", "mobile",
                  "office_location", "default_report_theme", "page_theme"]
