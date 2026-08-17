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


class RawConfigForm(forms.Form):
    """Base shape shared by every whole-file raw-text config editor on this app (Grafana's
    custom.ini, Prometheus's prometheus.yml, and its three rule files): a free-text changelog
    note plus one big textarea holding the entire file. Subclassed per screen only so each has
    its own name in forms.py/views.py — the fields are identical."""

    note = forms.CharField(
        max_length=200, required=False,
        widget=forms.TextInput(attrs={"placeholder": "What changed and why (optional)"}))
    content = forms.CharField(
        widget=forms.Textarea(attrs={
            "rows": 40, "spellcheck": "false", "class": "mono",
            "style": "font-family:Consolas,monospace;font-size:12.5px;white-space:pre;"
                     "tab-size:2;width:100%;box-sizing:border-box"}))


class GrafanaConfigForm(RawConfigForm):
    """The whole custom.ini as text — see GrafanaConfigRevision for why this isn't decomposed
    into per-setting fields, and for how the SMTP password line is masked in `content`."""


class PrometheusConfigForm(RawConfigForm):
    """The whole prometheus.yml as text — see PrometheusConfigRevision for why this isn't
    decomposed into per-setting fields. Also reused as-is for the rule-file sub-pages
    (prometheus_rule_file view) — same note+content shape, no secrets involved either way."""


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
