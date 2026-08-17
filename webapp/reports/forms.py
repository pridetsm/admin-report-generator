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


class GrafanaConfigForm(forms.Form):
    """A plain Form, not a ModelForm — `password` must NEVER be pre-populated from a stored
    value (it's shown once, on submit, and never round-tripped back to the browser), which a
    model-bound field can't express. Every other field mirrors GrafanaConfigRevision 1:1."""

    note = forms.CharField(
        max_length=200, required=False,
        widget=forms.TextInput(attrs={"placeholder": "What changed and why (optional)"}))

    # [server]
    protocol = forms.ChoiceField(choices=[("https", "https"), ("http", "http")])
    cert_file = forms.CharField(max_length=512, required=False)
    cert_key = forms.CharField(max_length=512, required=False)
    root_url = forms.CharField(max_length=512, required=False,
                               widget=forms.TextInput(attrs={"placeholder": "https://…:3000"}))

    # [security]
    allow_embedding = forms.BooleanField(required=False)

    # [smtp]
    smtp_enabled = forms.BooleanField(required=False)
    smtp_host = forms.CharField(max_length=256, required=False,
                                widget=forms.TextInput(attrs={"placeholder": "smtp.office365.com:587"}))
    smtp_user = forms.CharField(max_length=256, required=False)
    password = forms.CharField(
        max_length=256, required=False, widget=forms.PasswordInput(render_value=False),
        help_text="Leave blank to keep the current password")
    smtp_skip_verify = forms.BooleanField(required=False)
    smtp_from_address = forms.CharField(max_length=256, required=False)
    smtp_from_name = forms.CharField(max_length=128, required=False)
    smtp_ehlo_identity = forms.CharField(max_length=128, required=False)
    smtp_starttls_policy = forms.ChoiceField(choices=[
        ("Always", "Always"), ("OpportunisticStartTLS", "OpportunisticStartTLS"),
        ("MandatoryStartTLS", "MandatoryStartTLS"), ("NoStartTLS", "NoStartTLS")])

    # [alerting]
    execute_alerts = forms.BooleanField(required=False)


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
