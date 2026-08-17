from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

_phone_validator = RegexValidator(
    regex=r"^[0-9+()\-.\s]{3,40}$",
    message="Enter a valid phone number (digits, spaces and + ( ) - . only).",
)
# lenient URL check — accepts IPs and internal hostnames (URLField would reject e.g. http://prometheus:9090)
_url_validator = RegexValidator(
    regex=r"^https?://\S+$",
    message="Enter a URL starting with http:// or https://",
)


class UserProfile(models.Model):
    """Extended, non-authentication user data (a OneToOne to the auth User, which owns
    username / password / email / flags). Auto-created for every user; filled manually by an
    administrator or automatically on the user's first LDAP/vault login. The canonical e-mail
    stays on the auth User and is OPTIONAL — a profile can exist without one."""

    SOURCE_CHOICES = [("manual", "Manual"), ("ldap", "LDAP")]
    THEME_CHOICES = [("dark", "Dark"), ("light", "Light")]
    PAGE_THEME_CHOICES = [("system", "Follow system"), ("dark", "Dark"), ("light", "Light")]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                related_name="profile")

    # ---- identity / directory ----
    employee_id = models.CharField(max_length=64, blank=True)
    job_title = models.CharField(max_length=128, blank=True)
    department = models.CharField(max_length=128, blank=True)
    phone = models.CharField(max_length=40, blank=True, validators=[_phone_validator])
    mobile = models.CharField(max_length=40, blank=True, validators=[_phone_validator])
    office_location = models.CharField(max_length=128, blank=True)
    distinguished_name = models.CharField("distinguished name (LDAP)", max_length=512, blank=True)

    # ---- preferences ----
    default_report_theme = models.CharField(max_length=10, choices=THEME_CHOICES, default="dark")
    page_theme = models.CharField(max_length=10, choices=PAGE_THEME_CHOICES, default="system")

    # ---- notifications ----
    notifications_seen_at = models.DateTimeField(null=True, blank=True,
                                                 help_text="When this user last opened notifications")

    # ---- provenance / metadata ----
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default="manual")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="profiles_created")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["employee_id"]),
            models.Index(fields=["department"]),
        ]

    def __str__(self):
        return f"Profile · {self.user.get_username()}"

    @property
    def display_name(self) -> str:
        return self.user.get_full_name() or self.user.get_username()

    @property
    def email(self) -> str:
        """Convenience: the (optional) e-mail from the auth User; '' when unset."""
        return self.user.email or ""


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def _ensure_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


class ReportSubmission(models.Model):
    """One generated report — the metadata plus every input the admin supplied.

    The full per-system answers/comments live in `annotations` (JSON) so the audit trail
    is complete without a wide schema; the denormalised counts exist for cheap list views.
    """

    THEME_CHOICES = [("dark", "Dark"), ("light", "Light")]
    DELIVERY_CHOICES = [("download", "Download"), ("email", "Email")]

    created_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="report_submissions",
    )
    author = models.CharField(max_length=120, blank=True, help_text="Name signed on the report")
    theme = models.CharField(max_length=10, choices=THEME_CHOICES, default="dark")
    delivery = models.CharField(max_length=10, choices=DELIVERY_CHOICES, default="download")
    recipients = models.CharField(max_length=512, blank=True, help_text="Comma-separated, if emailed")

    prom_url = models.CharField(max_length=256, blank=True)
    systems_count = models.PositiveIntegerField(default=0)
    hosts_count = models.PositiveIntegerField(default=0)
    immediate_count = models.PositiveIntegerField(default=0)   # red flags across all systems
    watch_count = models.PositiveIntegerField(default=0)       # amber flags across all systems

    summary_comment = models.TextField(blank=True)
    # {system_name: {"flags": {flag_key: "Yes"|"No"}, "comment": str}}
    annotations = models.JSONField(default=dict, blank=True)
    # Full snapshot of what the report presented (overview KPIs + per-system flagged items,
    # each merged with the admin's Yes/No answer) so History can render the report verbatim
    # without re-querying Prometheus.
    report_content = models.JSONField(default=dict, blank=True)
    filename = models.CharField(max_length=256, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        who = self.author or (self.generated_by and self.generated_by.get_username()) or "unknown"
        return f"Report {self.created_at:%Y-%m-%d %H:%M} · {self.theme} · {who}"

    @property
    def flags_answered(self) -> int:
        return sum(
            1
            for sysd in self.annotations.values()
            for ans in (sysd.get("flags", {}) or {}).values()
            if ans in ("Yes", "No")
        )


class SystemConfig(models.Model):
    """Runtime, admin-editable system settings (a singleton, pk=1). Where set, these OVERRIDE
    config.ini — notably the Prometheus server the dashboard fetches its data from, so an
    Administrator can repoint it without touching files."""

    prometheus_url = models.CharField(
        max_length=256, blank=True, validators=[_url_validator],
        help_text="Prometheus base URL the dashboard fetches from (blank = use config.ini)")
    grafana_url = models.CharField(
        max_length=1024, blank=True, validators=[_url_validator],
        help_text="Live Grafana dashboard URL (blank = use config.ini)")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        verbose_name = "system configuration"
        verbose_name_plural = "system configuration"

    def __str__(self):
        return "System configuration"

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class GrafanaConfigRevision(models.Model):
    """A point-in-time snapshot of Grafana's custom.ini. APPEND-ONLY — a save always creates
    a new row, never edits or deletes one, so the full history is browsable and the live file
    can be regenerated from any row. `current()` (the most recent row) is what the edit
    screen shows and what the live file was last rendered from; see reports/grafana_admin.py
    for the render/write/restart logic. The DB is the version history — there is no per-version
    file kept on disk, only the one live custom.ini, fully overwritten on every apply."""

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")
    note = models.CharField(max_length=200, blank=True,
                            help_text="What changed and why (optional)")

    # [server]
    protocol = models.CharField(max_length=8, default="https",
                                choices=[("https", "https"), ("http", "http")])
    cert_file = models.CharField(max_length=512, blank=True)
    cert_key = models.CharField(max_length=512, blank=True)
    root_url = models.CharField(max_length=512, blank=True, validators=[_url_validator])

    # [security]
    allow_embedding = models.BooleanField(default=True)

    # [smtp]
    smtp_enabled = models.BooleanField(default=True)
    smtp_host = models.CharField(max_length=256, blank=True)
    smtp_user = models.CharField(max_length=256, blank=True)
    smtp_password_encrypted = models.TextField(
        blank=True, help_text="Fernet ciphertext — see reports/crypto.py. Never plaintext.")
    smtp_skip_verify = models.BooleanField(default=False)
    smtp_from_address = models.CharField(max_length=256, blank=True)
    smtp_from_name = models.CharField(max_length=128, blank=True)
    smtp_ehlo_identity = models.CharField(max_length=128, blank=True)
    smtp_starttls_policy = models.CharField(
        max_length=32, default="Always",
        choices=[("Always", "Always"), ("OpportunisticStartTLS", "OpportunisticStartTLS"),
                 ("MandatoryStartTLS", "MandatoryStartTLS"), ("NoStartTLS", "NoStartTLS")])

    # [alerting]
    execute_alerts = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Grafana config revision"

    def __str__(self):
        return f"Grafana config @ {self.created_at:%d %b %Y %H:%M}"

    @classmethod
    def current(cls):
        """The most recent revision, or None if nothing has ever been saved yet (the edit
        screen falls back to parsing the live file in that case — see grafana_admin.py)."""
        return cls.objects.first()


class RoleRequest(models.Model):
    """A user's request for a role (Django group). Administrators approve/reject these."""

    STATUS_CHOICES = [("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected")]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name="role_requests")
    role = models.CharField(max_length=64)   # requested role / group name
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="role_decisions")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user} → {self.role} ({self.status})"


class EmailRecipient(models.Model):
    """A curated address for the 'e-mail report to' chooser. Managed in the Django admin
    (Reports › Email recipients) so admins maintain the list in-app, not in config.ini."""

    email = models.EmailField(unique=True)
    name = models.CharField(max_length=120, blank=True, help_text="Display name (optional)")
    default_selected = models.BooleanField(
        default=False, help_text="Pre-ticked in the send dialog")
    active = models.BooleanField(default=True, help_text="Untick to hide without deleting")

    class Meta:
        ordering = ["name", "email"]
        verbose_name = "email recipient"

    def __str__(self):
        return f"{self.name} <{self.email}>" if self.name else self.email

    @property
    def label(self) -> str:
        return f"{self.name} · {self.email}" if self.name else self.email
