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
    can be regenerated from any row. `current()` (the most recent row) is what the edit screen
    shows and what the live file was last written from; see reports/grafana_admin.py for the
    mask/unmask/write/restart logic. The DB is the version history — there is no per-version
    file kept on disk, only the one live custom.ini, fully overwritten on every apply.

    `content` holds the WHOLE file as raw text (not one field per setting — custom.ini can hold
    any Grafana directive, and a field-per-setting form can only ever cover the ones already
    modeled). It is ALWAYS the MASKED text — the `password = ...` line under [smtp] is replaced
    with grafana_admin.PASSWORD_PLACEHOLDER, never the real value — so browsing history, or
    viewing this in Django admin, never exposes the real secret. `smtp_password_encrypted`
    holds the real value, separately, at rest as Fernet ciphertext (see reports/crypto.py);
    it's spliced back into `content` only at the moment the live file is actually written."""

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")
    note = models.CharField(max_length=200, blank=True,
                            help_text="What changed and why (optional)")
    content = models.TextField(
        default="", help_text="The entire custom.ini text, MASKED (see class docstring).")
    smtp_password_encrypted = models.TextField(
        blank=True, help_text="Fernet ciphertext — see reports/crypto.py. Never plaintext.")

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


class PrometheusConfigRevision(models.Model):
    """A point-in-time snapshot of the ENTIRE prometheus.yml text. APPEND-ONLY, same shape as
    GrafanaConfigRevision — but the file (443 lines, 11 scrape jobs, ~60 host targets, and
    extensive hand-written rationale comments) is edited as raw YAML text rather than
    decomposed into per-setting fields: a generic re-serialization would either be enormous
    or would silently drop every comment. See reports/prometheus_admin.py — `validate()` runs
    the real `promtool check config` (not just a YAML parse) before anything is ever applied."""

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")
    note = models.CharField(max_length=200, blank=True,
                            help_text="What changed and why (optional)")
    content = models.TextField(help_text="The entire prometheus.yml text.")

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Prometheus config revision"

    def __str__(self):
        return f"Prometheus config @ {self.created_at:%d %b %Y %H:%M}"

    @classmethod
    def current(cls):
        return cls.objects.first()


class PrometheusRuleFileRevision(models.Model):
    """Same append-only/raw-text shape as PrometheusConfigRevision, for the three files
    prometheus.yml's `rule_files:` list references (confirmed via `promtool check config`:
    alerts.yml, t24_services.yml, folder_exporter_rules.yml). One shared model/table for all
    three rather than three near-identical models — `filename` distinguishes them, `current()`
    and the view/URL are parametrized by it. See reports/prometheus_admin.py — validated with
    `promtool check rules` (standalone rule syntax check, independent of prometheus.yml)."""

    RULE_FILE_CHOICES = [
        ("alerts.yml", "alerts.yml"),
        ("t24_services.yml", "t24_services.yml"),
        ("folder_exporter_rules.yml", "folder_exporter_rules.yml"),
    ]

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")
    note = models.CharField(max_length=200, blank=True,
                            help_text="What changed and why (optional)")
    filename = models.CharField(max_length=64, choices=RULE_FILE_CHOICES)
    content = models.TextField(help_text="The entire rule file's text.")

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Prometheus rule file revision"

    def __str__(self):
        return f"{self.filename} @ {self.created_at:%d %b %Y %H:%M}"

    @classmethod
    def current(cls, filename):
        return cls.objects.filter(filename=filename).first()


class SnmpConfigRevision(models.Model):
    """A point-in-time snapshot of the snmp_exporter's `auths:` credential profiles —
    NOT the whole snmp.yml. That file's other ~2MB (`modules:`) is generator output ("manual
    changes will be lost" per its own header); see reports/snmp_admin.py for why this only
    ever reads/writes that one small section's text, never the whole file.

    APPEND-ONLY, same principle as GrafanaConfigRevision: `profiles` is
    {profile_name: {field: value, ...}, ...}, ALWAYS with every secret field (community,
    password, priv_password — see snmp_admin.SECRET_FIELDS) replaced by
    snmp_admin.PASSWORD_PLACEHOLDER, so browsing history or viewing this in Django admin never
    exposes a real credential. `secrets_encrypted` holds the real values, separately, at rest
    as Fernet ciphertext keyed the same way ({profile_name: {field: ciphertext, ...}}); they
    are spliced back in only at the moment the live file is actually written."""

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")
    note = models.CharField(max_length=200, blank=True,
                            help_text="What changed and why (optional)")
    profiles = models.JSONField(
        default=dict, help_text="{profile: {field: value, ...}}, secrets MASKED (see class docstring).")
    secrets_encrypted = models.JSONField(
        default=dict, help_text="{profile: {field: ciphertext, ...}} — Fernet, never plaintext.")

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "SNMP config revision"

    def __str__(self):
        return f"SNMP config @ {self.created_at:%d %b %Y %H:%M}"

    @classmethod
    def current(cls):
        return cls.objects.first()


class BackupPolicyRevision(models.Model):
    """A point-in-time snapshot of the per-host backup-frequency overrides
    generate_report.backup_cutoff() reads (see BACKUP_MAX_AGE_DAYS / reload_backup_policy
    there) — how many days old a host's newest backup may be and still count as CURRENT.
    Almost every host backs up daily; a host on a slower cycle (BSA's database, every 3rd
    day) needs its own entry here, otherwise the gap between its runs reads as a missing
    backup. "Frequency" is the only component this models today — see
    reports/backup_policy_admin.py's docstring for room to add more later (e.g. an expected
    time-of-day) without reshaping this field.

    APPEND-ONLY, same principle as the other config revisions. `policy` is
    {instance: {"frequency_days": N}, ...} — sparse: a host absent from it just gets the
    daily default, so filling this in gradually never hides an existing host's status. No
    secrets here, so unlike Grafana/SNMP there is nothing to mask or encrypt."""

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")
    note = models.CharField(max_length=200, blank=True,
                            help_text="What changed and why (optional)")
    policy = models.JSONField(
        default=dict, help_text="{instance: {\"frequency_days\": N}, ...} — sparse overrides only.")

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Backup policy revision"

    def __str__(self):
        return f"Backup policy @ {self.created_at:%d %b %Y %H:%M}"

    @classmethod
    def current(cls):
        return cls.objects.first()


class RoleScope(models.Model):
    """Which systems (from prometheus.yml) a role's workspace covers.

    Picking a role on the role-selection screen scopes the dashboard to that role's systems;
    "Load all my roles" is the union across every role the user holds. An EMPTY `systems`
    list means "unrestricted" — the role sees the whole estate — so the mapping can be filled
    in gradually without ever hiding data by accident.
    """

    role = models.CharField(max_length=64, unique=True,
                            help_text="Role (Django group) name, e.g. 'Network Admin'")
    systems = models.JSONField(
        default=list, blank=True,
        help_text="System names from prometheus.yml. Empty = this role sees every system.")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        ordering = ["role"]
        verbose_name = "role scope"

    def __str__(self):
        n = len(self.systems or [])
        return f"{self.role} → {n} system(s)" if n else f"{self.role} → all systems"

    @classmethod
    def systems_for(cls, roles):
        """The set of system names the given roles may see, or None for 'unrestricted'.

        None (not an empty set) is returned when ANY of the roles is unmapped, because an
        unmapped role means "everything" — and a union with everything is everything.
        """
        roles = [r for r in roles if r]
        if not roles:
            return None
        rows = {r.role: (r.systems or []) for r in cls.objects.filter(role__in=roles)}
        allowed: set = set()
        for role in roles:
            mapped = rows.get(role)
            if not mapped:          # unmapped, or mapped to an empty list -> unrestricted
                return None
            allowed.update(mapped)
        return allowed


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
