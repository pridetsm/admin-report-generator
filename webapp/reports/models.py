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


class AlertGroup(models.Model):
    """A named group of stakeholders who want to hear about problems on a set of systems —
    deliberately freeform (the admin names it however their organization actually thinks about
    it, e.g. "Payments Team" — no fixed taxonomy underneath).

    UNLIKE RoleScope, an EMPTY `systems` list here means the group covers NOTHING, not "the
    whole estate" — a freshly created group must not silently start alerting on everything
    before anyone has picked systems for it. Silence, not everything, is the safe default for
    an alerting feature (the opposite of the safe default for a dashboard-visibility scope).
    """

    MIN_SEVERITY_CHOICES = [
        ("red", "Red only"),
        ("amber", "Red + Amber"),
    ]
    # A typical setup (2026-09-03): fire once on the incident, then keep firing every X
    # minutes for as long as it's still open, going silent the moment a poll finds it
    # resolved. `renotify_interval_minutes` IS that X, directly -- not a "once vs daily"
    # choice between two fixed cadences (what this field replaced): blank/0 means "once, then
    # silent until resolved" (no repeat at all), any positive number of minutes means "repeat
    # at least that often" -- "at least", because resolution and re-notification are BOTH only
    # ever checked when the alert poller actually runs (see reports.alerting.run_alert_cycle,
    # invoked on its own schedule), so an interval shorter than the poller's own cadence can't
    # fire any faster than the poller itself does.
    DEFAULT_RENOTIFY_MINUTES = 60
    # The same category strings generate_report.Flag.category already carries on every
    # finding (disk/ram/cpu/service/backup/unreachable/untracked) -- reused as-is rather than
    # inventing a second taxonomy, so a group's filter always means exactly what the report's
    # own flags mean. "folder" is a documented exception: generate_report.flagged_for_system
    # never emits it (folder-over-expected-size is only ever a report-level banner there, see
    # folder_over_expected_detail) -- reports.alerting synthesizes a matching Flag itself,
    # entirely within the alerting engine, rather than touching the shared report-engine file
    # (which exists in 3 kept-in-sync copies) just to add one more category.
    #
    # "backup_uncleared" is a PLACEHOLDER, on request (2026-09-03) -- no detection exists for
    # it anywhere yet (not in generate_report.py, not synthesized in alerting.py the way
    # "folder" is). Listed here so it has a stable key/label ready for whenever that check IS
    # built, but views._category_grid_rows marks it inapplicable for every system
    # unconditionally, same visual treatment "folder" gets for a system with no watched
    # folder -- never a live, tickable checkbox anywhere until real detection backs it.
    #
    # "undrained_folders" (2026-09-04) is REAL, not a placeholder -- same shape as "folder":
    # generate_report.flagged_for_system never emits it either, so reports.alerting
    # synthesizes it, this time from reports.folders.snapshot() (the Folder Watch screen's own
    # live verdict per payment-queue folder: files waiting whose oldest has aged past its
    # amber/red limit -- see folders.verdict's own docstring). A DRAINED folder (files<=0,
    # folders.py's "idle") is healthy and never flags; this is specifically the folder that
    # ISN'T draining. Same T24-only applicability as "folder" -- both read the identical
    # folder_exporter job in prometheus.yml, see folders.folder_watch_systems.
    #
    # LABELS (2026-09-04): "folder" and "undrained_folders" are the two folder-monitoring
    # categories -- named "Size monitoring" and "Drainage monitoring" respectively so the two
    # failure modes read as a pair: a folder that has grown too big (Size) vs. a folder that
    # isn't being emptied in time (Drainage). The stored KEYS are unchanged ("folder" /
    # "undrained_folders") -- only the display label moved -- since the key is also what a
    # saved AlertGroup.categories JSON blob already has written into real rows; renaming the
    # key would need a data migration for no behavioural gain.
    CATEGORY_CHOICES = [
        ("disk", "Disk usage"),
        ("ram", "RAM usage"),
        ("cpu", "CPU usage"),
        ("service", "Service down"),
        ("backup", "Backup missing"),
        ("unreachable", "Component unreachable"),
        ("untracked", "Backup untracked"),
        ("folder", "Size monitoring"),
        ("backup_uncleared", "Uncleared backups"),
        ("undrained_folders", "Drainage monitoring"),
    ]

    name = models.CharField(max_length=120, unique=True)
    systems = models.JSONField(
        default=list, blank=True,
        help_text="System names from prometheus.yml this group covers. Empty = covers "
                   "nothing yet (unlike Role scopes, empty here is not ‘all systems’).")
    categories = models.JSONField(
        default=dict, blank=True,
        help_text="{system name: [category, ...]} -- per-system, not global, since not every "
                   "system tracks the same things (e.g. only some have named service checks). "
                   "A system ABSENT from this dict, or present with an empty list, means ALL "
                   "categories for THAT system -- unlike `systems` above, missing/empty here "
                   "means everything, not nothing, because this field was added after groups "
                   "already existed in the wild and an empty-means-nothing default would have "
                   "silently gone quiet for every one of them the moment it appeared.")
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, blank=True, related_name="alert_groups",
        help_text="App users notified via their account e-mail.")
    emails = models.JSONField(
        default=list, blank=True,
        help_text="Plain e-mail addresses for stakeholders with no account.")
    min_severity = models.CharField(max_length=10, choices=MIN_SEVERITY_CHOICES, default="red")
    renotify_interval_minutes = models.PositiveIntegerField(
        null=True, blank=True, default=DEFAULT_RENOTIFY_MINUTES,
        help_text="Re-notify at least this often while a finding stays open. Blank or 0 = "
                   "fire once, then stay silent until resolved.")
    active = models.BooleanField(default=True, help_text="Untick to pause without deleting.")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        ordering = ["name"]
        verbose_name = "alert group"

    def __str__(self):
        n = len(self.systems or [])
        return f"{self.name} → {n} system(s)" if n else f"{self.name} → no systems yet"

    def recipient_emails(self) -> list:
        """De-duplicated stakeholder addresses: plain emails + active users' own account
        e-mail (blank OR malformed addresses silently dropped rather than erroring the whole
        group -- some legacy User rows carry the literal string "None" as their .email, which
        is non-blank so a truthiness check alone lets it through)."""
        from django.core.exceptions import ValidationError as _VE
        from django.core.validators import validate_email as _validate_email

        def _valid(addr: str) -> bool:
            try:
                _validate_email(addr)
                return True
            except _VE:
                return False

        addrs = {e.strip() for e in (self.emails or []) if e.strip()}
        addrs |= {u.email.strip() for u in self.users.filter(is_active=True) if u.email}
        return sorted(a for a in addrs if _valid(a))

    def category_matches(self, system: str, category: str) -> bool:
        """Whether a Flag of this category, on THIS system, clears the group's own per-system
        filter -- a system absent from `categories`, or present with an empty list, means
        every category qualifies for it (see that field's own help_text for why that default
        differs from `systems`/`emails`)."""
        allowed = (self.categories or {}).get(system) or []
        return not allowed or category in allowed

    @property
    def stakeholder_count(self) -> int:
        return self.users.count() + len(self.emails or [])


class AlertFinding(models.Model):
    """One (group, system, flag) row's notification state — the dedup ledger the alert poller
    (see reports.alerting) consults every cycle to decide new / reminder / skip / resolved.
    `flag_key` is generate_report.Flag.key, the SAME stable key the report itself uses to marry
    an admin's Yes/No answer back to a flagged row — this table only remembers WHEN something
    was last seen/notified, it never re-derives whether it's actually wrong (that stays exactly
    generate_report.flagged_for_system's job, called fresh every poll).

    Both renotify behaviours read off the same three timestamps:
      "once"  -> notify only when last_notified_at is NULL or the row was just reopened.
      "daily" -> notify when last_notified_at is NULL, OR >=24h have passed since it.
    An escalation (band worsens amber -> red on an already-notified, still-open row) always
    forces a fresh notification regardless of renotify_mode -- a stakeholder told "amber" needs
    to hear when it becomes "red", not stay silent because they were "already told" something
    less severe.

    A resolved row (resolved_at set) that reappears is treated as brand-new: its timestamps
    reset on the SAME row rather than a second row being created, so history for one
    (group, system, flag) triple always lives in exactly one place."""

    group = models.ForeignKey(AlertGroup, on_delete=models.CASCADE, related_name="findings")
    system = models.CharField(max_length=120)            # System.name from prometheus.yml
    flag_key = models.CharField(max_length=255)           # generate_report.Flag.key
    band = models.CharField(max_length=10)                # last-seen "red" / "amber"
    text = models.CharField(max_length=500, blank=True)   # last-seen Flag.text, for the e-mail
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    last_notified_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("group", "system", "flag_key")
        ordering = ["-last_seen_at"]
        verbose_name = "alert finding state"

    def __str__(self):
        state = "resolved" if self.resolved_at else "open"
        return f"{self.group.name} · {self.system} · {self.flag_key} ({state})"


class GeneratedScript(models.Model):   # noqa: E303 — appended after EmailRecipient
    """The definition of one agent-side checker script — the thing the script is generated FROM.

    EDITABLE, unlike the *ConfigRevision models beside it. Those are append-only because they
    hold a whole file whose previous versions you may need to restore. This holds a handful of
    parameters for a script that is regenerated from them on demand: the definition IS the
    current state, and "restore the old one" means changing a path back and regenerating. An
    append-only history of two-line diffs would be ceremony, not safety.

    Secrets never live in `parameters`. They go in `secrets_encrypted` as a Fernet-encrypted
    JSON map (reports/crypto.py) and are substituted into the script only as it is written to
    the configuration folder, which is gitignored. See reports/scripts.py.
    """

    name = models.CharField(
        max_length=120,
        help_text="What this checks, e.g. 'BSA SQL backup'. Becomes the filename stem.")
    script_type = models.CharField(
        max_length=32, help_text="Key from reports.scripts.SCRIPT_TYPES")
    system = models.CharField(
        max_length=120, blank=True,
        help_text="The system in prometheus.yml this belongs to — for the generated header, "
                  "so a file on a host says which estate it serves.")
    host = models.CharField(
        max_length=200, blank=True,
        help_text="Where it runs. Recorded for the operator; the script itself doesn't use it.")
    parameters = models.JSONField(
        default=dict, blank=True,
        help_text="Non-secret field values. NEVER put a credential here — see secrets_encrypted.")
    secrets_encrypted = models.TextField(
        blank=True, help_text="Fernet ciphertext — see reports/crypto.py. Never plaintext.")
    notes = models.TextField(blank=True, help_text="Anything the next person needs to know.")

    last_generated_at = models.DateTimeField(null=True, blank=True)
    last_generated_files = models.JSONField(
        default=list, blank=True, help_text="Paths written by the last generate.")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        ordering = ["script_type", "name"]
        verbose_name = "generated script"
        constraints = [
            # one definition per name per type: two would render to the same filename and
            # silently overwrite each other in the configuration folder
            models.UniqueConstraint(fields=["script_type", "name"],
                                    name="unique_script_name_per_type"),
        ]

    def __str__(self):
        return f"{self.name} ({self.script_type})"

    def secret_values(self) -> dict:
        """The decrypted secret map. {} when unset or undecryptable (e.g. SECRET_KEY rotated),
        which callers treat the same as "none set" rather than failing the render."""
        import json

        from . import crypto

        raw = crypto.decrypt(self.secrets_encrypted or "")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            return {}

    @property
    def secret_names(self) -> list:
        """Which secrets are set, for display. Names only — never the values."""
        return sorted(self.secret_values().keys())
