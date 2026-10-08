import datetime
import re

from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

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


# Categories that are really the SAME monitored thing at a different severity tier -- a
# finding's category prefix (and therefore its flag_key, which is always built "category:...")
# changes as it escalates/de-escalates (disk -> high_disk -> very_high_disk, and the same for
# cpu/ram/folder/drainage -- the 2026-09-30/10-01 severity-matrix redesign's whole point: a
# NEW category per severity tier, not one category whose band varies, see alert_catalog's own
# module docstring). CommentIndexEntry and reports.alert_catalog.comment_history() both need
# to treat all of one group as the SAME real finding for comment-history purposes even though
# they are different categories for alerting purposes -- discovered 2026-10-01 when an exact
# flag_key match turned up "no comments" for RTGS's Database:/u01 (now "high_disk:...") despite
# 54 real comments on record under "disk:Database:/u01" for the identical mount, days earlier
# in the same escalation.
_SEVERITY_SIBLING_GROUPS = [
    {"disk", "high_disk", "very_high_disk"},
    {"cpu", "high_cpu", "very_high_cpu"},
    {"ram", "high_ram", "very_high_ram"},
    {"folder", "very_high_folder"},
    {"undrained_folders", "queue_stuck"},
    {"backup_uncleared", "backup_overdue"},
]
_SIBLING_CATEGORIES_OF = {cat: group for group in _SEVERITY_SIBLING_GROUPS for cat in group}


def comment_index_suffix(category: str, flag_key: str) -> str:
    """flag_key with its OWN category prefix stripped off -- the stable identity a finding
    keeps across a severity-tier category change (see _SEVERITY_SIBLING_GROUPS' own comment).
    Falls back to flag_key verbatim when it doesn't start with "category:" (a few categories
    were never built flag_key-prefixed that way, see reports.alert_catalog._parse_component's
    own comment) -- those simply never had siblings to begin with, so an unchanged flag_key is
    already its own correct, stable identity."""
    prefix = category + ":"
    return flag_key[len(prefix):] if category and flag_key.startswith(prefix) else flag_key


def sibling_flag_keys(category: str, flag_key: str) -> set:
    """Every flag_key this exact finding could have been recorded under at ANY severity tier
    it has ever been at -- {flag_key} alone when `category` has no known siblings or the
    prefix didn't match (safe no-op fallback, identical to the old exact-match behaviour)."""
    suffix = comment_index_suffix(category, flag_key)
    if suffix == flag_key:
        return {flag_key}
    return {f"{c}:{suffix}" for c in _SIBLING_CATEGORIES_OF.get(category, {category})}


# Relevance filter (2026-10-01, on request: "are you sure the targetted comments are relevant
# to the exact issue" / "comments picked for sc corporate actions service being down are
# talking about ram") -- `comment` is a PER-SYSTEM field, one free-text box covering whatever
# that system's report row looked like that day, not one box per flag. The naive "this flag
# was present in the submission, so the comment must be about it" rule (which both the
# original version of this feature AND the first sibling-category fix still used) turned out
# to be WRONG in two different, both real, confirmed ways:
#   1. Two flags of the SAME family present the same day (e.g. RTGS had Database:/u01 AND
#      Backend:/perago both flagged) -- a comment plainly naming one mount
#      ("Database - /u01 93%...") was being attributed to the OTHER, unrelated mount too,
#      purely because both happened to be flagged in the same run.
#   2. Only ONE flag present, but the comment box simply wasn't about it at all (Temenos had
#      exactly one flag that day, "service:...:SC.CORPORATE.ACTIONS DOWN", yet the comment was
#      "T24 DB - RAM threshold raised... buffer cache runs at 90-95% RAM by design" --
#      evidently a standing/carried-forward note, not necessarily describing THAT day's
#      specific flag). "Only one flag -> trust blindly" is not actually safe.
# FAMILY_WORDS below is deliberately small and literal (no stemming/NLP) -- grounded in the
# REAL category vocabulary this report form's own flag text already uses (reports.network's
# own Flag.text strings), not guessed. It only needs to catch a STRONG, unambiguous signal
# that a comment is about a *different* family than the flag being checked -- it is not trying
# to be a general-purpose classifier.
_FAMILY_OF_CATEGORY = {}
for _fam, _cats in {
    "disk": {"disk", "high_disk", "very_high_disk", "flash_storage_critical"},
    "cpu": {"cpu", "high_cpu", "very_high_cpu"},
    "ram": {"ram", "high_ram", "very_high_ram"},
    "folder": {"folder", "very_high_folder", "undrained_folders", "queue_stuck"},
    "backup": {"backup", "backup_uncleared", "backup_overdue", "staleness"},
    "service": {"service", "degraded", "degrading", "potentially_degrading", "unreachable"},
    "temperature": {"temperature"},
}.items():
    for _cat in _cats:
        _FAMILY_OF_CATEGORY[_cat] = _fam

_FAMILY_WORDS = {
    "disk": {"disk", "utilization", "mount", "volume", "partition", "archiving"},
    "cpu": {"cpu", "processor", "load average"},
    "ram": {"ram", "memory", "buffer cache"},
    "folder": {"folder", "queue", "drain", "draining"},
    "backup": {"backup", "no backup"},
    "service": {"service", "down", "stopped", "restart", "degraded", "unreachable"},
    "temperature": {"temperature", "thermal", "overheating"},
}


def category_family(category: str) -> str:
    return _FAMILY_OF_CATEGORY.get(category, category)


def _comment_lines(comment: str) -> list:
    return [l.strip() for l in re.split(r"[\r\n]+", comment) if l.strip()]


def _trim_comment_for(comment: str, lines: list, family: str, needle: str = "") -> str:
    """One multi-topic system-level comment, narrowed to just the line(s) actually about ONE
    specific flag -- a real admin habit this report form's own users have (one line per topic,
    confirmed across multiple real systems), confirmed necessary 2026-10-01 ("this is the disk
    usage issue yet it also picked a comment related to no backup" -- a comment genuinely did
    cover BOTH a disk mount AND a separate, real backup finding for the same system the same
    day, each on its own line; showing the WHOLE blob -- including the unrelated finding's own
    detail -- under "disk usage" specifically was exactly the complaint, and would have made a
    useless verbatim "mute with this reason" for the disk alert). Falls back to the whole
    comment when it isn't actually multi-line, or when no individual line matches (never
    silently hides a comment comment_relevant_flag_keys already decided WAS relevant).

    When `needle` (a specific resource) is given, ONLY it decides which lines match -- family
    words are NOT also consulted here. Found necessary in the SAME real example: the backup
    line explicitly says "...due to insufficient DISK space", so the disk family's own word
    "disk" matched it too even though that line is about the backup finding, not the disk one
    -- a specific resource ("/u01") is unambiguous where a generic family word plainly is not,
    so once a needle is available it should be the ONLY signal, not just an additional one."""
    if len(lines) <= 1:
        return comment
    if needle:
        picked = [l for l in lines if needle.lower() in l.lower()]
    else:
        own_words = _FAMILY_WORDS.get(family, set())
        picked = [l for l in lines if any(w in l.lower() for w in own_words)]
    return "\n".join(picked) if picked else comment


def comment_relevant_flag_keys(sysd: dict) -> dict:
    """{flag_key: comment text} for whichever of this system's own flags (one submission) its
    system-level `comment` can be confidently attributed to -- see this module's own comment
    above for the two real, confirmed ways "every flag present that day" was wrong. Precision
    over recall throughout: this feeds a "mute with this reason" action, so a missed-but-real
    comment (shows as "not addressed yet") is a far safer failure than a wrongly-attributed one
    (a believable-looking but factually unrelated mute justification).

    Per flag: when another flag of the SAME family is ALSO present that day, only a comment
    that names THIS flag's own resource (not component -- see _trim_comment_for's sibling fix
    note below) counts. When this flag is the only one of its family that day, the comment
    counts UNLESS it contains another family's own vocabulary without containing anything of
    this flag's family (the Temenos/RAM case) -- a detected contradiction, not just an
    unlabelled-but-plausible generic note. The TEXT returned is narrowed to the matching
    line(s) only when the comment turned out to be genuinely multi-topic (see
    _trim_comment_for) -- never the other topic's own detail, even when both are real."""
    comment = (sysd.get("comment") or "").strip()
    flags = sysd.get("flags", [])
    if not comment or not flags:
        return {}
    low = comment.lower()
    lines = _comment_lines(comment)
    by_family: dict = {}
    for f in flags:
        by_family.setdefault(category_family(f.get("category", "")), []).append(f)

    out: dict = {}
    for f in flags:
        key, category = f.get("key", ""), f.get("category", "")
        family = category_family(category)
        same_family = by_family.get(family, [])
        if len(same_family) > 1:
            # Resource specifically, not component -- siblings sharing one HOST/component but
            # different mounts (e.g. "DB:D:" vs "DB:E:") would otherwise both match on the
            # shared "DB" even though the comment only ever names one drive letter (2026-10-01
            # fix, found while verifying the Temenos case: CRB's own disk:DB:D: was being
            # pulled in by a comment that only discussed E: and RAM, purely because "DB" -- the
            # component both mounts share -- is a substring of the comment).
            suffix = comment_index_suffix(category, key)
            component, _, resource = suffix.partition(":") if suffix != key else ("", "", "")
            needle = resource or component
            if needle and needle.lower() in low:
                out[key] = _trim_comment_for(comment, lines, family, needle)
            continue
        own_words = _FAMILY_WORDS.get(family, set())
        other_words = {w for fam, ws in _FAMILY_WORDS.items() if fam != family for w in ws}
        has_own = any(w in low for w in own_words)
        has_other = any(w in low for w in other_words)
        if has_other and not has_own:
            continue   # contradicts: names a DIFFERENT family's vocabulary, not this one's
        out[key] = _trim_comment_for(comment, lines, family)
    return out


class CommentIndexEntry(models.Model):
    """Fast lookup cache for reports.alert_catalog.comment_history() -- one row per (system,
    suffix), `comments` holding up to the last 10 real admin comments on record for it, newest
    first. `suffix` (see comment_index_suffix) rather than flag_key is the key, specifically so
    a finding's comment history survives its own category changing across a severity escalation
    (see _SEVERITY_SIBLING_GROUPS' own comment for the bug this fixes).

    Built lazily: comment_history() does one full, genuinely comprehensive historical walk
    across every sibling flag_key THE FIRST TIME a given (system, suffix) is ever looked up,
    then persists the result here so every future lookup -- for a new comment on an escalated
    OR de-escalated tier, or just the admin clicking the same tile again -- is a single indexed
    row read, never another full-table walk. Kept current for free from then on by
    `_index_new_report_submission` below, a post_save signal on ReportSubmission that fires for
    EVERY report type's own submission view without needing to touch any of their (currently
    ten separate) call sites individually (2026-10-01, on request: "set up a better mechanism
    for new reports so you wont have to do the same comprehensive search again")."""
    system = models.CharField(max_length=120)
    suffix = models.CharField(max_length=255)
    comments = models.JSONField(default=list, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("system", "suffix")]
        verbose_name = "comment index entry"
        verbose_name_plural = "comment index entries"

    def __str__(self):
        return f"{self.system} / {self.suffix} ({len(self.comments)} comments)"


@receiver(post_save, sender=ReportSubmission)
def _index_new_report_submission(sender, instance, created, **kwargs):
    """Keeps CommentIndexEntry current for every NEW report submission, from whichever of the
    report form's (currently ten) own views created it -- see CommentIndexEntry's own
    docstring. Only ever PREPENDS: a freshly submitted report is always the newest comment for
    whatever it touches, so there is never a need to re-sort, just cap at 10. Only indexes a
    flag when comment_relevant_flag_keys says the comment is actually about it (see that
    function's own comment for the two real misattributions this guards against).

    Also where auto-mute (2026-10-01, on request: "in future set up a mechanism where if an
    issue occurs and has 3 or more duplicate comments on different report runs automatically
    mute alert") runs -- the natural point, since this is already the one place that fires for
    EVERY new report submission regardless of which of the ten views created it, and it has
    just finished computing this exact flag's own up-to-date comment history. See
    alert_catalog.maybe_auto_mute's own docstring for the matching/safety rules."""
    if not created:
        return
    from . import alert_catalog

    for sysd in (instance.report_content or {}).get("systems", []):
        system = sysd.get("name", "")
        comment = (sysd.get("comment") or "").strip()
        if not system or not comment:
            continue
        relevant_keys = comment_relevant_flag_keys(sysd)
        if not relevant_keys:
            continue
        seen_suffixes = set()
        for f in sysd.get("flags", []):
            flag_key, category = f.get("key", ""), f.get("category", "")
            if not flag_key or flag_key not in relevant_keys:
                continue
            suffix = comment_index_suffix(category, flag_key)
            if suffix in seen_suffixes:
                continue   # one system-level comment answers for every flag in this run
            seen_suffixes.add(suffix)
            entry, _ = CommentIndexEntry.objects.get_or_create(system=system, suffix=suffix)
            author = instance.author or (instance.generated_by.get_username() if instance.generated_by_id else "")
            new_row = {"created_at": instance.created_at.isoformat(), "comment": relevant_keys[flag_key],
                      "author": author, "flag_key": flag_key}
            entry.comments = [new_row] + list(entry.comments or [])[:9]
            entry.save(update_fields=["comments", "updated_at"])
            alert_catalog.maybe_auto_mute(system, category, flag_key, entry.comments)


class AutomatedReportInstance(models.Model):
    """One generated Automated Report (spec "New Promt.txt", Phase 5 item 13: "Store every
    generated report ... so historical reports remain browsable — mirror the existing
    versioned-storage pattern already used elsewhere in the console"). APPEND-ONLY, same
    shape as GrafanaConfigRevision/ReportSubmission's own history: a row is written once at
    generation time and never edited, so `content` (a JSON-safe dict built by
    reports.automated_reports.report_to_dict) is a permanent, self-contained snapshot --
    re-rendering an old instance never depends on live data that may since have changed.

    `distributed`/`distributed_at` record whether this particular instance was actually
    e-mailed (Phase 7 shadow mode: SystemConfig.automated_reports_distribution_enabled gates
    this independently of generation -- a report can exist here without ever having gone out).
    """

    REPORT_TYPE_CHOICES = [
        ("weekly_trend", "Weekly Operational Trend Report"),
        ("monthly_recurring", "Monthly Recurring Issues Report"),
        ("quarterly_summary", "Quarterly Management Summary"),
        ("system_attention", "System Attention Report"),
        ("admin_observations", "Administrator Observations Digest"),
        ("anomaly_log", "Anomaly / Fluke Log"),
    ]

    report_type = models.CharField(max_length=32, choices=REPORT_TYPE_CHOICES, db_index=True)
    generated_at = models.DateTimeField(default=timezone.now, db_index=True)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    ai_provider = models.CharField(max_length=20, blank=True, default="")
    ai_requested_provider = models.CharField(max_length=20, blank=True, default="")
    ai_error = models.TextField(blank=True, default="")
    # JSON-safe dict from reports.automated_reports.report_to_dict -- everything the detail
    # template/e-mail needs to re-render this exact instance, permanently.
    content = models.JSONField(default=dict, blank=True)
    distributed = models.BooleanField(default=False)
    distributed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-generated_at"]
        verbose_name = "automated report instance"

    def __str__(self):
        return f"{self.get_report_type_display()} · {self.generated_at:%Y-%m-%d %H:%M}"


class AutomatedFindingAction(models.Model):
    """One (system, flag_key) finding's admin-recorded Comment / Fix needed? / Resolved --
    2026-09-10, spec item 10a. LIVE/CURRENT record, edited via the report detail screen;
    reports.automated_reports.generate_automated_report reads this at GENERATION time and
    freezes whatever it finds into that run's own AutomatedReportInstance.content (which stays
    immutable afterward, same as every other field there) -- so a report always shows exactly
    what was on record the moment it ran, while THIS table keeps moving forward for the next
    run to read.

    Keyed on (system, flag_key) alone -- the SAME stable identity AlertFinding/IssueOccurrence
    already use elsewhere in this app for "the same real finding across time" -- NOT scoped per
    report_type: the identical underlying issue shown by weekly_trend and monthly_recurring
    alike is one real thing an administrator is tracking, not two.

    "Current status, as recorded by administrators, not today's comment" (item 10a's own
    framing): a value here is NEVER reset or cleared automatically -- it carries forward,
    unchanged, into every future report run until an admin explicitly edits it again, so nobody
    has to re-type "awaiting storage team ticket" every single week just because the underlying
    issue is still open.

    fix_needed/resolved are tri-state (unset / yes / no), not booleans -- item 10a's own
    reasoning: "'fix needed: yes / resolved: no' is a materially different state from 'fix
    needed: no / resolved: yes' or 'unset', and a single free-text column can't represent that
    distinction." `updated_at` is kept even though the visible report table may not render it
    directly -- item 10a's own note: "the timestamp is what would let a future staleness
    indicator... be added later without changing the carry-forward behavior itself.\""""

    UNSET, YES, NO = "", "yes", "no"
    TRISTATE_CHOICES = [(UNSET, "—"), (YES, "Yes"), (NO, "No")]

    system = models.CharField(max_length=120)
    flag_key = models.CharField(max_length=255)
    comment = models.TextField(blank=True, default="")
    fix_needed = models.CharField(max_length=8, choices=TRISTATE_CHOICES, blank=True, default=UNSET)
    resolved = models.CharField(max_length=8, choices=TRISTATE_CHOICES, blank=True, default=UNSET)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        unique_together = [("system", "flag_key")]
        verbose_name = "automated report finding action"

    def __str__(self):
        return f"{self.system} / {self.flag_key}"

    @property
    def is_unset(self) -> bool:
        """Neither Fix needed? nor Resolved has ever been recorded -- item 10a: "highlight rows
        where Fix needed?/Resolved are unset directly in the table"."""
        return not self.fix_needed and not self.resolved


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
    # Automated Reports' AI narrative provider (2026-09-07, on request: "make a two pronged
    # approach... leave a slot open for copilot api key but do generate at least one report
    # using anthropic just for reference") -- see reports/ai_narrative.py's own docstring for
    # the provider abstraction this feeds. Blank/"copilot" both currently mean "no working AI
    # narrative available" (Copilot has no implementation yet, only a reserved slot) -- the
    # report generator ALWAYS falls back to a plain, statistics-only narrative rather than
    # failing, whatever this is set to.
    NARRATIVE_PROVIDER_CHOICES = [
        ("", "Off (statistics only)"),
        ("anthropic", "Anthropic (Claude)"),
        ("copilot", "Microsoft 365 Copilot — not yet implemented, reserved for your own key"),
    ]
    narrative_provider = models.CharField(
        max_length=20, choices=NARRATIVE_PROVIDER_CHOICES, blank=True, default="",
        help_text="Which AI provider the Automated Reports engine calls for the narrative "
                  "sections. A report always generates even if this is off, unreachable, or "
                  "misconfigured -- see reports/ai_narrative.py.")
    # Fernet ciphertext at rest (reports/crypto.py, same pattern as every other stored secret
    # in this app, e.g. GrafanaConfigRevision.smtp_password_encrypted) -- never the plaintext
    # key. Use .anthropic_api_key()/.copilot_api_key() to read the decrypted value.
    anthropic_api_key_encrypted = models.TextField(blank=True, default="")
    copilot_api_key_encrypted = models.TextField(
        blank=True, default="",
        help_text="Reserved slot for the company's own Microsoft 365 Copilot API key -- no "
                  "working Copilot integration exists yet (see reports/ai_narrative.py), "
                  "selecting this provider currently always falls back to the offline "
                  "narrative regardless of whether a key is stored here.")
    # Phase 7 rollout gate (spec "New Promt.txt", items 15-16): scheduled Automated Reports
    # ALWAYS generate and store (shadow mode) regardless of this flag -- it only controls
    # whether a finished instance is also e-mailed out. Defaults to False on purpose: the spec
    # requires an administrator to review at least one full cycle of the shortest-window
    # report type for accuracy before distribution is turned on -- that review is a human
    # judgement call this field cannot make for them, so it stays off until someone
    # deliberately flips it on the Automated Reports screen.
    automated_reports_distribution_enabled = models.BooleanField(
        default=False,
        help_text="Off = shadow mode: reports generate and store on schedule but are not "
                  "e-mailed. Review generated reports for accuracy before enabling.")
    # Estate-wide default notification window (2026-10-02, on request: "have a default alert
    # window set for each and every alert subject to any specific change from the admins...
    # make every alert share Innocent Nyama Alert group alert window"). Innocent Nyama's own
    # real window turned out to be 07:45-17:00 Mon-Fri, not what was recalled -- RTGS Team's
    # and T24 Team's own 07:45-21:00-every-day pattern was confirmed as the actual default
    # instead. Only applies to a Monitoring AlertGroup that has NOT set its own
    # schedule_enabled=True -- see AlertGroup.in_schedule's own comment -- so an admin's own
    # explicit per-group schedule always wins; this is a fallback, never an override.
    default_alert_window_start = models.TimeField(
        default=datetime.time(7, 45),
        help_text="Default notification window start for any Monitoring Alert Group that "
                  "hasn't set its own schedule. Overridden per-group by that group's own "
                  "schedule, once set.")
    default_alert_window_end = models.TimeField(
        default=datetime.time(21, 0),
        help_text="Default notification window end -- see default_alert_window_start.")
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

    def anthropic_api_key(self) -> str:
        from . import crypto
        return crypto.decrypt(self.anthropic_api_key_encrypted or "")

    def copilot_api_key(self) -> str:
        from . import crypto
        return crypto.decrypt(self.copilot_api_key_encrypted or "")


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



class DrainageThresholdConfig(models.Model):
    """Singleton (pk=1): admin-editable age limits for PAYMENT & INTERFACE QUEUE folders
    (reports.folders' "queue" watch_type -- Drainage Monitoring's own name for how long the
    OLDEST file in a folder may wait before it counts as drifting/a fault). Backup and log
    folders are a DIFFERENT drainage mechanism (a different cadence, on request, 2026-09-04:
    "there is different types of drainage monitoring we have backup drainage monitoring and
    payment and interface queues these have a different cadence to be set") -- their drain
    window is normally INTUITED from that system's own backup cadence (see
    reports.folders.backup_drain_limits / reports.backup_policy_admin), not this flat pair;
    `backup_red_seconds_overrides` below is the admin-settable override onto that otherwise-
    automatic calculation, kept on this same model since it is still fundamentally a drainage
    threshold, just for the other kind of folder.

    PER-SYSTEM (2026-09-04: "these overrides for backup are done at system level" -- each
    system's own backup cadence already produces a different automatic value, so one flat
    number for every system was the wrong shape; a same-day EARLIER version of this field was
    exactly that single flat override, replaced before it ever shipped to a real admin).

    On request (2026-09-04): "there needs to be a way to specify per alert type
    configuration" -- the queue amber/red pair had until this point only ever been a hardcoded
    module constant in reports/folders.py (most recently hand-edited the same day, 60s/120s ->
    300s/600s, "currently some folders are not draining"), the exact kind of change this model
    now lets an admin make themselves.

    `amber_seconds` no longer feeds any alert (only "red" is alertable, 2026-09-04) -- it is
    kept here because it still drives Folder Watch's own amber tile colour and the daily
    report's amber chip, just no longer editable from Per Alert Config (see
    reports/views.py's config_alerts "display" section instead).

    Ships empty (all fields None): effective_seconds falls back to DEFAULT_AMBER_SECONDS/
    DEFAULT_RED_SECONDS (300/600 -- matching reports.folders.AMBER_SECONDS/RED_SECONDS'
    current shipped values by number, not by import, to avoid a models.py -> folders.py
    import at Django app-loading time), so an admin who never opens this screen gets exactly
    today's behaviour. `backup_red_seconds_overrides` ships empty too ({}), meaning every
    system keeps its own automatic calculation; a system present in this dict uses its own
    fixed override instead, every other system is unaffected."""

    DEFAULT_AMBER_SECONDS = 300
    DEFAULT_RED_SECONDS = 600

    amber_seconds = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="Seconds before a queue folder's oldest file counts as drifting. Blank = use the default (5 minutes).")
    red_seconds = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="Seconds before a queue folder's oldest file counts as a fault. Blank = use the default (10 minutes).")
    backup_red_seconds_overrides = models.JSONField(
        default=dict, blank=True,
        help_text="{system name: seconds} -- an explicit override, per system, onto the "
                  "otherwise-automatic backup-cadence calculation for BACKUP folders. A "
                  "system absent from this dict keeps its automatic value.")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        verbose_name = "drainage threshold configuration"
        verbose_name_plural = "drainage threshold configuration"

    def __str__(self):
        amber, red = self.effective_seconds
        return f"Drainage thresholds: {amber}s amber / {red}s red"

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    @property
    def effective_seconds(self) -> tuple:
        amber = self.amber_seconds if self.amber_seconds is not None else self.DEFAULT_AMBER_SECONDS
        red = self.red_seconds if self.red_seconds is not None else self.DEFAULT_RED_SECONDS
        return amber, red


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
    can_edit_own_alert_groups = models.BooleanField(
        default=False,
        help_text="Members may edit an Alert group they belong to (add stakeholders, not "
                  "remove; can't delete the group). A general opt-in, not hardcoded to one "
                  "role — see roles.can_edit_alert_group().")
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
    receives_automated_reports = models.BooleanField(
        default=False,
        help_text="Gets scheduled Automated Reports e-mails once distribution is enabled "
                  "(a separate list from 'Pre-ticked in the send dialog', which only affects "
                  "manually generated reports).")

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

    ONE group model for EVERY alert, classified by `alert_type`/`alert_subtype` (2026-09-05,
    on request: "alert groups must be for all alerts even if there are system alerts, let
    user specify this in the alert type and sub type in alert groups... we just want
    everything to make sense and be solid"). Was two structurally separate models
    (AlertGroup + a since-retired SystemAlertGroup) until this date -- merged because the
    STAKEHOLDER half (name/systems/users/emails/active/reminders) is identical in shape for
    both, and having two parallel "who gets notified" tables was exactly the kind of
    almost-but-not-quite-duplicated concept the user is asking to resolve here. What's
    genuinely different between classifications is confined to a few fields, not the model:
      "monitoring" (ALERT_TYPE_MONITORING) -- the original kind: a monitored VALUE crosses a
          threshold (disk/ram/cpu/service/backup/etc, reports.alerting). Uses `categories`,
          `min_severity`, `imminent_reminder_minutes`, and `reminder_minutes` as a CAPPED,
          daily-renewing schedule (a list of several values -- see reminder_minutes' own
          help_text).
      "system" (ALERT_TYPE_SYSTEM) -- a checker/exporter itself has stopped reporting fresh
          data (reports.system_alerts). `categories`/`min_severity`/
          `imminent_reminder_minutes` are unused for this type (a staleness finding has no
          severity or category to filter). `reminder_minutes` is instead read as a
          ONE-ELEMENT list holding a single PERSISTENT interval (see
          effective_system_reminder_minutes) -- there is no capped schedule to front-load
          since there is no escalation tier, just "still stale" or not.
      `alert_subtype` only has meaning under "system" (currently exactly one: "staleness",
      ALERT_SUBTYPE_STALENESS -- Staleness Alert, reports.models.FreshnessCheck). Blank for
      "monitoring". A future second system subtype would follow the exact same shape: add a
      choice here, teach reports.system_alerts (or a sibling engine) to filter on it, no new
      group model.

    `alert_type` is set at CREATION and treated as immutable afterward by the UI (not exposed
    as an editable field on the per-group edit screen) -- switching a group's type after it
    has accumulated real AlertFinding or SystemAlertFinding history would leave that history
    orphaned against a now-nonsensical detection engine, so the edit screen shows it as a
    read-only label and a fresh group is the correct way to reclassify.
    """

    ALERT_TYPE_MONITORING = "monitoring"
    ALERT_TYPE_SYSTEM = "system"
    ALERT_TYPE_CHOICES = [
        (ALERT_TYPE_MONITORING, "Monitoring Alert"),
        (ALERT_TYPE_SYSTEM, "System Alert"),
    ]
    ALERT_SUBTYPE_STALENESS = "staleness"
    ALERT_SUBTYPE_CHOICES = [
        (ALERT_SUBTYPE_STALENESS, "Staleness Alert"),
    ]
    DEFAULT_SYSTEM_ALERT_REMINDER_MINUTES = 60

    # Labels use the app's own severity vocabulary (Imminent/Critical), not the raw red/amber
    # band the value is still stored and matched as internally (on request, 2026-09-04: "stop
    # using your made up red amber severity scale... use imminent critical and warning
    # throughout the application"). "red" only ever displays as Critical or Imminent (see
    # alert_email_templates._severity's own mapping).
    #
    # There used to be a second choice, "amber"/"Warning and above" -- removed the same day
    # ("there are no expected alerts for warning severity...only imminent and critical
    # thresholds"): every group's floor is now fixed at Critical & Imminent only, so there is
    # exactly one choice left. The field itself is kept (existing rows, AlertFinding history)
    # rather than dropped, but reports.alerting.severity_meets no longer takes it as an
    # argument -- amber findings never reach any group's notification pipeline any more, full
    # stop, not just below whichever floor a group happened to pick.
    MIN_SEVERITY_CHOICES = [
        ("red", "Critical & Imminent only"),
    ]
    # How a still-open finding gets re-notified (2026-09-04): a CAPPED schedule of reminders
    # per finding PER DAY -- N minutes after the finding's first notification of THAT DAY, for
    # each N in THIS GROUP'S OWN reminder_minutes below -- then silence for the rest of the
    # day. Once local midnight passes, a still-open finding's cycle RENEWS and it gets another
    # day's worth of reminders (on request, 2026-09-04: "3 reminders on that particular day
    # then reset on next day") -- see AlertFinding's own docstring and
    # reports.alerting._decide's 'renew' action for the exact mechanics. Replaces the earlier
    # configurable-single-interval design (renotify_interval_minutes, repeating indefinitely):
    # a capped, front-loaded schedule (fast first nudge, then progressively later ones) reads
    # a genuine incident-alerting pattern back at the group rather than an open-ended repeat
    # someone has to remember to silence, while the daily renewal stops a long-lived finding
    # from going silent for good after its first day. PER-GROUP (2026-09-04: "notification
    # reminder schedule should be group specific") -- was a single app-wide AlertScheduleConfig
    # singleton until this date; that model is gone, replaced by this field, migrated
    # one-for-one so no group's behaviour changed the moment this shipped. Both resolution and
    # reminders are only ever checked when the poller runs, so the schedule can't fire any
    # faster than that -- "at least N minutes", never exactly.
    DEFAULT_REMINDER_MINUTES = [10, 40, 60]
    # Generous, not a real cap -- "people can set whatever reminders they want, make it fully
    # customizable" (2026-09-04). Still a defined number rather than truly unbounded, so a
    # fat-fingered paste can't produce a schedule long enough to make the reminder e-mail (or
    # this form) unusable; no reasonable admin should ever come near it.
    MAX_REMINDER_COUNT = 20
    DEFAULT_IMMINENT_REMINDER_MINUTES = 10
    # The same category strings generate_report.Flag.category already carries on every
    # finding (disk/ram/cpu/service/backup/unreachable/untracked) -- reused as-is rather than
    # inventing a second taxonomy, so a group's filter always means exactly what the report's
    # own flags mean. "folder" is a documented exception: generate_report.flagged_for_system
    # itself never emits it (folder-over-expected-size is only ever a report-level banner
    # there, see folder_over_expected_detail) -- reports.alerting.folder_size_flags_by_system
    # synthesizes a matching Flag instead, kept in alerting.py (not the shared report-engine
    # file, which exists in 3 kept-in-sync copies and has no Django dependency to reach
    # reports.folders with) rather than touching that file just to add one more category.
    # reports.services.capture_snapshot (2026-09-07, on request: "a lot of folder issues fly
    # under the radar") calls the SAME function to merge these into the System Admin Report
    # too, so a folder issue reads identically whether it triggered an e-mail or is being seen
    # in the report for the first time -- one synthesis, two consumers, not a second copy.
    #
    # "backup_uncleared" started as a PLACEHOLDER (2026-09-03, no detection anywhere yet) and
    # became REAL 2026-09-07 (on request: "we need a custom notification for backup and log
    # drainage") -- reports.alerting.backup_uncleared_folder_flags_by_system synthesizes it
    # from reports.folders.snapshot() (the Temenos Backup & Log Folders, watch_type "backup"/
    # "logs"), applicable per system via folders.backup_drainage_systems() (views.
    # _category_grid_rows). DELIBERATELY kept separate from "undrained_folders" below, even
    # though both read the same snapshot() -- a payment queue is expected to drain itself
    # automatically (Critical-only, no grace period); a backup/log folder is cleared by a
    # HUMAN on a schedule, so this is the ONE category severity_meets lets through at amber/
    # Warning (a gentle first notice the moment it passes its own due date -- see
    # folders.backup_drain_limits' own red_seconds), escalating to red/Critical only after
    # alerting.MAX_BACKUP_OVERDUE_SECONDS (3 days) of being overdue. Also merged into the
    # System Admin Report by reports.services.capture_snapshot, same as "folder" above.
    #
    # "undrained_folders" (2026-09-04) is REAL, not a placeholder -- same shape as "folder":
    # generate_report.flagged_for_system never emits it either, so reports.alerting.
    # undrained_folder_flags_by_system synthesizes it, this time from reports.folders.
    # snapshot() (the Folder Watch screen's own live verdict per payment-queue folder: files
    # waiting whose oldest has aged past its amber/red limit -- see folders.verdict's own
    # docstring). A DRAINED folder (files<=0, folders.py's "idle") is healthy and never flags;
    # this is specifically the folder that ISN'T draining. Same T24-only applicability as
    # "folder" -- both read the identical folder_exporter job in prometheus.yml, see
    # folders.folder_watch_systems. Also merged into the System Admin Report, same as above.
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
        # THREE tiers now, three category keys (2026-10-01): "disk" (amber/Warning only --
        # see _CATEGORY_BANDS' own comment), "high_disk" (Critical, <95%), "very_high_disk"
        # (Imminent, >=95%). Started as a 2-way split ("for disk usage there is one that is
        # imminent and a version of it that is critical... make these two alert types disk
        # usage and Very high disk usage" -- 95% matching network.py's pre-existing
        # flash_storage_critical precedent) then became 3-way the same day ("do not name them
        # the exact same thing across severities" -- the old red/<95% band was still sharing
        # "disk"'s own name with the amber band). See _tier()'s own category exception.
        ("high_disk", "High disk usage"),
        ("very_high_disk", "Very high disk usage"),
        ("ram", "Ram usage"),
        # Same three-tier split, RAM instead of disk (2026-10-01, on request: "rename ram
        # usage across severities"). See generate_report.RAM_IMMINENT_PCT's own comment.
        ("high_ram", "High RAM usage"),
        ("very_high_ram", "Very high RAM usage"),
        ("cpu", "Cpu usage"),
        # Same three-tier split, CPU instead of disk (2026-10-01, on request: "cpu usage is
        # also between 2 severities" -> "do not name them the exact same thing across
        # severities"). CPU here is a 5-minute average, not an instant spike, so a sustained
        # >=95% average is a real signal, not noise, even though CPU naturally spikes more
        # often than disk fills up. See generate_report.CPU_IMMINENT_PCT's own comment.
        ("high_cpu", "High CPU usage"),
        ("very_high_cpu", "Very high CPU usage"),
        ("service", "Service down"),
        # "degraded" (2026-10-01, on request: "reserve service down for actual services that
        # are down") -- split out of "service", which network.py had been using since
        # 2026-09-29 for EVERY reachable-device operational finding (OSPF adjacency loss,
        # PSU/fan failure, interface errors/saturation/discards, temperature, recent reboot,
        # interface/AP down-regressions) for lack of a dedicated bucket at the time (see that
        # fix's own comment, still on network.py's FlagVM call sites, for the full history).
        # "service" now means exactly what its label says: a NAMED service/process/listener/
        # cluster-resource is down (generate_report.py's win_service/t24_service_up/
        # oracle_listener checks, network.py's cluster_resource_failed). "degraded"/
        # "degrading"/"potentially_degrading" are everything else read FROM a device that
        # answered -- running, but impaired -- split further by severity (2026-10-01, on
        # request: "some of these discards are too severe to lump all together") into the
        # SAME three tiers the Alert Matrix's own panels already use: "degraded" = red/
        # Critical, "degrading" = amber/Warning, "potentially_degrading" = note/Note. This is
        # NOT a live recomputation for most flag_keys -- almost every one of them already has
        # a FIXED band at its network.py call site (e.g. iface_discards is always amber,
        # ospf_adjacency_lost is always red), so this just gives each one the distinct name
        # its own fixed severity deserves. temp_high WAS the one exception (genuinely red
        # above 75C, amber below), tracking its live band into "degraded"/"degrading" --
        # pulled back OUT into its own "temperature" category the same day (on request:
        # "create a new issue type called temperature") once a real temp_high finding (Core
        # Switch) turned out to still be showing as "unreachable", traced to a genuinely
        # orphaned IssueOccurrence row from BEFORE that switch was renamed "Core Switch (HQ)"
        # and moved into the Network domain -- never touched since because nothing in any
        # current topology still answers to the old name (see
        # 0068_temperature_category_and_orphan_cleanup's own docstring). "temperature" behaves like
        # every OTHER category here (disk/ram/cpu): ONE category, appearing as a row in
        # whichever severity panel(s) its current band lands in -- not severity-encoded in
        # the category name the way degraded/degrading/potentially_degrading are. That split
        # stays for everything else in this family (interface/link/OSPF/PSU findings, which
        # each have a genuinely FIXED band per flag_key); temperature is the one finding here
        # whose band legitimately varies live, so giving it its own severity-coded name was
        # actively confusing rather than clarifying.
        ("degraded", "Degraded"),
        ("degrading", "Degrading"),
        ("potentially_degrading", "Potentially degrading"),
        ("temperature", "Temperature"),
        ("backup", "Backup missing"),
        ("unreachable", "Component unreachable"),
        ("untracked", "Backup untracked"),
        # "untracked_metrics" (2026-10-01, on request: "how does this error fit under backups
        # untracked category" -> "make it untracked metrics instead") -- split out of
        # "untracked", which network.py's metrics_missing/counter_width findings had been
        # using too, for lack of a dedicated bucket: "untracked" ORIGINALLY meant exactly one
        # thing -- generate_report.py's `Flag(f"untracked:{sysm.name}", "... UNTRACKED (no
        # backup check on any host)", "amber", "untracked")` -- but network.py's per-device
        # SNMP-coverage check ("N of 19 requested metrics are not collected: PoE power draw,
        # BGP sessions, ...") and its 32-bit-counter-wrap warning reused the same category,
        # which is not a backup gap at all. This had a REAL side effect, not just a confusing
        # label: the Network/Infrastructure "no backups tracked" blanket silence (see
        # [[project_category_wide_silence]]/[[project_alert_matrix]]) was silently muting
        # metrics_missing findings too, since it shared the same category -- splitting this
        # out stops that gap without touching that silence at all (it no longer matches).
        ("untracked_metrics", "Untracked metrics"),
        ("folder", "Size monitoring"),
        # "very_high_folder" (2026-10-01, on request: "same split for folder size too") --
        # "folder" has no percentage-of-capacity reading the way disk/CPU/RAM do (a size-over-
        # expected check is unbounded), so the equivalent severe line is a RATIO of actual to
        # expected size instead of an absolute percent -- see
        # alerting.FOLDER_IMMINENT_RATIO's own comment (2x expected, a judgment call, not an
        # existing precedent like DISK_IMMINENT_PCT had).
        ("very_high_folder", "Folder far over expected size"),
        ("backup_uncleared", "Backup & log drainage"),
        # "backup_overdue" (2026-10-01, on request: "keep severity escalation but define
        # newer alerts as they escalate... instead of having one issue have one alert that
        # varies between multiple severity levels have one issue with multiple alerts
        # depending on severity") -- split out of "backup_uncleared"'s own existing Warning-
        # then-Critical-after-3-days ladder (alerting.MAX_BACKUP_OVERDUE_SECONDS, unchanged):
        # the SAME trigger, but the escalated (>=3 days overdue) state is now a genuinely
        # DIFFERENT category/flag_key, not the same one turning red -- closes the Warning
        # finding and opens a new Critical one, the same "two alert types, not one that
        # varies" pattern used for degraded/degrading. "backup_uncleared" itself is amber-only
        # from here on.
        ("backup_overdue", "Backup & log drainage overdue"),
        ("undrained_folders", "Drainage monitoring"),
        # "queue_stuck" (2026-10-01, on request: "do not name them the exact same thing
        # across severities") -- split out of "undrained_folders", which used to span BOTH
        # amber/Warning (a queue running a little behind) and red/Imminent (a queue that has
        # genuinely stopped draining) under the one name. "undrained_folders" is amber-only
        # from here on; "queue_stuck" is the red/Imminent sibling. See
        # alerting.undrained_folder_flags_by_system's own docstring for the full split.
        ("queue_stuck", "Queue not draining"),
    ]
    # Purely a DISPLAY grouping for the categories checkbox grid (2026-09-07, on request:
    # "in the alert picker (checkboxes) we need to delineate between Interface queue folder
    # group, backup folder group, and size monitoring folder group") -- these three
    # categories are all folder_exporter-backed and easy to mix up by name alone
    # ("Drainage monitoring" vs "Backup & log drainage" vs "Size monitoring" don't visually
    # read as a family); a small header label over each one in the grid ties it back to
    # which PHYSICAL folder type it watches. Not used anywhere in detection/matching logic --
    # category_matches/severity_meets/etc. never consult this.
    CATEGORY_GROUP_LABELS = {
        "undrained_folders": "Interface queue folder group",
        "backup_uncleared": "Backup folder group",
        "folder": "Size monitoring folder group",
    }

    name = models.CharField(max_length=120, unique=True)
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPE_CHOICES,
                                  default=ALERT_TYPE_MONITORING,
                                  help_text="Set at creation; not changed afterward (see this "
                                            "model's own docstring).")
    alert_subtype = models.CharField(max_length=20, choices=ALERT_SUBTYPE_CHOICES, blank=True,
                                     default="",
                                     help_text="Only meaningful when alert_type is System "
                                               "Alert. Blank for Monitoring Alert.")
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
    reminder_minutes = models.JSONField(
        default=list, blank=True,
        help_text="Ascending minutes-after-first-notification, one per reminder, for THIS "
                   "group. Empty = use the shipped default (10, 40, 60).")
    # IMMINENT findings (component unreachable) ignore reminder_minutes/its daily cap entirely
    # -- on request (2026-09-04: "treat all component down alerts as imminent... we need to be
    # made aware of it... willing to have a persistent notification until resolved") they
    # instead repeat every `imminent_reminder_minutes` minutes SINCE THE LAST reminder,
    # indefinitely, until the finding resolves -- see reports.alerting._decide's own
    # imminent-specific branch. Blank = the shipped default (10 minutes).
    imminent_reminder_minutes = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="How often (minutes) an unresolved IMMINENT finding (component "
                  "unreachable) re-reminds, forever, until resolved. Blank = 10.")
    active = models.BooleanField(default=True, help_text="Untick to pause without deleting.")
    # A SCHEDULE, not a second "active" toggle (2026-09-07, on request: "people are asking
    # for these alerts to be schedulable... enable them at a certain time and disable them
    # at a certain time, even in terms of days") -- `active` is the admin's own manual
    # pause/resume; a schedule is an automatic, recurring version of the same thing that
    # re-arms itself without anyone touching a switch. Off by default (schedule_enabled=
    # False) so every existing group's behaviour is completely unchanged until an admin
    # opts one in. When enabled, `schedule_days` (0=Monday..6=Sunday, ISO weekday-1) gates
    # which days the group may fire at all, and `schedule_start`/`schedule_end` gate a daily
    # time-of-day window -- see `in_schedule`'s own docstring for how the two combine and
    # for the overnight-wrap case (`schedule_end` earlier than `schedule_start`).
    schedule_enabled = models.BooleanField(
        default=False, help_text="Restrict this group to a recurring day/time window. Off = "
                                 "always active (subject only to the Active toggle above).")
    schedule_days = models.JSONField(
        default=list, blank=True,
        help_text="0=Monday .. 6=Sunday. Empty while schedule_enabled means every day.")
    schedule_start = models.TimeField(
        null=True, blank=True,
        help_text="Daily window start (local time). Blank with schedule_end also blank = "
                  "all day (only schedule_days restricts it).")
    schedule_end = models.TimeField(
        null=True, blank=True,
        help_text="Daily window end (local time). Earlier than Start means the window "
                  "crosses midnight, e.g. 22:00 -> 06:00.")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        ordering = ["name"]
        verbose_name = "alert group"

    def __str__(self):
        n = len(self.systems or [])
        return f"{self.name} → {n} system(s)" if n else f"{self.name} → no systems yet"

    # "muted should mean the same thing we cant have a muted unmuted transient state... when
    # i tell you to pause a notification... this should translate to a mute" (2026-10-02).
    # Pausing/reactivating a Monitoring group now WRITES real AlertSilence rows at the moment
    # it happens, rather than the dashboard re-deriving "is this paused right now" fresh on
    # every request from `active` alone (alert_catalog._compute_paused_scope, now removed --
    # that split "muted" into two parallel concepts: a real AlertSilence row, and a live-
    # computed condition, each needing its own branch through current_state/severity_matrix/
    # muted_alerts/muted_matrix/alert_unmute/alert_comment_history). One whole-category silence
    # (flag_key="", the SAME shape AlertSilence already uses for "mute every component, current
    # and future, under this category" -- see that field's own help_text) per (system,
    # category) this group actually covers, so a NEW finding that starts while still paused is
    # covered immediately, same guarantee the old live-computed version had, just real rows now
    # instead of nothing on disk. `from_group_pause=True` marks these as this save's own doing,
    # not an admin's independent silence that happens to reference the same group, so
    # reactivating only ever releases exactly what pausing created.
    def save(self, *args, **kwargs):
        was_active = None
        if self.pk and self.alert_type == self.ALERT_TYPE_MONITORING:
            was_active = (type(self).objects.filter(pk=self.pk)
                         .values_list("active", flat=True).first())
        super().save(*args, **kwargs)
        if self.alert_type != self.ALERT_TYPE_MONITORING:
            return
        if not self.active:
            # Re-syncs to the CURRENT systems/categories on every save while paused, not just
            # the one save that flips the switch -- a system or category added to an ALREADY-
            # paused group needs its own pause-silence too, or the binding above has a gap for
            # exactly the finding an admin just told it to cover (materialize is idempotent,
            # see its own "already covered" skip, so re-running it on an unrelated field edit
            # costs nothing and creates nothing new for what's already covered).
            self._materialize_pause_silences()
        elif was_active is False:   # explicitly WAS paused (not a brand-new group) -- reactivated
            self._release_pause_silences()

    def _materialize_pause_silences(self):
        import datetime as _dt

        from django.utils import timezone as dj_timezone

        all_categories = [k for k, _ in self.CATEGORY_CHOICES]
        # 10 years, not a short renewal window like a normal silence (AlertSilence's own
        # "forced renewal" reasoning doesn't apply here -- this is released programmatically
        # the moment the group reactivates, never by calendar date, so there's nothing for a
        # short expiry to usefully force a review of.
        expires = dj_timezone.now() + _dt.timedelta(days=3650)
        for system in (self.systems or []):
            for category in all_categories:
                if not self.category_matches(system, category):
                    continue
                if AlertSilence.objects.filter(system=system, category=category, flag_key="",
                                               active=True).exists():
                    continue   # already covered -- an admin's own real silence, never duplicated
                AlertSilence.objects.create(
                    system=system, category=category, flag_key="", group=self,
                    reason="Notification for this alert is paused.",
                    created_by=self.updated_by, expires_at=expires, from_group_pause=True)

    def _release_pause_silences(self):
        AlertSilence.objects.filter(group=self, from_group_pause=True, active=True).update(active=False)

    def in_schedule(self, when) -> bool:
        """Whether `when` (an aware datetime already converted to LOCAL time by the caller --
        see reports.alerting/reports.system_alerts' own timezone.localtime(now) call) falls
        inside this group's own schedule.

        Unscheduled groups (schedule_enabled=False) are an opt-in narrowing when a group HAS
        set its own schedule -- never a new way to silence a group that hasn't asked for one.
        But for a Monitoring group specifically, "hasn't asked for one" no longer means
        unconditionally always-in-schedule (2026-10-02, on request: "have a default alert
        window set for each and every alert... make every alert share Innocent Nyama Alert
        group alert window" -- confirmed instead against SystemConfig.default_alert_window_*,
        RTGS/T24 Team's own 07:45-21:00-every-day pattern, not Innocent Nyama's actual
        07:45-17:00-weekdays one, which the request misremembered). An admin's own explicit
        schedule on a specific group ALWAYS wins -- this is purely the fallback for a group
        that has never set one. System Alert groups (alert_type=ALERT_TYPE_SYSTEM, e.g.
        Staleness Alerts -- watching whether a CHECKER is still alive) are deliberately exempt
        from the default: time-of-day has no bearing on whether a checker has gone silent, so
        they keep the unconditional always-in-schedule behaviour this method always had.

        A day outside `schedule_days` fails outright regardless of time. With no days listed
        at all (empty list) every day qualifies -- "restrict the TIME only" is a real,
        useful configuration (e.g. business hours, every day). Blank start/end similarly
        means "restrict the DAYS only, any time of day qualifies." When both a window and
        `schedule_end < schedule_start` are given, the window is read as crossing midnight
        (e.g. 22:00 -> 06:00 covers the whole overnight period, not zero hours)."""
        if not self.schedule_enabled:
            if self.alert_type != self.ALERT_TYPE_MONITORING:
                return True
            sc = SystemConfig.get()   # same module, defined earlier in this file -- no import needed
            start, end = sc.default_alert_window_start, sc.default_alert_window_end
            if start is None or end is None:
                return True
            t = when.time()
            return start <= t <= end if start <= end else (t >= start or t <= end)
        if self.schedule_days and when.weekday() not in self.schedule_days:
            return False
        start, end = self.schedule_start, self.schedule_end
        if start is None or end is None:
            return True
        t = when.time()
        if start <= end:
            return start <= t <= end
        return t >= start or t <= end

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

    @property
    def effective_reminder_minutes(self) -> list:
        return list(self.reminder_minutes) if self.reminder_minutes else list(self.DEFAULT_REMINDER_MINUTES)

    @property
    def effective_imminent_reminder_minutes(self) -> int:
        return (self.imminent_reminder_minutes if self.imminent_reminder_minutes is not None
               else self.DEFAULT_IMMINENT_REMINDER_MINUTES)

    @property
    def effective_system_reminder_minutes(self) -> int:
        """For alert_type=ALERT_TYPE_SYSTEM groups only: the single persistent reminder
        interval, read from reminder_minutes[0] -- a system-type group's reminder_minutes is
        always a ONE-element list (set that way by config_alerts' own save path), unlike a
        monitoring group's capped multi-element schedule. One field serves both shapes rather
        than a second reminder column, since the two classifications never read it the same
        way at once (see this model's own docstring)."""
        return self.reminder_minutes[0] if self.reminder_minutes else self.DEFAULT_SYSTEM_ALERT_REMINDER_MINUTES


class AlertFinding(models.Model):
    """One (group, system, flag) row's notification state — the dedup ledger the alert poller
    (see reports.alerting) consults every cycle to decide new / reminder / skip / resolved.
    `flag_key` is generate_report.Flag.key, the SAME stable key the report itself uses to marry
    an admin's Yes/No answer back to a flagged row — this table only remembers WHEN something
    was last seen/notified, it never re-derives whether it's actually wrong (that stays exactly
    generate_report.flagged_for_system's job, called fresh every poll).

    The reminder schedule (2026-09-04, see AlertGroup.reminder_minutes -- group-specific, not
    app-wide) is capped PER CALENDAR DAY (local time) -- exactly len(reminder_minutes) reminders
    per finding per day, at reminder_minutes[i] minutes after `first_notified_at`, then silence
    for the REST OF THAT DAY -- driven by `reminder_count`
    (how many have gone out so far today) rather than a repeating interval off
    `last_notified_at`: the SCHEDULE is anchored to when the finding was first told about
    (today), not to whenever the last reminder happened to land, so a poll cycle running late
    never pushes every later reminder back too. Once local midnight passes since
    `first_notified_at`, a still-open finding's cycle RENEWS -- reminder_count and
    first_notified_at both reset as if it were being notified for the first time today (on
    request, 2026-09-04: "3 reminders on that particular day then reset on next day") -- so a
    finding open for a week is still heard about daily instead of going silent after its first
    day's reminders run out. See reports.alerting._decide's own docstring for the exact
    day-boundary check ('renew' action). `first_notified_at` is set once per cycle, the first
    time that cycle's notification succeeds, and never touched again until the row resets
    (escalation, reopen, or the daily renewal above) -- it is deliberately NOT the same field
    as `last_notified_at`, which keeps moving with each successful send and drives the
    e-mail's own "how manieth reminder" tag (reminder_count at send time + 1).

    An escalation (band worsens amber -> red on an already-notified, still-open row) always
    forces a fresh notification regardless of where the schedule was up to -- a stakeholder
    told "amber" needs to hear when it becomes "red", not stay silent because they were
    "already told" something less severe. This RESETS the schedule (reminder_count -> 0,
    first_notified_at -> None until the escalation's own notification succeeds) AND
    first_seen_at, the same reasoning as reopening a resolved finding below: it reads as a
    fresh incident, not a continuation of the old one's countdown. The daily renewal above is
    the one reset that does NOT touch first_seen_at, since it is still the same ongoing
    incident, not a new one -- only its notification cycle restarts for the new day.

    A resolved row (resolved_at set) that reappears is treated as brand-new: its timestamps
    AND its reminder schedule reset on the SAME row rather than a second row being created, so
    history for one (group, system, flag) triple always lives in exactly one place."""

    group = models.ForeignKey(AlertGroup, on_delete=models.CASCADE, related_name="findings")
    system = models.CharField(max_length=120)            # System.name from prometheus.yml
    flag_key = models.CharField(max_length=255)           # generate_report.Flag.key
    band = models.CharField(max_length=10)                # last-seen "red" / "amber"
    text = models.CharField(max_length=500, blank=True)   # last-seen Flag.text, for the e-mail
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    first_notified_at = models.DateTimeField(
        null=True, blank=True,
        help_text="When this finding's notification FIRST succeeded — the schedule's own "
                   "anchor point. Reset alongside reminder_count on reopen/escalation.")
    last_notified_at = models.DateTimeField(null=True, blank=True)
    reminder_count = models.PositiveSmallIntegerField(
        default=0, help_text="How many scheduled reminders have gone out so far "
                             "(cap = this finding's own group's current reminder count).")
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("group", "system", "flag_key")
        ordering = ["-last_seen_at"]
        verbose_name = "alert finding state"

    def __str__(self):
        state = "resolved" if self.resolved_at else "open"
        return f"{self.group.name} · {self.system} · {self.flag_key} ({state})"


class AlertSilence(models.Model):
    """A (system, flag_key) pair known to be noisy but SELF-RESOLVING -- e.g. a nightly batch
    job that legitimately spikes and clears every night -- pulled out of the normal every-
    poll/every-reminder notification path and rolled into ONE digest e-mail a day instead
    (2026-09-19, on request: "reduce the intrusiveness of alerts" for alerts "not being
    actioned at all by admins... that self resolve and then start again given times of the day
    or week"). Extends the same idea `alerting.ALERT_FLAG_SUPPRESSED` already used (a small,
    named, (system, flag_key)-scoped exemption list) but as a real, admin-manageable table
    instead of a hardcoded set, and BATCHED into a digest rather than dropped silently.

    `group` decides who hears the daily digest -- the SAME AlertGroup that would otherwise
    have been notified for this finding, so silencing never changes WHO ultimately sees it,
    only how often/when. See alerting.build_silenced_digest, this table's only reader, and
    alerting.SILENCE_ESCALATE_AFTER for the safety valve: a silence exists because a finding is
    EXPECTED to clear on its own; if one particular incident stops doing that and just stays
    open, normal immediate alerting resumes for it rather than trusting a rule that assumed a
    shorter-lived pattern -- a silence must never become a permanent blind spot for something
    that quietly turned into a real, ongoing problem.

    Deliberately EXPIRES (`expires_at`, default 60 days out) rather than lasting forever for
    the same reason -- a silence nobody ever revisits is indistinguishable from a blind spot.
    Forcing a renewal keeps a human deciding, on a cadence, that this is still expected/
    accepted behaviour, not something that was silenced once and forgotten.

    `category` + `flag_key` together decide SCOPE (2026-09-30, on request: "mute crb disk
    usage rtgs disk usage, ebis disk usage" -- a whole category, not one mount, and "add a new
    config in alerting to mute specific alert"). A non-blank `flag_key` silences exactly that
    one component, same as this table always worked. A BLANK `flag_key` with `category` set
    silences EVERY component under that category for this system -- current ones AND any added
    later (a 4th disk mount showing up next year is covered automatically, not just the ones
    that existed the day this was created). `category` is always set, even for a single-
    component silence, so alerting._silenced/build_silenced_digest never need a second lookup
    to know what kind of finding this is."""
    system = models.CharField(max_length=120)             # System.name from prometheus.yml
    category = models.CharField(max_length=32, choices=AlertGroup.CATEGORY_CHOICES, blank=True,
                                help_text="What this silences (reports.alerting.Flag.category).")
    flag_key = models.CharField(
        max_length=255, blank=True,                       # generate_report.Flag.key
        help_text="One specific component (e.g. disk:Database:/u01). Blank = every component "
                  "under `category` for this system, including ones added later.")
    group = models.ForeignKey(AlertGroup, on_delete=models.CASCADE, related_name="silences",
                              help_text="Whose digest this rolls into -- normally the same "
                                        "group that would otherwise be notified for it.")
    reason = models.TextField(blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                   on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text="Silencing stops automatically after this date -- a deliberate renewal, "
                  "not a permanent standing rule, keeps this reviewed periodically.")
    active = models.BooleanField(default=True)
    # Materialized by AlertGroup.save() the moment a Monitoring group is paused -- a REAL row
    # here, not a live-computed condition (2026-10-02, on request: "muted should mean the same
    # thing we cant have a muted unmuted transient state... when i tell you to pause a
    # notification... this should translate to a mute" -- replaces the first version of this
    # binding, alert_catalog._compute_paused_scope(), which derived "muted" fresh on every
    # request from AlertGroup.active instead of writing anything down, forcing current_state/
    # severity_matrix/muted_alerts/muted_matrix/alert_unmute/alert_comment_history to each
    # carry a second, parallel "or is it paused" branch alongside their real-silence one). Set
    # True only on silences AlertGroup.save() itself creates; marks them as the group's own
    # doing so reactivating that SAME group (and only that group) can find and release exactly
    # these rows again, without touching a silence an admin separately created by hand that
    # happens to reference the same group.
    from_group_pause = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "alert silence"

    def __str__(self):
        scope = self.flag_key or f"{self.category} (all)"
        return f"{self.system} · {scope} (until {self.expires_at:%Y-%m-%d})"

    @property
    def in_effect(self) -> bool:
        return self.active and self.expires_at > timezone.now()

    @property
    def is_category_wide(self) -> bool:
        return not self.flag_key


class IssueOccurrence(models.Model):
    """One (system, flag_key) incident, append-only -- the comprehensive occurrence ledger
    reports.alert_spikes' hourly Issue Spikes chart reads from (2026-09-07, on request, after
    checking real data: neither Prometheus's native ALERTS metric -- 5 alerting rules, all
    Temenos-only, confirmed live -- nor AlertFinding covered enough of the estate to chart
    against). Deliberately NOT AlertFinding: that table only ever remembers what at least one
    active AlertGroup has ticked for notification (see reports.alerting.run_alert_cycle's own
    eligible-flags filter) and only for systems some group actually covers -- a gap in
    AlertFinding is a gap in what nobody chose to be told about, not a gap in what actually
    happened. This table is written unconditionally, every alert-poller cycle (~5 minutes), for
    every system in the topology and every category generate_report.flagged_for_system
    produces, regardless of any AlertGroup's configuration -- see reports.alerting.
    record_occurrences, its only writer.

    Append-only like AlertFinding is NOT (see comment_correlation.py's own docstring on why a
    MUTABLE current-state table -- one row overwritten across multiple open/resolve cycles --
    is unreliable for historical analysis): a resolved row that reopens gets a BRAND NEW row
    here, never a reused one, so the full history of every distinct incident survives.

    One row per INCIDENT (a continuous open period), not one row per poll -- storage
    proportional to how many distinct problems occur, not how many times the poller happened to
    check (17 flags firing across the whole estate at any one instant, confirmed live
    2026-09-07, so a per-poll heartbeat row would mostly repeat "still true" for no benefit,
    growing unbounded for no real signal). "How many issues were active in hour X" is a
    standard overlap query against (started_at, resolved_at), not a row count."""

    system = models.CharField(max_length=120)             # System.name from prometheus.yml
    flag_key = models.CharField(max_length=255)            # generate_report.Flag.key
    category = models.CharField(max_length=40)             # generate_report.Flag.category
    band = models.CharField(max_length=10)                 # last-seen "red" / "amber" / "note"
    text = models.CharField(max_length=500, blank=True)    # last-seen Flag.text
    # "Systems" | "Infrastructure" | "Network" -- set by record_occurrences' OWN caller at
    # write time (2026-09-30, for the Alert Dashboard's domain bars/tables), never inferred
    # after the fact from category/flag_key: each of the two call sites already knows which
    # estate it's capturing (the Systems-loop call is always "Systems"; the kind-loop call
    # sits right next to the SAME LiveEstateOverview.update_or_create(kind=kind, ...) a few
    # lines below it, so kind is already in scope). Deliberately NOT a hand-maintained
    # flag_key-prefix catalog -- this session already paid down that exact mistake once for
    # the Prometheus metric archive (a hand-picked list silently drifting from what the app
    # actually produces); storing the true value at the one place it's already known avoids
    # repeating it here. Blank for rows written before this field existed -- see the
    # one-time backfill migration.
    domain = models.CharField(max_length=32, blank=True)
    started_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["system", "started_at"]),
            models.Index(fields=["category", "started_at"]),
        ]
        constraints = [
            # At most one OPEN row per (system, flag_key) at a time -- a PARTIAL unique index,
            # not unique_together, since unique_together would also forbid two RESOLVED rows
            # for the same key ever existing, which is exactly the history this table exists
            # to keep across multiple open/resolve cycles.
            models.UniqueConstraint(
                fields=["system", "flag_key"], condition=models.Q(resolved_at__isnull=True),
                name="one_open_issue_occurrence_per_system_flag"),
        ]
        ordering = ["-started_at"]
        verbose_name = "issue occurrence"

    def __str__(self):
        state = "resolved" if self.resolved_at else "open"
        return f"{self.system} · {self.flag_key} ({state})"


class EventGroup(models.Model):
    """A named group of stakeholders who want to hear about EVENTS -- deliberately a SEPARATE
    concept from AlertGroup (2026-09-04: "I want to decouple notifications from alerts...
    I want to have notification types, alert notification and event notification"). An alert
    is a THRESHOLD/STATE: something is currently wrong, it has a severity, it can resolve, and
    an unresolved one reminds you it's still wrong. An event is a single, discrete OCCURRENCE:
    something happened, once, at a point in time -- there is no severity to escalate and
    nothing to "resolve" (see reports.events' own module docstring for the engine this
    powers). Deliberately as thin as AlertGroup's own stakeholder half (systems/users/emails/
    active) with NONE of its alert-specific machinery (min_severity, categories, reminder
    schedules) -- an event group is just "who wants to hear about this system's events."""

    name = models.CharField(max_length=120, unique=True)
    systems = models.JSONField(
        default=list, blank=True,
        help_text="System names from prometheus.yml this group covers. Empty = covers "
                   "nothing yet.")
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, blank=True, related_name="event_groups",
        help_text="App users notified via their account e-mail.")
    emails = models.JSONField(
        default=list, blank=True,
        help_text="Plain e-mail addresses for stakeholders with no account.")
    active = models.BooleanField(default=True, help_text="Untick to pause without deleting.")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        ordering = ["name"]
        verbose_name = "event group"

    def __str__(self):
        n = len(self.systems or [])
        return f"{self.name} → {n} system(s)" if n else f"{self.name} → no systems yet"

    def recipient_emails(self) -> list:
        """Same de-duplicated-and-validated shape as AlertGroup.recipient_emails -- kept as an
        identical, separate copy rather than a shared mixin, since the two models are
        deliberately not coupled to each other (see this model's own docstring)."""
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

    @property
    def stakeholder_count(self) -> int:
        return self.users.count() + len(self.emails or [])


class AutomatedReportGroup(models.Model):
    """A named group of stakeholders who want to receive AUTOMATED REPORTS -- the FOURTH
    notification type (2026-09-08, on request: "Automated reporting must be dependant on the
    Notification engine we have already built, similar to event notifications... we also need
    Automated Report Groups and event groups in much the same way we have alert groups to
    maintain a consistent design"). Deliberately as thin as EventGroup's own stakeholder shape
    (users/emails/active) -- an automated report has no severity to escalate and nothing to
    "resolve" either, same reasoning EventGroup's own docstring gives for staying thin.

    No `systems` field (unlike AlertGroup/EventGroup): an Automated Report is estate-wide by
    design -- reports.automated_reports.generate_automated_report takes no system scope at
    all -- so there is no per-system dimension for a group to cover here.

    Supersedes the old flat EmailRecipient.receives_automated_reports boolean, which could only
    say "send this person every report type" with no way to say "only the quarterly one."
    `report_types` is this group's own version of AlertGroup.categories: which of
    AutomatedReportInstance.REPORT_TYPE_CHOICES this group is notified about. Empty means
    "covers nothing yet" -- the same convention AlertGroup.systems/EventGroup.systems already
    use for their own empty default, not categories' empty-means-everything one, since a
    freshly created group must not silently start receiving every report type."""

    name = models.CharField(max_length=120, unique=True)
    report_types = models.JSONField(
        default=list, blank=True,
        help_text="Which automated report types this group receives. Empty = receives "
                   "nothing yet.")
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, blank=True, related_name="automated_report_groups",
        help_text="App users notified via their account e-mail.")
    emails = models.JSONField(
        default=list, blank=True,
        help_text="Plain e-mail addresses for stakeholders with no account.")
    active = models.BooleanField(default=True, help_text="Untick to pause without deleting.")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")

    class Meta:
        ordering = ["name"]
        verbose_name = "automated report group"

    def __str__(self):
        n = len(self.report_types or [])
        return f"{self.name} → {n} report type(s)" if n else f"{self.name} → no report types yet"

    def recipient_emails(self) -> list:
        """Same de-duplicated-and-validated shape as AlertGroup/EventGroup.recipient_emails --
        kept as an identical, separate copy rather than a shared mixin, matching the same
        "deliberately not coupled" precedent EventGroup's own copy already established (see
        EventGroup.recipient_emails' own docstring)."""
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

    def covers_report_type(self, report_type: str) -> bool:
        return report_type in (self.report_types or [])

    @property
    def stakeholder_count(self) -> int:
        return self.users.count() + len(self.emails or [])


class SeenBackupFile(models.Model):
    """Dedup ledger for the "backup file dropped" event (reports.events.check_backup_drops)
    -- the FIRST event notification type (2026-09-04). One row per backup file this app has
    ever already notified about, so the SAME file appearing again next poll (backup_file's own
    textfile metric keeps reporting a file for as long as it stays within the freshness
    window, typically today+yesterday) is never re-announced as if it just dropped again.

    Keyed by (system, instance, filename) -- `instance` (not just filename) because two
    different hosts could coincidentally produce identically-named backup files without being
    the same event."""

    system = models.CharField(max_length=120)
    instance = models.CharField(max_length=120)     # the host instance backup_file came from
    filename = models.CharField(max_length=255)
    first_seen_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("system", "instance", "filename")


class FreshnessCheck(models.Model):
    """One watched checker/exporter source, for SYSTEM ALERTS (reports.system_alerts) --
    the THIRD notification type (2026-09-05), answering "is our own monitoring pipeline
    still telling the truth" rather than "is a value over a threshold" (AlertGroup) or "did a
    discrete thing happen" (EventGroup).

    Concrete motivating case: the T24 TSA services checker writes t24_service_up's own
    source data (t24_tsa_service_running) into a static file, t24_services.prom, re-served
    by windows_exporter's textfile collector. Prometheus's SCRAPE of that endpoint can be
    perfectly healthy forever while the FILE ITSELF stops being rewritten by whatever script
    or scheduled task produces it -- found 2026-09-05 to have gone silently stale for 12+
    days, during which every one of that file's last-known values (all "running") kept
    reading back as current truth. `windows_textfile_mtime_seconds{instance, file}` is the
    one signal that actually tells the two apart: it moves only when the FILE is rewritten,
    never merely because the scrape succeeded.

    Deliberately a plain admin-configurable list, not hard-coded to T24: any future checker
    script that goes silent is covered by adding one more row here, not by writing a second
    bespoke watchdog. 2026-09-05, on request ("a staleness alert for each and every
    system... all metrics as consolidated and structured as belonging to that system"),
    `reports.management.commands.seed_freshness_checks` walks the WHOLE topology and creates
    one row per real checker source it can find -- see that command's own docstring for the
    two metric families it looks for and how it intuits each one's own `max_age_seconds`.

    `kind` picks WHICH Prometheus signal this row watches -- not every checker's staleness is
    a textfile's own mtime:
      "textfile_mtime" -- windows_textfile_mtime_seconds{instance, file}: how old THIS FILE's
          own last write is. Needs `file`. Windows-only (windows_exporter's textfile
          collector) -- the ORIGINAL, single mechanism this model had before 2026-09-05.
      "backup_check"   -- backup_check_timestamp_seconds{instance}: the backup checker
          SCRIPT's own last-run time (the same metric reports.folders/reports.alerting
          already read for the NO BACKUP flag's own timestamp gate -- see
          project_backup_check_timestamp_gate). Needs no `file` -- this metric is one series
          per instance, not per file -- and it exists on BOTH windows_exporter and
          node_exporter hosts, which is what lets one FreshnessCheck kind cover a Linux
          database host exactly the same way as a Windows one.
    """

    KIND_TEXTFILE_MTIME = "textfile_mtime"
    KIND_BACKUP_CHECK = "backup_check"
    KIND_CHOICES = [
        (KIND_TEXTFILE_MTIME, "Textfile mtime (windows_exporter, needs a file)"),
        (KIND_BACKUP_CHECK, "Backup checker timestamp (any host, no file needed)"),
    ]

    name = models.CharField(max_length=200, help_text="What this checks, e.g. "
                            "\"T24 TSA Services Checker\".")
    system = models.CharField(
        max_length=120,
        help_text="System name from prometheus.yml this checker belongs to -- a "
                  "SystemAlertGroup covering this system is notified when it goes stale.")
    kind = models.CharField(max_length=20, choices=KIND_CHOICES, default=KIND_TEXTFILE_MTIME)
    instance = models.CharField(
        max_length=200, help_text="Scrape target serving this signal, e.g. \"10.0.212.3:9182\".")
    file = models.CharField(
        max_length=255, blank=True,
        help_text="Required for \"Textfile mtime\" only: the .prom filename windows_exporter's "
                  "textfile collector reports under the `file` label, e.g. \"t24_services.prom\". "
                  "Leave blank for \"Backup checker timestamp\".")
    max_age_seconds = models.PositiveIntegerField(
        default=7200,
        help_text="How old this file's own last write may get before it's considered "
                  "stale. Set this to comfortably more than the checker's real run "
                  "interval, or every normal gap between runs will falsely alert.")
    # OPTIONAL correlation with folder_exporter's OWN job-scheduler metrics (2026-09-05,
    # on request, after a real investigation found the T24 checker jobs reporting 100%
    # success -- exit_code=0, "ok" on every one of thousands of runs, most recent success
    # timestamped SECONDS before the alert fired -- while the file they're supposed to
    # produce hadn't moved in 12+ days: the job scheduler and the file's own mtime were
    # telling two completely different stories, and nothing surfaced that mismatch until an
    # admin had to go query both by hand). When both fields are set, the alert e-mail shows
    # scheduler_job_last_success_timestamp_seconds{instance=scheduler_instance,
    # exported_job=scheduler_job} alongside the file's own staleness, so "job says healthy,
    # file says stale" -- the exact signature of a script that runs, exits 0, but silently
    # never reaches its own write step -- is visible without a manual cross-query. Blank on
    # either side simply omits this line; not every FreshnessCheck's source is a
    # folder_exporter job.
    scheduler_instance = models.CharField(
        max_length=200, blank=True,
        help_text="Optional: the folder_exporter instance running this checker as a "
                  "scheduled job, e.g. \"10.0.212.3:9847\" (NOT the same port as the "
                  "textfile-collector Instance above). Leave blank if this file isn't "
                  "produced by a folder_exporter job.")
    scheduler_job = models.CharField(
        max_length=200, blank=True,
        help_text="Optional: that job's own name (folder_exporter.yml's `jobs: - name:`), "
                  "e.g. \"t24_service_checker\" -- shown as scheduler_job_last_success_"
                  "timestamp_seconds's `exported_job` label.")
    active = models.BooleanField(default=True, help_text="Untick to stop watching without deleting.")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("instance", "file")
        ordering = ["system", "name"]
        verbose_name = "freshness check"

    def __str__(self):
        return f"{self.system} · {self.name}"


class SystemAlertFinding(models.Model):
    """One (group, check) row's notification state -- the dedup ledger
    reports.system_alerts.run_system_alert_cycle consults every poll to decide new / remind
    / skip / resolved, the same role AlertFinding plays for reports.alerting. No `band`/`text`
    columns: a FreshnessCheck carries no severity and its own current age is recomputed fresh
    every poll rather than stored, so there is nothing here worth snapshotting beyond the
    notification timestamps themselves.

    `group` is AlertGroup (2026-09-05: SystemAlertGroup was merged into AlertGroup -- see
    AlertGroup's own docstring -- so this points at the SAME model AlertFinding.group does;
    `related_name="system_alert_findings"` keeps the two reverse accessors distinct since
    AlertFinding already claims `related_name="findings"` on that model)."""

    group = models.ForeignKey(AlertGroup, on_delete=models.CASCADE, related_name="system_alert_findings")
    # NOT named "check" -- models.Model already has a check() classmethod (the system-check
    # framework's own hook), and a field of that name shadows it (Django's own models.E020).
    freshness_check = models.ForeignKey(FreshnessCheck, on_delete=models.CASCADE, related_name="findings")
    first_seen_at = models.DateTimeField()
    first_notified_at = models.DateTimeField(null=True, blank=True)
    last_notified_at = models.DateTimeField(null=True, blank=True)
    reminder_count = models.PositiveSmallIntegerField(default=0)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("group", "freshness_check")
        ordering = ["-first_seen_at"]
        verbose_name = "system alert finding state"

    def __str__(self):
        state = "resolved" if self.resolved_at else "open"
        return f"{self.group.name} · {self.freshness_check.name} ({state})"
        verbose_name = "seen backup file"

    def __str__(self):
        return f"{self.system} · {self.instance} · {self.filename}"


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


class MetricSample(models.Model):
    """One captured hourly reading of a Prometheus percentage/throughput series -- RAM/CPU/Disk
    per instance+mount, and SWIFT transaction throughput -- so the Hourly Activity / SWIFT
    charts are no longer bounded by Prometheus's own retention window (2026-09-18, on request:
    "store this data in the database... so we can have a much longer retention window").

    `metric_key` is a join key back to PROMETHEUS'S OWN identity space, not this app's
    system/label naming: "ram:{instance}" / "cpu:{instance}" / "disk:{instance}:{mount}" /
    "swift". Built the same way on every write (reports.metric_history.capture_now/backfill)
    and every read (report_charts.resource_percent_series/swift_transaction_series), so a
    lookup always finds what was captured for that exact series even if this app's own
    system/label display naming for that instance changes later. NOT keyed on system/label
    directly, because those belong to THIS app's topology config, and reusing them here would
    mean a rename in systems_config.yml silently orphans every sample captured under the old
    name.

    Captured hourly by reports.metric_history.capture_now (scheduled the same way the alert/
    event/system-alert pollers already are -- see deploy/gms/folder_exporter.yml, job
    metric_history_capture), independent of which categories/components happen to be
    "currently flagged" in any one report -- every RAM/CPU/Disk series across the WHOLE
    topology is captured every run, not just whatever a report instance's own recurring_issues
    turned up, so a component that becomes newsworthy later still has history behind it.

    No FK to any topology model -- Component/System are plain dataclasses read fresh from
    systems_config.yml on every report, not persisted rows, so there is nothing here to point
    at."""
    metric_key = models.CharField(max_length=255)
    taken_at = models.DateTimeField()
    value = models.FloatField()

    class Meta:
        verbose_name = "metric sample"
        indexes = [models.Index(fields=["metric_key", "taken_at"])]
        constraints = [
            # capture_now runs hourly and backfill runs once over the same window -- either
            # could otherwise double up a point for the same series/hour; ignore_conflicts=True
            # bulk_create calls on both sides rely on this to silently skip a re-capture rather
            # than duplicate it.
            models.UniqueConstraint(fields=["metric_key", "taken_at"], name="unique_metric_sample_point"),
        ]
        ordering = ["taken_at"]

    def __str__(self):
        return f"{self.metric_key} @ {self.taken_at:%Y-%m-%d %H:%M} = {self.value:.1f}"


class PrometheusRetentionRevision(models.Model):
    """`live_window_days` -- the single setting that drives BOTH how long Prometheus itself
    retains data locally (applied as --storage.tsdb.retention.time, see prometheus_admin.py)
    AND where reports.historical_query.series() reads a given time range from (live Prometheus
    for anything within this many days, prometheus_snapshot_db beyond it) -- see
    PROMETHEUS-RETENTION-PLAN.md, "Phase 4: one setting, two consumers".

    DELIBERATELY no separate saved-vs-applied state, unlike PrometheusConfigRevision/
    BackupPolicyRevision's usual Save/Save & Apply split: a row here is only ever created AT
    THE MOMENT an apply actually succeeds (prometheus_admin.write_retention_and_restart), so
    `current()` is always "the value genuinely live on the Prometheus service right now", never
    a staged draft. This is the fix for the plan's own logical-review finding #1: a routing
    function reading a saved-but-unapplied value could ask live Prometheus for a window it
    doesn't actually retain yet, silently returning partial/empty results instead of correctly
    falling back to the archive. Two systems keying off one setting is only safe if there is
    exactly one value to read, not a pending one and a live one that can disagree.
    """
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")
    note = models.CharField(max_length=200, blank=True)
    live_window_days = models.PositiveIntegerField(default=3)

    class Meta:
        verbose_name = "Prometheus retention revision"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.live_window_days}d @ {self.created_at:%Y-%m-%d %H:%M}"

    @classmethod
    def current_days(cls) -> int:
        """The applied live_window_days, or the model's own default (3) before any revision
        has ever been recorded -- see this model's own docstring on why "current" here always
        means "applied", never "saved but not yet live"."""
        row = cls.objects.first()
        return row.live_window_days if row else cls._meta.get_field("live_window_days").default


class MetricSampleRetentionRevision(models.Model):
    """How many days of MetricSample rows (prometheus_snapshot_db) to keep before a daily
    prune job deletes them -- see PROMETHEUS-RETENTION-PLAN.md Phase 3 step 6. Same lighter
    revision shape as BackupPolicyRevision (a single Save IS the apply here -- there is no
    live file/service layer for this setting, the prune job just reads `.current_days()`
    fresh each run, the same live-DB-read idiom AlertGroup.reminder_minutes already uses for
    alerting.py/system_alerts.py -- unlike PrometheusRetentionRevision above, there is no
    second system that could drift out of sync with this one, so the extra apply step that
    setting needs for correctness would just be friction here)."""
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True, related_name="+")
    note = models.CharField(max_length=200, blank=True)
    retention_days = models.PositiveIntegerField(default=400)

    class Meta:
        verbose_name = "Metric history retention revision"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.retention_days}d @ {self.created_at:%Y-%m-%d %H:%M}"

    @classmethod
    def current_days(cls) -> int:
        row = cls.objects.first()
        return row.retention_days if row else cls._meta.get_field("retention_days").default


class DatabaseBackupRun(models.Model):
    """One row per weekly offline pg_dump attempt (admin_report AND prometheus_snapshot_db,
    each gets its own row) -- see PROMETHEUS-RETENTION-PLAN.md Phase 5. Not admin-edited, just
    a history log the config screen reads (same "audit trail, not a knob" role
    PrometheusSnapshotRun would have played in this plan's earlier, since-dropped
    native-snapshot design)."""
    STATUS_CHOICES = [("running", "Running"), ("ok", "OK"), ("failed", "Failed")]

    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    database = models.CharField(max_length=100)          # "admin_report" | "prometheus_snapshot_db"
    destination_path = models.CharField(max_length=500, blank=True)
    size_bytes = models.BigIntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="running")
    error = models.TextField(blank=True)

    class Meta:
        verbose_name = "Database backup run"
        ordering = ["-started_at"]

    def __str__(self):
        return f"{self.database} @ {self.started_at:%Y-%m-%d %H:%M} ({self.status})"


class LiveEstateOverview(models.Model):
    """One row per estate ("system_admin" | "network" | "infrastructure" | "active_directory")
    -- the Executive Dashboard's own poller-fed cache (2026-09-18, on request: "broaden alert
    poller to cover infrastructure and network metrics and just use this as default poller to
    feed both alerts and live dashboards").

    Written every ~5 minutes by reports.alerting.run_alert_cycle, which already pays for a live
    capture of every estate to populate IssueOccurrence -- this table just also keeps the fully-
    computed `overview` dict (glance/immediate/watch/banners) and per-system flag list from that
    SAME capture, verbatim, using the identical build_overview()/network._network_overview()/
    _infra_overview() engine the live "generate a report" flow itself uses. No threshold or
    tile logic is reimplemented here.

    The dashboard (views._live_report_sections) reads this table instead of live-capturing on
    every page view -- a single fast DB read instead of paying a fresh Prometheus/SNMP round
    trip PER VISITOR, at the cost of the read being "as of the last poll" (≤5 minutes stale)
    rather than instantaneous. Falls back to the last ReportSubmission if a row doesn't exist
    yet (e.g. right after a deploy, before the first poll)."""
    kind = models.CharField(max_length=40, unique=True)
    captured_at = models.DateTimeField()
    overview = models.JSONField()
    systems = models.JSONField()

    class Meta:
        verbose_name = "live estate overview"

    def __str__(self):
        return f"{self.kind} @ {self.captured_at:%Y-%m-%d %H:%M}"


class MonitoredInterface(models.Model):
    """Sticky "should be up" baseline for one SNMP interface (device + ifIndex) on the
    Switches & Routers estate (2026-09-23, on request: "take a snapshot of all currently on
    interfaces and monitor them... if any of these at any given point goes down now it's a
    problem... not to say ignore all other interfaces, keep monitoring them, but in a
    different sheet").

    A port this estate has NEVER been seen up on is presumed administratively disabled on
    purpose (an unused wall jack, a spare uplink) -- see network._device_flags' own comment on
    why ifAdminStatus can't tell the two apart here (confirmed absent from this vendor's SNMP
    module, not just unread). The FIRST time a port is observed up, it enters this table and
    becomes part of the monitored set for good, barring a manual reset -- from then on, seeing
    it down again is a genuine regression, not an assumption, and network._device_flags()
    flags it as one on every run until it comes back up.

    `is_scoped` (2026-09-23, narrowing the above: "we only want to monitor these interfaces
    not all of them... uplink, accesspoint, links going to other switches") -- True once CDP
    has EVER identified this port as an access point, an uplink, or a neighbour link to
    another switch, and STAYS True from then on even once CDP stops reporting it, which is
    exactly what happens the moment the port actually goes down (CDP's own neighbour cache
    ages the entry out within its hold-time once the two sides stop exchanging frames). Without
    this stickiness, the one moment a monitored port fails -- when its CDP entry disappears
    along with the link -- would also be the moment it silently fell out of "monitored" and
    stopped being flagged at all, which is backwards. Only rows with is_scoped=True count
    toward "monitored" anywhere in the report now; a row that was up once but never
    CDP-classified (most ports) stays in this table for history but is never flagged.

    Updated on every collect() the Switches & Routers estate produces -- both the alert
    poller's own cycle and any admin viewing the live report -- not just a scheduled job: an
    "up" observation from EITHER source is equally real, so either is enough to (re)confirm
    the baseline or clear a standing regression. See network._update_interface_baseline()."""

    device = models.CharField(max_length=120)    # the SNMP target -- collect()'s own `instance`
    if_index = models.CharField(max_length=20)
    if_name = models.CharField(max_length=255, blank=True)   # cached for display if it later drops off
    first_seen_up_at = models.DateTimeField()
    last_seen_up_at = models.DateTimeField()
    last_checked_at = models.DateTimeField()
    currently_up = models.BooleanField(default=True)
    is_scoped = models.BooleanField(
        default=False,
        help_text="Ever CDP-identified as an AP/uplink/neighbour link -- sticky, see this "
                  "model's own docstring for why it must never be unset once True.")

    class Meta:
        unique_together = ("device", "if_index")
        verbose_name = "monitored interface baseline"

    def __str__(self):
        return f"{self.device}:{self.if_index} ({'up' if self.currently_up else 'DOWN'})"


class MonitoredAccessPoint(models.Model):
    """Sticky "should be joined" baseline for one wireless access point on a WLC (2026-09-29,
    on request: "we need to monitor all access points connected to these wireless
    contreollers whether they are connected ore have gone down") -- the SAME sticky-baseline
    idea MonitoredInterface's own docstring already established for switch ports, applied to
    APs for the same underlying reason: CISCO-LWAPP-AP-MIB's cLApTable only ever lists an AP
    while it's actually JOINED to the controller -- an AP that loses power, reboots, or drops
    its CAPWAP tunnel simply DISAPPEARS from the walk, the exact same "the one moment it fails
    is the moment its own row vanishes" problem CDP neighbours have for interfaces. Without
    this table, a downed AP would be invisible rather than flagged -- every AP that WAS seen
    joined enters here and stays tracked for good; the report reads `currently_up` against
    that history to tell "genuinely never known" apart from "was up, now missing."

    No `is_scoped`-equivalent needed here, unlike MonitoredInterface: every AP CISCO-LWAPP-
    AP-MIB ever reports IS the thing being asked for ("all access points"), not a narrowed
    subset CDP has to identify a purpose for first.

    Updated on every collect() the Switches & Routers estate produces, same cadence as
    MonitoredInterface. See network._update_ap_baseline()."""

    device = models.CharField(max_length=120)    # the SNMP target -- collect()'s own `instance`
    ap_name = models.CharField(max_length=255)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    last_checked_at = models.DateTimeField()
    currently_up = models.BooleanField(default=True)

    class Meta:
        unique_together = ("device", "ap_name")
        verbose_name = "monitored access point baseline"

    def __str__(self):
        return f"{self.device}:{self.ap_name} ({'up' if self.currently_up else 'DOWN'})"
