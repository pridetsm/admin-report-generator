from django.core.management.base import BaseCommand

import generate_report as gr
from reports import system_alerts


# Textfile-collector sources this app KNOWS the real update cadence for (from the actual
# folder_exporter.yml `jobs:` entries on the hosts that produce them -- 2026-09-05), each
# mapped to an intuited max_age_seconds: comfortably above the real interval, tight enough to
# still catch a genuinely dead checker in a reasonable time. Deliberately a reviewed allowlist
# rather than "seed every windows_textfile_mtime_seconds file this app can see" -- a file this
# command doesn't understand the cadence of would only get a guessed threshold worth nothing,
# and backup_file.prom (present on nearly every system) is intentionally EXCLUDED here since
# backup-checker staleness is watched via backup_check_timestamp_seconds instead (see below) --
# that metric is the checker SCRIPT's own last-run time, not a file's mtime, and it exists on
# both windows_exporter and node_exporter hosts, so one mechanism covers Windows and Linux
# checkers alike instead of two.
KNOWN_TEXTFILE_CHECKS = {
    # T24 TSA services checker -- every_seconds: 300 in that host's folder_exporter.yml.
    # 1200s (20m, 4x the real interval) catches a dead checker within the hour without ever
    # flagging on ordinary scheduler jitter.
    ("10.0.212.3:9182", "t24_services.prom"): {
        "name": "T24 TSA Services Checker", "max_age_seconds": 1200},
    # Count Swift Transactions -- also every_seconds: 300 on the same host, same reasoning.
    ("10.0.212.3:9182", "transactions.prom"): {
        "name": "T24 Transactions Checker", "max_age_seconds": 1200},
    # COB Time Calculator -- cron "0 7 * * 0,2-6" (daily except Monday) on the T24 DB host.
    # The longest NORMAL gap is Sunday 07:00 -> Tuesday 07:00 (Monday skipped) = 48h; 60h
    # clears that with margin while still catching a genuinely dead checker within ~2.5 days.
    ("10.0.212.4:9182", "cob_time.prom"): {
        "name": "T24 COB Time Calculator", "max_age_seconds": 60 * 3600},
    # HCI cluster metrics -- real cadence not documented anywhere this app can read; 6h is an
    # intuited default reflecting that cluster health data is normally near-live, deliberately
    # NOT tuned to the 6.88 DAYS stale this file actually read at seed time (2026-09-05) --
    # that staleness is itself a live finding this check surfaces, not something to mask by
    # picking a looser threshold to match it.
    ("10.100.246.3:9182", "cluster_metrics.prom"): {
        "name": "HCI Cluster Metrics", "max_age_seconds": 6 * 3600},
    # WMI workaround script, 3 hosts -- real cadence unknown; 2h is a generic, admin-tunable
    # starting point ("workaround" scripts are typically minutes-frequency, so 2h leaves wide
    # margin) rather than a guess dressed up as a known interval.
    ("10.100.249.201:9182", "wmi_workaround_metrics.prom"): {
        "name": "WMI Workaround Metrics", "max_age_seconds": 2 * 3600},
    ("10.100.246.4:9182", "wmi_workaround_metrics.prom"): {
        "name": "WMI Workaround Metrics", "max_age_seconds": 2 * 3600},
    ("10.100.246.5:9182", "wmi_workaround_metrics.prom"): {
        "name": "WMI Workaround Metrics", "max_age_seconds": 2 * 3600},
}

# Backup checker staleness ("a skipped day", 2026-09-05 on request) -- ANY instance
# currently reporting backup_check_timestamp_seconds gets one row, regardless of system,
# regardless of Windows/Linux. 30h (24h + 6h buffer) tolerates a checker that runs a little
# late without masking a genuinely skipped day.
BACKUP_CHECK_MAX_AGE_SECONDS = 30 * 3600


class Command(BaseCommand):
    help = ("Walk the whole topology and create one FreshnessCheck per real checker source "
           "this app can find live in Prometheus -- backup_check_timestamp_seconds for every "
           "instance that has it, plus the known-cadence textfile sources in "
           "KNOWN_TEXTFILE_CHECKS above. Idempotent (get_or_create): never overwrites an "
           "already-existing row's admin-tuned name/max_age, only fills in ones that don't "
           "exist yet.")

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Report what would be created; no DB writes.")

    def handle(self, *args, **options):
        from reports.models import FreshnessCheck, SystemConfig

        dry_run = options["dry_run"]
        cfg = gr.load_config()
        sc = SystemConfig.get()
        if sc.prometheus_url:
            cfg.prom = sc.prometheus_url
        prom = gr.Prometheus(cfg.prom, cfg.http_timeout, cfg.verify_tls)
        prom.ping()

        topo = gr.load_topology(cfg.prometheus_yml, scope="all")
        inst_to_system = {}
        inst_to_display = {}
        for s in topo:
            for c in s.components:
                inst_to_system[c.instance] = s.name
                inst_to_display[c.instance] = c.label

        created, skipped, existing = [], [], []

        # ---- backup checker staleness: one row per live instance ----
        for row in prom.query("backup_check_timestamp_seconds"):
            instance = row["labels"].get("instance")
            system = inst_to_system.get(instance) or row["labels"].get("system")
            if not (instance and system):
                skipped.append(f"backup_check_timestamp_seconds instance={instance!r} -- "
                               f"not in topology, skipped")
                continue
            label = inst_to_display.get(instance) or system
            if FreshnessCheck.objects.filter(instance=instance, file="").exists():
                existing.append(f"{system} · {label} Backup Checker ({instance})")
                continue
            created.append(f"{system} · {label} Backup Checker ({instance}) "
                           f"max_age={BACKUP_CHECK_MAX_AGE_SECONDS}s")
            if not dry_run:
                FreshnessCheck.objects.create(
                    name=f"{label} Backup Checker", system=system,
                    kind=FreshnessCheck.KIND_BACKUP_CHECK, instance=instance, file="",
                    max_age_seconds=BACKUP_CHECK_MAX_AGE_SECONDS)

        # ---- known-cadence textfile sources: only ones confirmed live right now ----
        for (instance, file), spec in KNOWN_TEXTFILE_CHECKS.items():
            rows = prom.query(f'windows_textfile_mtime_seconds{{instance="{instance}", file="{file}"}}')
            if not rows:
                skipped.append(f"{instance} / {file} -- no live series, skipped")
                continue
            system = inst_to_system.get(instance) or rows[0]["labels"].get("system")
            if not system:
                skipped.append(f"{instance} / {file} -- not in topology, skipped")
                continue
            if FreshnessCheck.objects.filter(instance=instance, file=file).exists():
                existing.append(f"{system} · {spec['name']} ({instance} / {file})")
                continue
            created.append(f"{system} · {spec['name']} ({instance} / {file}) "
                           f"max_age={spec['max_age_seconds']}s")
            if not dry_run:
                FreshnessCheck.objects.create(
                    name=spec["name"], system=system,
                    kind=FreshnessCheck.KIND_TEXTFILE_MTIME, instance=instance, file=file,
                    max_age_seconds=spec["max_age_seconds"])

        for line in created:
            self.stdout.write(self.style.SUCCESS(f"{'would create' if dry_run else 'created'}: {line}"))
        for line in existing:
            self.stdout.write(f"already exists: {line}")
        for line in skipped:
            self.stdout.write(self.style.WARNING(f"skipped: {line}"))
        self.stdout.write(self.style.SUCCESS(
            f"created={len(created)} existing={len(existing)} skipped={len(skipped)}"))
