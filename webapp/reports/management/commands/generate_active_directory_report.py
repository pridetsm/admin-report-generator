"""Unattended, scheduled twin of reports.views.active_directory_generate (the interactive
picker -> review -> generate flow) -- mirrors generate_automated_report.py's own shape
(generate -> store ReportSubmission -> resolve recipients -> conditionally e-mail ->
distinguish "generated but not e-mailed" from a hard failure), but for the XLSX Active
Directory Report, not a narrative Automated Report.

No CLI arguments (folder_exporter.yml's job runner launches `command:` as one literal process
path with no argv splitting -- see run_active_directory_report.bat's own header), and no
--force-distribute switch: unlike the narrative Automated Reports, there is no shadow-mode
flag gating this at all. SystemConfig.automated_reports_distribution_enabled is a rollout
switch specifically for the six narrative report types (currently off) -- gating this
explicitly-requested job behind an unrelated, off-by-default flag would silently defeat the
point of scheduling it (2026-09-12: "schedule the active directory report to run at 07:30
hrs, put me as the only recipient of that report group").

The E-MAIL ITSELF is send_report/mail_report.py's own render_html()/analyse(), called
directly and unmodified (bar one new `title` parameter -- see that function's own docstring)
-- NOT a second, hand-built template (2026-09-14, on request: "the mailing script...for the
scheduled report is the wrong one, use the one we use for the standalone systems"; after
several attempts at hand-porting its markup kept missing pieces, "go to the mailing script
and wrap that code around active directory data... go to the standalone folder and get this
code as is"). This only works because Active Directory is now a real, capturable System list
in generate_report.py's OWN topology (load_topology(scope="ad") -- see AD_SYSTEMS' own
comment there for the full history) rather than existing only in network.py's separate
engine; capture() needed zero changes, since it already queries Prometheus globally rather
than per-topology. The XLSX ATTACHMENT stays network.build_infrastructure_report's own
richer, AD-specific report (replication/NTP/cluster-storage tables generate_report.py's own
engine has no concept of) -- only the EMAIL BODY changed engines, the same split the
standalone System Admin Report itself uses (a summary e-mail, a fuller xlsx attached).

SECOND ATTACHMENT (2026-09-17, on request: "attach a fresh copy of the cluster health report
alongside the active directory report"): also captures and builds a fresh Cluster Health
Report (the same network.build_infrastructure_report the interactive infra_generate view
produces, default title, scoped to every non-AD windows-kind device -- HCI Cluster + Disaster
Recovery Cluster today) and attaches it to the SAME e-mail, via mail_report.send_email's new
multi-attachment support. Best-effort: a failure capturing/building the Cluster Health half
(logged as a warning) still lets the Active Directory Report send on its own -- one broken
attachment must never silently swallow the other, working one. Stored as its own
ReportSubmission (kind="infrastructure"), same as the interactive flow, so History/the
Executive Dashboard see a real Cluster Health Report generation here, not just an attachment
riding along invisibly. The e-mail's subject/severity reflects the WORSE of the two reports'
own findings (AD's mail_report.analyse() thresholds and Cluster Health's own red/amber
counts, two different threshold systems that were never going to be merged into one -- see
network.email_windows_report's own module comment on why Cluster Health gets its own
renderer instead of reusing this file's render_html()), so a Cluster Health-only critical
never hides behind an "all healthy" AD headline.
"""
from __future__ import annotations

import dataclasses
import uuid

from django.core.management.base import BaseCommand
from django.utils import timezone

import generate_report as gr    # send_report/ -- see config.settings' own sys.path insert
import mail_report as mr        # same module the standalone System Admin Report mailer uses

from reports import network
from reports.automated_reports_mail import automated_report_recipients
from reports.models import ReportSubmission

REPORT_TYPE = "active_directory"


class Command(BaseCommand):
    help = ("Generate the Active Directory Report headlessly, store it (ReportSubmission, "
           "the same History table the interactive picker writes to), and e-mail it to "
           "every active Reporting group covering 'active_directory'.")

    def handle(self, *args, **options):
        theme = "dark"                 # unattended: no user profile to read a preference from
        author = "Automated"           # unattended: no request.user
        annotations: dict = {}         # unattended: nobody reviewing flags/writing comments
        summary_comment = ""

        only = {d["key"] for d in network.DEVICES if d.get("system") in network.AD_SYSTEMS}
        token = uuid.uuid4().hex
        try:
            snapshot = network.capture_snapshot(token, only=only, infra=True)
        except network.NetworkUnavailable as exc:
            # Prometheus down at 07:30 is an operational hiccup, not a code failure -- exit
            # cleanly so folder_exporter's own job log shows a clean, expected skip rather
            # than a crash trace; tomorrow's run is unaffected.
            self.stderr.write(self.style.WARNING(f"Skipped: Prometheus unavailable ({exc})."))
            return

        data = network.build_infrastructure_report(
            snapshot, theme=theme, author=author, annotations=annotations,
            summary_comment=summary_comment, report_title="ACTIVE DIRECTORY REPORT")
        filename = network.active_directory_report_filename(theme, timezone.localtime())

        report_content = {
            "kind": "active_directory",
            "overview": snapshot.overview,
            "systems": [{
                "name": s.name, "hosts": s.hosts,
                "flags": [{"key": f.key, "text": f.text, "band": f.band,
                          "category": f.category, "answer": ""} for f in s.flags],
                "comment": "",
            } for s in snapshot.systems],
        }

        recipients = automated_report_recipients(REPORT_TYPE)
        delivery = "email" if recipients else "download"

        submission = ReportSubmission.objects.create(
            generated_by=None, author=author, theme=theme, delivery=delivery,
            recipients=", ".join(recipients), prom_url=snapshot.prom_url,
            systems_count=len(snapshot.systems),
            hosts_count=sum(s.hosts for s in snapshot.systems),
            immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
            summary_comment=summary_comment, annotations=annotations,
            report_content=report_content, filename=filename,
        )
        self.stdout.write(self.style.SUCCESS(
            f"Generated {filename} (id={submission.pk}) "
            f"systems={submission.systems_count} hosts={submission.hosts_count}"))

        # Cluster Health Report -- second, best-effort attachment (2026-09-17). Every non-AD
        # windows-kind device: the same scope infra_form's own picker offers, and the same
        # default `report_title` build_infrastructure_report already uses for the interactive
        # flow, so this is byte-for-byte the report an admin clicking through infra_report
        # would get right now, not a cut-down variant.
        infra_data = infra_filename = infra_snapshot = None
        infra_only = {d["key"] for d in network.DEVICES
                     if d.get("kind") == "windows" and d.get("system") not in network.AD_SYSTEMS}
        try:
            infra_snapshot = network.capture_snapshot(uuid.uuid4().hex, only=infra_only, infra=True)
            infra_data = network.build_infrastructure_report(
                infra_snapshot, theme=theme, author=author, annotations={}, summary_comment="")
            infra_filename = network.infrastructure_report_filename(theme, timezone.localtime())
        except Exception as exc:   # noqa: BLE001 -- best-effort second attachment: ANY failure
            # here (not just NetworkUnavailable -- a bad build, a missing field, anything) must
            # never take down the AD report's own already-successful capture/send below it.
            self.stderr.write(self.style.WARNING(
                f"Cluster Health Report skipped ({exc}) -- sending the Active Directory Report alone."))
            infra_data = infra_filename = infra_snapshot = None

        if infra_data is not None:
            infra_report_content = {
                "kind": "infrastructure",
                "overview": infra_snapshot.overview,
                "systems": [{
                    "name": s.name, "hosts": s.hosts,
                    "flags": [{"key": f.key, "text": f.text, "band": f.band,
                              "category": f.category, "answer": ""} for f in s.flags],
                    "comment": "",
                } for s in infra_snapshot.systems],
            }
            infra_submission = ReportSubmission.objects.create(
                generated_by=None, author=author, theme=theme, delivery=delivery,
                recipients=", ".join(recipients), prom_url=infra_snapshot.prom_url,
                systems_count=len(infra_snapshot.systems),
                hosts_count=infra_snapshot.hosts_count,
                immediate_count=infra_snapshot.immediate_count, watch_count=infra_snapshot.watch_count,
                summary_comment="", annotations={},
                report_content=infra_report_content, filename=infra_filename,
            )
            self.stdout.write(self.style.SUCCESS(
                f"Generated {infra_filename} (id={infra_submission.pk}) "
                f"systems={infra_submission.systems_count} hosts={infra_submission.hosts_count}"))

        if not recipients:
            self.stdout.write("No active Reporting group covers 'active_directory' -- "
                              "stored only, not e-mailed.")
            return

        import tempfile
        from pathlib import Path

        try:
            # A SEPARATE live capture from the xlsx above, through generate_report.py's own
            # engine rather than network.py's (see this command's own module docstring) --
            # the two engines have no shared Store to reuse, the same way the standalone
            # System Admin Report's own e-mail vs. xlsx were already two engines before this
            # change ever existed for AD.
            #
            # WARN raised to 80 for this call specifically (2026-09-21, on request, after a
            # screenshot: "this threshold is not what was agreed on" -- AD Sync's RAM at 79%
            # was showing as a Warning) -- mail_report.py's own module default is WARN=75/
            # CRIT=90, business-estate-oriented; network.py's own engine, used for every OTHER
            # CPU/RAM/disk reading anywhere in the Infrastructure/AD realm (HCI/DR cluster
            # nodes' own per-node flags -- see network.py's _windows_device_flags and its
            # siblings, all consistently 80/90), amber's at 80, not 75. CRIT is untouched: 90
            # already agrees with network.py's own red threshold everywhere it's used, only
            # WARN was ever out of step. This is a narrower, more surgical fix than reworking
            # analyse() to take separate RAM/CPU/disk thresholds -- one shared pair, raised to
            # match the number actually agreed for this estate, not the business-report one.
            cfg = gr.load_config()
            prom = gr.Prometheus(cfg.prom, cfg.http_timeout, getattr(cfg, "verify_tls", True))
            ad_systems = gr.load_topology(cfg.prometheus_yml, scope="ad")
            ad_store = gr.capture(prom, ad_systems, cfg)
            # capture() queries Prometheus GLOBALLY (see this command's own module docstring),
            # so store.links comes back holding EVERY web link the whole estate monitors, not
            # just AD's -- mr.analyse()'s own web-link check (unlike its RAM/CPU/disk/services
            # checks, which are already scoped per system) has no `systems` filter of its own,
            # so an unreachable or expiring-cert business-system web link would otherwise show
            # up in the Critical/Warning sections of what's meant to be an AD/Infrastructure-
            # only e-mail (2026-09-21, on request, after a screenshot: "I saw some of the
            # errors and warnings from system admin report sneaking in to the infrastructure
            # reports mailing template"). AD has no web links of its own (domain controllers
            # don't serve public HTTPS content, see render_html's own show_web_links=False
            # below), so scoping this down should make that finding-list empty every time, not
            # just smaller.
            gr.scope_links_to_systems(ad_store, ad_systems)
            ad_cfg = dataclasses.replace(cfg, chip_amber=80)
            unreach, crit, warn, nodata = mr.analyse(ad_store, ad_systems, cfg=ad_cfg)

            mailcfg = mr.load_mail_config(str(gr.DEFAULT_CONFIG))
            mailcfg["from_name"] = "RBZ Monitoring Console · Reporting"
            mailcfg["author"] = author
            mailcfg["grafana"] = cfg.grafana
            mailcfg["prom"] = cfg.prom
            mailcfg["elevated"] = cfg.overview_threshold
            mailcfg["report_url"] = "https://monitoring.rbz.co.zw"
            # List form (2026-09-17), not the single attachment_name/attachment_theme keys --
            # see _attachment_block's own docstring. Also fixes a latent mislabel: the legacy
            # fallback text always says "the complete System Admin Report", which was already
            # wrong for this AD e-mail before today (nobody had touched this path to notice).
            mailcfg["attachments"] = [{
                "name": filename, "theme": theme,
                "label": "the complete Active Directory Report",
                "detail": "(Services / Memory / Disk / Replication / NTP per domain controller)",
            }]
            attachment_names = [filename]
            if infra_data is not None:
                mailcfg["attachments"].append({
                    "name": infra_filename, "theme": theme,
                    "label": "the complete Cluster Health Report",
                    "detail": "(Services / Memory / Disk / Storage volumes per cluster node)",
                })
                attachment_names.append(infra_filename)

            # Combined severity (2026-09-17): AD's own mail_report.analyse() bands and Cluster
            # Health's own red/amber counts are two different threshold systems (see this
            # command's own module docstring) -- never merged into one number, but the WORSE
            # of the two decides the subject/headline band so a Cluster Health-only critical
            # can't hide behind an "all healthy" AD subject line.
            infra_red = infra_snapshot.immediate_count if infra_snapshot else 0
            infra_amber = infra_snapshot.watch_count if infra_snapshot else 0
            if unreach:
                sev = f"{len(unreach)} unreachable"
            elif crit or infra_red:
                parts = [f"{len(crit)} AD critical"] if crit else []
                if infra_red:
                    parts.append(f"{infra_red} cluster critical")
                sev = " · ".join(parts)
            elif warn or infra_amber:
                parts = [f"{len(warn)} AD warning"] if warn else []
                if infra_amber:
                    parts.append(f"{infra_amber} cluster warning")
                sev = " · ".join(parts)
            else:
                sev = "all healthy"
            # "Infrastructure Reports" (2026-09-17, on request: "the mailing template is still
            # titled Active Directory Report this should instead be Infrastructure Reports")
            # once BOTH reports are riding this e-mail -- with only the AD half (Cluster
            # Health capture failed, see above), it genuinely is just the Active Directory
            # Report, so that title stays accurate for that fallback case.
            report_names = "Infrastructure Reports" if infra_data is not None \
                else "Active Directory Report"
            subject = f"{report_names} — {timezone.localdate():%d %b %Y} — {sev}"
            # extra_estate (2026-09-17, on request: "we have 8 nodes which essentially are
            # devices from the cluster health report... add Cluster count and Cluster Nodes,
            # remove the Hosts tile... totals updated to show all devices from both reports")
            # -- straight from infra_snapshot's own Snapshot properties, so this e-mail's
            # tiles can never disagree with the Cluster Health Report's own AT A GLANCE band.
            #
            # immediate_tiles/watch_tiles (2026-09-17, on request: "remove folder drainage
            # tile[,] try to add tiles more useful to these two reports storage critical for
            # example, they may be others") -- infra_snapshot.overview's own "immediate"/
            # "watch" bands ARE that "others": Components down, Nodes down, Storage critical,
            # Memory critical, High CPU, High memory, Cluster resources failed, already
            # computed by _infra_overview for the Cluster Health Report's own screen -- passed
            # straight through rather than re-derived, same reasoning as cluster_count/
            # cluster_nodes just above. (Storage at capacity, once also in this list, is gone
            # outright as of 2026-09-18 -- see network._infra_overview's own comment.)
            #
            # "Components down" pulled OUT of immediate_tiles and folded into extra_down
            # instead (2026-09-17, on request: "unreachable components and components down
            # can also be combined into a single tile... if one tile can represent both
            # reports' findings then have one tile") -- render_html's own "Unreachable
            # components" tile already has the bigger, whole-estate Total (combined_hosts);
            # this adds the Cluster Health estate's own down-count into that SAME tile's
            # numerator rather than showing a second, narrower-Total tile for the same idea.
            #
            # "Nodes down" dropped too, not folded in (2026-09-17, on request: "do we need a
            # nodes down if we have unreachable components[,] arn't nodes components" -- yes:
            # _infra_overview's own components_down ALREADY sums in cluster_nodes_down (see
            # its own comment), so Nodes down's numerator is always <= the Components down
            # figure already merged above -- adding it again would double-count the exact same
            # failures, not add coverage. Genuinely redundant once merged, unlike Cluster
            # count/Cluster nodes above (a different granularity, not a duplicate finding).
            infra_immediate = infra_snapshot.overview.get("immediate", []) if infra_snapshot else []
            # "Unreachable components" (2026-10-03: network._infra_overview's own tile was
            # renamed from "Components down" -- see that function's own comment -- "just to
            # standardise things" against the identically-renamed Systems/Network tiles; this
            # extraction, and views.py's own twin copy of this exact block, were both updated
            # in the same pass so they keep finding the tile under its new name).
            components_down = next(
                (int(str(t["value"]).split(" | ")[0]) for t in infra_immediate
                if t["label"] == "Unreachable components"), 0)
            # extra_disk/extra_disk_total now read "Storage critical" (immediate tier), not
            # "Storage at capacity" -- that watch-tier tile is GONE (2026-09-18, on request:
            # "storage capacity and storage critical are the same metric... combine every
            # occurrence", confirmed after a first pass: "infrastructure still views these as
            # separate" -- see network._infra_overview's own comment on the removal). "Storage
            # critical" is excluded from immediate_tiles' own generic "others" loop below for
            # the same reason "Unreachable components"/"Nodes down" already are: it's merged
            # into render_html's own "High disk usage" tile via extra_disk AND still gets its
            # own dedicated red banner (storage_critical_items / mail_report._cluster_storage_
            # critical_block) -- rendering it a THIRD time as a plain generic tile here would
            # be exactly the redundancy this whole change is about removing.
            extra_disk = next((int(str(t["value"]).split(" | ")[0]) for t in infra_immediate
                               if t["label"] == "Storage critical"), 0)
            extra_disk_total = next((int(str(t["value"]).split(" | ")[1]) for t in infra_immediate
                                     if t["label"] == "Storage critical"), 0)
            immediate_tiles = [t for t in infra_immediate
                              if t["label"] not in ("Unreachable components", "Nodes down", "Storage critical")]
            # "High CPU"/"High memory" pulled out of watch_tiles and folded into extra_cpu/
            # extra_ram instead (2026-09-17, corrected same day: "cpu and ram are different
            # metrics they still need different tiles i meant one tile for each metric[,]
            # remember there where multiple ram tiles" -- render_html's own "High CPU usage"/
            # "High RAM usage" tiles already exist for the AD side; these are the SAME two
            # metrics over the Cluster Health estate, not a third/fourth metric, so they merge
            # into those same two tiles rather than sitting alongside them as duplicates).
            infra_watch = infra_snapshot.overview.get("watch", []) if infra_snapshot else []
            def _tile_num(label: str) -> int:
                return next((int(str(t["value"]).split(" | ")[0]) for t in infra_watch
                            if t["label"] == label), 0)
            extra_cpu = _tile_num("High CPU")
            extra_ram = _tile_num("High memory")
            watch_tiles = [t for t in infra_watch if t["label"] not in ("High CPU", "High memory")]
            # storage_critical_items (2026-09-17, on request: "critical storage usage... but
            # no critical banner to tell us exactly whats going on") -- see
            # network.critical_disk_items' own docstring; threshold left at its default (95)
            # to match the Storage critical tile above exactly.
            storage_critical_items = network.critical_disk_items(infra_snapshot)
            # cluster_count/cluster_nodes: CLUSTER devices/nodes only, NOT
            # len(infra_snapshot.systems)/.hosts_count -- those also count any non-cluster
            # device the same estate carries (fixed 2026-09-17, confirmed live: Standalone
            # Servers had inflated these from the true 3/10 to 6/13 -- see render_html's own
            # docstring on extra_estate for the full story). total_devices is the OLD
            # (uncorrected) value, deliberately kept as its own key -- combined_hosts genuinely
            # needs every device counted, cluster node or not.
            by_name = {d["name"]: d for d in network.DEVICES}
            cluster_count = sum(1 for s in infra_snapshot.systems if by_name.get(s.name, {}).get("cluster"))
            cluster_nodes = len(infra_snapshot._hci_nodes)
            total_devices = infra_snapshot.hosts_count
            extra_estate = ({"cluster_count": cluster_count,
                            "cluster_nodes": cluster_nodes,
                            "total_devices": total_devices,
                            "extra_down": components_down,
                            "extra_cpu": extra_cpu, "extra_ram": extra_ram,
                            "extra_disk": extra_disk, "extra_disk_total": extra_disk_total,
                            "storage_critical_items": storage_critical_items,
                            "immediate_tiles": immediate_tiles,
                            "watch_tiles": watch_tiles}
                           if infra_snapshot is not None else None)
            # number_font left at its default (2026-09-17, on request: "make all font in this
            # template be times new roman") -- inherits the template's own base font, no override.
            #
            # stale_metrics (2026-09-21, on request: "stale metrics warning not showing up in a
            # warning banner in mailing template") -- open reports.system_alerts findings
            # (FreshnessCheck/SystemAlertFinding) for any checker/exporter covering a system
            # THIS report actually touches (AD's own three, plus every device Cluster Health
            # captured), so a reader here sees "some of this may be stale" without needing to
            # separately notice that family's own e-mail. Scoped the same way scope_links_to_
            # systems above scopes web links -- only what this report is actually about.
            from reports.models import SystemAlertFinding

            def _age_str(seconds: float) -> str:
                days, rem = divmod(max(0, int(seconds)), 86400)
                hours, rem = divmod(rem, 3600)
                return f"{days}d {hours}h" if days else f"{hours}h {rem // 60}m"

            stale_systems = {s.name for s in ad_systems}
            if infra_snapshot is not None:
                stale_systems |= {s.name for s in infra_snapshot.systems}
            now = timezone.now()
            stale_metrics = [
                (f"{f.freshness_check.system} · {f.freshness_check.name}",
                 f"not updated in {_age_str((now - f.first_seen_at).total_seconds())}")
                for f in SystemAlertFinding.objects.filter(
                    freshness_check__system__in=stale_systems, resolved_at__isnull=True)
                    .select_related("freshness_check")
            ]
            # A SECOND, unrelated staleness mechanism (2026-09-21, on request, after a
            # screenshot: "RBZHQ-DC-204 is reachable (ping OK), but its own metrics-collection
            # script has not reported...") -- network.py's own relay-based reachability for a
            # device with no windows_exporter of its own (see that module's
            # _windows_device_flags, flag key "win_stale_but_pinging"). This ALREADY gets
            # captured above into `snapshot` (the network.py capture behind the XLSX
            # attachment) -- it was simply never carried over into the e-mail body, which
            # reads from a completely different engine/topology that has no concept of DC-204
            # at all (generate_report.py's own AD topology only has 203/ROOT-01/etc., not 204
            # -- confirmed live: it's genuinely absent, not misclassified). The flag's own text
            # is already a complete, self-explanatory sentence, so it's passed straight
            # through as the detail rather than reformatted.
            stale_metrics += [
                (sysvm.name, f.text) for sysvm in snapshot.systems for f in sysvm.flags
                if f.key == "win_stale_but_pinging"
            ]
            html_body = mr.render_html(ad_store, ad_systems, unreach, crit, warn, nodata, mailcfg,
                                       title=report_names.upper(), system_label="Devices",
                                       show_backups=False, show_web_links=False, show_swift=False,
                                       show_cob=False, show_certs=False, show_queues=False,
                                       extra_estate=extra_estate, stale_metrics=stale_metrics)
            text_body = mr.plain_summary(unreach, crit, warn, nodata, mailcfg["report_url"],
                                         attachment_names)

            tmpdir = tempfile.mkdtemp(prefix="ad_report_")
            attachments = [Path(tmpdir) / filename]
            if infra_data is not None:
                attachments.append(Path(tmpdir) / infra_filename)
            try:
                attachments[0].write_bytes(data)
                if infra_data is not None:
                    attachments[1].write_bytes(infra_data)
                mr.send_email(mailcfg, recipients, subject, html_body, text_body, attachments)
            finally:
                for a in attachments:
                    try:
                        a.unlink()
                    except OSError:
                        pass
                try:
                    Path(tmpdir).rmdir()
                except OSError:
                    pass
        except Exception as exc:   # noqa: BLE001 -- a failed send must not look like a failed run
            self.stderr.write(self.style.WARNING(f"Generated but NOT e-mailed: {exc}"))
            return
        self.stdout.write(self.style.SUCCESS(f"E-mailed to {len(recipients)} recipient(s)."))
