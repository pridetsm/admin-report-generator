"""Unattended, scheduled twin of the four Networks Report pickers (Core Switches, Routers,
Wireless Controller, Access Switches) -- generate all four, store each as its own
ReportSubmission (same History table the interactive pickers write to), then e-mail them
together as ONE bundle (see network.email_network_reports_bundle) to every active Reporting
group covering 'network_reports' (2026-09-24, on request: "wire them in in reporting config to
send to the same people that recieve the infrastructure networks report at around the same
time").

CONCURRENCY (2026-09-24, on request: "these reports will be generated at around the same time
including systems admin report we need to strengthen this as it is a legitment source of
failure we will most certainly need advanced multi threading"). The four reports are
INDEPENDENT captures over four mutually exclusive device sets (see
network.core_switches_device_keys/routers_device_keys/wireless_controller_device_keys/
access_switches_device_keys -- each device belongs to exactly one, confirmed via
is_access_switch()'s own partition), so running them concurrently is both safe and the right
tool for the job: each one is dominated by network I/O (several Prometheus HTTP queries per
capture_snapshot() call), not CPU, which is exactly what Python's GIL does NOT serialize --
a thread blocked waiting on a socket releases the GIL, so four threads doing Prometheus round
trips genuinely overlap in wall-clock time. concurrent.futures.ThreadPoolExecutor is used
rather than asyncio (the whole call chain -- capture_snapshot, build_report, the Django ORM
writes inside _update_interface_baseline -- is synchronous throughout; rewriting it async
just to get four threads would be a much larger, riskier change for the same win) or
multiprocessing (four extra Python interpreters and their own Django app registries for what
is fundamentally an I/O wait, not real parallel computation -- ThreadPoolExecutor's threads
share this one process's already-loaded Django setup for free).

Each of the four is wrapped in its OWN try/except inside _build_one() below, run in its own
thread, with its own django.db.connections.close_all() cleanup once done (Django hands each
NEW thread its own lazily-created DB connection -- closing it explicitly when the thread's
one job is finished avoids leaking an idle connection for the rest of this process's life,
the standard practice for ORM work done outside the normal request/response cycle). A crash,
timeout, or Prometheus outage in ONE report can never take down the other three, or the
e-mail that bundles whichever of them succeeded -- exactly the isolation "legitimate source
of failure" was asking for. If any of the four failed, this command still sends the bundle
for the ones that DIDN'T, but exits non-zero (a real CommandError) so folder_exporter's own
job log -- and whoever reads it -- sees a clear, unmissable failure signal rather than a
quiet partial success indistinguishable from a full one.

No CLI arguments (folder_exporter.yml's job runner launches `command:` as one literal process
path with no argv splitting -- see run_network_reports.bat's own header, and
run_active_directory_report.bat's for the same lesson).
"""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.core.management.base import BaseCommand, CommandError
from django.db import connections
from django.utils import timezone

from reports import network
from reports.automated_reports_mail import automated_report_recipients
from reports.models import ReportSubmission

REPORT_TYPE = "network_reports"

# One entry per Networks Report picker (see network.py's own "four report-picker estates"
# comment above core_switches_device_keys) -- report_kind matches each one's own
# report_content["kind"]/CATALOGUE skip_for value exactly, so History/the Executive Dashboard
# and the catalogue-filtering both agree with what the interactive picker would have produced.
JOBS = [
    {"report_kind": "core_switches", "title": "Core Switches Report",
     "device_keys": network.core_switches_device_keys,
     "filename_fn": network.core_switches_report_filename},
    {"report_kind": "routers", "title": "Routers Report",
     "device_keys": network.routers_device_keys,
     "filename_fn": network.routers_report_filename},
    {"report_kind": "wireless_controller", "title": "Wireless Controller Report",
     "device_keys": network.wireless_controller_device_keys,
     "filename_fn": network.wireless_controller_report_filename},
    {"report_kind": "access_switches", "title": "Access Switches Report",
     "device_keys": network.access_switches_device_keys,
     "filename_fn": network.access_switches_report_filename},
]

THEME = "dark"          # unattended: no user profile to read a preference from
AUTHOR = "Automated"    # unattended: no request.user


def _build_one(job: dict) -> dict:
    """Capture + build ONE report, fully isolated -- runs in its own thread (see this
    module's own docstring). Returns a plain dict, never raises: every failure this function
    can hit (Prometheus down, a bad build, anything) is caught here and reported back as
    ok=False rather than propagated, so ThreadPoolExecutor's own future.result() in handle()
    below can never itself raise from a report's own failure."""
    report_kind, title = job["report_kind"], job["title"]
    try:
        keys = job["device_keys"]()
        token = uuid.uuid4().hex
        snapshot = network.capture_snapshot(token, only=keys, mode="switches_routers",
                                            report_kind=report_kind)
        data = network.build_report(snapshot, theme=THEME, author=AUTHOR,
                                    annotations={}, summary_comment="", title=title)
        filename = job["filename_fn"](THEME, timezone.localtime())
        return {"ok": True, "report_kind": report_kind, "title": title,
                "snapshot": snapshot, "data": data, "filename": filename}
    except network.NetworkUnavailable as exc:
        return {"ok": False, "report_kind": report_kind, "title": title,
                "error": f"Prometheus unavailable: {exc}"}
    except Exception as exc:   # noqa: BLE001 -- ANY failure here must stay isolated to
        # this one report; see the module docstring on why this is deliberately broad.
        return {"ok": False, "report_kind": report_kind, "title": title, "error": str(exc)}
    finally:
        # This thread's own lazily-created DB connection (capture_snapshot's interface
        # baseline writes, ReportSubmission is created by the caller instead -- see
        # handle() below) is done with for good; close it rather than leaving it idle for
        # the rest of this process's short life (see module docstring).
        connections.close_all()


class Command(BaseCommand):
    help = ("Generate all four Networks Report pickers (Core Switches, Routers, Wireless "
           "Controller, Access Switches) headlessly and CONCURRENTLY, store each as its own "
           "ReportSubmission, and e-mail them together as one bundle to every active "
           "Reporting group covering 'network_reports'.")

    def handle(self, *args, **options):
        results = []
        with ThreadPoolExecutor(max_workers=len(JOBS), thread_name_prefix="network_report") as pool:
            futures = {pool.submit(_build_one, job): job for job in JOBS}
            for future in as_completed(futures):
                job = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:   # noqa: BLE001 -- defense in depth: _build_one
                    # itself never raises (see its own docstring), but a future can still
                    # surface a thread-level failure (e.g. the thread was killed) that never
                    # reached its own try/except.
                    results.append({"ok": False, "report_kind": job["report_kind"],
                                    "title": job["title"], "error": f"thread failure: {exc}"})

        # Stable order (JOBS' own, not completion order -- threads finish whenever Prometheus
        # answers) for the e-mail bundle and the log below, so a rerun with identical data
        # produces an identical-looking report, not one that shuffles with timing noise.
        order = {job["report_kind"]: i for i, job in enumerate(JOBS)}
        results.sort(key=lambda r: order[r["report_kind"]])

        succeeded = [r for r in results if r["ok"]]
        failed = [r for r in results if not r["ok"]]

        for r in failed:
            self.stderr.write(self.style.WARNING(f"{r['title']}: skipped ({r['error']})"))

        recipients = automated_report_recipients(REPORT_TYPE)
        delivery = "email" if recipients else "download"

        for r in succeeded:
            snapshot = r["snapshot"]
            report_content = {
                "kind": r["report_kind"],
                "overview": snapshot.overview,
                "systems": [{
                    "name": s.name, "hosts": s.hosts,
                    "flags": [{"key": f.key, "text": f.text, "band": f.band,
                              "category": f.category, "answer": ""} for f in s.flags],
                    "comment": "",
                } for s in snapshot.systems],
            }
            submission = ReportSubmission.objects.create(
                generated_by=None, author=AUTHOR, theme=THEME, delivery=delivery,
                recipients=", ".join(recipients), prom_url=snapshot.prom_url,
                systems_count=len(snapshot.systems),
                hosts_count=sum(s.hosts for s in snapshot.systems),
                immediate_count=snapshot.immediate_count, watch_count=snapshot.watch_count,
                summary_comment="", annotations={},
                report_content=report_content, filename=r["filename"],
            )
            self.stdout.write(self.style.SUCCESS(
                f"Generated {r['filename']} (id={submission.pk}) "
                f"systems={submission.systems_count} hosts={submission.hosts_count}"))

        if not succeeded:
            self.stderr.write(self.style.ERROR("All four reports failed -- nothing to store or e-mail."))
            raise CommandError(f"{len(failed)}/{len(JOBS)} network reports failed this run.")

        if not recipients:
            self.stdout.write("No active Reporting group covers 'network_reports' -- "
                              "stored only, not e-mailed.")
        else:
            try:
                subject = network.email_network_reports_bundle(succeeded, recipients=recipients,
                                                                author=AUTHOR)
            except Exception as exc:   # noqa: BLE001 -- a failed send must not look like a
                # failed generation; the CommandError below (if any) is about GENERATION
                # failures, not this.
                self.stderr.write(self.style.WARNING(f"Generated but NOT e-mailed: {exc}"))
            else:
                self.stdout.write(self.style.SUCCESS(
                    f"E-mailed {len(succeeded)}/{len(JOBS)} report(s) to "
                    f"{len(recipients)} recipient(s): {subject}"))

        if failed:
            raise CommandError(
                f"{len(failed)}/{len(JOBS)} network reports failed this run: "
                + ", ".join(f"{r['title']} ({r['error']})" for r in failed))
