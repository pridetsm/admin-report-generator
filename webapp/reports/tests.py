"""End-to-end smoke tests for the Report Builder.

The report engine's capture() needs a live Prometheus, so we patch capture_snapshot with a
synthetic snapshot built from generate_report's own dataclasses. Everything else — auth,
templates, the generate/download path, and the audit row — is exercised for real.
"""
import contextlib
import datetime
import io
import json
import pathlib
import re
import shutil
import tempfile
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.html import escape
from unittest import mock

import generate_report as gr
import yaml

from . import folders, network
from . import keycloak as kc
from .directory import AuthConfig, HttpAuthBackend, search_directory
from .models import (PrometheusConfigRevision, ReportSubmission, RoleRequest,
                     RoleScope, SystemConfig)
from .roles import ROLE_NAMES, ROLE_PAGES, is_network_admin, role_icon
from .services import FlagVM, Snapshot, SystemVM, build_overview, list_systems


def _snapshot_from(systems, store, cfg, only, token):
    """Build a Snapshot from engine systems, honouring an `only` set of names (mirrors
    capture_snapshot's scoping) so the two-step select->capture flow is exercised for real."""
    if only is not None:
        systems = [s for s in systems if s.name in only]
    svms = [SystemVM(s.name, len(s.components),
                     [FlagVM(f.key, f.text, f.band, f.category)
                      for f in gr.flagged_for_system(store, s, cfg)])
            for s in systems]
    return Snapshot(
        token=token, captured_at=datetime.datetime(2026, 7, 17, 9, 0), prom_url=cfg.prom,
        systems=svms, overview=build_overview(store, systems, cfg),
        _store=store, _systems=systems, _cfg=cfg,
    )


def _synthetic_snapshot(token: str, only=None) -> Snapshot:
    cfg = gr.Config()
    sysm = gr.System("Efin", [gr.Component("DB", "10.0.201.3:9182")])
    store = gr.Store(
        disk={"10.0.201.3:9182": {"C:": {"used": 95.0, "free": 5.0, "size": 100.0}}},
        ram={"10.0.201.3:9182": 82.0}, cpu={"10.0.201.3:9182": 93.0},
        cob=None, swift=1.0,
        services={"Efin": [("OracleSvc", False, "system", "Efin DB")]},
        up={"10.0.201.3:9182": 1.0},
        links={"https://x.rbz.co.zw": {"up": True, "cert_days": 200.0}},
        backups={},
    )
    return _snapshot_from([sysm], store, cfg, only, token)


def _two_system_snapshot(token: str, only=None) -> Snapshot:
    """Two systems (Efin flagged, Core healthy) so subset selection has something to exclude."""
    cfg = gr.Config()
    efin = gr.System("Efin", [gr.Component("DB", "10.0.201.3:9182")])
    core = gr.System("Core", [gr.Component("APP", "10.0.202.4:9182")])
    store = gr.Store(
        disk={"10.0.201.3:9182": {"C:": {"used": 95.0, "free": 5.0, "size": 100.0}},
              "10.0.202.4:9182": {"C:": {"used": 20.0, "free": 80.0, "size": 100.0}}},
        ram={"10.0.201.3:9182": 82.0, "10.0.202.4:9182": 30.0},
        cpu={"10.0.201.3:9182": 93.0, "10.0.202.4:9182": 10.0},
        cob=None, swift=1.0,
        services={"Efin": [("OracleSvc", False, "system", "Efin DB")], "Core": []},
        up={"10.0.201.3:9182": 1.0, "10.0.202.4:9182": 1.0},
        links={}, backups={},
    )
    return _snapshot_from([efin, core], store, cfg, only, token)


class ReportBuilderFlow(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("tester", password="pw12345!")
        self.user.groups.add(Group.objects.create(name="Report Users"))   # give them a role

    def _open_report(self, systems):
        """Drive the two-step flow: select systems -> capture -> return the report's token.

        `systems` is the include_system value(s) posted from the selection screen.
        """
        resp = self.client.post(reverse("report"), {"include_system": systems}, follow=True)
        m = re.search(r'name="token" value="(\w+)"', resp.content.decode())
        return m.group(1) if m else None

    def test_form_requires_login(self):
        resp = self.client.get(reverse("report_form"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/accounts/login/", resp["Location"])

    def test_landing_is_selection_and_does_not_capture(self):
        """The landing page lists systems from topology WITHOUT any Prometheus capture."""
        self.client.login(username="tester", password="pw12345!")
        with mock.patch("reports.views.capture_snapshot") as cap:
            resp = self.client.get(reverse("report_form"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Efin")                 # a real system from prometheus.yml
        self.assertContains(resp, "include_system")       # the selection checkboxes
        cap.assert_not_called()                           # <-- no capture on the landing page

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_report_requires_prior_selection(self, _cap):
        """GET /report/ without having chosen systems bounces back to selection."""
        self.client.login(username="tester", password="pw12345!")
        resp = self.client.get(reverse("report"))
        self.assertRedirects(resp, reverse("report_form"))

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_full_generate_flow(self, _cap):
        # report theme is now a user setting on the profile
        self.user.profile.default_report_theme = "light"
        self.user.profile.save()
        self.client.login(username="tester", password="pw12345!")

        # 1) selection -> capture -> report screen with the flagged system + a token
        token = self._open_report("Efin")
        self.assertIsNotNone(token)

        # 2) generate: answer the first flag "Yes", add a comment (theme comes from the setting)
        resp = self.client.post(reverse("generate"), {
            "token": token, "author": "K. Sindiso",
            "summary_comment": "Incident window snapshot.",
            "fix__0__0": "Yes",
            "comment__0": "DB team engaged.",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp["Content-Type"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.assertGreater(len(resp.content), 5000)          # a real xlsx came back
        self.assertIn("attachment", resp["Content-Disposition"])

        # 3) an audit row was saved with the answers
        sub = ReportSubmission.objects.get()
        self.assertEqual(sub.theme, "light")
        self.assertEqual(sub.author, "K. Sindiso")
        self.assertEqual(sub.generated_by, self.user)
        self.assertEqual(sub.immediate_count, 3)             # disk 95% + cpu 93% + service DOWN
        self.assertEqual(sub.watch_count, 2)                 # RAM 82% + untracked backups (both amber)
        self.assertIn("Efin", sub.annotations)
        self.assertEqual(sub.annotations["Efin"]["comment"], "DB team engaged.")
        self.assertTrue(any(v == "Yes" for v in sub.annotations["Efin"]["flags"].values()))

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    @mock.patch("mail_report.send_email")   # never touch real SMTP in a test
    def test_email_flow(self, mock_send, _cap):
        self.client.login(username="tester", password="pw12345!")
        token = self._open_report("Efin")

        resp = self.client.post(reverse("generate"), {
            "token": token, "theme": "dark", "author": "K. Sindiso",
            "action": "email", "recipients": "ops@rbz.co.zw, dba@rbz.co.zw",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "e-mailed")
        # send_email was called once with our recipients + a real xlsx attachment
        self.assertEqual(mock_send.call_count, 1)
        args = mock_send.call_args.args
        self.assertEqual(args[1], ["ops@rbz.co.zw", "dba@rbz.co.zw"])   # recipients
        self.assertIn("K. Sindiso", args[2])                            # author is in the subject
        self.assertTrue(str(args[5]).endswith(".xlsx"))                 # attachment path

        sub = ReportSubmission.objects.get()
        self.assertEqual(sub.delivery, "email")
        self.assertIn("ops@rbz.co.zw", sub.recipients)

    def test_email_without_recipients_is_rejected(self):
        self.client.login(username="tester", password="pw12345!")
        with mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot):
            token = self._open_report("Efin")
        resp = self.client.post(reverse("generate"), {
            "token": token, "theme": "dark", "action": "email", "recipients": "  ",
        })
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(ReportSubmission.objects.count(), 0)

    def test_expired_snapshot_is_handled(self):
        self.client.login(username="tester", password="pw12345!")
        resp = self.client.post(reverse("generate"), {"token": "deadbeef"})
        self.assertEqual(resp.status_code, 410)
        self.assertContains(resp, "expired", status_code=410)

    def test_report_theme_setting(self):
        self.client.login(username="tester", password="pw12345!")
        self.client.post(reverse("set_report_theme"), {"theme": "light"})
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.default_report_theme, "light")

    def test_report_theme_ajax_returns_json_no_redirect(self):
        # The Settings menu changes the theme via AJAX so the page never reloads
        # (and the admin's captured form entries are preserved).
        self.client.login(username="tester", password="pw12345!")
        resp = self.client.post(reverse("set_report_theme"), {"theme": "light"},
                                HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"ok": True, "theme": "light"})
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.default_report_theme, "light")

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_every_visit_to_the_report_captures_fresh_metrics(self, cap):
        """Landing on the report ALWAYS re-captures — a plain refresh, "Continue that
        report", or any other route in. A report is a statement about now, so a screen that
        quietly served numbers captured minutes ago was the more dangerous default."""
        self.client.login(username="tester", password="pw12345!")
        pat = r'name="token" value="(\w+)"'

        t1 = self._open_report("Efin")
        self.assertEqual(cap.call_count, 1)

        t2 = re.search(pat, self.client.get(reverse("report")).content.decode()).group(1)
        self.assertNotEqual(t1, t2)
        self.assertEqual(cap.call_count, 2)

        t3 = re.search(pat, self.client.get(reverse("report"), {"fresh": "1"}).content.decode()).group(1)
        self.assertNotEqual(t2, t3)
        self.assertEqual(cap.call_count, 3)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_author_autofills_from_profile(self, _cap):
        self.user.first_name = "Pride"; self.user.last_name = "Moyo"; self.user.save()
        self.user.profile.job_title = "Systems Administrator"
        self.user.profile.save()
        self.client.login(username="tester", password="pw12345!")
        token = self._open_report("Efin")
        self.client.post(reverse("generate"), {"token": token})   # no author typed
        sub = ReportSubmission.objects.get()
        self.assertEqual(sub.author, "Pride Moyo, Systems Administrator")

    def test_report_stamps_author_in_every_by_cell(self):
        # Every "By" line in the .xlsx must carry the literal author name (not an Excel
        # formula), so it shows in any viewer — not just Excel-with-recalc.
        import io

        import openpyxl

        from reports.services import build_report
        snap = _synthetic_snapshot("tok")
        data = build_report(snap, theme="dark", author="Jane Doe, DBA",
                            annotations={}, summary_comment="")
        ws = openpyxl.load_workbook(io.BytesIO(data)).active
        by_values = [
            ws.cell(c.row, c.column + 1).value
            for row in ws.iter_rows() for c in row
            if isinstance(c.value, str) and c.value.strip() == "By"
        ]
        self.assertTrue(by_values, "report has no 'By' cells")
        self.assertTrue(all(v == "Jane Doe, DBA" for v in by_values), by_values)

    def test_submission_detail_legacy_row(self):
        """A row saved before report_content existed still renders (falls back to annotations)."""
        self.client.login(username="tester", password="pw12345!")
        sub = ReportSubmission.objects.create(
            generated_by=self.user, author="K. Sindiso", theme="dark", delivery="download",
            systems_count=1, immediate_count=1,
            annotations={"Efin": {"flags": {"efin.db.disk": "Yes"}, "comment": "DB team engaged."}},
        )
        resp = self.client.get(reverse("submission_detail", args=[sub.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Efin")
        self.assertContains(resp, "DB team engaged.")

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_generate_stores_content_and_detail_replays_it(self, _cap):
        self.client.login(username="tester", password="pw12345!")
        token = self._open_report("Efin")
        self.client.post(reverse("generate"), {
            "token": token, "author": "K. Sindiso",
            "summary_comment": "Incident window snapshot.",
            "fix__0__0": "Yes", "comment__0": "DB team engaged.",
        })
        sub = ReportSubmission.objects.get()
        # the generated content was frozen onto the row
        self.assertIn("systems", sub.report_content)
        self.assertIn("overview", sub.report_content)
        self.assertEqual(sub.report_content["systems"][0]["name"], "Efin")
        # and the detail page replays it (overview + the admin's comment)
        resp = self.client.get(reverse("submission_detail", args=[sub.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Overview (generated)")
        self.assertContains(resp, "Incident window snapshot.")
        self.assertContains(resp, "DB team engaged.")

    def test_back_nav_walks_hierarchy(self):
        self.client.login(username="tester", password="pw12345!")
        # History's parent is the Dashboard (home)
        r = self.client.get(reverse("history"))
        self.assertEqual(r.context["back_url"], reverse("report_form"))
        self.assertEqual(r.context["back_label"], "System Picker")
        # A report detail's parent is History (not home) — one level up the tree
        sub = ReportSubmission.objects.create(generated_by=self.user, theme="dark")
        r = self.client.get(reverse("submission_detail", args=[sub.pk]))
        self.assertEqual(r.context["back_url"], reverse("history"))
        self.assertEqual(r.context["back_label"], "History")

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_the_dashboard_offers_the_open_report_back(self, _cap):
        """The System Analyses Dashboard IS the picker, so arriving mid-report left only one
        way forward — choose systems again, which clears the snapshot token and discards
        answers already typed. It now surfaces the open report instead.

        Landing here must not itself discard anything: that only happens on a deliberate
        re-selection.
        """
        self.client.login(username="tester", password="pw12345!")
        clean = self.client.get(reverse("report_form")).content.decode()
        self.assertNotIn("You have a report open", clean)

        self._open_report("Efin")
        r = self.client.get(reverse("report_form"))
        self.assertContains(r, "You have a report open")
        self.assertContains(r, "Continue that report")
        self.assertContains(r, "Efin")
        # merely visiting kept the report intact
        self.assertEqual(self.client.session.get("report_systems"), ["Efin"])
        self.assertTrue(self.client.session.get("snapshot_token"))
        self.assertEqual(self.client.get(reverse("report")).status_code, 200)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_the_systems_screen_keeps_its_own_nouns(self, _cap):
        """The two flows share one template, so a change made for one must not rename the
        other's screen."""
        self.client.login(username="tester", password="pw12345!")
        self._open_report("Efin")
        body = self.client.get(reverse("report")).content.decode()
        self.assertIn("System Analyses Dashboard", body)
        self.assertIn("system selected", body)
        self.assertIn("Systems needing attention", body)
        self.assertIn('href="%s" title="Go back to system selection"' % reverse("report_form"), body)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_back_returns_to_an_open_report_not_to_the_picker(self, _cap):
        """Home is the system PICKER. Walking the plain tree took an admin who stepped into
        History mid-report out to a screen whose only offer was to start again — and picking
        systems there clears the snapshot token, discarding answers already typed.

        While a report is open, Back retraces what they were DOING rather than how they
        began it. With no report open the tree is unchanged.
        """
        self.client.login(username="tester", password="pw12345!")
        # nothing open yet: History goes back to the Dashboard as before
        r = self.client.get(reverse("history"))
        self.assertEqual(r.context["back_url"], reverse("report_form"))

        self._open_report("Efin")                       # a report is now open
        for page in ("history", "connect"):
            r = self.client.get(reverse(page))
            self.assertEqual(r.context["back_url"], reverse("report"),
                             f"Back from {page} should return to the open report")
            self.assertEqual(r.context["back_label"], "Report")

        # the deeper tree is untouched — a child still walks to its own parent, not to
        # the open report, because its parent is not the home screen
        sub = ReportSubmission.objects.create(generated_by=self.user, theme="dark")
        r = self.client.get(reverse("submission_detail", args=[sub.pk]))
        self.assertEqual(r.context["back_url"], reverse("history"))

    @mock.patch("reports.views.capture_snapshot", side_effect=_two_system_snapshot)
    def test_selection_scopes_capture_and_report(self, cap):
        """Selecting a subset scopes the CAPTURE (only=names) and the audit row + content."""
        self.client.login(username="tester", password="pw12345!")
        # include ONLY Efin (Core unticked) -> capture is called with only={'Efin'}
        token = self._open_report("Efin")
        self.assertEqual(cap.call_args.kwargs.get("only"), {"Efin"})
        self.client.post(reverse("generate"), {
            "token": token, "author": "K. Sindiso",
            "fix__0__0": "Yes", "comment__0": "DB team engaged.",
        })
        sub = ReportSubmission.objects.get()
        self.assertEqual(sub.systems_count, 1)                       # not 2
        names = [s["name"] for s in sub.report_content["systems"]]
        self.assertEqual(names, ["Efin"])                           # Core excluded
        self.assertNotIn("Core", sub.annotations)
        # overview reflects the subset: one system, not two
        self.assertEqual(sub.report_content["overview"]["glance"][0]["value"], 1)

    @mock.patch("reports.views.capture_snapshot", side_effect=_two_system_snapshot)
    def test_selecting_all_systems_reports_all(self, _cap):
        self.client.login(username="tester", password="pw12345!")
        token = self._open_report(["Efin", "Core"])
        self.client.post(reverse("generate"), {"token": token, "author": "K. Sindiso"})
        sub = ReportSubmission.objects.get()
        self.assertEqual(sub.systems_count, 2)
        self.assertEqual({s["name"] for s in sub.report_content["systems"]}, {"Efin", "Core"})

    def test_report_post_without_selection_returns_to_picker_without_capturing(self):
        """Submitting the selection screen with nothing ticked never captures."""
        self.client.login(username="tester", password="pw12345!")
        with mock.patch("reports.views.capture_snapshot") as cap:
            resp = self.client.post(reverse("report"), {}, follow=True)
        self.assertRedirects(resp, reverse("report_form"))
        cap.assert_not_called()
        self.assertEqual(ReportSubmission.objects.count(), 0)

    @mock.patch("reports.views.capture_snapshot", side_effect=_two_system_snapshot)
    def test_report_with_unknown_selection_returns_to_picker(self, _cap):
        """A selection that matches no topology system captures empty -> back to the picker."""
        self.client.login(username="tester", password="pw12345!")
        resp = self.client.post(reverse("report"), {"include_system": "Nonexistent"}, follow=True)
        self.assertRedirects(resp, reverse("report_form"))
        self.assertEqual(ReportSubmission.objects.count(), 0)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_recently_reported_badge_appears(self, _cap):
        """A system reported minutes ago is flagged on the selection screen (no capture needed)."""
        self.client.login(username="tester", password="pw12345!")
        ReportSubmission.objects.create(
            generated_by=self.user, theme="dark", delivery="download", systems_count=1,
            report_content={"systems": [{"name": "Efin"}]},
        )
        resp = self.client.get(reverse("report_form"))
        self.assertEqual(resp.status_code, 200)
        rep = {s["name"]: s["reported"] for s in resp.context["select_systems"]}
        self.assertIsNotNone(rep["Efin"])                           # badge data present
        self.assertEqual(rep["Efin"]["by"], "tester")

    def test_scoped_capture_drops_other_systems_links(self):
        """Web/cert KPIs must reflect only the selected systems — links captured globally by the
        engine are dropped when they don't belong to a selected system."""
        from reports.services import _scope_links_to_systems
        efin = gr.System("Efin", [gr.Component("DB", "10.0.201.3:9182")])
        store = gr.Store(
            disk={}, ram={}, cpu={}, cob=None, swift=None, services={}, up={},
            links={
                "https://efin.rbz.co.zw": {"up": True, "cert_days": 200.0},
                "http://cms.rbz.co.zw": {"up": True, "cert_days": None},
            },
            backups={},
        )
        _scope_links_to_systems(store, [efin])          # scope to Efin only
        self.assertEqual(list(store.links), ["https://efin.rbz.co.zw"])   # CMS link dropped
        # and the overview built from the scoped store counts only Efin's (1 https, 0 http)
        ov = build_overview(store, [efin], gr.Config())
        web = [w for w in ov["watch"] if w["label"] == "Web encryption"][0]
        self.assertEqual(web["value"], "1 | 1")   # https | total, not https | http

    def test_ldap_down_banner_lists_dependents(self):
        """When the LDAP probe reports down, the overview gets a red, top banner naming the
        dependent systems; up / unmonitored produce no LDAP banner."""
        gcms = gr.System("GCMS", [gr.Component("App/DB", "10.100.247.23:9182")])

        def store(ldap):
            return gr.Store(disk={}, ram={}, cpu={}, cob=1200.0, swift=1.0, services={"GCMS": []},
                            up={"10.100.247.23:9182": 1.0}, links={}, backups={}, ldap_up=ldap)

        cfg = gr.Config()
        down = build_overview(store(False), [gcms], cfg)["banners"]
        # LDAP down means nobody can sign in — an outage already underway, so IMMINENT,
        # which bands it "critical" rather than plain red.
        self.assertTrue(down and "LDAP" in down[0]["head"])          # first = top priority
        self.assertEqual(down[0]["severity"], "imminent")
        self.assertEqual(down[0]["band"], "critical")
        # the dependents are a table row now, not a middot-joined sentence
        self.assertIn("GCMS", " ".join(r["values"] for r in down[0]["rows"]))
        for state in (True, None):   # up / not monitored -> no LDAP banner
            self.assertFalse(any("LDAP" in b["head"] for b in build_overview(store(state), [gcms], cfg)["banners"]))

    def test_mark_notifications_seen(self):
        self.client.login(username="tester", password="pw12345!")
        resp = self.client.post(reverse("mark_notifications_seen"))
        self.assertEqual(resp.status_code, 200)
        self.user.profile.refresh_from_db()
        self.assertIsNotNone(self.user.profile.notifications_seen_at)


class HttpAuthDefaults(TestCase):
    """Org auth is opt-in: while not configured it must no-op so local login still works."""

    @mock.patch("reports.directory.load_auth_config", return_value=AuthConfig(enabled=False))
    def test_backend_returns_none_when_not_ready(self, _cfg):
        self.assertIsNone(HttpAuthBackend().authenticate(None, username="x", password="y"))

    def test_search_is_always_empty(self):
        self.assertEqual(search_directory("pmoyo"), [])

    def test_search_endpoint(self):
        u = get_user_model().objects.create_user("t2", password="pw12345!")
        u.groups.add(Group.objects.create(name="R"))
        self.client.login(username="t2", password="pw12345!")
        resp = self.client.get(reverse("recipient_search"), {"q": "pmoyo"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"results": []})

    @mock.patch("reports.directory.load_auth_config",
                return_value=AuthConfig(enabled=True, url="https://vault:7272/api/auth",
                                        success_field="username", email_field="email",
                                        first_name_field="firstName", last_name_field="lastName",
                                        department_field="departmentName", dn_field="distinguishedName"))
    def test_success_provisions_user_and_profile(self, _cfg):
        # mirrors the real /api/auth success payload
        payload = {"username": "jo", "firstName": "Jo", "lastName": "Doe", "email": "jo@x",
                   "departmentName": "ICT", "distinguishedName": "CN=jo,OU=ICT,DC=x",
                   "enabled": True, "accountNonLocked": True, "credentialsNonExpired": True}

        class FakeResp:
            status = 200
            def read(self): return json.dumps(payload).encode()
            def __enter__(self): return self
            def __exit__(self, *a): return False
        with mock.patch("urllib.request.urlopen", return_value=FakeResp()):
            user = HttpAuthBackend().authenticate(None, username="jo", password="pw")
        self.assertIsNotNone(user)
        self.assertEqual(user.email, "jo@x")
        self.assertEqual(user.first_name, "Jo")
        self.assertFalse(user.is_staff)            # ordinary user
        # extended profile populated from the directory response
        self.assertEqual(user.profile.department, "ICT")
        self.assertEqual(user.profile.distinguished_name, "CN=jo,OU=ICT,DC=x")
        self.assertEqual(user.profile.source, "ldap")

    @mock.patch("reports.directory.load_auth_config",
                return_value=AuthConfig(enabled=True, url="https://vault:7272/api/auth",
                                        success_field="username"))
    def test_disabled_account_is_rejected(self, _cfg):
        payload = {"username": "jo", "enabled": False}      # 200 but account disabled

        class FakeResp:
            status = 200
            def read(self): return json.dumps(payload).encode()
            def __enter__(self): return self
            def __exit__(self, *a): return False
        with mock.patch("urllib.request.urlopen", return_value=FakeResp()):
            self.assertIsNone(HttpAuthBackend().authenticate(None, username="jo", password="pw"))

    @mock.patch("reports.directory.load_auth_config",
                return_value=AuthConfig(enabled=True, url="https://vault:7272/"))
    def test_bad_credentials_return_none(self, _cfg):
        import urllib.error
        err = urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b"{}"))
        with mock.patch("urllib.request.urlopen", side_effect=err):
            self.assertIsNone(HttpAuthBackend().authenticate(None, username="jo", password="bad"))


class RoleGate(TestCase):
    """A signed-in user with no role is bounced to the 'no role' page until one is granted."""

    def test_user_without_role_is_redirected(self):
        get_user_model().objects.create_user("norole", password="pw12345!")
        self.client.login(username="norole", password="pw12345!")
        resp = self.client.get(reverse("report_form"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("no_role"), resp["Location"])

    def test_no_role_page_renders(self):
        get_user_model().objects.create_user("norole2", password="pw12345!")
        self.client.login(username="norole2", password="pw12345!")
        resp = self.client.get(reverse("no_role"))
        self.assertContains(resp, "No role assigned")

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_user_with_a_role_gets_in(self, _cap):
        u = get_user_model().objects.create_user("hasrole", password="pw12345!")
        u.groups.add(Group.objects.create(name="Reporters"))
        self.client.login(username="hasrole", password="pw12345!")
        self.assertEqual(self.client.get(reverse("report_form")).status_code, 200)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_superuser_bypasses_gate(self, _cap):
        get_user_model().objects.create_superuser("root", "r@x.com", "pw12345!")
        self.client.login(username="root", password="pw12345!")
        self.assertEqual(self.client.get(reverse("report_form")).status_code, 200)


class RoleWorkflow(TestCase):
    """Request roles from the no-role page; Administrators approve/reject and manage roles."""

    def _admin(self, username="adm"):
        u = get_user_model().objects.create_user(username, password="pw12345!")
        u.groups.add(Group.objects.get(name="Administrator"))
        return u

    def test_request_creates_pending(self):
        u = get_user_model().objects.create_user("req1", password="pw12345!")
        self.client.login(username="req1", password="pw12345!")
        resp = self.client.post(reverse("no_role"), {"roles": ["System Admin", "Network Admin"]})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(RoleRequest.objects.filter(user=u, status="pending").count(), 2)

    def test_console_requires_administrator(self):
        u = get_user_model().objects.create_user("plain", password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))    # a role, but not Administrator
        self.client.login(username="plain", password="pw12345!")
        self.assertEqual(self.client.get(reverse("roles_console")).status_code, 302)

    def test_administrator_approves_request_and_grants_role(self):
        self._admin()
        requester = get_user_model().objects.create_user("req2", password="pw12345!")
        rr = RoleRequest.objects.create(user=requester, role="Network Admin")
        self.client.login(username="adm", password="pw12345!")
        self.client.post(reverse("roles_console"),
                         {"action": "decide", "request_id": rr.id, "decision": "approve"})
        rr.refresh_from_db()
        self.assertEqual(rr.status, "approved")
        self.assertTrue(requester.groups.filter(name="Network Admin").exists())

    def test_administrator_sets_roles_directly(self):
        self._admin("adm2")
        target = get_user_model().objects.create_user("tgt", password="pw12345!")
        self.client.login(username="adm2", password="pw12345!")
        self.client.post(reverse("roles_console"),
                         {"action": "set_roles", "user_id": target.id,
                          "roles": ["System Admin", "Gov Systems Admin"]})
        self.assertEqual(set(target.groups.values_list("name", flat=True)),
                         {"System Admin", "Gov Systems Admin"})


class ProfileTests(TestCase):
    """Every user gets a profile; profiles work without an e-mail; fields are validated."""

    def _user_with_role(self, name):
        u = get_user_model().objects.create_user(name, password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))
        return u

    def test_profile_auto_created(self):
        u = get_user_model().objects.create_user("p1", password="pw12345!")
        self.assertTrue(hasattr(u, "profile"))
        self.assertEqual(u.profile.source, "manual")

    def test_profile_saves_without_email(self):
        u = self._user_with_role("p2")
        self.client.login(username="p2", password="pw12345!")
        resp = self.client.post(reverse("profile"), {
            "first_name": "Pride", "last_name": "Moyo", "email": "",   # no e-mail
            "employee_id": "E123", "job_title": "Engineer", "department": "ICT",
            "office_location": "HQ", "phone": "", "mobile": "",
            "default_report_theme": "light", "page_theme": "system",
        })
        self.assertEqual(resp.status_code, 302)
        u.refresh_from_db()
        self.assertEqual(u.email, "")                       # e-mail stays optional
        self.assertEqual(u.first_name, "Pride")
        self.assertEqual(u.profile.department, "ICT")
        self.assertEqual(u.profile.default_report_theme, "light")

    def test_invalid_phone_rejected(self):
        self._user_with_role("p3")
        self.client.login(username="p3", password="pw12345!")
        resp = self.client.post(reverse("profile"), {
            "first_name": "", "last_name": "", "email": "",
            "phone": "not a phone!!!", "mobile": "", "employee_id": "", "job_title": "",
            "department": "", "office_location": "", "default_report_theme": "dark", "page_theme": "system",
        })
        self.assertEqual(resp.status_code, 200)             # re-renders with the error
        self.assertContains(resp, "valid phone")


class SystemSettingsTests(TestCase):
    """Administrator can repoint the Prometheus/Grafana the dashboard fetches from."""

    def test_settings_requires_administrator(self):
        u = get_user_model().objects.create_user("nonadmin", password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))    # a role, but not Administrator
        self.client.login(username="nonadmin", password="pw12345!")
        self.assertEqual(self.client.get(reverse("system_settings")).status_code, 302)

    def test_administrator_saves_prometheus_url(self):
        a = get_user_model().objects.create_user("adm3", password="pw12345!")
        a.groups.add(Group.objects.get(name="Administrator"))
        self.client.login(username="adm3", password="pw12345!")
        resp = self.client.post(reverse("system_settings"),
                                {"prometheus_url": "http://new:9090", "grafana_url": ""})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(SystemConfig.get().prometheus_url, "http://new:9090")

    @mock.patch("reports.services.build_overview", return_value={})
    @mock.patch("reports.services.gr")
    def test_capture_uses_admin_prometheus_url(self, grm, _ov):
        sc = SystemConfig.get()
        sc.prometheus_url = "http://custom:9090"
        sc.save()
        cfg = type("Cfg", (), {"prom": "http://config:9090", "grafana": "g",
                               "prometheus_yml": "y", "http_timeout": 5,
                               "verify_tls": True})()
        grm.load_config.return_value = cfg
        grm.load_topology.return_value = []
        grm.Prometheus.return_value = mock.MagicMock()
        grm.capture.return_value = mock.MagicMock(services={})
        from .services import capture_snapshot
        snap = capture_snapshot("tok")
        # the admin's URL override wins, and the TLS setting rides along with it
        grm.Prometheus.assert_called_once_with("http://custom:9090", 5, True)
        self.assertEqual(snap.prom_url, "http://custom:9090")


class KeycloakRoleSync(TestCase):
    """Keycloak is the role store; Django groups mirror it. Disabled -> local groups untouched."""

    def test_disabled_is_noop(self):
        u = get_user_model().objects.create_user("k1", password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))
        kc.sync_user_roles(u)                                   # [keycloak] enabled=false -> no-op
        self.assertTrue(u.groups.filter(name="System Admin").exists())

    @mock.patch("reports.keycloak._api")
    @mock.patch("reports.keycloak._user_id", return_value="uid-1")
    @mock.patch("reports.keycloak._token", return_value="tok")
    @mock.patch("reports.keycloak.load_config",
                return_value=kc.KeycloakConfig(enabled=True, base_url="https://kc", realm="r",
                                               client_id="c", client_secret="s"))
    def test_sync_mirrors_keycloak_roles(self, _cfg, _tok, _uid, api):
        api.return_value = [{"name": "Administrator"}, {"name": "Network Admin"},
                            {"name": "offline_access"}]   # last one is not in our catalogue
        u = get_user_model().objects.create_user("k2", password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))   # stale local role, should be dropped
        kc.sync_user_roles(u)
        self.assertEqual(set(u.groups.values_list("name", flat=True)),
                         {"Administrator", "Network Admin"})


# ============================================================================ #
#  FOLDER WATCH
# ============================================================================ #
def _series(metric, value, **labels):
    labels["__name__"] = metric
    return {"labels": labels, "value": float(value)}


def _folder_series(*, name="PAYNET.IN", instance="10.0.212.3:9847", now=None, files=1,
                   oldest_ago=20, newest_ago=None, exists=1, folder_up=1, scanned_ago=30,
                   size=2048, timed_out=0, over_amber=0, over_red=0, added_ago=45,
                   job="folder_exporter", source=None, via=None, destination=None,
                   fmt=None):
    """One folder's worth of exposition as folder_exporter publishes it.

    Note what this can express that the old textfile exposition could not: a file COUNT
    independent of the ages, and absolute TIMESTAMPS rather than ages frozen at run time.
    `files=0` is a genuinely drained folder — it no longer has to be inferred from a
    zero age.

    over_amber/over_red drive the age histogram, whose buckets sit at the module's limits.
    """
    now = time.time() if now is None else now
    base = {"target": name, "instance": instance, "job": job, "display": "Temenos/T24 App"}
    # The message-path labels ride on every series, exactly as folder_exporter emits them.
    for k, v in (("source", source), ("via", via), ("destination", destination),
                 ("format", fmt)):
        if v:
            base[k] = v
    out = [
        _series("folder_files", files, **base),
        _series("folder_exists", exists, **base),
        _series("folder_up", folder_up, **base),
        _series("folder_size_bytes", size, **base),
        _series("folder_last_scan_timestamp_seconds", now - scanned_ago, **base),
        _series("folder_scan_timed_out", timed_out, **base),
        _series("folder_files_added_total", 12, **base),
        _series("folder_files_removed_total", 11, **base),
    ]
    if files > 0 and oldest_ago is not None:
        out.append(_series("folder_oldest_file_timestamp_seconds", now - oldest_ago, **base))
        newest = oldest_ago if newest_ago is None else newest_ago
        out.append(_series("folder_newest_file_timestamp_seconds", now - newest, **base))
    if added_ago is not None:
        out.append(_series("folder_last_file_added_timestamp_seconds", now - added_ago, **base))

    # Cumulative histogram: bucket(le) counts files at or under that age.
    out.append(_series("folder_file_age_seconds_count", files, **base))
    out.append(_series("folder_file_age_seconds_bucket", files - over_amber,
                       le=str(folders.AMBER_SECONDS), **base))
    out.append(_series("folder_file_age_seconds_bucket", files - over_red,
                       le=str(folders.RED_SECONDS), **base))
    return out


def _exporter_up(*, instance="10.0.212.3:9847", value=1, job="folder_exporter"):
    """`up` for the exporter itself — the proof Prometheus is still reaching it."""
    return [_series("up", value, instance=instance, job=job)]


class FolderWatchVerdict(TestCase):
    """The state machine on its own — it decides every colour on the screen."""

    def _v(self, **kw):
        args = dict(age=60, files=1, readable=True, stale=False, scan_ok=True,
                    amber_seconds=900, red_seconds=1800)
        args.update(kw)
        return folders.verdict(**args)

    def test_bands(self):
        """Judged on the live age against this folder's own two limits."""
        self.assertEqual(self._v(age=60), "green")
        self.assertEqual(self._v(age=899), "green")
        self.assertEqual(self._v(age=900), "amber")     # inclusive at the boundary
        self.assertEqual(self._v(age=1799), "amber")
        self.assertEqual(self._v(age=1800), "red")
        self.assertEqual(self._v(age=99999), "red")

    def test_the_configured_limits_are_one_and_two_minutes(self):
        """These are payment queues: a message that has sat two minutes has missed its
        window. Pinned because the figure is easy to loosen by accident, and because the
        histogram buckets in folder_exporter.yml have to carry matching boundaries for the
        "N past the limit" counts to remain answerable."""
        self.assertEqual(folders.AMBER_SECONDS, 60)
        self.assertEqual(folders.RED_SECONDS, 120)
        v = folders.verdict(age=119, files=1, readable=True, stale=False)
        self.assertEqual(v, "amber")
        v = folders.verdict(age=120, files=1, readable=True, stale=False)
        self.assertEqual(v, "red")

    def test_per_folder_limits_are_honoured(self):
        """An outbound folder that legitimately holds files needs its own limits, not a
        loosening of everybody's."""
        self.assertEqual(self._v(age=2000, amber_seconds=3600, red_seconds=7200), "green")
        self.assertEqual(self._v(age=4000, amber_seconds=3600, red_seconds=7200), "amber")

    def test_empty_folder_is_idle_not_green(self):
        """A drained folder is the healthy steady state, but it is NOT the same as
        'files present and all fresh' — the grid distinguishes the two."""
        self.assertEqual(self._v(files=0), "idle")

    def test_a_drained_folder_is_idle_even_with_a_stale_oldest_timestamp(self):
        """The count decides emptiness now, not the age. Under the old exposition this had
        to be inferred from a zero age, so a folder emptied between runs could still be
        judged on the age of a file that was no longer there."""
        self.assertEqual(self._v(files=0, age=99999), "idle")

    def test_unreadable_stale_and_failed_scans_are_unknown_never_green(self):
        """The one thing this screen must never do is show green for a folder nobody is
        looking at: Prometheus keeps serving the last values it saw."""
        self.assertEqual(self._v(readable=False), "unknown")
        self.assertEqual(self._v(stale=True), "unknown")
        self.assertEqual(self._v(scan_ok=False), "unknown")
        self.assertEqual(self._v(files=0, stale=True), "unknown")
        # a breach we cannot vouch for is unknown, NOT red — reporting a fault from a dead
        # exporter is as wrong as reporting health from one
        self.assertEqual(self._v(age=99999, stale=True), "unknown")


class FolderWatchSnapshot(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("fw", password="pw12345!")
        self.user.groups.add(Group.objects.get(name="System Admin"))
        self.client.login(username="fw", password="pw12345!")

    def _patch(self, series, processed=None):
        """`processed` maps folder name -> files that left it over the window, answering
        the second (range) query. None means that query returns nothing, which is the case
        the tile has to survive without showing a zero it cannot stand behind."""
        prom = mock.MagicMock()

        def answer(expr):
            if expr.startswith("increase("):
                return [_series("", v, target=n, instance="10.0.212.3:9847")
                        for n, v in (processed or {}).items()]
            return series

        prom.query.side_effect = answer
        return mock.patch("reports.folders._prometheus", return_value=(prom, "http://prom:9090"))

    def test_states_end_to_end(self):
        now = time.time()
        series = (_folder_series(name="FRESH.IN", now=now, oldest_ago=30) +
                  _folder_series(name="AGEING.IN", now=now, oldest_ago=90) +
                  _folder_series(name="STUCK.IN", now=now, files=3, oldest_ago=4000, over_red=2) +
                  _folder_series(name="DRAINED.OUT", now=now, files=0) +
                  _folder_series(name="GONE.IN", now=now, files=0, exists=0) +
                  _exporter_up())
        with self._patch(series):
            snap = folders.snapshot()
        got = {f["name"]: f["state"] for f in snap["folders"]}
        self.assertEqual(got, {"FRESH.IN": "green", "AGEING.IN": "amber", "STUCK.IN": "red",
                               "DRAINED.OUT": "idle", "GONE.IN": "unknown"})
        self.assertEqual(snap["counts"]["red"], 1)
        self.assertEqual(snap["counts"]["amber"], 1)
        self.assertEqual(snap["worst_folder"]["name"], "STUCK.IN")
        self.assertEqual(snap["total"], 5)

    def test_age_ticks_from_the_published_timestamp(self):
        """The exporter publishes the oldest file's mtime, so the age is a live subtraction
        rather than something reconstructed from a run timestamp."""
        now = time.time()
        series = _folder_series(now=now, oldest_ago=420) + _exporter_up()
        with self._patch(series):
            snap = folders.snapshot()
        f = snap["folders"][0]
        self.assertAlmostEqual(f["age"], 420, delta=3)
        self.assertAlmostEqual(f["oldest_mtime"], now - 420, delta=3)

    def test_total_and_over_limit_counts_are_both_reported(self):
        """The headline gain over the old exposition: how deep the queue is AND how much of
        it is past the line, instead of only the second number."""
        now = time.time()
        series = _folder_series(now=now, files=9, oldest_ago=4000,
                                over_amber=5, over_red=3) + _exporter_up()
        with self._patch(series):
            snap = folders.snapshot()
        f = snap["folders"][0]
        self.assertEqual(f["files"], 9)
        self.assertEqual(f["over_red"], 3)
        self.assertEqual(f["over_amber"], 5)

    def test_over_limit_is_none_when_no_bucket_matches_the_limit(self):
        """Without a histogram bucket at the limit there is no honest answer, so the field
        is None rather than a number derived from the wrong boundary."""
        now = time.time()
        series = [s for s in _folder_series(now=now, files=4, oldest_ago=100)
                  if s["labels"].get("le") != str(folders.RED_SECONDS)]
        with self._patch(series + _exporter_up()):
            snap = folders.snapshot()
        self.assertIsNone(snap["folders"][0]["over_red"])
        self.assertEqual(snap["folders"][0]["files"], 4)

    def test_stale_scan_makes_that_folder_unknown(self):
        """Freshness is per folder now, so one folder that stopped being scanned does not
        drag the others down with it — and cannot hide behind them either."""
        now = time.time()
        series = (_folder_series(name="PAYNET.IN", now=now, oldest_ago=5,
                                 scanned_ago=folders.STALE_AFTER + 60) +
                  _folder_series(name="EFIN.IN", now=now, oldest_ago=5, scanned_ago=10) +
                  _exporter_up())
        with self._patch(series):
            snap = folders.snapshot()
        states = {f["name"]: f["state"] for f in snap["folders"]}
        self.assertEqual(states, {"PAYNET.IN": "unknown", "EFIN.IN": "green"})
        stalled = [f for f in snap["folders"] if f["name"] == "PAYNET.IN"][0]
        self.assertTrue(stalled["stale"])
        self.assertIn("not been scanned recently", stalled["reason"])

    def test_header_reports_when_fresh_data_last_arrived(self):
        """"Last scanned" is a ticking clock, and a reader takes that to mean "how long since
        new data landed" — so the NEWEST scan wins and the figure returns to zero on every
        scrape. Using the oldest made it start a whole interval above zero and never reset."""
        now = time.time()
        series = (_folder_series(name="A.IN", now=now, scanned_ago=10) +
                  _folder_series(name="B.IN", now=now, scanned_ago=140) +
                  _exporter_up())
        with self._patch(series):
            snap = folders.snapshot()
        self.assertAlmostEqual(snap["last_run"], now - 10, delta=3)

    def test_a_single_stalled_folder_still_shows_despite_a_fresh_header(self):
        """The safety property the old 'oldest scan' header was protecting: it must survive
        the change. B.IN stopped being scanned, so its tile is unknown even though the
        header reads current off A.IN."""
        now = time.time()
        series = (_folder_series(name="A.IN", now=now, scanned_ago=5) +
                  _folder_series(name="B.IN", now=now,
                                 scanned_ago=folders.STALE_AFTER + 60) +
                  _exporter_up())
        with self._patch(series):
            snap = folders.snapshot()
        states = {f["name"]: f["state"] for f in snap["folders"]}
        self.assertEqual(states["B.IN"], "unknown")
        self.assertEqual(snap["counts"]["unknown"], 1)
        self.assertLess(now - snap["last_run"], 10)     # header itself reads fresh

    def test_missing_scan_timestamp_is_unknown(self):
        """No proof of life at all -> unknown, not a green grid."""
        series = [s for s in _folder_series()
                  if s["labels"]["__name__"] != "folder_last_scan_timestamp_seconds"]
        with self._patch(series + _exporter_up()):
            snap = folders.snapshot()
        self.assertEqual(snap["folders"][0]["state"], "unknown")

    def test_exporter_down_makes_every_folder_unknown(self):
        """up == 0 means Prometheus is serving values it can no longer refresh."""
        now = time.time()
        with self._patch(_folder_series(now=now, oldest_ago=5) + _exporter_up(value=0)):
            snap = folders.snapshot()
        self.assertEqual(snap["folders"][0]["state"], "unknown")
        self.assertFalse(snap["exporter_up"])
        self.assertIn("not answering", snap["folders"][0]["reason"])

    def test_failed_scan_is_unknown_even_when_the_numbers_look_fine(self):
        """folder_up 0 means that scan hit a problem, so its readings are not evidence of
        anything — including of health."""
        now = time.time()
        with self._patch(_folder_series(now=now, oldest_ago=5, folder_up=0) + _exporter_up()):
            snap = folders.snapshot()
        self.assertEqual(snap["folders"][0]["state"], "unknown")
        self.assertFalse(snap["run_ok"])
        self.assertIn("reported an error", snap["folders"][0]["reason"])

    def test_timed_out_scan_is_unknown_and_says_so(self):
        """A scan cut short returns partial data: fewer files than are really there, which
        would read as a folder that had just drained."""
        now = time.time()
        with self._patch(_folder_series(now=now, oldest_ago=5, timed_out=1) + _exporter_up()):
            snap = folders.snapshot()
        self.assertEqual(snap["folders"][0]["state"], "unknown")
        self.assertIn("cut short", snap["folders"][0]["reason"])

    def test_same_folder_name_on_two_hosts_stays_separate(self):
        now = time.time()
        series = (_folder_series(instance="10.0.212.3:9847", now=now, oldest_ago=30) +
                  _folder_series(instance="10.0.212.9:9847", now=now, oldest_ago=9999) +
                  _exporter_up(instance="10.0.212.3:9847") +
                  _exporter_up(instance="10.0.212.9:9847"))
        with self._patch(series):
            snap = folders.snapshot()
        self.assertEqual(len(snap["folders"]), 2)
        self.assertEqual({f["state"] for f in snap["folders"]}, {"green", "red"})

    def test_per_folder_threshold_override_applies(self):
        now = time.time()
        series = _folder_series(name="SLOW.OUT", now=now, oldest_ago=3600) + _exporter_up()
        with mock.patch.dict(folders.THRESHOLDS, {"SLOW.OUT": (7200, 14400)}, clear=False):
            with self._patch(series):
                snap = folders.snapshot()
        f = snap["folders"][0]
        self.assertEqual(f["state"], "green")
        self.assertGreaterEqual(f["age"], 3600)
        self.assertEqual(f["red_seconds"], 14400)

    def test_page_renders_a_tile_per_folder(self):
        now = time.time()
        series = (_folder_series(name="PAYNET.IN", now=now, files=4, oldest_ago=4000, over_red=1) +
                  _folder_series(name="ALLIANCE.OUT_MX", now=now, files=0) +
                  _exporter_up())
        with self._patch(series):
            resp = self.client.get(reverse("folder_watch_temenos"))
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        self.assertContains(resp, "PAYNET.IN")
        self.assertContains(resp, "ALLIANCE.OUT_MX")
        self.assertEqual(body.count('class="fw-tile"'), 2)
        self.assertIn('data-state="red"', body)
        self.assertIn('data-state="idle"', body)
        # the badge is the TOTAL waiting, which the old exposition could not supply
        self.assertIn(">4</span>", body)

    def test_no_metrics_explains_deployment_instead_of_an_empty_grid(self):
        with self._patch([]):
            resp = self.client.get(reverse("folder_watch_temenos"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "No folder metrics are being reported yet")
        self.assertNotContains(resp, 'class="fw-tile"')

    def test_prometheus_down_is_an_error_not_an_all_clear(self):
        prom = mock.MagicMock()
        prom.query.side_effect = OSError("connection refused")
        with mock.patch("reports.folders._prometheus", return_value=(prom, "http://prom:9090")):
            resp = self.client.get(reverse("folder_watch_temenos"))
            data = self.client.get(reverse("folder_watch_data"))
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(data.status_code, 502)
        self.assertFalse(json.loads(data.content)["ok"])

    def test_json_endpoint_carries_timestamps_for_the_live_tick(self):
        """The browser re-ages tiles itself, so the payload must hand it the oldest file's
        TIMESTAMP — not a pre-computed age, which would freeze between polls. It also needs
        each folder's own limits, since the browser re-runs the verdict locally."""
        now = time.time()
        series = _folder_series(now=now, oldest_ago=100) + _exporter_up()
        with self._patch(series):
            resp = self.client.get(reverse("folder_watch_data"))
        payload = json.loads(resp.content)
        f = payload["folders"][0]
        self.assertIn("now", payload)
        self.assertIn("stale_after", payload)
        for key in ("oldest_mtime", "checked_at", "files", "readable", "scan_ok",
                    "reachable", "amber_seconds", "red_seconds"):
            self.assertIn(key, f)

    def test_header_clock_is_client_side_and_owes_nothing_to_the_payload(self):
        """The header clock counts from when THIS PAGE last pulled data, so it resets on
        every poll. It used to show the host's last run — necessary when the metrics came
        from a .prom file that was re-served unchanged between scheduled runs, and
        misleading now that the exporter is a live service.

        The payload's `now` is the only thing it may anchor to. Whether a folder's readings
        are stale stays a per-folder judgement, which the tiles carry.
        """
        now = time.time()
        series = _folder_series(now=now, oldest_ago=100, scanned_ago=42) + _exporter_up()
        with self._patch(series):
            page = self.client.get(reverse("folder_watch_temenos"))
        body = page.content.decode()
        # counts from the render, not from any scan timestamp
        self.assertIn('<b id="fwRunAgo">0:00</b>', body)
        self.assertIn("lastUpdate = data.now", body)
        # the scan timestamp must NOT drive it any more
        self.assertNotIn("serverNow() - data.last_run", body)
        self.assertNotIn("last checked", body)
        # The header's red threshold comes from the page's own rhythm, not the payload.
        self.assertIn("var UPDATE_STALE_S = (POLL_MS / 1000) * 4;", body)
        self.assertIn("sinceUpdate > UPDATE_STALE_S", body)
        # ...but PER-FOLDER staleness still uses the backend value, and must keep doing so:
        # that is the judgement about the readings, which is a different question entirely.
        self.assertIn("> data.stale_after", body)

    def test_message_path_is_read_from_the_exporter_labels(self):
        """source/via/destination are declared per folder in folder_exporter.yml and ride on
        every series, so a jammed folder can name the flow that has stopped."""
        now = time.time()
        series = _folder_series(name="ALLIANCE.IN_MT", now=now, source="RTGS",
                                via="SWIFT", destination="T24", fmt="mt") + _exporter_up()
        with self._patch(series):
            snap = folders.snapshot()
        f = snap["folders"][0]
        self.assertEqual(f["path"], ["RTGS", "SWIFT", "T24"])
        self.assertEqual(f["path_text"], "RTGS → SWIFT → T24")
        self.assertEqual(f["format"], "MT")          # upper-cased for the tab badge

    def test_a_direct_feed_has_two_stops_not_an_empty_hop(self):
        """PAYNET feeds T24 with no translation layer. Drawing a hop there would assert a
        SWIFT leg that does not exist, so the absent `via` collapses out of the path."""
        now = time.time()
        series = _folder_series(name="PAYNET.IN", now=now, source="PAYNET",
                               destination="T24") + _exporter_up()
        with self._patch(series):
            snap = folders.snapshot()
        f = snap["folders"][0]
        self.assertEqual(f["path"], ["PAYNET", "T24"])
        self.assertEqual(f["path_text"], "PAYNET → T24")
        self.assertEqual(f["format"], "")            # no format badge on this tile

    def test_a_folder_with_no_path_labels_renders_without_one(self):
        """The labels are optional: a folder that predates them, or one somebody adds in a
        hurry, must still get a tile rather than an empty arrow."""
        now = time.time()
        with self._patch(_folder_series(name="SOMETHING.IN", now=now) + _exporter_up()):
            snap = folders.snapshot()
        self.assertEqual(snap["folders"][0]["path"], [])
        self.assertEqual(snap["folders"][0]["path_text"], "")

    def test_the_path_is_rendered_and_searchable_on_the_tile(self):
        now = time.time()
        series = (_folder_series(name="ALLIANCE.IN_MT", now=now, source="RTGS", via="SWIFT",
                                 destination="T24", fmt="mt") + _exporter_up())
        with self._patch(series):
            body = self.client.get(reverse("folder_watch_temenos")).content.decode()
        self.assertIn('<span class="fw-fmt">MT</span>', body)
        self.assertIn('class="fw-path"', body)
        for hop in ("RTGS", "SWIFT", "T24"):
            self.assertIn(hop, body)
        # typing a flow name in the filter box has to narrow to it
        self.assertRegex(body, r'data-search="[^"]*rtgs → swift → t24[^"]*"')

    def test_processed_counts_files_that_left_since_midnight(self):
        """Throughput is what separates "deep because busy" from "deep because stopped".
        It comes from increase() rather than the raw counter, which runs from exporter start
        and would drop to near zero after any mid-day service restart."""
        now = time.time()
        series = (_folder_series(name="PAYNET.IN", now=now) +
                  _folder_series(name="EFIN.IN", now=now) + _exporter_up())
        with self._patch(series, processed={"PAYNET.IN": 531.4, "EFIN.IN": 0.0}):
            snap = folders.snapshot()
        got = {f["name"]: f["processed"] for f in snap["folders"]}
        self.assertEqual(got, {"PAYNET.IN": 531, "EFIN.IN": 0})   # rounded to whole files
        self.assertEqual(snap["processed_total"], 531)
        self.assertEqual(snap["processed_window"], "today")

    def test_the_processed_window_starts_at_local_midnight(self):
        """The count has to empty with the working day, so the range is the time since
        local midnight rather than a rolling 24h."""
        # 14:30:20 -> 52220s since midnight
        t = time.mktime(time.struct_time((2026, 8, 12, 14, 30, 20, 0, 0, -1)))
        self.assertEqual(folders._processed_query(t),
                         "increase(folder_files_removed_total[52220s])")
        # one second past midnight: floored, never [0s], which is invalid PromQL
        t0 = time.mktime(time.struct_time((2026, 8, 12, 0, 0, 1, 0, 0, -1)))
        self.assertEqual(folders._processed_query(t0),
                         "increase(folder_files_removed_total[15s])")
        # and just before midnight it spans nearly the whole day
        t23 = time.mktime(time.struct_time((2026, 8, 12, 23, 59, 59, 0, 0, -1)))
        self.assertEqual(folders._processed_query(t23),
                         "increase(folder_files_removed_total[86399s])")

    def test_processed_is_absent_rather_than_zero_when_unavailable(self):
        """A folder we cannot measure must not read "processed 0" — that is a claim that
        nothing has been handled, which is exactly the alarming case."""
        now = time.time()
        with self._patch(_folder_series(name="PAYNET.IN", now=now) + _exporter_up()):
            snap = folders.snapshot()
        self.assertIsNone(snap["folders"][0]["processed"])
        # ...and the tile carries no line at all, rather than an empty-looking one.
        # Checked against the MARKUP with scripts stripped: the source contains the string
        # "processed 0" in a comment explaining this very rule.
        with self._patch(_folder_series(name="PAYNET.IN", now=now) + _exporter_up()):
            body = self.client.get(reverse("folder_watch_temenos")).content.decode()
        markup = re.sub(r"<script.*?</script>", "", body, flags=re.S)
        self.assertNotIn("processed 0", markup)
        self.assertIn('<span class="fw-proc" data-proc-el></span>', markup)

    def test_a_failing_throughput_query_does_not_break_the_grid(self):
        """Throughput is a nice-to-have. If that query fails the folders must still render:
        losing a secondary figure cannot be allowed to take out the whole screen."""
        now = time.time()
        series = _folder_series(name="PAYNET.IN", now=now) + _exporter_up()
        prom = mock.MagicMock()

        def answer(expr):
            if expr.startswith("increase("):
                raise RuntimeError("range query failed")
            return series

        prom.query.side_effect = answer
        with mock.patch("reports.folders._prometheus",
                        return_value=(prom, "http://prom:9090")):
            snap = folders.snapshot()
        self.assertEqual(len(snap["folders"]), 1)
        self.assertEqual(snap["folders"][0]["state"], "green")
        self.assertIsNone(snap["folders"][0]["processed"])

    def test_negative_extrapolation_from_increase_is_floored(self):
        """increase() extrapolates at the range edges and can return a small negative on a
        sparse series. "processed -1" would be nonsense on a tile."""
        now = time.time()
        with self._patch(_folder_series(name="PAYNET.IN", now=now) + _exporter_up(),
                         processed={"PAYNET.IN": -0.4}):
            snap = folders.snapshot()
        self.assertEqual(snap["folders"][0]["processed"], 0)

    def test_the_refresh_indicators_are_a_fixed_rhythm_on_every_poll(self):
        """The clock and the wave both mark one thing: the page asked for data and got an
        answer. Both fire on EVERY successful poll, on a fixed cadence, so the number counts
        0 -> the poll interval and the grid ripples at the same moment, every time.

        Gating either on whether the DATA changed makes both stutter — the refresh happened
        on the same rhythm whether or not a file moved, and a user reading the number needs
        to know when the next one is due, not how lively the folders have been.
        """
        now = time.time()
        with self._patch(_folder_series(now=now) + _exporter_up()):
            body = self.client.get(reverse("folder_watch_temenos")).content.decode()
        self.assertIn("var POLL_MS = 10000;", body)
        # both reset unconditionally in the success path, not behind a data-changed guard
        success = re.search(r'live_txt\.textContent = "live";(.*?)\}\)', body, re.S).group(1)
        self.assertIn("lastUpdate = fresh.now", success)
        self.assertIn("playWave()", success)
        # the data-signature gate is gone entirely
        self.assertNotIn("signature(", body)
        self.assertNotIn("next !== sig", body)

    def test_the_page_does_not_reload_itself_on_a_timer(self):
        """Values arrive by poll and are repainted in place. The only reload left is the
        folder set changing on the host, which invalidates the server-rendered tiles."""
        now = time.time()
        with self._patch(_folder_series(now=now) + _exporter_up()):
            body = self.client.get(reverse("folder_watch_temenos")).content.decode()
        self.assertNotIn("REFRESH_MS", body)
        self.assertNotIn("autoRefresh", body)
        self.assertNotIn("refreshDue", body)      # would throw once its declaration went
        self.assertEqual(body.count("window.location.reload()"), 1)
        self.assertIn("keysOf(fresh.folders) !== shape", body)

    def test_no_template_comment_text_reaches_the_screen(self):
        """A {# #} comment is SINGLE-LINE in Django. Written across two lines it is not a
        comment at all — it renders as literal text, and inside the tile loop that put a
        paragraph of developer prose on every folder. Anything spanning lines must use
        {% comment %}. This asserts on the text a user can actually read, with script and
        style blocks stripped, so ordinary JS comments do not trip it."""
        now = time.time()
        with self._patch(_folder_series(now=now) + _exporter_up()):
            resp = self.client.get(reverse("folder_watch_temenos"))
        body = resp.content.decode()
        visible = re.sub(r"<script.*?</script>", "", body, flags=re.S)
        visible = re.sub(r"<style.*?</style>", "", visible, flags=re.S)
        visible = re.sub(r"<[^>]+>", " ", visible)
        for leak in ("{#", "#}", "endcomment", "{% comment"):
            self.assertNotIn(leak, visible, f"template comment syntax leaked: {leak}")
        # the prose of every comment block in the template must stay out of the page
        self.assertNotIn("previous exporter", visible)
        self.assertNotIn("muscle memory", visible)

    def test_requires_login(self):
        self.client.logout()
        resp = self.client.get(reverse("folder_watch_temenos"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/accounts/login/", resp["Location"])

    def test_back_nav_points_at_folder_watch_not_home(self):
        """Temenos is a CHILD of Folder Watch, so Back walks one level up the tree."""
        now = time.time()
        with self._patch(_folder_series(now=now) + _exporter_up()):
            resp = self.client.get(reverse("folder_watch_temenos"))
        self.assertContains(resp, "Back to Folder Watch")

    def test_page_load_spinner_is_suppressed_here(self):
        """The page repaints in place rather than reloading, so the global spinner would
        only ever dim the screen for a navigation nobody asked for."""
        now = time.time()
        with self._patch(_folder_series(now=now) + _exporter_up()):
            resp = self.client.get(reverse("folder_watch_temenos"))
        self.assertNotContains(resp, 'id="pageSpinner"')
        # ...but it is still there on an ordinary page
        self.assertContains(self.client.get(reverse("history")), 'id="pageSpinner"')


class FolderWatchDurations(TestCase):
    """Ages read as a clock, not as a rounded unit: 2:12, never '2m'."""

    def test_minutes_and_seconds(self):
        self.assertEqual(folders._fmt_age(0), "0:00")
        self.assertEqual(folders._fmt_age(42), "0:42")
        self.assertEqual(folders._fmt_age(132), "2:12")
        self.assertEqual(folders._fmt_age(3599), "59:59")

    def test_hours_and_days_keep_the_seconds(self):
        self.assertEqual(folders._fmt_age(3600), "1:00:00")
        self.assertEqual(folders._fmt_age(4350), "1:12:30")
        self.assertEqual(folders._fmt_age(97451), "1d 3:04:11")

    def test_none_and_negatives(self):
        self.assertEqual(folders._fmt_age(None), "—")
        self.assertEqual(folders._fmt_age(-5), "0:00")


class FolderWatchAccess(TestCase):
    """Folder Watch and everything under it is System Admin only."""

    def setUp(self):
        self.other = get_user_model().objects.create_user("nofw", password="pw12345!")
        self.other.groups.add(Group.objects.get(name="Network Admin"))
        self.admin = get_user_model().objects.create_user("fwadm", password="pw12345!")
        self.admin.groups.add(Group.objects.get(name="System Admin"))

    def _patch(self, series):
        prom = mock.MagicMock()
        prom.query.return_value = series
        return mock.patch("reports.folders._prometheus", return_value=(prom, "http://prom:9090"))

    def test_another_role_is_turned_away_from_every_folder_url(self):
        """Hiding the nav link is not access control — the URLs have to refuse too."""
        self.client.login(username="nofw", password="pw12345!")
        for name in ("folder_watch", "folder_watch_temenos"):
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 302, name)
            self.assertIn(reverse("report_form"), resp["Location"], name)
        self.assertEqual(self.client.get(reverse("folder_watch_data")).status_code, 403)

    def test_nav_group_is_hidden_from_other_roles_and_shown_to_system_admin(self):
        self.client.login(username="nofw", password="pw12345!")
        self.assertNotContains(self.client.get(reverse("history")), "Folder Watch")

        self.client.login(username="fwadm", password="pw12345!")
        page = self.client.get(reverse("history"))
        self.assertContains(page, "Folder Watch")
        self.assertContains(page, reverse("folder_watch_temenos"))

    def test_parent_page_lists_temenos(self):
        self.client.login(username="fwadm", password="pw12345!")
        resp = self.client.get(reverse("folder_watch"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Temenos")
        self.assertContains(resp, reverse("folder_watch_temenos"))

    def test_superuser_passes_without_the_group(self):
        su = get_user_model().objects.create_superuser("root", password="pw12345!")
        self.client.force_login(su)
        self.assertEqual(self.client.get(reverse("folder_watch")).status_code, 200)


# =============================================================================== #
#  NETWORK ADMIN REPORT
#
#  Phase 1 renders three collected metrics and declares twelve uncollected ones. The
#  tests below are weighted accordingly: most guard the DECLARATION, because that is
#  the part a reader can be misled by. A panel that is empty because nothing measures
#  it must never be readable as a clean bill of health.
# =============================================================================== #
#: the real core switch target. Fixtures use it so scoping — which matches on `instance`
#: against the DEVICES inventory — resolves the same way it does in production.
_DEV_TARGET = "10.100.210.253"


def _snmp_series(up=3, down=2, instance=_DEV_TARGET):
    """ifOperStatus shaped like snmp_exporter's if_mib output: ifIndex only, and ifDescr
    present but EMPTY, which is what the real device actually returns."""
    oper = []
    for i in range(up):
        oper.append({"labels": {"ifIndex": str(i + 1), "ifDescr": "",
                                "instance": instance, "system": "RBZ Network"}, "value": 1.0})
    for i in range(down):
        oper.append({"labels": {"ifIndex": str(100 + i), "ifDescr": "",
                                "instance": instance, "system": "RBZ Network"}, "value": 2.0})
    return oper


def _stamp(series, instance=_DEV_TARGET):
    """Put `instance` on rate series, as Prometheus does.

    Rates are keyed by (instance, ifIndex) because ifIndex is only unique WITHIN a device —
    keying on it alone would blend two switches' port 1 the moment a second is onboarded.
    """
    for r in series or []:
        r["labels"].setdefault("instance", instance)
    return series or []


def _snmp_prom(oper, rin=None, rout=None):
    """A Prometheus whose answers depend on which query it is asked."""
    rin, rout = _stamp(rin), _stamp(rout)
    prom = mock.MagicMock()

    def q(expr):
        if expr == "ifOperStatus":
            return oper
        if expr.startswith("rate(ifInOctets"):
            return rin
        if expr.startswith("rate(ifOutOctets"):
            return rout
        if expr.startswith("up{"):
            return [{"labels": {"instance": _DEV_TARGET}, "value": 1.0}]
        if expr == "vector(1)":
            return [{"labels": {}, "value": 1.0}]    # reachability probe
        # Everything else is genuinely absent. The catch-all used to answer ANY query with a
        # dummy series, which meant a metric the fixture had never heard of — ifHCInOctets,
        # ifHighSpeed — arrived looking collected, and the code under test took the rich path
        # against data that did not exist.
        return []

    prom.query.side_effect = q
    return mock.patch("reports.network._prometheus", return_value=(prom, "http://prom:9090"))


class NetworkReportCollection(TestCase):
    """What collect() makes of the exporter's output."""

    def test_link_states_are_split_on_ifoperstatus_1(self):
        with _snmp_prom(_snmp_series(up=4, down=3)):
            d = network.collect()
        self.assertEqual((d["iface_count"], d["up_count"], d["down_count"]), (7, 4, 3))

    def test_non_up_states_other_than_down_are_named_not_lumped(self):
        """IF-MIB has seven states. 'lowerLayerDown' is not the same fault as 'down', and a
        report rendering both as the word 'down' sends someone to check the wrong cable."""
        oper = _snmp_series(up=1, down=0)
        oper.append({"labels": {"ifIndex": "9", "instance": _DEV_TARGET}, "value": 7.0})
        with _snmp_prom(oper):
            d = network.collect()
        self.assertEqual([i["status_text"] for i in d["down_ports"]], ["lower layer down"])

    def test_interfaces_fall_back_to_index_when_ifdescr_is_empty(self):
        """ifDescr is collected as a label but arrives empty, so there is no name to show.
        'ifIndex 3' is honestly unhelpful; 'Interface 3' would imply a name we do not have."""
        with _snmp_prom(_snmp_series(up=1, down=0)):
            d = network.collect()
        self.assertEqual(d["interfaces"][0]["name"], "ifIndex 1")
        self.assertFalse(d["has_names"])

    def test_a_real_ifdescr_is_preferred_when_the_walk_ever_provides_one(self):
        oper = _snmp_series(up=1, down=0)
        oper[0]["labels"]["ifDescr"] = "GigabitEthernet1/0/1"
        with _snmp_prom(oper):
            d = network.collect()
        self.assertEqual(d["interfaces"][0]["name"], "GigabitEthernet1/0/1")
        self.assertTrue(d["has_names"])

    def test_octets_are_converted_to_bits_per_second(self):
        """SNMP counts OCTETS; network people speak in bits. A factor of eight is the
        difference between 'this port is fine' and 'this port is saturated'."""
        rin = [{"labels": {"ifIndex": "1"}, "value": 1000000.0}]        # 1 MB/s
        with _snmp_prom(_snmp_series(up=1, down=0), rin=rin):
            d = network.collect()
        self.assertEqual(d["interfaces"][0]["in_bps"], 8000000.0)
        self.assertEqual(d["interfaces"][0]["in_text"], "8.0 Mbps")

    def test_longest_bar_is_full_width_and_nothing_overflows(self):
        """Bars scale to the heaviest SINGLE direction shown. Scaling to a port's in+out
        total instead leaves the longest bar short of full, so the visual maximum is a
        length nothing ever occupies and every bar reads quieter than the truth."""
        rin = [{"labels": {"ifIndex": "1"}, "value": 100.0},
               {"labels": {"ifIndex": "2"}, "value": 50.0}]
        rout = [{"labels": {"ifIndex": "1"}, "value": 100.0},
                {"labels": {"ifIndex": "2"}, "value": 25.0}]
        with _snmp_prom(_snmp_series(up=3, down=0), rin=rin, rout=rout):
            d = network.collect()
        widths = [p for i in d["busiest"] for p in (i["in_pct"], i["out_pct"])]
        self.assertEqual(max(widths), 100.0)
        self.assertTrue(all(0 <= w <= 100 for w in widths), widths)

    def test_counter_wrap_time_is_computed_from_the_live_peak(self):
        """The wrap figure is the page's central caveat, so it must track the traffic. A
        hardcoded constant on a page whose point is 'this number is under-reported' would
        be its own small lie. 2^32 bytes at 8 bytes/s = 2^29 seconds."""
        rin = [{"labels": {"ifIndex": "1"}, "value": 8.0}]
        with _snmp_prom(_snmp_series(up=1, down=0), rin=rin):
            d = network.collect()
        self.assertEqual(d["wrap_seconds"], round((2 ** 32) / 8))

    def test_a_missing_metric_does_not_break_the_page(self):
        """Nothing polls ifHighSpeed today; if a query fails or the metric is absent the
        report must still render the parts that do exist."""
        prom = mock.MagicMock()
        oper = _snmp_series(up=2, down=1)

        def q(expr):
            if expr == "ifOperStatus":
                return oper
            if expr.startswith("rate("):
                raise RuntimeError("no such metric")
            return [{"labels": {}, "value": 1.0}]

        prom.query.side_effect = q
        with mock.patch("reports.network._prometheus", return_value=(prom, "http://p")):
            d = network.collect()
        self.assertEqual(d["up_count"], 2)
        self.assertEqual(d["busiest"], [])

    def test_prometheus_being_down_is_raised_not_rendered_as_zero(self):
        """An unreachable Prometheus must not become 'zero interfaces, all quiet'."""
        prom = mock.MagicMock()
        prom.query.side_effect = RuntimeError("connection refused")
        with mock.patch("reports.network._prometheus", return_value=(prom, "http://p")):
            with self.assertRaises(network.NetworkUnavailable):
                network.collect()


class NetworkReportPage(TestCase):
    """The report screen is the SAME screen the systems flow uses.

    One device is one "system" and its faults are its flags, so reports/form.html renders
    both. These tests are about the network content reaching that screen intact — above all
    the measurement caveats, which must travel as findings rather than being lost with the
    standalone page they used to live on.
    """

    def setUp(self):
        self.user = get_user_model().objects.create_user("netadm", password="pw12345!")
        self.user.groups.add(Group.objects.get(name="Network Admin"))
        self.client.login(username="netadm", password="pw12345!")

    def _body(self):
        rin = [{"labels": {"ifIndex": "1"}, "value": 90000000.0}]
        rout = [{"labels": {"ifIndex": "1"}, "value": 40000000.0}]
        with _snmp_prom(_snmp_series(up=3, down=2), rin=rin, rout=rout):
            self.client.post(reverse("network_report"), {"include_device": "core-switch"})
            resp = self.client.get(reverse("network_report"))
        self.assertEqual(resp.status_code, 200)
        return resp.content.decode()

    def test_it_renders_the_systems_annotation_screen(self):
        """Not a parallel screen that will drift — literally the same template."""
        rin = [{"labels": {"ifIndex": "1"}, "value": 9000.0}]
        with _snmp_prom(_snmp_series(), rin=rin):
            self.client.post(reverse("network_report"), {"include_device": "core-switch"})
            resp = self.client.get(reverse("network_report"))
        self.assertTemplateUsed(resp, "reports/form.html")

    def test_the_device_is_named_as_the_subject(self):
        self.assertIn("Core Switch", self._body())

    def test_it_submits_to_the_network_generator(self):
        """The shared template differs between the two flows in exactly one thing."""
        body = self._body()
        self.assertIn('action="%s"' % reverse("network_generate"), body)
        self.assertNotIn('action="%s"' % reverse("generate"), body)

    def test_ports_that_are_not_up_are_raised_as_a_watch_item_not_an_incident(self):
        """Without ifAdminStatus a shut port looks exactly like a failed one, and on a
        311-port switch most are simply unused. Calling that an incident daily is how a
        report teaches people to ignore it."""
        body = self._body()
        self.assertIn("interfaces are not up", body)
        self.assertIn("admin status is not collected", body)

    def test_the_counter_width_caveat_travels_as_a_finding(self):
        """The admins asked for ifHCInOctets by name and are not getting it. A throughput
        figure without that caveat is a wrong number wearing a confident face — so it is a
        flagged item on the report, not a footnote on a page that no longer exists."""
        body = self._body()
        self.assertIn("under-reported", body)
        self.assertIn("ifHCInOctets", body)

    def test_the_uncollected_metrics_are_reported_as_a_finding(self):
        """The count is MEASURED against Prometheus now, not written into the table, so the
        assertion derives it the same way rather than hardcoding a number that goes stale the
        day a metric starts being collected."""
        body = self._body()
        self.assertIn("not collected", body)
        with _snmp_prom(_snmp_series(up=3, down=2)):
            data = network.collect(only={"core-switch"})
        self.assertGreater(data["count_missing"], 0)
        self.assertIn(f"{data['count_missing']} of {len(network.CATALOGUE)} requested metrics", body)

    def test_nothing_is_flagged_that_is_not_measured(self):
        """No band is invented for a metric that is not polled — an amber row for "CPU
        unknown" would put a fault on screen that no measurement supports."""
        with _snmp_prom(_snmp_series(up=2, down=0)):
            snap = network.capture_snapshot("t", only={"core-switch"})
        keys = {f.key for f in snap.systems[0].flags}
        for never in ("cpu", "memory", "temperature", "psu", "bgp", "wifi"):
            self.assertNotIn(never, keys)

    def test_the_screen_speaks_of_devices_not_systems(self):
        """The shared template is the systems screen. Handed to a network admin unchanged it
        read "System Analyses Dashboard · 1 system selected" above a switch — someone else's
        screen with their device on it."""
        body = self._body()
        self.assertIn("Network Device Picker", body)
        self.assertNotIn("System Analyses Dashboard", body)
        self.assertIn("1 device selected", body)
        self.assertIn("Devices needing attention", body)

    def test_change_selection_returns_to_the_device_picker(self):
        """It pointed at the systems picker, which would have walked a network admin into
        another role's screen — and one that cannot start a network report."""
        body = self._body()
        self.assertIn('href="%s" title="Go back to device selection"' % reverse("network_dashboard"), body)
        self.assertNotIn('href="%s" title="Go back to' % reverse("report_form"), body)

    def test_no_template_comment_text_reaches_the_screen(self):
        """Django's {# #} is SINGLE-LINE. Spanning it across lines renders it as visible
        prose, which has already shipped to this UI once."""
        body = self._body()
        visible = re.sub(r"<script.*?</script>", "", body, flags=re.S)
        visible = re.sub(r"<style.*?</style>", "", visible, flags=re.S)
        visible = re.sub(r"<[^>]+>", " ", visible)
        for leak in ("{#", "#}", "endcomment", "comment %}"):
            self.assertNotIn(leak, visible, "template comment syntax leaked: " + leak)

class NetworkReportAccess(TestCase):
    """The report is for the people who run the network gear."""

    def setUp(self):
        self.net = get_user_model().objects.create_user("na", password="pw12345!")
        self.net.groups.add(Group.objects.get(name="Network Admin"))
        self.sys = get_user_model().objects.create_user("sa", password="pw12345!")
        self.sys.groups.add(Group.objects.get(name="System Admin"))
        self.gov = get_user_model().objects.create_user("ga", password="pw12345!")
        self.gov.groups.add(Group.objects.get(name="Gov Systems Admin"))

    def test_requires_login(self):
        resp = self.client.get(reverse("network_report"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/accounts/login/", resp["Location"])

    def test_an_unrelated_role_is_turned_away_from_the_url_itself(self):
        """Hiding the nav link is not access control."""
        self.client.login(username="ga", password="pw12345!")
        resp = self.client.get(reverse("network_report"))
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn("/network/", resp["Location"])

    def test_the_nav_link_follows_the_same_rule_as_the_url(self):
        """A visible link to a page that bounces you is worse than no link at all.

        The network screens are reached through their own dashboard now, so the link to
        look for is that dashboard rather than the report directly."""
        self.client.login(username="ga", password="pw12345!")
        self.assertNotContains(self.client.get(reverse("history")), "Network Device Picker")
        self.client.logout()
        self.client.login(username="na", password="pw12345!")
        self.assertContains(self.client.get(reverse("history")), "Network Device Picker")

    def test_only_network_admin_holds_it(self):
        """Systems and network are separated deliberately: the System Analyses Dashboard is
        the systems role's screen and the network ones are not. A platform admin who needs
        these is granted the Network Admin role, which leaves a record."""
        self.assertTrue(is_network_admin(self.net))
        self.assertFalse(is_network_admin(self.sys))
        self.assertFalse(is_network_admin(self.gov))


# =============================================================================== #
#  SUPERUSER ACCOUNT MANAGEMENT
#
#  Resetting a password and deleting an account are the two things this console does
#  that cannot be undone from inside it. The tests are therefore mostly about REFUSAL:
#  who is turned away, and which deletions are blocked outright.
# =============================================================================== #
class AccountManagementAccess(TestCase):
    """Only a superuser reaches these actions — the Administrator role is not enough."""

    def setUp(self):
        U = get_user_model()
        self.root = U.objects.create_superuser("root", password="pw12345!")
        self.spare = U.objects.create_superuser("spare", password="pw12345!")
        self.roleadm = U.objects.create_user("radm", password="pw12345!")
        self.roleadm.groups.add(Group.objects.get(name="Administrator"))
        self.victim = U.objects.create_user("victim", password="pw12345!")

    def test_an_administrator_cannot_reset_a_password(self):
        """Administrator manages who holds which role. This one can take an account over,
        which is a different kind of power and deliberately not granted with it."""
        self.client.login(username="radm", password="pw12345!")
        self.client.post(reverse("roles_console"), {
            "action": "reset_password", "user_id": self.victim.pk,
            "new_password": "hijacked!123", "new_password2": "hijacked!123"})
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.check_password("pw12345!"))

    def test_an_administrator_cannot_delete_an_account(self):
        self.client.login(username="radm", password="pw12345!")
        self.client.post(reverse("roles_console"), {
            "action": "delete_user", "user_id": self.victim.pk,
            "confirm_username": "victim"})
        self.assertTrue(get_user_model().objects.filter(pk=self.victim.pk).exists())

    def test_the_column_is_hidden_from_a_non_superuser(self):
        self.client.login(username="radm", password="pw12345!")
        self.assertNotContains(self.client.get(reverse("roles_console")), "Delete account")

    def test_a_superuser_sees_it(self):
        self.client.login(username="root", password="pw12345!")
        self.assertContains(self.client.get(reverse("roles_console")), "Delete account")


class AccountPasswordReset(TestCase):
    def setUp(self):
        U = get_user_model()
        self.root = U.objects.create_superuser("root", password="pw12345!")
        self.victim = U.objects.create_user("victim", password="oldpw12345!")
        self.client.login(username="root", password="pw12345!")

    def _post(self, pw1, pw2=None):
        return self.client.post(reverse("roles_console"), {
            "action": "reset_password", "user_id": self.victim.pk,
            "new_password": pw1, "new_password2": pw1 if pw2 is None else pw2}, follow=True)

    def test_a_superuser_can_reset_another_account(self):
        self._post("Str0ng!Passphrase42")
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.check_password("Str0ng!Passphrase42"))

    def test_mismatched_confirmation_changes_nothing(self):
        """A typo in the second box must not half-apply — the admin would walk away believing
        a password they never actually set."""
        resp = self._post("Str0ng!Passphrase42", "Str0ng!Passphrase43")
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.check_password("oldpw12345!"))
        self.assertContains(resp, "did not match")

    def test_a_weak_password_is_refused_by_django_s_own_validators(self):
        resp = self._post("123")
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.check_password("oldpw12345!"))
        self.assertNotContains(resp, "Password reset for")

    def test_the_stored_value_is_a_hash_not_the_password(self):
        """The reason this console can set a password but never show one."""
        self._post("Str0ng!Passphrase42")
        self.victim.refresh_from_db()
        self.assertNotIn("Str0ng!Passphrase42", self.victim.password)
        self.assertTrue(self.victim.password.startswith("pbkdf2_"))


class AccountDeletion(TestCase):
    def setUp(self):
        U = get_user_model()
        self.root = U.objects.create_superuser("root", password="pw12345!")
        self.victim = U.objects.create_user("victim", password="pw12345!")
        self.client.login(username="root", password="pw12345!")

    def _delete(self, target, confirm):
        return self.client.post(reverse("roles_console"), {
            "action": "delete_user", "user_id": target.pk,
            "confirm_username": confirm}, follow=True)

    def test_a_superuser_can_delete_an_ordinary_account(self):
        self._delete(self.victim, "victim")
        self.assertFalse(get_user_model().objects.filter(username="victim").exists())

    def test_the_username_must_be_typed_back_exactly(self):
        """There is no undo, so a stray click must not be sufficient."""
        resp = self._delete(self.victim, "vict")
        self.assertTrue(get_user_model().objects.filter(username="victim").exists())
        self.assertContains(resp, "Type the username exactly")

    def test_you_cannot_delete_the_account_you_are_signed_in_as(self):
        resp = self._delete(self.root, "root")
        self.assertTrue(get_user_model().objects.filter(username="root").exists())
        self.assertContains(resp, "signed in as")

    def test_the_superuser_population_can_never_reach_zero(self):
        """The one irreversible mistake this console could make is an app whose account tools
        nobody can reach, recoverable only from a shell on the server.

        What actually prevents it is the self-guard, not the last-superuser check: a
        superuser deleting ANOTHER superuser always leaves themselves behind, and they
        cannot delete themselves. So the invariant is tested here as an invariant."""
        U = get_user_model()
        other = U.objects.create_superuser("root2", password="pw12345!")
        self.client.logout()
        self.client.login(username="root2", password="pw12345!")

        self._delete(self.root, "root")                    # allowed: two superusers existed
        self.assertFalse(U.objects.filter(username="root").exists())

        resp = self._delete(other, "root2")                # refused: it is the actor's own
        self.assertTrue(U.objects.filter(username="root2").exists())
        self.assertContains(resp, "signed in as")
        self.assertEqual(U.objects.filter(is_superuser=True, is_active=True).count(), 1)

    def test_the_last_superuser_guard_counts_correctly(self):
        """Unreachable through the UI while the self-guard stands, so it is verified
        directly — an unexercised guard is a guard nobody knows is broken."""
        from reports.views import _other_superusers
        U = get_user_model()
        self.assertEqual(_other_superusers(self.root), 0)   # root is the only one
        second = U.objects.create_superuser("root2", password="pw12345!")
        self.assertEqual(_other_superusers(self.root), 1)
        second.is_active = False                            # a disabled account is no fallback
        second.save(update_fields=["is_active"])
        self.assertEqual(_other_superusers(self.root), 0)

    def test_deleting_an_account_keeps_its_reports_and_their_attribution(self):
        """The audit trail must outlive the account. generated_by is SET_NULL and the author
        name is stored as text, so history stays readable after the person leaves."""
        sub = ReportSubmission.objects.create(
            author="V. Ictim", generated_by=self.victim, theme="dark",
            report_content={}, annotations={})
        self._delete(self.victim, "victim")
        sub.refresh_from_db()
        self.assertIsNone(sub.generated_by)
        self.assertEqual(sub.author, "V. Ictim")

    def test_a_deleted_account_can_no_longer_sign_in(self):
        self._delete(self.victim, "victim")
        self.client.logout()
        self.assertFalse(self.client.login(username="victim", password="pw12345!"))


# =============================================================================== #
#  ROLE SELECTION
#
#  Choosing a role NARROWS a menu the user was already entitled to see. The most
#  important tests here are the ones proving it cannot do the opposite.
# =============================================================================== #
class RoleSelectScreen(TestCase):
    def setUp(self):
        U = get_user_model()
        self.multi = U.objects.create_user("multi", password="pw12345!")
        self.multi.groups.add(Group.objects.get(name="System Admin"))
        self.multi.groups.add(Group.objects.get(name="Network Admin"))
        self.single = U.objects.create_user("single", password="pw12345!")
        self.single.groups.add(Group.objects.get(name="System Admin"))

    def test_it_is_where_login_lands(self):
        """LOGIN_REDIRECT_URL points here, so the choice is offered before the menu is."""
        resp = self.client.post(reverse("login"),
                                {"username": "multi", "password": "pw12345!"})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("role_select"))

    def test_a_user_with_one_role_is_never_asked(self):
        """A question with a single answer is a speed bump. The one role is applied silently
        and the user goes straight to work."""
        self.client.login(username="single", password="pw12345!")
        resp = self.client.get(reverse("role_select"))
        self.assertRedirects(resp, reverse("report_form"))
        self.assertEqual(self.client.session.get("active_role"), "System Admin")

    def test_every_role_is_listed_held_or_not(self):
        """Showing only what you hold made the app look like it had two different ideas of
        how many roles exist — the first-login screen has always listed them all. A role you
        do not hold appears muted, with a request in place of the switch."""
        self.client.login(username="multi", password="pw12345!")
        resp = self.client.get(reverse("role_select"))
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        for role in ROLE_NAMES:
            self.assertIn(role, body)
        # held -> switch, not held -> request
        self.assertIn('name="role" value="System Admin"', body)
        self.assertIn('name="request_role" value="Gov Systems Admin"', body)

    def test_a_role_you_do_not_hold_can_be_requested_from_here(self):
        """The same action the first-login screen offers, so the two screens differ in
        presentation and not in what they can do."""
        self.client.login(username="multi", password="pw12345!")
        self.client.post(reverse("role_select"), {"request_role": "Gov Systems Admin"}, follow=True)
        self.assertTrue(RoleRequest.objects.filter(
            user__username="multi", role="Gov Systems Admin", status="pending").exists())

    def test_requesting_a_role_twice_does_not_stack_requests(self):
        self.client.login(username="multi", password="pw12345!")
        for _ in range(2):
            self.client.post(reverse("role_select"), {"request_role": "Security Admin"}, follow=True)
        self.assertEqual(RoleRequest.objects.filter(
            user__username="multi", role="Security Admin").count(), 1)

    def test_a_superuser_is_offered_every_role(self):
        """is_superuser already passes every gate, so the roles it can act as ARE all of
        them. An empty picker would describe a restriction that does not exist."""
        get_user_model().objects.create_superuser("root", password="pw12345!")
        self.client.login(username="root", password="pw12345!")
        resp = self.client.get(reverse("role_select"))
        for role in ROLE_NAMES:
            self.assertContains(resp, role)

    def test_choosing_a_role_records_it_and_gets_on_with_the_job(self):
        """Landing is role-specific: picking Network Admin must not drop you on a systems
        screen your own role no longer shows."""
        self.client.login(username="multi", password="pw12345!")
        resp = self.client.post(reverse("role_select"), {"role": "Network Admin"})
        self.assertRedirects(resp, reverse("network_dashboard"))
        self.assertEqual(self.client.session["active_role"], "Network Admin")

    def test_there_is_no_every_role_at_once_option(self):
        """A role is the hat being worn. An everything-at-once mode let the menu show screens
        from estates the admin was not working in — the thing this screen exists to prevent.
        Removed from the page AND from the view, so it cannot be reached by posting a value
        the screen no longer renders."""
        self.client.login(username="multi", password="pw12345!")
        self.assertNotContains(self.client.get(reverse("role_select")), "Show every role I hold")

        self.client.post(reverse("role_select"), {"role": "Network Admin"})
        resp = self.client.post(reverse("role_select"), {"role": "__all__"}, follow=True)
        self.assertContains(resp, "not a role you hold")
        self.assertEqual(self.client.session.get("active_role"), "Network Admin")   # unchanged

    def test_the_drawer_head_names_the_role_being_worn(self):
        """The head names the ROLE, not the account — the account is already on the profile
        widget, and the role is what decides everything else in the drawer."""
        self.client.login(username="multi", password="pw12345!")
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        body = self.client.get(reverse("history")).content.decode()
        head = body[body.find("drawer-head"):body.find("</div>", body.find("drawer-head"))]
        self.assertIn("System Admin", head)
        self.assertNotIn("multi", head)

    def test_the_way_back_is_offered_only_when_there_is_a_choice(self):
        """Asserted on the LINK rather than its wording, so relabelling the entry does not
        quietly turn this into a test of nothing."""
        self.client.login(username="multi", password="pw12345!")
        body = self.client.get(reverse("history")).content.decode()
        self.assertIn(reverse("role_select"), body)
        self.assertIn("Back to role select", body)
        self.client.logout()
        self.client.login(username="single", password="pw12345!")
        self.assertNotIn(reverse("role_select"),
                         self.client.get(reverse("history")).content.decode())

    def test_the_drawer_has_no_close_button_of_its_own(self):
        """It closes on the backdrop, on Escape, and on the title that opened it, so a
        dedicated chevron was a control earning its space three times over. app.js binds it
        defensively, so its absence is a no-op there — this pins that it stays absent."""
        self.client.login(username="multi", password="pw12345!")
        body = self.client.get(reverse("history")).content.decode()
        self.assertNotIn("drawerClose", body)


    def test_the_picker_renders_without_any_navigation(self):
        """The menu is what this screen is choosing. Showing it here would let the user walk
        straight past the question the page exists to ask."""
        self.client.login(username="multi", password="pw12345!")
        body = self.client.get(reverse("role_select")).content.decode()
        self.assertNotIn('class="topbar"', body)
        self.assertNotIn('class="drawer"', body)
        for link in ("System Picker", "Folder Watch", "Network Device Picker"):
            self.assertNotIn(link, body)

    def test_the_picker_is_never_a_trap(self):
        """No header means no Sign out in the usual place, so the page carries its own."""
        self.client.login(username="multi", password="pw12345!")
        self.assertContains(self.client.get(reverse("role_select")), "Sign out")

    def test_ordinary_pages_still_have_their_chrome(self):
        """The chrome block is overridden on ONE page; every other page must be untouched."""
        self.client.login(username="multi", password="pw12345!")
        body = self.client.get(reverse("history")).content.decode()
        self.assertIn('class="topbar"', body)
        self.assertIn("System Picker", body)

    def test_the_picker_describes_the_job_not_the_software(self):
        """"Adds 2 screens" describes the app; someone deciding which hat to put on needs to
        know whose job it is. Every role must carry a description, including the empty ones —
        a blank tile is the one thing worse than a screen count."""
        from reports.roles import ROLE_DESCRIPTIONS
        self.client.login(username="multi", password="pw12345!")
        body = self.client.get(reverse("role_select")).content.decode()
        self.assertNotIn("Adds ", body)
        self.assertNotIn("screens to the menu", body)
        for role in ROLE_NAMES:
            self.assertTrue(ROLE_DESCRIPTIONS.get(role), f"{role} has no description")

    def test_a_data_endpoint_is_never_counted_as_a_screen(self):
        """folder_watch_data is polled by JavaScript, never navigated to; `report` and
        `generate` are steps inside the dashboard rather than destinations. role_screens()
        is what any future "what does this role open" copy must be built from."""
        from reports.roles import ROLE_PAGES as RP, role_screens
        screens = role_screens("System Admin")
        for hidden in ("folder_watch_data", "report", "generate"):
            self.assertNotIn(hidden, screens)
        self.assertLess(len(screens), len(RP["System Admin"]))


class RoleSelectCannotGrant(TestCase):
    """The whole point: selecting a role narrows, never widens."""

    def setUp(self):
        U = get_user_model()
        self.net = U.objects.create_user("netonly", password="pw12345!")
        self.net.groups.add(Group.objects.get(name="Network Admin"))
        self.client.login(username="netonly", password="pw12345!")

    def test_a_role_you_do_not_hold_is_refused(self):
        """The refusal is the assertion. Following the redirect then lands on the picker,
        which auto-applies this user's ONE role — correct behaviour, and the reason the
        check below is 'not Administrator' rather than 'nothing at all'."""
        resp = self.client.post(reverse("role_select"), {"role": "Administrator"}, follow=True)
        self.assertContains(resp, "not a role you hold")
        self.assertNotEqual(self.client.session.get("active_role"), "Administrator")
        self.assertEqual(self.client.session.get("active_role"), "Network Admin")

    def test_a_forged_session_value_grants_nothing(self):
        """Even if the session key is set to a role the user does not hold, every gate must
        still refuse — the picker is navigation, not access control."""
        session = self.client.session
        session["active_role"] = "Administrator"
        session.save()
        resp = self.client.get(reverse("roles_console"))
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn("/roles/", resp["Location"])

    def test_an_unheld_selection_is_discarded_rather_than_trusted(self):
        session = self.client.session
        session["active_role"] = "Administrator"
        session.save()
        body = self.client.get(reverse("history")).content.decode()
        # falls back to UNSCOPED rather than to the role that was forged into the session
        self.assertNotIn(">Roles<", body)
        self.assertNotIn(reverse("roles_console"), body)

    def test_a_revoked_role_stops_applying_immediately(self):
        """The role is checked against what is held on every request, so revoking it while
        someone is signed in takes effect at once rather than at their next login."""
        self.net.groups.add(Group.objects.get(name="System Admin"))
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        self.assertEqual(self.client.session["active_role"], "System Admin")
        self.net.groups.remove(Group.objects.get(name="System Admin"))
        self.assertNotContains(self.client.get(reverse("history")), "Folder Watch")


class RoleScopedMenu(TestCase):
    def setUp(self):
        U = get_user_model()
        self.u = U.objects.create_user("multi", password="pw12345!")
        for r in ("System Admin", "Network Admin", "Administrator"):
            self.u.groups.add(Group.objects.get(name=r))
        self.client.login(username="multi", password="pw12345!")

    def _menu(self):
        return self.client.get(reverse("history")).content.decode()

    def test_with_no_role_chosen_the_menu_is_the_union_as_before(self):
        """Unscoped is a real state, not an unfinished one — a bookmark or a deep link must
        not dead-end at a chooser."""
        body = self._menu()
        for link in ("Folder Watch", "Network Device Picker", "Roles"):
            self.assertIn(link, body)

    def test_choosing_system_admin_hides_the_other_roles_screens(self):
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        body = self._menu()
        self.assertIn("Folder Watch", body)
        self.assertNotIn(">Roles<", body)

    def test_choosing_administrator_hides_folder_watch(self):
        self.client.post(reverse("role_select"), {"role": "Administrator"})
        body = self._menu()
        self.assertNotIn("Folder Watch", body)
        self.assertIn("Roles", body)

    def test_the_notification_dot_never_outlives_its_panel(self):
        """The panel is gated on the scoped flag, so a dot that opens an empty menu would
        read as a bug — and worse, train people to ignore it."""
        RoleRequest.objects.create(user=self.u, role="System Admin", status="pending")
        self.client.post(reverse("role_select"), {"role": "Administrator"})
        self.assertContains(self.client.get(reverse("history")), "reddot")
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        self.assertNotContains(self.client.get(reverse("history")), "reddot")

    def test_common_screens_stay_in_every_role(self):
        """Connect and History belong to everyone. The DASHBOARDS do not — systems and
        network each have their own, which is the whole point of the separation, so the
        systems dashboard is deliberately absent from this list."""
        for role in ("System Admin", "Network Admin", "Administrator"):
            self.client.post(reverse("role_select"), {"role": role})
            body = self._menu()
            for link in ("Connect", "History"):
                self.assertIn(link, body, f"{link} vanished under {role}")

    def test_each_role_sees_only_its_own_dashboard(self):
        """The counterpart to the test above: the dashboards are exactly what is NOT common."""
        expected = {
            "System Admin":  ("System Picker", "Network Device Picker"),
            "Network Admin": ("Network Device Picker", "System Picker"),
        }
        for role, (present, absent) in expected.items():
            self.client.post(reverse("role_select"), {"role": role})
            body = self._menu()
            self.assertIn(present, body, f"{present} missing under {role}")
            self.assertNotIn(absent, body, f"{absent} leaked into {role}")


    def test_every_screen_a_role_owns_is_reachable_from_its_drawer(self):
        """The drawer is what answers "what does this role open". A screen the role owns but
        the drawer never lists reads as a page that does not exist — which is exactly how
        Configuration hid: it lived only under the settings menu.

        Driven from ROLE_PAGES so a new screen cannot be added without a way in.
        """
        from reports.roles import ROLE_PAGES, role_screens

        for role in ("System Admin", "Network Admin", "Administrator"):
            self.client.post(reverse("role_select"), {"role": role})
            body = self._menu()
            drawer = body[body.find('id="drawer"'):body.find("</nav>")]
            for page in role_screens(role):
                self.assertIn(reverse(page), drawer,
                              f"{page} is owned by {role} but absent from its drawer")

class EmptyRoles(TestCase):
    """Roles that exist with their estate still to come.

    They own no screens, and must not borrow another role's dashboard to look furnished —
    an empty menu is the honest description of where these roles currently stand.
    """

    def setUp(self):
        self.u = get_user_model().objects.create_user("gov2", password="pw12345!")
        self.u.groups.add(Group.objects.get(name="Gov Systems Admin"))
        self.client.login(username="gov2", password="pw12345!")

    def test_both_empty_roles_own_no_screens(self):
        for role in ("Gov Systems Admin", "Security Admin"):
            self.assertEqual(ROLE_PAGES[role], set(), role)

    def test_security_admin_exists_as_a_group(self):
        """Seeded by migration, so a fresh deployment has it without anyone running a
        command — the roles console can only tick a role that exists."""
        self.assertTrue(Group.objects.filter(name="Security Admin").exists())
        self.assertIn("Security Admin", ROLE_NAMES)

    def test_the_empty_screen_names_the_role_being_worn(self):
        """One screen serves every empty role, so it has to say which one you are in."""
        self.u.groups.add(Group.objects.get(name="Security Admin"))
        for role in ("Gov Systems Admin", "Security Admin"):
            self.client.post(reverse("role_select"), {"role": role})
            resp = self.client.get(reverse("role_empty"))
            self.assertContains(resp, role)
            self.assertContains(resp, "Nothing to see here")

    def test_it_is_not_given_another_role_s_dashboard(self):
        body = self.client.get(reverse("history")).content.decode()
        self.assertNotIn("System Analyses Dashboard", body)
        self.assertNotIn("Network Device Picker", body)

    def test_it_lands_on_a_screen_that_admits_it_is_empty(self):
        """Not History, not another role's dashboard. A role with nothing in it should look
        like a role with nothing in it."""
        resp = self.client.post(reverse("role_select"), {"role": "Gov Systems Admin"})
        self.assertRedirects(resp, reverse("role_empty"))
        self.assertContains(self.client.get(reverse("role_empty")), "Nothing to see here")

    def test_the_empty_screen_offers_a_way_back(self):
        """Nothing here is a dead end."""
        self.u.groups.add(Group.objects.get(name="System Admin"))   # now holds two roles
        resp = self.client.get(reverse("role_empty"))
        self.assertContains(resp, reverse("role_select"))

    def test_a_holder_of_only_this_role_is_not_sent_round_a_loop(self):
        """The picker auto-applies a single role, so a Back button pointing at it would
        bounce straight back to this page. A button that returns you where you already are
        is worse than none, so the exit offered is sign-out."""
        body = self.client.get(reverse("role_empty")).content.decode()
        page = body[body.find("gs-wrap"):]          # the screen itself, not the app chrome
        self.assertNotIn(reverse("role_select"), page)
        self.assertIn("Sign out", page)

    def test_the_screen_belongs_to_the_role(self):
        other = get_user_model().objects.create_user("notgov", password="pw12345!")
        other.groups.add(Group.objects.get(name="System Admin"))
        self.client.logout()
        self.client.login(username="notgov", password="pw12345!")
        self.assertEqual(self.client.get(reverse("role_empty")).status_code, 302)



class RoleScopedNavigation(TestCase):
    """A bookmark to another role's page explains itself instead of vanishing."""

    def setUp(self):
        U = get_user_model()
        self.u = U.objects.create_user("multi", password="pw12345!")
        self.u.groups.add(Group.objects.get(name="System Admin"))
        self.u.groups.add(Group.objects.get(name="Administrator"))
        self.client.login(username="multi", password="pw12345!")

    def test_a_page_outside_the_active_role_sends_you_to_the_picker(self):
        self.client.post(reverse("role_select"), {"role": "Administrator"})
        resp = self.client.get(reverse("folder_watch"), follow=True)
        self.assertContains(resp, "belongs to the System Admin role")

    def test_the_page_opens_normally_once_the_role_matches(self):
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        self.assertEqual(self.client.get(reverse("folder_watch")).status_code, 200)

    def test_unscoped_navigation_is_never_interrupted(self):
        self.client.post(reverse("role_select"), {"role": "__all__"})
        self.assertEqual(self.client.get(reverse("folder_watch")).status_code, 200)

    def test_a_page_the_user_cannot_hold_is_left_to_the_view_to_refuse(self):
        """The middleware is a navigation aid. It must never be the only thing standing
        between a user and a page, so for a role they do not hold it does nothing at all
        and the view's own permission check answers."""
        other = get_user_model().objects.create_user("gov", password="pw12345!")
        other.groups.add(Group.objects.get(name="Gov Systems Admin"))
        self.client.logout()
        self.client.login(username="gov", password="pw12345!")
        resp = self.client.get(reverse("folder_watch"))
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn(reverse("role_select"), resp["Location"])


# =============================================================================== #
#  THE TWO DASHBOARDS
#
#  Systems and network are separate estates with separate landing screens. Most of
#  these tests guard the SEPARATION, because the failure mode is quiet: a switch
#  listed among the business systems looks plausible until someone reports on it.
# =============================================================================== #
class DashboardsAreSeparate(TestCase):
    def setUp(self):
        U = get_user_model()
        self.sys = U.objects.create_user("sysadm", password="pw12345!")
        self.sys.groups.add(Group.objects.get(name="System Admin"))
        self.net = U.objects.create_user("netadm2", password="pw12345!")
        self.net.groups.add(Group.objects.get(name="Network Admin"))

    def _drawer(self, who):
        self.client.logout()
        self.client.login(username=who, password="pw12345!")
        body = self.client.get(reverse("history")).content.decode()
        return body[body.find('id="drawer"'):body.find("</nav>")]

    def test_the_systems_dashboard_belongs_to_the_systems_role(self):
        self.assertIn("System Picker", self._drawer("sysadm"))

    def test_a_network_admin_is_not_shown_the_systems_dashboard(self):
        self.assertNotIn("System Picker", self._drawer("netadm2"))

    def test_the_network_dashboard_belongs_to_the_network_role(self):
        self.assertIn("Network Device Picker", self._drawer("netadm2"))

    def test_a_system_admin_is_not_shown_the_network_dashboard(self):
        """An earlier draft let System Admin read the network screens. The roles have since
        been separated deliberately, and a systems menu full of switch screens is exactly
        what that separation exists to prevent."""
        self.assertNotIn("Network Device Picker", self._drawer("sysadm"))

    def test_a_system_admin_is_refused_the_network_urls(self):
        """Hiding the link is not access control."""
        self.client.login(username="sysadm", password="pw12345!")
        for name in ("network_dashboard", "network_report"):
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 302, name)

    def test_each_role_lands_on_its_own_dashboard(self):
        """Picking a role and then being dropped on another role's screen would undo the
        choice with the very redirect that follows it."""
        self.client.login(username="netadm2", password="pw12345!")
        resp = self.client.post(reverse("role_select"), {"role": "Network Admin"})
        self.assertRedirects(resp, reverse("network_dashboard"))


class NetworkDevicePicker(TestCase):
    def setUp(self):
        self.u = get_user_model().objects.create_user("netadm3", password="pw12345!")
        self.u.groups.add(Group.objects.get(name="Network Admin"))
        self.client.login(username="netadm3", password="pw12345!")

    def _get(self, up=1.0, ifaces=3):
        oper = [{"labels": {"ifIndex": str(i + 1), "instance": "10.100.210.253"}, "value": 1.0}
                for i in range(ifaces)]
        prom = mock.MagicMock()

        def q(expr):
            if expr.startswith("up{"):
                return ([{"labels": {"instance": "10.100.210.253"}, "value": up}]
                        if up is not None else [])
            if expr == "ifOperStatus":
                return oper
            return [{"labels": {}, "value": 1.0}]

        prom.query.side_effect = q
        with mock.patch("reports.network._prometheus", return_value=(prom, "http://p")):
            return self.client.get(reverse("network_dashboard"))

    def test_it_lists_exactly_the_one_device_monitored_today(self):
        """A SELECTION tile, matching the systems picker — the two dashboards ask the same
        question of different inventories, so they are the same screen."""
        resp = self._get()
        body = resp.content.decode()
        self.assertEqual(body.count('name="include_device"'), len(network.DEVICES))
        self.assertContains(resp, "Core Switch")
        self.assertContains(resp, _DEV_TARGET)

    def test_it_submits_to_the_report(self):
        """Select, then continue — the systems flow exactly."""
        body = self._get().content.decode()
        self.assertIn('action="%s"' % reverse("network_report"), body)
        self.assertIn("Capture &amp; continue", body)

    def test_it_is_structurally_the_systems_picker(self):
        """Same screen, different inventory. Asserted on the pieces rather than a screenshot:
        header card, stat pills, section label, select-all, filter, running count, tile
        anatomy, sticky action bar and the empty-filter row."""
        body = self._get().content.decode()
        for piece in ('class="snap"', "sys-stats", "Devices to include", "chk-pill",
                      "sys-filter", "selectCountTop", "sys-mono", "sys-tick",
                      "sysNoResults", "actionbar", "sel-pill"):
            self.assertIn(piece, body, f"{piece} missing — the two pickers have diverged")

    def _grid(self, **kw):
        """Just the tile grid. The stylesheet block names the same classes, so asserting on
        the whole page would pass on a CSS rule and prove nothing about the markup."""
        body = self._get(**kw).content.decode()
        return body[body.find('id="selectList"'):body.find('id="sysNoResults"')]

    def test_a_healthy_device_carries_no_state_badge(self):
        """The badge sits in the slot the systems tiles use for "recently reported" and only
        appears when something is wrong, so a healthy grid looks exactly like that one."""
        self.assertNotIn("badge-state", self._grid())

    def test_an_unreachable_device_says_so_on_its_tile(self):
        self.assertIn("not responding", self._grid(up=0.0))

    def test_submitting_nothing_is_stopped_before_the_post(self):
        """The systems picker guards its own submit; this one does too, in the same words."""
        self.assertContains(self._get(), "Select at least one device")

    def test_a_responding_device_shows_its_interface_count(self):
        """The sub-line carries the count, exactly where a system tile carries "5 hosts"."""
        grid = self._grid(up=1.0, ifaces=4)
        self.assertIn("4 interfaces", grid)
        self.assertNotIn("badge-state", grid)      # healthy: no badge

    def test_a_device_that_fails_its_scrape_says_so(self):
        self.assertIn("not responding", self._grid(up=0.0))

    def test_never_scraped_is_not_rendered_as_down(self):
        """`up == 0` means Prometheus tried and failed; no `up` at all means it never tried.
        Rendering them alike sends someone to check a cable over a missing scrape config."""
        grid = self._grid(up=None)
        self.assertIn("not scraped", grid)
        self.assertNotIn("not responding", grid)


class NetworkDeviceIsNotASystem(TestCase):
    """The core switch must never appear among the business systems."""

    def setUp(self):
        self.u = get_user_model().objects.create_user("sysadm2", password="pw12345!")
        self.u.groups.add(Group.objects.get(name="System Admin"))
        self.client.login(username="sysadm2", password="pw12345!")

    def test_the_topology_contains_no_network_device(self):
        """The systems picker reads systems_config.yml; the switch lives only as a label on
        the SNMP metrics. This asserts the two inventories stay disjoint."""
        names = {s["name"] for s in list_systems()}
        for d in network.DEVICES:
            self.assertNotIn(d["system"], names)
            self.assertNotIn(d["name"], names)

    def test_the_systems_picker_shows_no_switch(self):
        body = self.client.get(reverse("report_form")).content.decode()
        for probe in ("RBZ Network", "Core Switch", "10.100.210.253"):
            self.assertNotIn(probe, body)


class CssTokenHygiene(TestCase):
    """Every CSS custom property a template uses must actually be defined somewhere.

    This exists because the mistake is silent. `var(--card, #fff)` on an app with no --card
    does not fail, warn, or fall back to something sensible — it renders #fff in every theme,
    so the page simply stops responding to dark mode and nothing anywhere says why. It cost
    three templates before it was spotted by eye.
    """

    #: tokens supplied by the browser/user agent rather than by app.css
    _EXTERNAL = {"--mono-h"}

    def _defined_in(self, text):
        """Tokens this file supplies: CSS declarations, plus any set from JavaScript.

        The JS half matters — the folder-watch wave sets --fw-delay per tile with
        setProperty, and its var() fallback is a real pre-script value rather than a
        hardcoded colour standing in for a theme.
        """
        return (set(re.findall(r"(--[a-z0-9-]+)\s*:", text))
                | set(re.findall(r"""setProperty\(\s*["'](--[a-z0-9-]+)""", text)))

    def test_no_template_uses_an_undefined_custom_property(self):
        import pathlib

        root = pathlib.Path(settings.BASE_DIR)
        app_css = (root / "static" / "css" / "app.css").read_text(encoding="utf-8")
        global_tokens = self._defined_in(app_css) | self._EXTERNAL

        offenders = []
        for tpl in (root / "templates").rglob("*.html"):
            text = tpl.read_text(encoding="utf-8")
            # a page may define its own tokens inline (the network report does); those count
            known = global_tokens | self._defined_in(text)
            for used in set(re.findall(r"var\(\s*(--[a-z0-9-]+)", text)):
                if used not in known:
                    offenders.append(f"{tpl.name}: {used}")

        self.assertEqual(offenders, [], "undefined CSS custom properties: " + ", ".join(offenders))

    def test_app_css_itself_is_clean(self):
        import pathlib

        app_css = (pathlib.Path(settings.BASE_DIR) / "static" / "css" / "app.css").read_text(encoding="utf-8")
        known = self._defined_in(app_css) | self._EXTERNAL
        undefined = {u for u in re.findall(r"var\(\s*(--[a-z0-9-]+)", app_css) if u not in known}
        self.assertEqual(undefined, set())


class DrawerCurrentIndicator(TestCase):
    """The accent marker showing which screen is open.

    Its whole value is being unambiguous, so the tests are mostly about it appearing exactly
    once — a marker on two rows, or on a row that is always lit, says nothing.
    """

    def setUp(self):
        self.u = get_user_model().objects.create_user("marker", password="pw12345!")
        for r in ("System Admin", "Network Admin", "Administrator"):
            self.u.groups.add(Group.objects.get(name=r))
        self.client.login(username="marker", password="pw12345!")

    def _drawer(self, url_name, role):
        self.client.post(reverse("role_select"), {"role": role})
        if url_name == "network_report":
            # the report covers a SELECTION, so it bounces to the picker without one
            with _snmp_prom(_snmp_series()):
                self.client.post(reverse("network_report"), {"include_device": "core-switch"})
                body = self.client.get(reverse(url_name)).content.decode()
        else:
            body = self.client.get(reverse(url_name)).content.decode()
        return body[body.find('id="drawer"'):body.find("</nav>")]

    def test_exactly_one_entry_is_marked_current(self):
        for url_name, role in (("report_form", "System Admin"),
                               ("folder_watch", "System Admin"),
                               ("folder_watch_temenos", "System Admin"),
                               ("network_dashboard", "Network Admin"),
                               ("network_report", "Network Admin"),
                               ("history", "Administrator"),
                               ("roles_console", "Administrator"),
                               ("system_settings", "Administrator")):
            drawer = self._drawer(url_name, role)
            self.assertEqual(drawer.count("is-current"), 1,
                             f"{url_name} should mark exactly one drawer entry")

    def test_the_marked_entry_is_the_page_you_are_on(self):
        drawer = self._drawer("system_settings", "Administrator")
        marked = re.search(r'<a href="([^"]+)"[^>]*is-current', drawer)
        self.assertIsNotNone(marked)
        self.assertEqual(marked.group(1), reverse("system_settings"))

    def test_a_child_screen_also_lights_its_parent(self):
        """On Temenos, Folder Watch shows which branch you are inside rather than going dark
        while its own child is open."""
        drawer = self._drawer("folder_watch_temenos", "System Admin")
        parent = re.search(r'<a href="([^"]+)"[^>]*is-ancestor', drawer)
        self.assertIsNotNone(parent)
        self.assertEqual(parent.group(1), reverse("folder_watch"))

    def test_the_home_screen_is_never_marked_as_a_branch(self):
        """Every page descends from home, so marking it would accent the dashboard on all of
        them — and a marker that is nearly always lit stops meaning "you are here"."""
        for url_name in ("folder_watch", "folder_watch_temenos"):
            drawer = self._drawer(url_name, "System Admin")
            dash = re.search(r'<a href="' + reverse("report_form") + r'"([^>]*)>', drawer)
            self.assertIsNotNone(dash)
            self.assertNotIn("is-ancestor", dash.group(1))
            self.assertNotIn("is-current", dash.group(1))

    def test_the_marker_is_not_colour_alone(self):
        """A screen reader gets the same information from aria-current that a sighted user
        gets from the accent bar."""
        drawer = self._drawer("history", "Administrator")
        self.assertIn('aria-current="page"', drawer)
        self.assertEqual(drawer.count('aria-current="page"'), 1)

    def test_the_accent_styles_are_theme_tokens(self):
        """The marker must follow the theme, which is exactly what the tile bug was."""
        import pathlib

        css = (pathlib.Path(settings.BASE_DIR) / "static" / "css" / "app.css").read_text(encoding="utf-8")
        block = css[css.index(".drawer a.is-current,"):]
        self.assertNotIn("#", block.split("/* ---- ")[0] if "/* ---- " in block else block[:600])


class BrandBackCaret(TestCase):
    """The caret on the brand pill: step OUT of the current role, from any screen.

    Distinct from the canvas back button, which walks one level up inside a role. This one
    has a single destination — the role picker — and the point of these tests is that the
    destination does not vary by role.
    """

    def setUp(self):
        U = get_user_model()
        self.multi = U.objects.create_user("caret", password="pw12345!")
        for r in ("System Admin", "Network Admin", "Administrator"):
            self.multi.groups.add(Group.objects.get(name=r))
        self.single = U.objects.create_user("caret1", password="pw12345!")
        self.single.groups.add(Group.objects.get(name="System Admin"))

    def _caret(self, path_name, role=None):
        if role:
            self.client.post(reverse("role_select"), {"role": role})
        body = self.client.get(reverse(path_name)).content.decode()
        pill = body[body.find("brand-pill"):body.find("spacer")]
        return re.search(r'class="brand-back" href="([^"]+)"', pill), pill

    def test_it_returns_to_the_picker_from_every_role_including_system_admin(self):
        """The System Admin screens used to be the exception — their back led to the System
        Analyses Dashboard rather than out of the role."""
        self.client.login(username="caret", password="pw12345!")
        for role in ("System Admin", "Network Admin", "Administrator"):
            for page in ("history", "connect"):
                match, _ = self._caret(page, role)
                self.assertIsNotNone(match, f"caret missing on {page} as {role}")
                self.assertEqual(match.group(1), reverse("role_select"),
                                 f"caret on {page} as {role} does not return to the picker")

    def test_the_caret_and_crest_are_a_single_control(self):
        """They look like one button, so a click anywhere on them must do one thing. Two
        anchors side by side would mean the half a user aims at decides where they land."""
        self.client.login(username="caret", password="pw12345!")
        _, pill = self._caret("history", "System Admin")
        anchors = re.findall(r'class="(brand-[a-z-]+)" href="([^"]+)"', pill)
        self.assertEqual(anchors, [("brand-back", reverse("role_select"))])
        # the crest lives INSIDE that anchor rather than beside it
        self.assertRegex(pill, r'class="brand-back"[^>]*>.*?brand-logo')

    def test_a_single_role_user_keeps_the_crest_as_a_home_link(self):
        """Without a caret there is nothing to merge, so the crest keeps its old job."""
        self.client.login(username="caret1", password="pw12345!")
        _, pill = self._caret("history")
        self.assertIn(('brand-icon', reverse("report_form")),
                      re.findall(r'class="(brand-[a-z-]+)" href="([^"]+)"', pill))

    def test_it_is_hidden_when_there_is_only_one_role(self):
        """The picker auto-applies a single role and would bounce straight back, so the
        button would be a no-op that looks like a way out."""
        self.client.login(username="caret1", password="pw12345!")
        match, pill = self._caret("history")
        self.assertIsNone(match)
        self.assertNotIn("has-back", pill)

    def test_the_pill_is_told_it_has_a_caret(self):
        """The pill's left padding tightens to sit the caret against the crest. That rides a
        modifier class rather than :has(), which this codebase treats as an unsafe bet on
        the Edge build here — the same reason color-mix is avoided."""
        self.client.login(username="caret", password="pw12345!")
        _, pill = self._caret("history", "System Admin")
        self.assertIn("has-back", pill)

    def test_no_picker_class_is_left_without_a_rule(self):
        """The network picker reused select.html's markup while its styles were still inline
        in that template, so every shared class resolved to nothing: stat pills rendered as
        run-together text, the resume bar as loose prose, the search icon adrift of its box.

        Nothing errors when a class has no rule — the page just looks wrong — so this asserts
        that every class either template puts on the page is actually defined somewhere.
        """
        import pathlib

        css = (pathlib.Path(settings.BASE_DIR) / "static" / "css" / "app.css").read_text(encoding="utf-8")
        defined = set(re.findall(r"\.([a-z][a-z0-9-]*)", css))

        self.client.login(username="caret", password="pw12345!")
        for role, url_name in (("Network Admin", "network_dashboard"),
                               ("System Admin", "report_form")):
            self.client.post(reverse("role_select"), {"role": role})
            with _snmp_prom(_snmp_series()):
                body = self.client.get(reverse(url_name)).content.decode()
            page = body[body.find('<div class="container"'):]
            inline = set(re.findall(r"\.([a-z][a-z0-9-]*)",
                                    "".join(re.findall(r"<style>(.*?)</style>", body, re.S))))
            used = {c for attr in re.findall(r'class="([^"]+)"', page) for c in attr.split()}
            missing = sorted(u for u in used if u not in defined and u not in inline)
            self.assertEqual(missing, [], f"{url_name}: classes with no CSS rule: {missing}")

    def test_the_stylesheet_does_not_rely_on_has(self):
        import pathlib

        css = (pathlib.Path(settings.BASE_DIR) / "static" / "css" / "app.css").read_text(encoding="utf-8")
        # strip comments first: the rationale for avoiding :has() naturally mentions it
        code = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        self.assertNotIn(":has(", code)


class NetworkReportFlow(TestCase):
    """Select devices, then report on them — the systems flow, for network gear.

    The point of these tests is that the report covers what the admin CHOSE. Which devices a
    report covers is the admin's statement about their own estate, not a default the app
    picked for them.
    """

    def setUp(self):
        self.u = get_user_model().objects.create_user("netflow", password="pw12345!")
        self.u.groups.add(Group.objects.get(name="Network Admin"))
        self.client.login(username="netflow", password="pw12345!")

    def test_choosing_a_device_redirects_rather_than_rendering(self):
        """Post/Redirect/Get, as the systems picker does — a browser refresh on the report
        must never re-submit the selection."""
        with _snmp_prom(_snmp_series()):
            resp = self.client.post(reverse("network_report"), {"include_device": "core-switch"})
        self.assertRedirects(resp, reverse("network_report"), fetch_redirect_response=False)
        self.assertEqual(self.client.session["network_devices"], ["core-switch"])

    def test_the_report_needs_a_selection_first(self):
        """Arriving with nothing chosen sends the admin to the picker rather than quietly
        reporting on every device."""
        with _snmp_prom(_snmp_series()):
            resp = self.client.get(reverse("network_report"))
        self.assertRedirects(resp, reverse("network_dashboard"), fetch_redirect_response=False)

    def test_submitting_nothing_is_refused(self):
        resp = self.client.post(reverse("network_report"), {}, follow=True)
        self.assertContains(resp, "Select at least one device")
        self.assertIsNone(self.client.session.get("network_devices"))

    def test_an_unknown_device_key_is_discarded(self):
        """The key is checked against the inventory, so a hand-edited form cannot widen the
        report to something that is not monitored."""
        resp = self.client.post(reverse("network_report"),
                                {"include_device": "not-a-device"}, follow=True)
        self.assertContains(resp, "Select at least one device")
        self.assertIsNone(self.client.session.get("network_devices"))

    def test_the_report_covers_only_the_chosen_device(self):
        """Scoping is on the `instance` label, so a report naming the core switch cannot
        quietly include another device sharing the SNMP job."""
        oper = _snmp_series(up=2, down=0)
        oper += [{"labels": {"ifIndex": "1", "instance": "10.0.0.99"}, "value": 1.0},
                 {"labels": {"ifIndex": "2", "instance": "10.0.0.99"}, "value": 1.0}]
        with _snmp_prom(oper):
            data = network.collect(only={"core-switch"})
        self.assertEqual(data["devices"], [_DEV_TARGET])
        self.assertEqual(data["iface_count"], 2)

    def test_rates_do_not_blend_two_devices_ports(self):
        """ifIndex is unique only WITHIN a device. Keyed on it alone, a second switch's port 1
        would land on the first switch's port 1 the day it is onboarded."""
        oper = [{"labels": {"ifIndex": "1", "instance": _DEV_TARGET}, "value": 1.0}]
        rin = [{"labels": {"ifIndex": "1", "instance": "10.0.0.99"}, "value": 1000.0}]
        with _snmp_prom(oper, rin=rin):
            data = network.collect(only={"core-switch"})
        self.assertIsNone(data["interfaces"][0]["in_bps"])   # the other device's rate, ignored


class NetworkGenerate(TestCase):
    """Generating the report — the systems flow, for network gear."""

    def setUp(self):
        self.u = get_user_model().objects.create_user("netgen", password="pw12345!")
        self.u.groups.add(Group.objects.get(name="Network Admin"))
        self.client.login(username="netgen", password="pw12345!")

    def _open(self):
        with _snmp_prom(_snmp_series(up=3, down=2)):
            self.client.post(reverse("network_report"), {"include_device": "core-switch"})
            body = self.client.get(reverse("network_report")).content.decode()
        return re.search(r'name="token" value="([^"]+)"', body).group(1)

    def test_it_returns_a_real_xlsx(self):
        resp = self.client.post(reverse("network_generate"),
                                {"token": self._open(), "author": "P. Moyo"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"],
                         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.assertIn("Network Admin Report", resp["Content-Disposition"])
        self.assertGreater(len(resp.content), 4000)
        self.assertTrue(resp.content.startswith(b"PK"))      # a real zip container

    def test_the_answers_are_recorded_against_the_device(self):
        token = self._open()
        self.client.post(reverse("network_generate"), {
            "token": token, "author": "P. Moyo",
            "summary_comment": "Phase 1 review.",
            "fix__0__0": "No", "comment__0": "Unused access ports.",
        })
        sub = ReportSubmission.objects.latest("id")
        self.assertEqual(sub.author, "P. Moyo")
        self.assertEqual(sub.summary_comment, "Phase 1 review.")
        self.assertIn("Core Switch", sub.annotations)
        self.assertEqual(sub.annotations["Core Switch"]["comment"], "Unused access ports.")
        self.assertEqual([s["name"] for s in sub.report_content["systems"]], ["Core Switch"])

    def test_the_report_can_be_generated_more_than_once(self):
        """The page stays open after a download, so Generate has to work a second time. It
        used to consume the snapshot — pressing it again died with "this snapshot expired",
        and coming back after e-mailing hit the same wall, which read as e-mailing having
        forced a refresh. Freshness is guaranteed by every GET re-capturing, not by
        destroying the snapshot underneath the page that is still showing it."""
        token = self._open()
        for _ in range(3):
            resp = self.client.post(reverse("network_generate"), {"token": token, "author": "P. Moyo"})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.content.startswith(b"PK"))

    def test_a_system_admin_cannot_generate_a_network_report(self):
        other = get_user_model().objects.create_user("sysgen", password="pw12345!")
        other.groups.add(Group.objects.get(name="System Admin"))
        self.client.logout()
        self.client.login(username="sysgen", password="pw12345!")
        resp = self.client.post(reverse("network_generate"), {"token": "x"})
        self.assertEqual(resp.status_code, 302)

    def _xlsx(self, **post):
        body = {"token": self._open(), "author": "P. Moyo"}
        body.update(post)
        return self.client.post(reverse("network_generate"), body)

    def _sheet(self, content):
        import io
        from openpyxl import load_workbook
        return load_workbook(io.BytesIO(content)).active

    def test_the_workbook_is_painted_from_the_engine_palette(self):
        """Not a second set of colours that drifts. The build swaps gr.PALETTES the same way
        the systems build does, so "dark" means one thing in this app."""
        for theme in ("dark", "light"):
            ws = self._sheet(self._xlsx(theme=theme).content)
            pal = gr.PALETTES[theme]
            # column A is the crest gutter now (the logo floats over it, as in the systems
            # report), so the body starts at B — sample there, not in the margin
            fills = {ws.cell(r, c).fill.fgColor.rgb for r in range(1, 20) for c in (1, 2, 3)}
            for key in ("BG", "CARD", "HDR"):
                self.assertIn(str(pal[key]), fills, f"{theme}: {key} missing from the canvas")
            self.assertEqual(ws.cell(3, 2).font.color.rgb, str(pal["WHITE"]))   # title

    def test_the_two_themes_are_actually_different(self):
        dark = self._sheet(self._xlsx(theme="dark").content).cell(3, 2).fill.fgColor.rgb
        light = self._sheet(self._xlsx(theme="light").content).cell(3, 2).fill.fgColor.rgb
        self.assertNotEqual(dark, light)

    def test_the_canvas_is_painted_rather_than_left_white(self):
        """On the dark theme an unpainted sheet frames the report in white and the whole
        thing reads as broken."""
        ws = self._sheet(self._xlsx(theme="dark").content)
        self.assertEqual(ws.cell(2, 7).fill.fgColor.rgb, str(gr.PALETTES["dark"]["BG"]))

    def test_the_theme_is_named_in_the_filename_as_it_is_for_systems(self):
        self.assertIn("(light).xlsx", self._xlsx(theme="light")["Content-Disposition"])
        self.assertIn("(dark).xlsx", self._xlsx(theme="dark")["Content-Disposition"])

    def test_the_theme_is_recorded_on_the_audit_row(self):
        self._xlsx(theme="light")
        self.assertEqual(ReportSubmission.objects.latest("id").theme, "light")

    def test_an_unknown_theme_falls_back_rather_than_erroring(self):
        resp = self._xlsx(theme="chartreuse")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(ReportSubmission.objects.latest("id").theme, "dark")

    def test_no_theme_posted_uses_the_admins_saved_preference(self):
        """Same order the systems flow uses, so the two never disagree about what "no
        choice" means."""
        prof = self.u.profile
        prof.default_report_theme = "light"
        prof.save()
        self._xlsx()
        self.assertEqual(ReportSubmission.objects.latest("id").theme, "light")

    def test_the_workbook_states_how_to_read_its_numbers(self):
        """A spreadsheet outlives the screen it was made on, and these figures are wrong in a
        specific, knowable way. The caveats have to be inside the artifact."""
        import io
        from openpyxl import load_workbook

        resp = self.client.post(reverse("network_generate"),
                                {"token": self._open(), "author": "P. Moyo"})
        wb = load_workbook(io.BytesIO(resp.content))
        text = " ".join(str(c.value) for row in wb.active.iter_rows() for c in row if c.value)
        self.assertIn("FLOOR", text)
        self.assertIn("ifHighSpeed", text)
        self.assertIn("ifAdminStatus", text)


class NetworkOpenReportParity(TestCase):
    """Continuing an open report behaves the same in both estates.

    Both pickers DISCARD the answers already typed if you re-select on them, so every part of
    "you have one open" has to work the same way — the resume bar, the Back button, and the
    snapshot being retired when a new selection is made.
    """

    def setUp(self):
        self.u = get_user_model().objects.create_user("parity", password="pw12345!")
        for r in ("System Admin", "Network Admin"):
            self.u.groups.add(Group.objects.get(name=r))
        self.client.login(username="parity", password="pw12345!")
        self.client.post(reverse("role_select"), {"role": "Network Admin"})

    def _open(self):
        with _snmp_prom(_snmp_series()):
            self.client.post(reverse("network_report"), {"include_device": "core-switch"})
            self.client.get(reverse("network_report"))

    def _picker(self):
        with _snmp_prom(_snmp_series()):
            return self.client.get(reverse("network_dashboard")).content.decode()

    def test_the_resume_bar_appears_once_a_report_is_open(self):
        self.assertNotIn("You have a report open", self._picker())
        self._open()
        body = self._picker()
        self.assertIn("You have a report open", body)
        self.assertIn("Continue that report", body)
        self.assertIn("Core Switch", body)

    def test_the_resume_bar_outlives_the_snapshot(self):
        """Gated on the cached token as well, the bar vanished the moment the snapshot lapsed
        — stranding the admin on the one screen that discards their answers."""
        self._open()
        session = self.client.session
        session.pop("network_token")          # snapshot expired; the selection remains
        session.save()
        self.assertIn("You have a report open", self._picker())

    def test_re_selecting_retires_the_previous_snapshot(self):
        """Otherwise a second run silently reports the FIRST selection's numbers."""
        self._open()
        first = self.client.session["network_token"]
        with _snmp_prom(_snmp_series()):
            self.client.post(reverse("network_report"), {"include_device": "core-switch"})
        self.assertIsNone(self.client.session.get("network_token"))
        with _snmp_prom(_snmp_series()):
            self.client.get(reverse("network_report"))
        self.assertNotEqual(self.client.session["network_token"], first)

    def test_back_returns_to_the_open_report(self):
        """The picker is how the report was started; the report is what the admin was doing.
        Back retraces the second."""
        self._open()
        body = self.client.get(reverse("history")).content.decode()
        self.assertIn('class="backnav" href="%s"' % reverse("network_report"), body)

    def test_back_never_lands_on_another_role_s_dashboard(self):
        """The nav tree is rooted at the SYSTEMS dashboard, so without a role-aware fallback a
        network admin's Back led to a screen that is not in their menu."""
        body = self.client.get(reverse("history")).content.decode()
        self.assertIn('class="backnav" href="%s"' % reverse("network_dashboard"), body)
        self.assertNotIn('class="backnav" href="%s"' % reverse("report_form"), body)

    def test_the_systems_flow_is_untouched(self):
        """The rule is per-estate: a system admin's open report still wins for them."""
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        session = self.client.session
        session["report_systems"] = ["Efin"]
        session.save()
        body = self.client.get(reverse("history")).content.decode()
        self.assertIn('class="backnav" href="%s"' % reverse("report"), body)


def _build_overview(unreachable=False, nearfull=False, certs=None, ldap=False):
    """Run services.build_overview with the banner conditions dialled in.

    The gr.* helpers are patched rather than a Store fabricated: those helpers are what decide
    a condition holds, so faking their inputs would be testing the fixture instead of the
    code. Everything not under test is patched to "nothing wrong", so each test's banner is
    the only one that appears unless it asks for more.
    """
    from reports import services

    store = mock.MagicMock(services={}, links={}, cob=1.0, swift=1.0)
    systems = [mock.MagicMock(components=[1])]
    cfg = mock.MagicMock(overview_threshold=80, chip_red=90)

    ur = [("Efin", "DB", None), ("RTGS", "Backend", None)] if unreachable else []
    nf = [("Eagle", "DR", "/u01", 97.0), ("CEPECS", "Web", "/u01", 93.0)] if nearfull else []
    expired = [("vault.example", -3.0)] if certs == "expired" else []
    expiring = [("rtgs.example", 12.0)] if certs in ("expiring", "expired") else []

    patches = {
        "services_down": 0, "ram_pressure": (0, []), "cpu_pressure": (0, []),
        "disk_high": (0, 0, "good"), "backup_missing": [], "backup_untracked": [],
        "cert_rollup": (expired, expiring), "unreachable": ur, "disk_near_full": nf,
        "ldap_alert": ["Efin"] if ldap else [], "backup_missing_band": "good",
        # counters the overview tiles read; irrelevant to banners but they must not explode
        "backup_tracked_hosts": 1, "cert_monitored": 1,
    }
    with contextlib.ExitStack() as stack:
        for name, value in patches.items():
            stack.enter_context(mock.patch.object(services.gr, name, return_value=value))
        return services.build_overview(store, systems, cfg)


class BannerSeverity(TestCase):
    """Three named levels — imminent, critical, warning — on the screen and in the workbook.

    The label is spelled out rather than implied by an accent colour, because colour alone
    does not survive a printout, a colourblind reader, or someone who was never told what
    amber means in this report.
    """

    def _overview(self, **kw):
        return _build_overview(**kw)

    def test_every_banner_carries_one_of_the_three_levels(self):
        ov = self._overview(unreachable=True, nearfull=True, certs="expiring")
        self.assertTrue(ov["banners"])
        for b in ov["banners"]:
            self.assertIn(b["severity"], ("imminent", "critical", "warning"), b["head"])
            self.assertEqual(b["sev_label"], gr.SEVERITY[b["severity"]]["label"])

    def test_unreachable_is_always_imminent(self):
        """Not a metric out of range — the loss of our ability to see one. Every other
        finding is at least still being measured."""
        ov = self._overview(unreachable=True)
        banner = next(b for b in ov["banners"] if "Unreachable" in b["head"])
        self.assertEqual(banner["severity"], "imminent")
        self.assertEqual(banner["sev_label"], "IMMINENT")

    def test_disk_near_full_is_critical(self):
        ov = self._overview(nearfull=True)
        banner = next(b for b in ov["banners"] if "Disk near-full" in b["head"])
        self.assertEqual(banner["severity"], "critical")

    def test_an_expired_cert_is_critical_but_merely_expiring_is_a_warning(self):
        """One is an outage now — browsers reject the site. The other is a diary entry."""
        self.assertEqual(
            next(b for b in self._overview(certs="expired")["banners"] if "SSL" in b["head"])["severity"],
            "critical")
        self.assertEqual(
            next(b for b in self._overview(certs="expiring")["banners"] if "SSL" in b["head"])["severity"],
            "warning")

    def test_banners_are_ordered_most_severe_first(self):
        ov = self._overview(unreachable=True, nearfull=True, certs="expiring")
        ranks = [gr.SEVERITY[b["severity"]]["rank"] for b in ov["banners"]]
        self.assertEqual(ranks, sorted(ranks))

    def test_the_colour_band_is_derived_from_the_severity(self):
        """Set by hand in two places, a banner could read amber on screen and red in the
        file. The band follows the severity so they cannot disagree."""
        expected = {"imminent": "critical", "critical": "red", "warning": "amber"}
        for b in self._overview(unreachable=True, nearfull=True, certs="expiring")["banners"]:
            self.assertEqual(b["band"], expected[b["severity"]])

    def test_the_detail_is_rows_not_a_run_on_paragraph(self):
        """A dozen hosts joined by middots re-wraps at the window edge and reads as prose —
        you cannot scan down it to find your system."""
        ov = self._overview(unreachable=True)
        banner = next(b for b in ov["banners"] if "Unreachable" in b["head"])
        self.assertTrue(banner["rows"])
        for row in banner["rows"]:
            self.assertIn("label", row)
            self.assertIn("values", row)
        self.assertNotIn("·", " ".join(r["values"] for r in banner["rows"]))

    def test_the_engine_and_the_webapp_share_one_vocabulary(self):
        """gr.SEVERITY is the single source; the webapp reads its labels and ranks from it
        rather than keeping a second copy to drift."""
        self.assertEqual(sorted(gr.SEVERITY), ["critical", "imminent", "warning"])
        for name, spec in gr.SEVERITY.items():
            self.assertEqual(spec["label"], name.upper())


class OpenReportExpiry(TestCase):
    """The "you have a report open" widget expires with the snapshot it refers to.

    The widget offers to CONTINUE a report, so it has to stop offering when that stops being
    possible — otherwise it invites an admin back to numbers captured hours ago.
    """

    def setUp(self):
        self.u = get_user_model().objects.create_user("expiry", password="pw12345!")
        for r in ("System Admin", "Network Admin"):
            self.u.groups.add(Group.objects.get(name=r))
        self.client.login(username="expiry", password="pw12345!")

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_the_widget_counts_down_on_the_snapshot_clock(self, _cap):
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        self.client.post(reverse("report"), {"include_system": "Efin"})
        self.client.get(reverse("report"))
        body = self.client.get(reverse("report_form")).content.decode()
        self.assertIn("You have a report open", body)
        left = int(re.search(r'data-left="(\d+)"', body).group(1))
        self.assertGreater(left, 0)
        self.assertLessEqual(left, settings.SNAPSHOT_TTL)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_when_it_runs_out_the_report_closes_and_the_widget_goes(self, _cap):
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        self.client.post(reverse("report"), {"include_system": "Efin"})
        self.client.get(reverse("report"))

        session = self.client.session
        session["report_expires_at"] = time.time() - 1      # wind past the deadline
        session.save()

        body = self.client.get(reverse("report_form")).content.decode()
        self.assertNotIn("You have a report open", body)
        self.assertIsNone(self.client.session.get("report_systems"))
        self.assertIsNone(self.client.session.get("snapshot_token"))

    def test_the_network_estate_behaves_the_same(self):
        self.client.post(reverse("role_select"), {"role": "Network Admin"})
        with _snmp_prom(_snmp_series()):
            self.client.post(reverse("network_report"), {"include_device": "core-switch"})
            self.client.get(reverse("network_report"))
            body = self.client.get(reverse("network_dashboard")).content.decode()
            self.assertIn("You have a report open", body)
            self.assertRegex(body, r'data-left="\d+"')

            session = self.client.session
            session["network_expires_at"] = time.time() - 1
            session.save()
            body = self.client.get(reverse("network_dashboard")).content.decode()
        self.assertNotIn("You have a report open", body)
        self.assertIsNone(self.client.session.get("network_devices"))

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_the_countdown_script_is_absent_when_nothing_is_open(self, _cap):
        """It reloads the page at zero, so shipping it with no report open would reload a
        screen nobody asked to reload."""
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        self.assertNotIn("resumeCountdown", self.client.get(reverse("report_form")).content.decode())


class GenerateIsRepeatable(TestCase):
    """The page stays open after a download, so Generate has to work more than once."""

    def setUp(self):
        self.user = get_user_model().objects.create_user("regen", password="pw12345!")
        self.user.groups.add(Group.objects.create(name="Report Users"))
        self.client.login(username="regen", password="pw12345!")

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def _token(self, _cap):
        self.client.post(reverse("report"), {"include_system": "Efin"})
        body = self.client.get(reverse("report")).content.decode()
        return re.search(r'name="token" value="(\w+)"', body).group(1)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_downloading_twice_works(self, _cap):
        token = self._token()
        for _ in range(3):
            resp = self.client.post(reverse("generate"),
                                    {"token": token, "author": "P", "theme": "dark",
                                     "action": "download"})
            self.assertEqual(resp.status_code, 200)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    @mock.patch("mail_report.send_email", return_value="Subject")
    def test_the_report_still_works_after_e_mailing(self, _send, _cap):
        """E-mailing used to consume the snapshot, so going back to the report hit "this
        snapshot expired" — which reads as e-mailing having forced a refresh."""
        token = self._token()
        sent = self.client.post(reverse("generate"),
                                {"token": token, "author": "P", "theme": "dark",
                                 "action": "email", "recipients": "ops@rbz.co.zw"})
        self.assertEqual(sent.status_code, 200)
        after = self.client.post(reverse("generate"),
                                 {"token": token, "author": "P", "theme": "dark",
                                  "action": "download"})
        self.assertEqual(after.status_code, 200)


class BackNavigationChain(TestCase):
    """Back walks one step up the tree, and the tree is the same shape in both estates:

        report  ->  picker  ->  Role Select

    The systems report used to be the exception — it had no Back at all and relied on the
    "Change systems" button in its own header, which is a different control in a different
    place from the one every other screen uses.
    """

    def setUp(self):
        self.u = get_user_model().objects.create_user("chain", password="pw12345!")
        for r in ("System Admin", "Network Admin"):
            self.u.groups.add(Group.objects.get(name=r))
        self.client.login(username="chain", password="pw12345!")

    def _back(self, url_name):
        return self.client.get(reverse(url_name)).context["back_url"]

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_the_systems_chain(self, _cap):
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        self.client.post(reverse("report"), {"include_system": "Efin"})
        self.assertEqual(self._back("report"), reverse("report_form"))
        self.assertEqual(self._back("report_form"), reverse("role_select"))

    def test_the_network_chain_is_the_same_shape(self):
        self.client.post(reverse("role_select"), {"role": "Network Admin"})
        with _snmp_prom(_snmp_series()):
            self.client.post(reverse("network_report"), {"include_device": "core-switch"})
            self.assertEqual(self._back("network_report"), reverse("network_dashboard"))
            self.assertEqual(self._back("network_dashboard"), reverse("role_select"))

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_back_from_a_report_never_points_at_itself(self, _cap):
        """The open-report override sends other pages BACK to the report; on the report it
        would hand its own URL over, so the button pointed where you already were."""
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        self.client.post(reverse("report"), {"include_system": "Efin"})
        self.assertNotEqual(self._back("report"), reverse("report"))

    def test_a_single_role_holder_gets_no_back_from_the_picker(self):
        """Role Select auto-applies one role and would bounce straight back, so the button
        would return them to where they already are."""
        one = get_user_model().objects.create_user("justone", password="pw12345!")
        one.groups.add(Group.objects.get(name="System Admin"))
        self.client.logout()
        self.client.login(username="justone", password="pw12345!")
        self.client.get(reverse("role_select"))
        self.assertIsNone(self._back("report_form"))


class PlatformDerivedFromTheScrapeJob(TestCase):
    """The pickers label each system Windows / Linux / hybrid straight from prometheus.yml.

    Deriving it from the SCRAPE JOB (not a `windows_os_info` / `node_os_info` query) is what
    keeps the picker free — that screen deliberately does no Prometheus round-trip at all —
    so these tests pin the derivation to the topology file and nothing else.
    """

    def _topology(self, yml: str):
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".yml", text=True)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(yml)
        self.addCleanup(os.unlink, path)
        return gr.load_topology(path)

    def _platform(self, yml: str) -> str:
        systems = self._topology(yml)
        return gr.platform_of_system(systems[0].components)

    def test_a_windows_exporter_job_reads_as_windows(self):
        self.assertEqual(self._platform("""
scrape_configs:
  - job_name: windows_exporter
    static_configs:
      - targets: ["10.0.0.11:9182"]
        labels: {system: Alpha}
"""), "windows")

    def test_a_node_exporter_job_reads_as_linux(self):
        self.assertEqual(self._platform("""
scrape_configs:
  - job_name: node_exporter
    static_configs:
      - targets: ["10.0.0.21:9100"]
        labels: {system: Alpha}
"""), "linux")

    def test_a_system_scraped_by_both_exporters_is_hybrid(self):
        self.assertEqual(self._platform("""
scrape_configs:
  - job_name: windows_exporter
    static_configs:
      - targets: ["10.0.0.11:9182"]
        labels: {system: Alpha}
  - job_name: node_exporter
    static_configs:
      - targets: ["10.0.0.21:9100"]
        labels: {system: Alpha}
"""), "hybrid")

    def test_a_web_probe_does_not_make_a_system_hybrid(self):
        """blackbox targets are URLs that carry a `system` label and land in the same grouping.
        Counting one as a platform would put a hybrid badge on every system with a web link."""
        self.assertEqual(self._platform("""
scrape_configs:
  - job_name: windows_exporter
    static_configs:
      - targets: ["10.0.0.11:9182"]
        labels: {system: Alpha}
  - job_name: blackbox_http
    static_configs:
      - targets: ["https://portal.example.org"]
        labels: {system: Alpha}
"""), "windows")

    def test_an_unrecognised_job_leaves_the_platform_unknown(self):
        """Better a monogram letter than a confidently wrong penguin."""
        self.assertEqual(self._platform("""
scrape_configs:
  - job_name: swift_transactions
    static_configs:
      - targets: ["10.0.0.99:8080"]
        labels: {system: Alpha}
"""), "")

    def test_the_port_classifies_a_job_whose_name_says_nothing(self):
        """A site that named its jobs by location still gets a platform: the exporter default
        ports are a convention firm enough to read when the name offers nothing."""
        self.assertEqual(self._platform("""
scrape_configs:
  - job_name: hosts-datacentre-2
    static_configs:
      - targets: ["10.0.0.11:9182"]
        labels: {system: Alpha}
"""), "windows")

    def test_a_probe_job_on_a_host_port_is_still_not_a_platform(self):
        """The port fallback must not fire for blackbox — its targets are URLs, and a probe
        job pointed at :9100 would otherwise be labelled a Linux host."""
        self.assertEqual(self._platform("""
scrape_configs:
  - job_name: windows_exporter
    static_configs:
      - targets: ["10.0.0.11:9182"]
        labels: {system: Alpha}
  - job_name: blackbox_probe
    static_configs:
      - targets: ["10.0.0.30:9100"]
        labels: {system: Alpha}
"""), "windows")


class TheSystemPickerShowsThePlatform(TestCase):
    """The glyph replaces the monogram letter, so the tile must never end up blank."""

    def setUp(self):
        self.u = get_user_model().objects.create_user("platadm", password="pw12345!")
        self.u.groups.add(Group.objects.get(name="System Admin"))
        self.client.login(username="platadm", password="pw12345!")

    def _picker(self, systems):
        with mock.patch("reports.views.list_systems", return_value=systems):
            return self.client.get(reverse("report_form")).content.decode()

    def test_a_windows_system_gets_the_windows_glyph_and_an_accessible_name(self):
        html = self._picker([{"name": "Alpha", "hosts": 2, "platform": "windows"}])
        self.assertIn("os-glyph os-windows", html)
        self.assertIn('aria-label="Windows"', html)

    def test_a_hybrid_system_shows_both_glyphs(self):
        html = self._picker([{"name": "Alpha", "hosts": 6, "platform": "hybrid"}])
        self.assertIn("os-windows", html)
        self.assertIn("os-linux", html)
        self.assertIn("sys-os--hybrid", html)

    def test_an_unknown_platform_falls_back_to_the_monogram_letter(self):
        html = self._picker([{"name": "Zeta", "hosts": 1, "platform": ""}])
        self.assertNotIn("os-glyph", html)
        # the badge is the ONLY thing in that slot, so an empty one is an empty tile
        self.assertRegex(html, r'class="sys-mono"[^>]*>\s*Z\s*</span>')

    def test_no_template_comment_text_reaches_the_screen(self):
        """Django's {# #} is SINGLE-LINE. Spanning it across lines renders it as literal
        prose — and inside the tile loop that would print a paragraph of developer notes on
        every system. The same guard the network report already carries, on the picker that
        now explains its glyph in a comment."""
        html = self._picker([{"name": "Alpha", "hosts": 2, "platform": "windows"}])
        visible = re.sub(r"<script.*?</script>", "", html, flags=re.S)
        visible = re.sub(r"<style.*?</style>", "", visible, flags=re.S)
        visible = re.sub(r"<[^>]+>", " ", visible)
        for leak in ("{#", "#}", "endcomment", "comment %}"):
            self.assertNotIn(leak, visible, "template comment syntax leaked: " + leak)


class TheTopologyPlatformDrivesConnect(TestCase):
    """Connect used to read the OS from the exporter PORT alone. The job name is the better
    signal, so a host scraped on a non-default port now still gets offered its protocol."""

    def test_the_job_derived_os_wins_over_the_port(self):
        from .connect import build_host
        h = build_host("Alpha", "app", "10.0.0.11:9999", None, "windows")
        self.assertEqual(h["os"], "windows")
        self.assertEqual(h["protocol"], "rdp")
        self.assertTrue(h["connectable"])

    def test_the_port_still_answers_when_no_hint_is_given(self):
        from .connect import build_host
        self.assertEqual(build_host("A", "l", "10.0.0.21:9100", None)["os"], "linux")

    def _connect_page(self, hosts):
        from .connect import build_host
        systems = [{"name": "Alpha",
                    "hosts": [build_host("Alpha", lbl, inst, {}, os_) for lbl, inst, os_ in hosts],
                    "up_count": 0, "down_count": 0}]
        with mock.patch("reports.connect.inventory", return_value=systems):
            return self.client.get(reverse("connect")).content.decode()

    def test_the_connect_row_carries_the_platform_glyph(self):
        u = get_user_model().objects.create_user("cxadm", password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))
        self.client.login(username="cxadm", password="pw12345!")
        html = self._connect_page([("app", "10.0.0.11:9182", "windows"),
                                   ("db", "10.0.0.21:9100", "linux")])
        self.assertIn("os-glyph os-windows", html)
        self.assertIn("os-glyph os-linux", html)

    def test_no_template_comment_text_reaches_the_connect_screen(self):
        """Django's {# #} is SINGLE-LINE; the glyph on this page is introduced by a comment."""
        u = get_user_model().objects.create_user("cxadm2", password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))
        self.client.login(username="cxadm2", password="pw12345!")
        html = self._connect_page([("app", "10.0.0.11:9182", "windows")])
        visible = re.sub(r"<script.*?</script>", "", html, flags=re.S)
        visible = re.sub(r"<style.*?</style>", "", visible, flags=re.S)
        visible = re.sub(r"<[^>]+>", " ", visible)
        for leak in ("{#", "#}", "endcomment", "comment %}"):
            self.assertNotIn(leak, visible, "template comment syntax leaked: " + leak)

    def test_a_legacy_component_degrades_to_unknown_rather_than_raising(self):
        """The report page derives the card's platform from the CACHED snapshot's components.
        One pickled before the field existed must read as unknown, not raise."""
        class Legacy:
            label, instance = "app", "10.0.0.11:9182"

        self.assertEqual(gr.platform_of_system([Legacy()]), "")

    def test_an_old_cached_snapshot_without_the_field_still_renders(self):
        """Snapshots are pickled into the cache. One captured BEFORE Component gained `os`
        unpickles without the attribute, and the connect strip must not 500 on it."""
        from .connect import hosts_from_snapshot

        class Legacy:                      # a Component as it was pickled pre-change
            label, instance = "app", "10.0.0.11:9182"

        systems = [type("S", (), {"name": "Alpha", "components": [Legacy()]})()]
        hosts = hosts_from_snapshot(systems, type("St", (), {"up": {}})())
        self.assertEqual(hosts["Alpha"][0]["os"], "windows")


class RoleGlyphs(TestCase):
    """Every role tile carries its own glyph, and the files behind them actually ship.

    The failure mode this guards is silent: a role added to the catalogue without an icon
    still renders (it falls back to its initial), and an icon whose file is missing still
    renders too — as a broken image on the first screen after sign-in, which is the worst
    place in the app to look unfinished.
    """

    def setUp(self):
        self.multi = get_user_model().objects.create_user("glyphs", password="pw12345!")
        self.multi.groups.add(Group.objects.get(name="System Admin"))
        self.multi.groups.add(Group.objects.get(name="Network Admin"))
        self.client.login(username="glyphs", password="pw12345!")

    def test_every_catalogue_role_has_a_glyph(self):
        for role in ROLE_NAMES:
            self.assertTrue(role_icon(role), f"{role} has no icon mapped")

    def test_every_glyph_file_exists(self):
        """A mapping is a promise about a file. Checked against the source tree rather than
        the manifest so the test fails at authoring time, not only after collectstatic."""
        import pathlib

        static_dir = pathlib.Path(settings.BASE_DIR) / "static"
        for role in ROLE_NAMES:
            self.assertTrue((static_dir / role_icon(role)).is_file(),
                            f"{role}: {role_icon(role)} is not in static/")

    def test_no_two_roles_share_a_glyph(self):
        """Five tiles wearing four symbols is a picker that cannot be read at a glance —
        which is the only reason to have icons rather than the initials they replaced."""
        used = [role_icon(r) for r in ROLE_NAMES]
        self.assertEqual(len(set(used)), len(used), "two roles share an icon")

    def test_the_picker_renders_each_glyph(self):
        body = self.client.get(reverse("role_select")).content.decode()
        for role in ROLE_NAMES:
            stem = role_icon(role).rsplit("/", 1)[-1].rsplit(".", 1)[0]
            self.assertIn(stem, body, f"{role}'s glyph is missing from the picker")

    def test_an_uncatalogued_role_falls_back_to_its_initial(self):
        """A Keycloak realm role with no entry here must not borrow another role's symbol."""
        self.assertEqual(role_icon("Some Future Role"), "")

    def test_the_two_deliberate_swaps_stay_swapped(self):
        """Administrator administers PEOPLE, so it takes the figure-at-a-console; System
        Admin's estate is the interlinked set of business systems, so it takes the node
        graph. Both read backwards from their filenames, which is exactly why a later tidy-up
        would "correct" them — this pins the intent.

        The node graph is kept away from Network Admin on purpose: two link-diagrams side by
        side read as one domain split in half rather than as two different jobs.
        """
        self.assertIn("system-administration", role_icon("Administrator"))
        self.assertIn("neural-networks", role_icon("System Admin"))
        self.assertIn("network-infrastructure", role_icon("Network Admin"))

# =========================================================================================
_FIXTURE_YML = """\
# Topology for the estate.
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  scrape_timeout: 10s

storage:
  tsdb:
    out_of_order_time_window: 30d

rule_files:
  - "alerts.yml"

scrape_configs:
  - job_name: "windows_exporter"
    scrape_interval: 15s
    static_configs:
      - targets: ["10.0.201.3:9182"]
        labels:
          app: "windows"
          system: "Efin"
          display: "Efin DB"
      - targets: ["10.0.212.3:9182"]
        labels:
          app: "windows"
          system: "Temenos"
          display: "Temenos/T24 App"
          tier: "gold"

  - job_name: "blackbox_http"
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets: ["https://rtgs.rbz.co.zw/"]
        labels:
          system: "RTGS"
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
"""


class PrometheusConfigBase(TestCase):
    """The labelled form and the raw editor are two views of ONE file with ONE history.

    Nothing here touches disk: the config both screens work from is the newest
    PrometheusConfigRevision, so seeding one is the whole fixture. The live file is only ever
    reached through prometheus_admin, which is mocked — these tests must never invoke promtool
    or restart a Windows service.
    """

    def setUp(self):
        PrometheusConfigRevision.objects.create(note="fixture", content=_FIXTURE_YML)
        self.admin = get_user_model().objects.create_user("cfgadmin", password="pw12345!")
        self.admin.groups.add(Group.objects.get(name="Administrator"))
        self.client.login(username="cfgadmin", password="pw12345!")

    def current(self) -> dict:
        """The newest revision, parsed — what the next form load will show."""
        return yaml.safe_load(PrometheusConfigRevision.current().content)

    def post_data(self, **overrides) -> dict:
        """The exact fields the rendered form submits for the fixture, unchanged."""
        data = {
            "action": "save",
            "g_scrape_interval": "15s", "g_evaluation_interval": "15s", "g_scrape_timeout": "10s",
            "storage_ooo_window": "30d", "rule_files": "alerts.yml",
            "job__0__name": "windows_exporter", "job__0__scrape_interval": "15s",
            "job__0__scrape_timeout": "", "job__0__metrics_path": "", "job__0__scheme": "",
            "sc__0__0__targets": "10.0.201.3:9182",
            "sc__0__0__l_app": "windows", "sc__0__0__l_system": "Efin",
            "sc__0__0__l_display": "Efin DB", "sc__0__0__l_role": "",
            "sc__0__1__targets": "10.0.212.3:9182",
            "sc__0__1__l_app": "windows", "sc__0__1__l_system": "Temenos",
            "sc__0__1__l_display": "Temenos/T24 App", "sc__0__1__l_role": "",
            "sc__0__1__xkey__0": "tier", "sc__0__1__xval__0": "gold",
            "job__1__name": "blackbox_http", "job__1__scrape_interval": "",
            "job__1__scrape_timeout": "", "job__1__metrics_path": "/probe", "job__1__scheme": "",
            "sc__1__0__targets": "https://rtgs.rbz.co.zw/",
            "sc__1__0__l_app": "", "sc__1__0__l_system": "RTGS",
            "sc__1__0__l_display": "", "sc__1__0__l_role": "",
        }
        data.update(overrides)
        return data


class PrometheusConfigForm(PrometheusConfigBase):
    def test_requires_administrator(self):
        u = get_user_model().objects.create_user("cfgnope", password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))
        self.client.login(username="cfgnope", password="pw12345!")
        for name in ("configuration", "config_yaml", "config_role_scopes"):
            self.assertEqual(self.client.get(reverse(name)).status_code, 302, name)

    def test_the_form_reads_the_same_revision_the_raw_editor_does(self):
        """The point of the merge: one source, not two."""
        resp = self.client.get(reverse("configuration"))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context["yaml_source"]["from_revision"])
        self.assertEqual(resp.context["yaml_source"]["revision"],
                         PrometheusConfigRevision.current())

    def test_form_shows_every_value_in_the_config(self):
        view = self.client.get(reverse("configuration")).context["view"]
        self.assertEqual(view["global"]["scrape_interval"], "15s")
        self.assertEqual(view["storage_out_of_order"], "30d")
        self.assertEqual(view["rule_files_text"], "alerts.yml")
        self.assertEqual([j["job_name"] for j in view["jobs"]],
                         ["windows_exporter", "blackbox_http"])
        efin = view["jobs"][0]["groups"][0]
        self.assertEqual(efin["targets_text"], "10.0.201.3:9182")
        self.assertEqual(efin["known"]["system"], "Efin")
        self.assertEqual(efin["known"]["display"], "Efin DB")
        # a label outside the well-known four still appears, as an editable extra row
        self.assertEqual(view["jobs"][0]["groups"][1]["extra"],
                         [{"i": 0, "key": "tier", "value": "gold"}])
        self.assertEqual(view["systems"], ["Efin", "RTGS", "Temenos"])
        # keys the form doesn't model are surfaced read-only rather than dropped
        self.assertIn("relabel_configs", view["jobs"][1]["preserved"])
        self.assertIn("params", view["jobs"][1]["preserved"])

    def test_saving_records_a_revision_and_does_not_touch_the_live_file(self):
        with mock.patch("reports.prometheus_admin.write_and_restart") as war:
            resp = self.client.post(reverse("configuration"), self.post_data())
        self.assertRedirects(resp, reverse("configuration"), fetch_redirect_response=False)
        self.assertEqual(PrometheusConfigRevision.objects.count(), 2)
        war.assert_not_called()          # Save is not Apply — nothing live changed

    def test_saving_unchanged_leaves_the_config_equivalent(self):
        before = self.current()
        self.client.post(reverse("configuration"), self.post_data())
        self.assertEqual(self.current(), before)

    def test_apply_goes_through_promtool_and_restarts(self):
        """Apply must use the same gate as the raw editor — never write the file itself."""
        with mock.patch("reports.prometheus_admin.write_and_restart",
                        return_value=(True, "validated, rewritten and restarted")) as war:
            self.client.post(reverse("configuration"), self.post_data(action="apply"))
        war.assert_called_once()
        # what it was handed is the text of the revision it just recorded
        self.assertEqual(war.call_args.args[0], PrometheusConfigRevision.current().content)

    def test_a_rejected_apply_still_keeps_the_edit_as_a_revision(self):
        """promtool refusing must not throw the admin's work away."""
        with mock.patch("reports.prometheus_admin.write_and_restart",
                        return_value=(False, "Rejected — promtool found a problem")):
            resp = self.client.post(reverse("configuration"),
                                    self.post_data(action="apply",
                                                   **{"sc__0__0__l_display": "Efin Database"}),
                                    follow=True)
        self.assertEqual(PrometheusConfigRevision.objects.count(), 2)
        self.assertContains(resp, "promtool found a problem")
        labels = self.current()["scrape_configs"][0]["static_configs"][0]["labels"]
        self.assertEqual(labels["display"], "Efin Database")

    def test_the_revision_note_is_recorded(self):
        self.client.post(reverse("configuration"), self.post_data(note="widened Efin"))
        self.assertEqual(PrometheusConfigRevision.current().note, "widened Efin")
        self.assertEqual(PrometheusConfigRevision.current().created_by, self.admin)

    def test_editing_a_label_is_written_to_the_revision(self):
        self.client.post(reverse("configuration"),
                         self.post_data(**{"sc__0__0__l_display": "Efin Database"}))
        labels = self.current()["scrape_configs"][0]["static_configs"][0]["labels"]
        self.assertEqual(labels["display"], "Efin Database")
        self.assertEqual(labels["system"], "Efin")

    def test_adding_a_target_group_lands_in_the_right_job(self):
        self.client.post(reverse("configuration"), self.post_data(**{
            "sc__0__2__targets": "10.0.201.9:9182\n10.0.201.10:9182",
            "sc__0__2__l_app": "windows", "sc__0__2__l_system": "Efin",
            "sc__0__2__l_display": "Efin App", "sc__0__2__l_role": "app",
        }))
        groups = self.current()["scrape_configs"][0]["static_configs"]
        self.assertEqual(len(groups), 3)
        self.assertEqual(groups[2]["targets"], ["10.0.201.9:9182", "10.0.201.10:9182"])
        self.assertEqual(groups[2]["labels"]["role"], "app")

    def test_removing_a_group_removes_only_that_group(self):
        """Rows are addressed by their original index, so a gap must not shift its neighbours."""
        data = self.post_data()
        for k in [k for k in data if k.startswith("sc__0__0__")]:
            del data[k]
        self.client.post(reverse("configuration"), data)
        groups = self.current()["scrape_configs"][0]["static_configs"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["labels"]["system"], "Temenos")

    def test_unmodelled_job_keys_survive_a_save(self):
        self.client.post(reverse("configuration"),
                         self.post_data(**{"job__1__metrics_path": "/probe2"}))
        job = self.current()["scrape_configs"][1]
        self.assertEqual(job["metrics_path"], "/probe2")
        self.assertEqual(job["params"], {"module": ["http_2xx"]})
        self.assertEqual(job["relabel_configs"],
                         [{"source_labels": ["__address__"], "target_label": "__param_target"}])

    def test_a_bad_duration_records_nothing(self):
        resp = self.client.post(reverse("configuration"),
                                self.post_data(g_scrape_interval="15 seconds"))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(any("15 seconds" in e for e in resp.context["errors"]))
        self.assertEqual(PrometheusConfigRevision.objects.count(), 1)

    def test_a_bad_label_name_records_nothing(self):
        resp = self.client.post(reverse("configuration"), self.post_data(**{
            "sc__0__0__xkey__0": "2bad", "sc__0__0__xval__0": "x"}))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context["errors"])
        self.assertEqual(PrometheusConfigRevision.objects.count(), 1)

    def test_duplicate_job_names_are_rejected(self):
        resp = self.client.post(reverse("configuration"),
                                self.post_data(job__1__name="windows_exporter"))
        self.assertTrue(any("unique" in e for e in resp.context["errors"]))

    def test_a_rejected_save_gives_the_admin_their_own_typing_back(self):
        resp = self.client.post(reverse("configuration"),
                                self.post_data(g_scrape_interval="15 seconds"))
        self.assertEqual(resp.context["view"]["global"]["scrape_interval"], "15 seconds")

    def test_an_unparseable_revision_explains_itself_instead_of_crashing(self):
        # a tab for indentation — the classic hand-edit that YAML rejects outright, and
        # exactly the mistake this form exists to stop people making
        PrometheusConfigRevision.objects.create(note="broken", content="global:\n\ta: 1\n")
        resp = self.client.get(reverse("configuration"))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("not valid YAML", resp.context["load_error"])

    def test_the_saved_config_still_loads_as_topology(self):
        """The whole point: whatever the form writes, the report engine can still read."""
        self.client.post(reverse("configuration"), self.post_data(**{
            "sc__0__2__targets": "10.0.201.9:9182", "sc__0__2__l_system": "Efin",
            "sc__0__2__l_display": "Efin App",
        }))
        out = pathlib.Path(tempfile.mkdtemp(prefix="promtopo_")) / "prometheus.yml"
        self.addCleanup(shutil.rmtree, str(out.parent), True)
        out.write_text(PrometheusConfigRevision.current().content, encoding="utf-8")
        systems = gr.load_topology(str(out))
        self.assertEqual(sorted(s.name for s in systems), ["Efin", "RTGS", "Temenos"])
        self.assertEqual(len(next(s for s in systems if s.name == "Efin").components), 2)


class PrometheusYamlView(PrometheusConfigBase):
    def test_it_shows_the_current_revision_verbatim(self):
        resp = self.client.get(reverse("config_yaml"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["raw"], _FIXTURE_YML)

    def test_download(self):
        resp = self.client.get(reverse("config_yaml"), {"download": "1"})
        self.assertIn("attachment", resp["Content-Disposition"])
        self.assertEqual(resp.content.decode(), _FIXTURE_YML)

    def test_it_follows_the_form_after_a_save(self):
        """Proves the two screens share a source rather than each holding their own copy."""
        self.client.post(reverse("configuration"),
                         self.post_data(**{"sc__0__0__l_display": "Efin Database"}))
        raw = self.client.get(reverse("config_yaml")).context["raw"]
        self.assertIn("Efin Database", raw)
        self.assertEqual(raw, PrometheusConfigRevision.current().content)

    def test_there_is_no_second_write_path(self):
        """promconfig must not grow its own file-writing/reload back door again."""
        from . import promconfig
        for gone in ("save", "reload_prometheus", "backups", "file_info", "yaml_path"):
            self.assertFalse(hasattr(promconfig, gone),
                             f"promconfig.{gone} is back — writes belong to prometheus_admin")


class RoleScopeConfig(PrometheusConfigBase):
    def test_systems_come_from_the_same_config(self):
        resp = self.client.get(reverse("config_role_scopes"))
        self.assertEqual(resp.context["systems"], ["Efin", "RTGS", "Temenos"])

    def test_saving_a_scope(self):
        self.client.post(reverse("config_role_scopes"), {
            "systems__System Admin": ["Efin", "Temenos"],
            "systems__Network Admin": ["RTGS"],
        })
        self.assertEqual(set(RoleScope.objects.get(role="System Admin").systems),
                         {"Efin", "Temenos"})
        self.assertEqual(RoleScope.objects.get(role="Gov Systems Admin").systems, [])

    def test_a_system_not_in_the_config_is_ignored(self):
        self.client.post(reverse("config_role_scopes"),
                         {"systems__System Admin": ["Efin", "MadeUp"]})
        self.assertEqual(RoleScope.objects.get(role="System Admin").systems, ["Efin"])
