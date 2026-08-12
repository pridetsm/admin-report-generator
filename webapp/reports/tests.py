"""End-to-end smoke tests for the Report Builder.

The report engine's capture() needs a live Prometheus, so we patch capture_snapshot with a
synthetic snapshot built from generate_report's own dataclasses. Everything else — auth,
templates, the generate/download path, and the audit row — is exercised for real.
"""
import datetime
import io
import json
import re
import time

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from unittest import mock

import generate_report as gr

from . import folders
from . import keycloak as kc
from .directory import AuthConfig, HttpAuthBackend, search_directory
from .models import ReportSubmission, RoleRequest, SystemConfig
from .services import FlagVM, Snapshot, SystemVM, build_overview


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
    def test_refresh_reuses_snapshot_but_fresh_forces_new(self, cap):
        self.client.login(username="tester", password="pw12345!")
        pat = r'name="token" value="(\w+)"'

        # choose systems -> first capture, land on the report screen
        t1 = self._open_report("Efin")
        self.assertEqual(cap.call_count, 1)
        # a plain revisit of the report reuses the same snapshot (timer keeps running)
        t2 = re.search(pat, self.client.get(reverse("report")).content.decode()).group(1)
        self.assertEqual(t1, t2)
        self.assertEqual(cap.call_count, 1)
        # ?fresh=1 explicitly re-captures and mints a new token
        t3 = re.search(pat, self.client.get(reverse("report"), {"fresh": "1"}).content.decode()).group(1)
        self.assertNotEqual(t1, t3)
        self.assertEqual(cap.call_count, 2)

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
        self.assertEqual(r.context["back_label"], "Dashboard")
        # A report detail's parent is History (not home) — one level up the tree
        sub = ReportSubmission.objects.create(generated_by=self.user, theme="dark")
        r = self.client.get(reverse("submission_detail", args=[sub.pk]))
        self.assertEqual(r.context["back_url"], reverse("history"))
        self.assertEqual(r.context["back_label"], "History")

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
        self.assertEqual(web["value"], "1 | 0")

    def test_ldap_down_banner_lists_dependents(self):
        """When the LDAP probe reports down, the overview gets a red, top banner naming the
        dependent systems; up / unmonitored produce no LDAP banner."""
        gcms = gr.System("GCMS", [gr.Component("App/DB", "10.100.247.23:9182")])

        def store(ldap):
            return gr.Store(disk={}, ram={}, cpu={}, cob=1200.0, swift=1.0, services={"GCMS": []},
                            up={"10.100.247.23:9182": 1.0}, links={}, backups={}, ldap_up=ldap)

        cfg = gr.Config()
        down = build_overview(store(False), [gcms], cfg)["banners"]
        self.assertTrue(down and down[0]["band"] == "red" and "LDAP" in down[0]["head"])  # first = top priority
        self.assertIn("GCMS", down[0]["detail"])
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
                               "prometheus_yml": "y", "http_timeout": 5})()
        grm.load_config.return_value = cfg
        grm.load_topology.return_value = []
        grm.Prometheus.return_value = mock.MagicMock()
        grm.capture.return_value = mock.MagicMock(services={})
        from .services import capture_snapshot
        snap = capture_snapshot("tok")
        grm.Prometheus.assert_called_once_with("http://custom:9090", 5)   # admin override wins
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
                   oldest_ago=60, newest_ago=None, exists=1, folder_up=1, scanned_ago=30,
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
                  _folder_series(name="AGEING.IN", now=now, oldest_ago=1000) +
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
