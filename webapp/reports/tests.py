"""End-to-end smoke tests for the Report Builder.

The report engine's capture() needs a live Prometheus, so we patch capture_snapshot with a
synthetic snapshot built from generate_report's own dataclasses. Everything else — auth,
templates, the generate/download path, and the audit row — is exercised for real.
"""
import datetime
import io
import json
import pathlib
import re
import shutil
import tempfile

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from unittest import mock

import generate_report as gr
import yaml

from . import keycloak as kc
from .directory import AuthConfig, HttpAuthBackend, search_directory
from .models import ReportSubmission, RoleRequest, RoleScope, SystemConfig
from .roles import ALL_ROLES, ALL_ROLES_LABEL
from .services import FlagVM, Snapshot, SystemVM, build_overview


def _synthetic_snapshot(token: str, *, systems_filter=None, scope_label: str = "") -> Snapshot:
    """Stands in for capture_snapshot(); mirrors its signature so the role-scoping arguments
    the view now passes are exercised rather than swallowed."""
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
    flags = [FlagVM(f.key, f.text, f.band, f.category)
             for f in gr.flagged_for_system(store, sysm, cfg)]
    return Snapshot(
        token=token, captured_at=datetime.datetime(2026, 7, 17, 9, 0), prom_url=cfg.prom,
        systems=[SystemVM("Efin", 1, flags)], overview=build_overview(store, [sysm], cfg),
        scope_label=scope_label,
        _store=store, _systems=[sysm], _cfg=cfg,
    )


class ReportBuilderFlow(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("tester", password="pw12345!")
        self.user.groups.add(Group.objects.create(name="Report Users"))   # give them a role

    def test_form_requires_login(self):
        resp = self.client.get(reverse("report_form"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/accounts/login/", resp["Location"])

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_full_generate_flow(self, _cap):
        # report theme is now a user setting on the profile
        self.user.profile.default_report_theme = "light"
        self.user.profile.save()
        self.client.login(username="tester", password="pw12345!")

        # 1) form renders with the flagged system + a token
        resp = self.client.get(reverse("report_form"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Efin")
        token = re.search(r'name="token" value="(\w+)"', resp.content.decode()).group(1)

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
        resp = self.client.get(reverse("report_form"))
        token = re.search(r'name="token" value="(\w+)"', resp.content.decode()).group(1)

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
            resp = self.client.get(reverse("report_form"))
            token = re.search(r'name="token" value="(\w+)"', resp.content.decode()).group(1)
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

        t1 = re.search(pat, self.client.get(reverse("report_form")).content.decode()).group(1)
        # a plain refresh reuses the same snapshot (timer keeps running, no re-capture)
        t2 = re.search(pat, self.client.get(reverse("report_form")).content.decode()).group(1)
        self.assertEqual(t1, t2)
        self.assertEqual(cap.call_count, 1)
        # ?fresh=1 explicitly re-captures and mints a new token
        t3 = re.search(pat, self.client.get(reverse("report_form"), {"fresh": "1"}).content.decode()).group(1)
        self.assertNotEqual(t1, t3)
        self.assertEqual(cap.call_count, 2)

    @mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot)
    def test_author_autofills_from_profile(self, _cap):
        self.user.first_name = "Pride"; self.user.last_name = "Moyo"; self.user.save()
        self.user.profile.job_title = "Systems Administrator"
        self.user.profile.save()
        self.client.login(username="tester", password="pw12345!")
        token = re.search(r'name="token" value="(\w+)"',
                          self.client.get(reverse("report_form")).content.decode()).group(1)
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
        token = re.search(r'name="token" value="(\w+)"',
                          self.client.get(reverse("report_form")).content.decode()).group(1)
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


# =========================================================================================
#  Role selection — a multi-role user chooses a workspace instead of getting all of them
# =========================================================================================
class RoleSelection(TestCase):
    fixtures: list = []

    def setUp(self):
        self.user = get_user_model().objects.create_user("multi", password="pw12345!")
        for r in ("System Admin", "Network Admin"):
            self.user.groups.add(Group.objects.get(name=r))
        self.solo = get_user_model().objects.create_user("solo", password="pw12345!")
        self.solo.groups.add(Group.objects.get(name="System Admin"))

    def test_multi_role_user_is_sent_to_the_chooser(self):
        self.client.login(username="multi", password="pw12345!")
        resp = self.client.get(reverse("report_form"))
        self.assertRedirects(resp, reverse("role_select"))

    def test_single_role_user_is_not_asked(self):
        """One role is not a choice — select it silently and go straight to the dashboard."""
        self.client.login(username="solo", password="pw12345!")
        with mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot):
            resp = self.client.get(reverse("report_form"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.client.session["active_role"], "System Admin")

    def test_chooser_offers_every_held_role_plus_load_all(self):
        self.client.login(username="multi", password="pw12345!")
        resp = self.client.get(reverse("role_select"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([t["value"] for t in resp.context["tiles"]],
                         ["System Admin", "Network Admin"])
        self.assertEqual(resp.context["all_tile"]["value"], ALL_ROLES)
        self.assertContains(resp, "Load all my roles")
        self.assertNotContains(resp, "Gov Systems Admin")     # a role they don't hold

    def test_choosing_a_role_stores_it_and_returns_to_the_dashboard(self):
        self.client.login(username="multi", password="pw12345!")
        resp = self.client.post(reverse("role_select"), {"role": "Network Admin"})
        self.assertRedirects(resp, reverse("report_form"), fetch_redirect_response=False)
        self.assertEqual(self.client.session["active_role"], "Network Admin")

    def test_load_all_my_roles_is_accepted(self):
        self.client.login(username="multi", password="pw12345!")
        self.client.post(reverse("role_select"), {"role": ALL_ROLES})
        self.assertEqual(self.client.session["active_role"], ALL_ROLES)

    def test_a_role_the_user_does_not_hold_is_refused(self):
        self.client.login(username="multi", password="pw12345!")
        self.client.post(reverse("role_select"), {"role": "Gov Systems Admin"})
        self.assertFalse(self.client.session.get("active_role"))

    def test_switching_role_discards_the_cached_snapshot(self):
        """A snapshot captured under one role's scope must not be re-served under another."""
        self.client.login(username="multi", password="pw12345!")
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        with mock.patch("reports.views.capture_snapshot", side_effect=_synthetic_snapshot):
            self.client.get(reverse("report_form"))
        self.assertTrue(self.client.session.get("snapshot_token"))
        self.client.post(reverse("role_select"), {"role": "Network Admin"})
        self.assertIsNone(self.client.session.get("snapshot_token"))


class RoleScoping(TestCase):
    """The active role decides which systems the capture (and so the report) covers."""

    def setUp(self):
        self.user = get_user_model().objects.create_user("scoped", password="pw12345!")
        for r in ("System Admin", "Network Admin"):
            self.user.groups.add(Group.objects.get(name=r))
        RoleScope.objects.create(role="System Admin", systems=["Efin", "CRB"])
        RoleScope.objects.create(role="Network Admin", systems=["RTGS"])
        self.client.login(username="scoped", password="pw12345!")

    def _capture_kwargs(self):
        with mock.patch("reports.views.capture_snapshot",
                        side_effect=_synthetic_snapshot) as cap:
            self.client.get(reverse("report_form"))
        return cap.call_args.kwargs

    def test_one_role_scopes_to_that_roles_systems(self):
        self.client.post(reverse("role_select"), {"role": "System Admin"})
        kwargs = self._capture_kwargs()
        self.assertEqual(kwargs["systems_filter"], {"Efin", "CRB"})
        self.assertEqual(kwargs["scope_label"], "System Admin")

    def test_load_all_my_roles_unions_the_scopes(self):
        self.client.post(reverse("role_select"), {"role": ALL_ROLES})
        kwargs = self._capture_kwargs()
        self.assertEqual(kwargs["systems_filter"], {"Efin", "CRB", "RTGS"})
        self.assertEqual(kwargs["scope_label"], ALL_ROLES_LABEL)

    def test_an_unmapped_role_is_unrestricted(self):
        RoleScope.objects.filter(role="Network Admin").update(systems=[])
        self.client.post(reverse("role_select"), {"role": "Network Admin"})
        self.assertIsNone(self._capture_kwargs()["systems_filter"])

    def test_unmapped_role_makes_the_union_unrestricted_too(self):
        """Union with 'everything' is everything — it must not silently shrink to the mapped role."""
        RoleScope.objects.filter(role="Network Admin").update(systems=[])
        self.client.post(reverse("role_select"), {"role": ALL_ROLES})
        self.assertIsNone(self._capture_kwargs()["systems_filter"])

    def test_capture_filters_the_topology(self):
        """The filter is applied to the topology, so scoped-out systems are never queried."""
        with mock.patch("reports.services.build_overview", return_value={}), \
             mock.patch("reports.services.gr") as grm:
            cfg = type("Cfg", (), {"prom": "http://p:9090", "grafana": "g",
                                   "prometheus_yml": "y", "http_timeout": 5})()
            grm.load_config.return_value = cfg
            grm.load_topology.return_value = [
                gr.System("Efin", [gr.Component("DB", "1:9182")]),
                gr.System("RTGS", [gr.Component("App", "2:9100")]),
                gr.System("CRB", [gr.Component("Web", "3:9182")]),
            ]
            grm.Prometheus.return_value = mock.MagicMock()
            grm.capture.return_value = mock.MagicMock(services={})
            grm.flagged_for_system.return_value = []
            from .services import capture_snapshot as real_capture
            snap = real_capture("tok", systems_filter={"Efin", "CRB"}, scope_label="System Admin")
        self.assertEqual([s.name for s in snap.systems], ["Efin", "CRB"])
        self.assertEqual(snap.scoped_out, 1)
        self.assertEqual(snap.scope_label, "System Admin")


# =========================================================================================
#  Configuration — prometheus.yml as a validated form, and the screens around it
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
    """Every Configuration test works against a throwaway prometheus.yml, never the real one."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="promcfg_")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = pathlib.Path(self.dir) / "prometheus.yml"
        self.path.write_text(_FIXTURE_YML, encoding="utf-8")
        self.override = override_settings(PROMETHEUS_YML=str(self.path))
        self.override.enable()
        self.addCleanup(self.override.disable)

        self.admin = get_user_model().objects.create_user("cfgadmin", password="pw12345!")
        self.admin.groups.add(Group.objects.get(name="Administrator"))
        self.client.login(username="cfgadmin", password="pw12345!")

    def current(self) -> dict:
        return yaml.safe_load(self.path.read_text(encoding="utf-8"))

    def post_data(self, **overrides) -> dict:
        """The exact fields the rendered form submits for the fixture, unchanged."""
        data = {
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

    def test_form_shows_every_value_in_the_file(self):
        resp = self.client.get(reverse("configuration"))
        self.assertEqual(resp.status_code, 200)
        view = resp.context["view"]
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

    def test_saving_unchanged_leaves_the_file_equivalent(self):
        before = self.current()
        resp = self.client.post(reverse("configuration"), self.post_data())
        self.assertRedirects(resp, reverse("configuration"), fetch_redirect_response=False)
        self.assertEqual(self.current(), before)

    def test_editing_a_label_is_written_to_the_file(self):
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

    def test_a_bad_duration_writes_nothing(self):
        before = self.path.read_text(encoding="utf-8")
        resp = self.client.post(reverse("configuration"),
                                self.post_data(g_scrape_interval="15 seconds"))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(any("15 seconds" in e for e in resp.context["errors"]))
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_a_bad_label_name_writes_nothing(self):
        before = self.path.read_text(encoding="utf-8")
        resp = self.client.post(reverse("configuration"), self.post_data(**{
            "sc__0__0__xkey__0": "2bad", "sc__0__0__xval__0": "x"}))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context["errors"])
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_duplicate_job_names_are_rejected(self):
        resp = self.client.post(reverse("configuration"),
                                self.post_data(job__1__name="windows_exporter"))
        self.assertTrue(any("unique" in e for e in resp.context["errors"]))

    def test_a_rejected_save_gives_the_admin_their_own_typing_back(self):
        resp = self.client.post(reverse("configuration"),
                                self.post_data(g_scrape_interval="15 seconds"))
        self.assertEqual(resp.context["view"]["global"]["scrape_interval"], "15 seconds")

    def test_saving_keeps_a_timestamped_backup(self):
        original = self.path.read_text(encoding="utf-8")
        self.client.post(reverse("configuration"),
                         self.post_data(**{"sc__0__0__l_display": "Efin Database"}))
        baks = list(pathlib.Path(self.dir).glob("prometheus.yml.*.bak"))
        self.assertEqual(len(baks), 1)
        self.assertEqual(baks[0].read_text(encoding="utf-8"), original)

    def test_an_unparseable_file_explains_itself_instead_of_crashing(self):
        self.path.write_text("global:\n  scrape_interval: 15s\n :::\n", encoding="utf-8")
        resp = self.client.get(reverse("configuration"))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("not valid YAML", resp.context["load_error"])

    def test_the_saved_file_still_loads_as_topology(self):
        """The whole point: whatever the form writes, the report engine can still read."""
        self.client.post(reverse("configuration"), self.post_data(**{
            "sc__0__2__targets": "10.0.201.9:9182", "sc__0__2__l_system": "Efin",
            "sc__0__2__l_display": "Efin App",
        }))
        systems = gr.load_topology(str(self.path))
        self.assertEqual(sorted(s.name for s in systems), ["Efin", "RTGS", "Temenos"])
        self.assertEqual(len(next(s for s in systems if s.name == "Efin").components), 2)


class PrometheusYamlView(PrometheusConfigBase):
    def test_live_yaml_shows_the_file_verbatim(self):
        resp = self.client.get(reverse("config_yaml"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["raw"], _FIXTURE_YML)

    def test_download(self):
        resp = self.client.get(reverse("config_yaml"), {"download": "1"})
        self.assertIn("attachment", resp["Content-Disposition"])
        self.assertEqual(resp.content.decode(), _FIXTURE_YML)

    @mock.patch("reports.promconfig.reload_prometheus", return_value=(True, "reloaded"))
    def test_reload_button_asks_prometheus(self, rl):
        sc = SystemConfig.get()
        sc.prometheus_url = "http://p:9090"
        sc.save()
        resp = self.client.post(reverse("prometheus_reload"))
        self.assertRedirects(resp, reverse("configuration"), fetch_redirect_response=False)
        rl.assert_called_once_with("http://p:9090")

    def test_reload_requires_administrator(self):
        u = get_user_model().objects.create_user("noreload", password="pw12345!")
        u.groups.add(Group.objects.get(name="System Admin"))
        self.client.login(username="noreload", password="pw12345!")
        with mock.patch("reports.promconfig.reload_prometheus") as rl:
            self.assertEqual(self.client.post(reverse("prometheus_reload")).status_code, 302)
        rl.assert_not_called()


class RoleScopeConfig(PrometheusConfigBase):
    def test_systems_come_from_the_live_yaml(self):
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

    def test_a_system_not_in_the_yaml_is_ignored(self):
        self.client.post(reverse("config_role_scopes"),
                         {"systems__System Admin": ["Efin", "MadeUp"]})
        self.assertEqual(RoleScope.objects.get(role="System Admin").systems, ["Efin"])
