# Dumont addition: export command, bootstrap script and the full rollout round trip.
# Not upstream Plane. The bootstrap script lives at the repo root (scripts/dumont/); when the
# tests run inside the API container (apps/api only) those tests are skipped.

import csv
import importlib.util
import io
import json
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from plane.dumont.access.sync import run_full_sync
from plane.tests.unit.dumont.access.conftest import (
    BASE_URL,
    ORG_ID,
    PROJECT_ID,
    make_project,
    make_user,
    pr_member,
    ws_member,
)


def _find_script():
    # Repo root in a checkout; `/` inside the API container when scripts/ is mounted at /scripts.
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "scripts" / "dumont" / "zitadel_access_bootstrap.py"
        if candidate.exists():
            return candidate
    return Path("/nonexistent/scripts/dumont/zitadel_access_bootstrap.py")


SCRIPT = _find_script()
PAT = "fake-admin-pat-do-not-print"


@pytest.fixture
def bootstrap():
    if not SCRIPT.exists():
        pytest.skip("scripts/dumont is not available in this checkout (API-only container)")
    spec = importlib.util.spec_from_file_location("zitadel_access_bootstrap", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def plane_world(db, workspace, create_user, access_env, create_bot_user, fake_zitadel):
    mo = make_project(workspace, "MO", create_user)
    odd = make_project(workspace, "A B", create_user)  # cannot be a role key
    pr_member(mo, create_user, 20)
    pr_member(odd, create_user, 20)
    linked = make_user("linked@example.test", sub="sub-linked")
    legacy = make_user("legacy@example.test")
    ws_member(workspace, linked, 15)
    ws_member(workspace, legacy, 5)
    pr_member(mo, linked, 15)
    pr_member(mo, legacy, 5)
    ws_member(workspace, create_bot_user, 20)
    # owner create_user (admin) has a Dumont login too
    from plane.db.models import Account

    Account.objects.create(user=create_user, provider="dumont", provider_account_id="sub-owner", access_token="x")
    # both Dumont logins belong to the Dumont organisation in ZITADEL
    fake_zitadel.org_users.update({"sub-linked": ORG_ID, "sub-owner": ORG_ID})
    access_env("dry-run")
    return {"mo": mo, "linked": linked, "legacy": legacy, "set_mode": access_env}


def _export(tmp_path, fmt="json"):
    target = tmp_path / f"export.{fmt}"
    out = io.StringIO()
    call_command("dumont_access_export", "--format", fmt, "--output", str(target), stdout=out)
    return target, out.getvalue()


@pytest.mark.unit
@pytest.mark.django_db
class TestExport:
    def test_json(self, plane_world, tmp_path):
        target, summary = _export(tmp_path)
        data = json.loads(target.read_text())
        assert data["format"] == "hangar-zitadel-access-export/v1" and data["workspace"] == "test-workspace"
        keys = {r["key"] for r in data["roles"]}
        assert {"hangar.workspace.member", "hangar.project.mo.admin", "hangar.project.mo.guest"} <= keys
        assert not any(".a b." in k or "a_b" in k for k in keys)
        users = {u["email"]: u for u in data["users"]}
        assert users["linked@example.test"]["zitadel_user_id"] == "sub-linked"
        assert users["linked@example.test"]["roles"] == ["hangar.project.mo.member", "hangar.workspace.member"]
        assert users["legacy@example.test"]["linked"] is False
        assert users["legacy@example.test"]["note"] == "no Dumont login yet"
        assert users["test@plane.so"]["roles"] == ["hangar.project.mo.admin", "hangar.workspace.admin"]
        assert not any(u.startswith("bot-") for u in users)
        assert any(s.get("kind") == "project" and s.get("identifier") == "A B" for s in data["skipped"])
        assert any(s.get("reason") == "bot" for s in data["skipped"])
        assert "3 users" in summary

    def test_csv(self, plane_world, tmp_path):
        target, _ = _export(tmp_path, "csv")
        rows = list(csv.DictReader(target.read_text().splitlines()))
        assert {"email", "zitadel_user_id", "linked", "role_key", "note"} == set(rows[0])
        assert {"linked@example.test", "legacy@example.test", "test@plane.so"} == {r["email"] for r in rows}

    def test_missing_workspace(self, plane_world, monkeypatch):
        with pytest.raises(CommandError):
            call_command("dumont_access_export", "--workspace", "nope", stdout=io.StringIO())


@pytest.mark.unit
@pytest.mark.django_db
class TestSyncCommand:
    def test_dry_run_json(self, plane_world, fake_zitadel):
        fake_zitadel.roles = ["hangar.workspace.member"]
        out = io.StringIO()
        call_command("dumont_access_sync", "--mode", "dry-run", "--json", stdout=out)
        report = json.loads(out.getvalue())
        assert report["status"] == "dry_run" and report["managed"]["workspace"] is True

    def test_human_output(self, plane_world, fake_zitadel):
        fake_zitadel.roles = ["hangar.workspace.member"]
        out = io.StringIO()
        call_command("dumont_access_sync", "--mode", "dry-run", stdout=out)
        text = out.getvalue()
        assert "status: dry_run" in text and "managed workspace: yes" in text

    def test_error_exit(self, plane_world, fake_zitadel):
        fake_zitadel.fail = 500
        with pytest.raises(CommandError) as exc:
            call_command("dumont_access_sync", "--mode", "dry-run", stdout=io.StringIO())
        assert exc.value.returncode == 1

    def test_brake_exit(self, plane_world, fake_zitadel, monkeypatch):
        plane_world["set_mode"]("enforce")
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "0")
        fake_zitadel.roles = ["hangar.workspace.member", "hangar.workspace.admin"]
        fake_zitadel.grant("sub-owner", "hangar.workspace.admin")
        with pytest.raises(CommandError) as exc:
            call_command("dumont_access_sync", stdout=io.StringIO())
        assert exc.value.returncode == 2

    def test_max_removals_flag_overrides_the_brake_once(self, plane_world, fake_zitadel, monkeypatch):
        plane_world["set_mode"]("enforce")
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "0")
        fake_zitadel.roles = ["hangar.workspace.member", "hangar.workspace.admin"]
        fake_zitadel.grant("sub-owner", "hangar.workspace.admin")
        out = io.StringIO()
        call_command("dumont_access_sync", "--mode", "dry-run", stdout=out)
        losing = int(out.getvalue().count("deactivate"))
        assert losing >= 1
        call_command("dumont_access_sync", "--max-removals", "50", "--json", stdout=(out := io.StringIO()))
        assert json.loads(out.getvalue())["status"] == "applied"
        with pytest.raises(CommandError) as exc:
            call_command("dumont_access_sync", "--max-removals", "-1", stdout=io.StringIO())
        assert exc.value.returncode == 1

    def test_enforce_refused_when_env_not_enforce(self, plane_world, fake_zitadel):
        with pytest.raises(CommandError):
            call_command("dumont_access_sync", "--mode", "enforce", stdout=io.StringIO())
        assert fake_zitadel.calls == []


def _session_for(fake):
    import requests

    session = requests.Session()
    session.mount("https://", fake)
    session.mount("http://", fake)
    return session


def _run_script(bootstrap, fake, export_path, *extra, env=None):
    out = io.StringIO()
    env = {"ZITADEL_ADMIN_PAT": PAT} if env is None else env
    code = bootstrap.main(
        [str(export_path), "--zitadel-url", BASE_URL, "--project-id", PROJECT_ID, "--org-id", ORG_ID, *extra],
        session=_session_for(fake),
        out=out,
        env=env,
    )
    return code, out.getvalue()


@pytest.mark.unit
@pytest.mark.django_db
class TestBootstrapScript:
    def test_plan_is_default_and_writes_nothing(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        fake_zitadel.issued.add(PAT)
        fake_zitadel.add_user("zitadel-legacy", "LEGACY@example.test")
        export_path, _ = _export(tmp_path)
        code, text = _run_script(bootstrap, fake_zitadel, export_path)
        assert code == 0 and "PLAN" in text
        assert fake_zitadel.writes == []
        assert "legacy@example.test: hangar.project.mo.guest, hangar.workspace.guest  [by e-mail]" in text
        assert PAT not in text

    def test_apply_requires_yes(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        export_path, _ = _export(tmp_path)
        with pytest.raises(SystemExit):
            _run_script(bootstrap, fake_zitadel, export_path, "--apply")
        assert fake_zitadel.calls == []

    def test_requires_pat(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        export_path, _ = _export(tmp_path)
        with pytest.raises(SystemExit):
            _run_script(bootstrap, fake_zitadel, export_path, env={})

    def test_round_trip_export_bootstrap_enforce(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        """off -> export -> bootstrap -> enforce changes nothing for people who already had access."""
        fake_zitadel.issued.add(PAT)
        fake_zitadel.roles = ["hangar_reader", "hangar_writer"]
        fake_zitadel.grant("sub-linked", "hangar_reader")  # an existing MCP grant must be kept
        fake_zitadel.add_user("zitadel-legacy", "legacy@example.test")
        export_path, _ = _export(tmp_path)

        code, text = _run_script(bootstrap, fake_zitadel, export_path, "--apply", "--yes")
        assert code == 0, text
        assert PAT not in text
        linked_grant = [g for g in fake_zitadel.grants if g["userId"] == "sub-linked"]
        assert len(linked_grant) == 1
        assert set(linked_grant[0]["roleKeys"]) == {
            "hangar_reader",
            "hangar.workspace.member",
            "hangar.project.mo.member",
        }
        assert "hangar.workspace.member" in fake_zitadel.roles

        # idempotent: a second apply writes nothing
        writes = len(fake_zitadel.writes)
        code, text = _run_script(bootstrap, fake_zitadel, export_path, "--apply", "--yes")
        assert code == 0 and len(fake_zitadel.writes) == writes

        # enforce now: nobody who had access loses it (legacy is kept until first Dumont login)
        plane_world["set_mode"]("enforce")
        report = run_full_sync()
        assert report["status"] == "applied", report
        assert report["changes"] == []

    def test_project_filter_and_skip_workspace(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        fake_zitadel.issued.add(PAT)
        export_path, _ = _export(tmp_path)
        code, text = _run_script(bootstrap, fake_zitadel, export_path, "--json", "--projects", "mo", "--skip-workspace")
        plan = json.loads(text)
        assert {r["key"] for r in plan["roles_to_create"]} == {
            "hangar.project.mo.admin",
            "hangar.project.mo.member",
            "hangar.project.mo.guest",
        }
        assert all(k.startswith("hangar.project.mo.") for g in plan["grants_to_create"] for k in g["role_keys"])
        assert any(s["reason"] == "not found in ZITADEL" for s in plan["skipped"])  # legacy not in fake users

    def test_org_boundary(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        """A Dumont login from another org gets nothing; a grant owned by another org is never updated."""
        fake_zitadel.issued.add(PAT)
        fake_zitadel.org_users["sub-linked"] = "999999999999999999"  # linked user lives in another org
        fake_zitadel.grant("sub-owner", "hangar_reader", grant_org="888", project_grant_id="pg-1")
        export_path, _ = _export(tmp_path)
        code, text = _run_script(bootstrap, fake_zitadel, export_path, "--json")
        assert code == 0, text
        plan = json.loads(text)
        assert {"user": "linked@example.test", "reason": "Dumont login belongs to another ZITADEL organisation"} in (
            plan["skipped"]
        )
        assert all(g["user_id"] != "sub-linked" for g in plan["grants_to_create"] + plan["grants_to_update"])
        # the owner's only grant is foreign: a new grant in the Dumont org is planned instead of an update
        assert [g["user_id"] for g in plan["grants_to_update"]] == []
        assert "sub-owner" in [g["user_id"] for g in plan["grants_to_create"]]
        user_searches = [c for c in fake_zitadel.api_calls("users/_search") if "inUserIdsQuery" in str(c[2])]
        assert user_searches, "linked users must be checked against the org"

    @pytest.mark.parametrize(
        "kwargs,reason",
        [
            ({"verified": False}, "e-mail match is outside the Dumont organisation or not verified"),
            (
                {"org": "999999999999999999", "leak": True},
                "e-mail match is outside the Dumont organisation or not verified",
            ),
        ],
    )
    def test_email_match_needs_verified_email_in_the_org(
        self, plane_world, fake_zitadel, bootstrap, tmp_path, kwargs, reason
    ):
        fake_zitadel.issued.add(PAT)
        fake_zitadel.add_user("zitadel-legacy", "legacy@example.test", **kwargs)
        export_path, _ = _export(tmp_path)
        code, text = _run_script(bootstrap, fake_zitadel, export_path, "--json")
        plan = json.loads(text)
        assert {"user": "legacy@example.test", "reason": reason} in plan["skipped"]
        assert all(g["user_id"] != "zitadel-legacy" for g in plan["grants_to_create"])

    def test_apply_prints_the_plan_first(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        fake_zitadel.issued.add(PAT)
        export_path, _ = _export(tmp_path)
        code, text = _run_script(bootstrap, fake_zitadel, export_path, "--apply", "--yes")
        assert code == 0, text
        assert text.index("APPLYING this plan:") < text.index("roles to create") < text.index("APPLIED")

    def test_update_rereads_the_grant_right_before_writing(
        self, plane_world, fake_zitadel, bootstrap, tmp_path, monkeypatch
    ):
        fake_zitadel.issued.add(PAT)
        fake_zitadel.roles = ["hangar_reader", "hangar_writer"]
        row = fake_zitadel.grant("sub-linked", "hangar_reader")
        export_path, _ = _export(tmp_path)
        real_apply = bootstrap.apply_plan

        def racing_apply(plan, zitadel, project_id):
            row["roleKeys"].append("hangar_writer")  # someone adds a key after the plan was read
            return real_apply(plan, zitadel, project_id)

        monkeypatch.setattr(bootstrap, "apply_plan", racing_apply)
        code, text = _run_script(bootstrap, fake_zitadel, export_path, "--apply", "--yes")
        assert code == 0, text
        assert set(row["roleKeys"]) == {
            "hangar_reader",
            "hangar_writer",
            "hangar.workspace.member",
            "hangar.project.mo.member",
        }

    @pytest.mark.parametrize(
        "attr,value,message", [("drop_result_on", "roles", "no 'result'"), ("truncate_after", 0, "empty page")]
    )
    def test_incomplete_answers_are_errors(self, plane_world, fake_zitadel, bootstrap, tmp_path, attr, value, message):
        fake_zitadel.issued.add(PAT)
        fake_zitadel.roles = ["hangar_reader"]
        setattr(fake_zitadel, attr, value)
        export_path, _ = _export(tmp_path)
        code, text = _run_script(bootstrap, fake_zitadel, export_path)
        assert code == 1 and message in text
        assert fake_zitadel.writes == []

    @pytest.mark.parametrize("org", ["2000:1", "2000 1"])
    def test_org_id_must_be_bare(self, plane_world, fake_zitadel, bootstrap, tmp_path, org):
        export_path, _ = _export(tmp_path)
        with pytest.raises(SystemExit):
            bootstrap.main(
                [str(export_path), "--zitadel-url", BASE_URL, "--project-id", PROJECT_ID, "--org-id", org],
                session=_session_for(fake_zitadel),
                out=io.StringIO(),
                env={"ZITADEL_ADMIN_PAT": PAT},
            )
        assert fake_zitadel.calls == []

    def test_org_id_defaults_to_the_shared_variable(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        fake_zitadel.issued.add(PAT)
        export_path, _ = _export(tmp_path)
        code = bootstrap.main(
            [str(export_path), "--zitadel-url", BASE_URL, "--project-id", PROJECT_ID],
            session=_session_for(fake_zitadel),
            out=io.StringIO(),
            env={"ZITADEL_ADMIN_PAT": PAT, "DUMONT_ZITADEL_ORG_ID": ORG_ID},
        )
        assert code == 0

    def test_zitadel_error_is_reported_without_pat(self, plane_world, fake_zitadel, bootstrap, tmp_path):
        export_path, _ = _export(tmp_path)
        fake_zitadel.fail = 403
        code, text = _run_script(bootstrap, fake_zitadel, export_path)
        assert code == 1 and "HTTP 403" in text and PAT not in text
