# Dumont addition: the reconciler against real models and a fake ZITADEL. Not upstream Plane.

import pytest
from django.core.cache import cache

from plane.db.models import ProjectMember, ProjectUserProperty, WorkspaceMember
from plane.dumont.access import hooks
from plane.dumont.access.sync import MANAGED_STATE_KEY, run_full_sync, run_user_sync
from plane.license.models import Instance, InstanceAdmin
from plane.tests.unit.dumont.access.conftest import (
    make_project,
    make_user,
    pr_member,
    pr_row,
    ws_member,
    ws_row,
)

WS_ROLES = ["hangar.workspace.admin", "hangar.workspace.member", "hangar.workspace.guest"]
MO_ROLES = ["hangar.project.mo.admin", "hangar.project.mo.member", "hangar.project.mo.guest"]


@pytest.fixture
def world(db, workspace, create_user, fake_zitadel, access_env):
    """Workspace 'test-workspace' (owner create_user = admin), projects MO (managed) and OPS (unmanaged).

    alice: linked, ws member, MO member     -> keeps
    bob:   linked, ws member, MO member     -> no grant: removed
    carol: linked, no rows                  -> granted: created
    dave:  linked, inactive ws row          -> granted admin: reactivated
    admin: linked, ws admin + MO admin      -> keeps (grant)
    """
    fake = fake_zitadel
    fake.roles = WS_ROLES + MO_ROLES + ["hangar_reader"]
    mo = make_project(workspace, "MO", create_user)
    ops = make_project(workspace, "OPS", create_user)
    users = {
        name: make_user(f"{name}@example.test", sub=f"sub-{name}")
        for name in ("alice", "bob", "carol", "dave", "admin")
    }
    ws_member(workspace, users["alice"], 15)
    ws_member(workspace, users["bob"], 15)
    ws_member(workspace, users["dave"], 15, is_active=False)
    ws_member(workspace, users["admin"], 20)
    pr_member(mo, users["alice"], 15)
    pr_member(mo, users["bob"], 15)
    pr_member(mo, users["admin"], 20)
    pr_member(ops, users["bob"], 15)
    pr_member(ops, users["admin"], 20)
    fake.grant("sub-alice", "hangar.workspace.member", "hangar.project.mo.member")
    fake.grant("sub-carol", "hangar.workspace.member", "hangar.project.mo.guest")
    fake.grant("sub-dave", "hangar.workspace.admin")
    fake.grant("sub-admin", "hangar.workspace.admin", "hangar.project.mo.admin", "hangar_writer")
    return {
        "fake": fake,
        "mo": mo,
        "ops": ops,
        "users": users,
        "workspace": workspace,
        "owner": create_user,
        "set_mode": access_env,
    }


def state(world):
    ws = world["workspace"]
    out = {}
    for row in WorkspaceMember.objects.filter(workspace=ws):
        out[("ws", row.member.email)] = (row.role, row.is_active)
    for row in ProjectMember.objects.filter(workspace=ws):
        out[(row.project.identifier, row.member.email)] = (row.role, row.is_active)
    return out


@pytest.mark.unit
@pytest.mark.django_db
class TestFullSync:
    def test_off_does_nothing(self, world):
        world["set_mode"]("off")
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "off"
        assert state(world) == before
        assert world["fake"].calls == []

    def test_dry_run_reports_and_writes_nothing(self, world):
        world["set_mode"]("dry-run")
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "dry_run"
        assert state(world) == before
        actions = sorted((c["scope"], c["email"], c["action"]) for c in report["changes"])
        assert actions == [
            ("MO", "bob@example.test", "deactivate"),
            ("MO", "carol@example.test", "create"),
            ("OPS", "bob@example.test", "deactivate"),
            ("workspace", "bob@example.test", "deactivate"),
            ("workspace", "carol@example.test", "create"),
            ("workspace", "dave@example.test", "reactivate"),
        ]
        assert report["managed"] == {"workspace": True, "projects": ["MO"]}
        # the owner (create_user) has no grant but is protected
        assert any(n["kind"] == "protected_kept" for n in report["notes"])

    def test_enforce_applies(self, world):
        report = run_full_sync()
        assert report["status"] == "applied", report
        assert report["applied"] == 6
        s = state(world)
        assert s[("ws", "bob@example.test")] == (15, False)
        assert s[("MO", "bob@example.test")] == (15, False)
        assert s[("OPS", "bob@example.test")] == (15, False)  # cascade, like Plane's remove member
        assert s[("ws", "carol@example.test")] == (15, True)
        assert s[("MO", "carol@example.test")] == (5, True)
        assert s[("ws", "dave@example.test")] == (20, True)
        assert s[("ws", "alice@example.test")] == (15, True)
        assert s[("ws", "test@plane.so")] == (20, True)  # owner untouched
        assert ProjectUserProperty.objects.filter(project=world["mo"], user=world["users"]["carol"]).count() == 1
        # rows are never hard-deleted
        assert WorkspaceMember.all_objects.filter(member=world["users"]["bob"]).count() == 1

    def test_enforce_is_idempotent(self, world):
        run_full_sync()
        after_first = state(world)
        report = run_full_sync()
        assert report["status"] == "applied" and report["changes"] == []
        assert state(world) == after_first

    def test_reactivating_project_member_reuses_row(self, world):
        run_full_sync()
        world["fake"].grant("sub-bob", "hangar.workspace.member", "hangar.project.mo.admin")
        run_full_sync()
        assert pr_row(world["mo"], world["users"]["bob"]).role == 20
        assert pr_row(world["mo"], world["users"]["bob"]).is_active
        assert ProjectMember.objects.filter(project=world["mo"], member=world["users"]["bob"]).count() == 1

    def test_create_with_leftover_user_property(self, world):
        carol = world["users"]["carol"]
        ProjectUserProperty.objects.create(project=world["mo"], user=carol, workspace=world["workspace"])
        report = run_full_sync()
        assert report["failed_scopes"] == []
        assert pr_row(world["mo"], carol).is_active

    @pytest.mark.parametrize("failure", [500, 401, "timeout", "badjson"])
    def test_zitadel_failure_changes_nothing(self, world, failure):
        world["fake"].fail = failure
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "error"
        assert state(world) == before

    def test_grants_failure_after_roles_changes_nothing(self, world):
        world["fake"].fail = 503
        world["fake"].fail_on = "grants"
        before = state(world)
        assert run_full_sync()["status"] == "error"
        assert state(world) == before

    def test_safety_brake(self, world, monkeypatch):
        world["fake"].grants.clear()  # ZITADEL suddenly answers "no grants at all"
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "aborted_brake"
        assert report["counts"]["deactivations"] > 5
        assert state(world) == before

    def test_brake_limit_is_configurable(self, world, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "2")
        assert run_full_sync()["status"] == "aborted_brake"  # bob loses 3 rows
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "3")
        assert run_full_sync()["status"] == "applied"

    def test_brake_not_applied_to_dry_run(self, world):
        world["set_mode"]("dry-run")
        world["fake"].grants.clear()
        assert run_full_sync()["status"] == "dry_run"

    def test_enforce_override_requires_env_enforce(self, world):
        world["set_mode"]("dry-run")
        report = run_full_sync(mode="enforce")
        assert report["status"] == "error" and "DUMONT_ACCESS_SYNC=enforce" in report["error"]

    def test_dry_run_override_while_off(self, world):
        world["set_mode"]("off")
        assert run_full_sync(mode="dry-run")["status"] == "dry_run"

    def test_incomplete_config(self, world, monkeypatch):
        monkeypatch.delenv("DUMONT_ACCESS_ZITADEL_KEY_JSON")
        report = run_full_sync()
        assert report["status"] == "error" and "DUMONT_ACCESS_ZITADEL_KEY_JSON" in report["error"]
        assert world["fake"].calls == []

    def test_missing_workspace(self, world, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_WORKSPACE_SLUG", "nope")
        assert run_full_sync()["status"] == "error"

    def test_pending_and_first_login(self, world):
        fake = world["fake"]
        fake.grant("sub-erin", "hangar.workspace.member", "hangar.project.mo.member", email="erin@example.test")
        report = run_full_sync()
        assert [p["zitadel_user_id"] for p in report["pending"]] == ["sub-erin"]
        # erin logs in with Dumont for the first time: the per-user sync applies her grants
        erin = make_user("erin@example.test", sub="sub-erin")
        report = run_user_sync(erin, "sub-erin")
        assert report["status"] == "applied", report
        assert ws_row(world["workspace"], erin).role == 15
        assert pr_row(world["mo"], erin).role == 15

    def test_unlinked_member_awaiting_login_is_kept(self, world):
        legacy = make_user("legacy@example.test")  # password login, no Dumont account yet
        ws_member(world["workspace"], legacy, 15)
        pr_member(world["mo"], legacy, 15)
        world["fake"].grant(
            "sub-legacy", "hangar.workspace.member", "hangar.project.mo.member", email="LEGACY@example.test"
        )
        run_full_sync()
        assert ws_row(world["workspace"], legacy).is_active
        assert pr_row(world["mo"], legacy).is_active

    def test_bots_and_instance_admins_untouched(self, world, create_bot_user):
        ws_member(world["workspace"], create_bot_user, 20)
        pr_member(world["mo"], create_bot_user, 20)
        ia = make_user("ia@example.test", sub="sub-ia")
        ws_member(world["workspace"], ia, 20)
        instance = Instance.objects.create(
            instance_name="t",
            instance_id="t",
            current_version="0",
            latest_version="0",
            last_checked_at="2026-01-01T00:00:00Z",
        )
        InstanceAdmin.objects.create(instance=instance, user=ia)
        report = run_full_sync()
        assert report["status"] == "applied"
        assert ws_row(world["workspace"], create_bot_user).is_active
        assert pr_row(world["mo"], create_bot_user).is_active
        assert ws_row(world["workspace"], ia).is_active

    def test_last_project_admin_never_removed(self, world):
        fake = world["fake"]
        for grant in fake.grants:
            if grant["userId"] == "sub-admin":
                grant["roleKeys"] = ["hangar.workspace.admin"]  # admin loses MO admin; MO has no other admin
        run_full_sync()
        assert pr_row(world["mo"], world["users"]["admin"]).is_active
        assert pr_row(world["mo"], world["users"]["admin"]).role == 20

    def test_stale_row_is_skipped(self, world, monkeypatch):
        from plane.dumont.access import sync as sync_module

        real_apply = sync_module.apply_plan

        def racing_apply(plan, workspace):
            # someone reactivates dave by hand between plan and apply
            WorkspaceMember.objects.filter(member=world["users"]["dave"]).update(is_active=True, role=5)
            return real_apply(plan, workspace)

        monkeypatch.setattr(sync_module, "apply_plan", racing_apply)
        report = run_full_sync()
        assert [s["user_id"] for s in report["stale"]] == [str(world["users"]["dave"].id)]
        assert ws_row(world["workspace"], world["users"]["dave"]).role == 5

    def test_managed_state_cached_for_the_lock(self, world):
        run_full_sync()
        state_ = cache.get(MANAGED_STATE_KEY)
        assert state_["workspace_managed"] is True and state_["identifiers"] == ["mo"]


@pytest.mark.unit
@pytest.mark.django_db
class TestPerUserSyncAndHooks:
    def test_user_sync_only_touches_that_user(self, world):
        report = run_user_sync(world["users"]["carol"], "sub-carol")
        assert report["status"] == "applied"
        assert {c["email"] for c in report["changes"]} == {"carol@example.test"}
        assert ws_row(world["workspace"], world["users"]["bob"]).is_active  # bob untouched here
        grants_calls = world["fake"].api_calls("grants")
        assert {"userIdQuery": {"userId": "sub-carol"}} in grants_calls[-1][2]["queries"]

    def test_user_sync_ignores_grants_of_others_even_if_server_returns_them(self, world, monkeypatch):
        from plane.dumont.access import zitadel as Z

        real = Z.ZitadelClient.list_user_grants

        def leaky(self, project_id, user_id=None):
            return real(self, project_id)  # a server ignoring the userId filter

        monkeypatch.setattr(Z.ZitadelClient, "list_user_grants", leaky)
        report = run_user_sync(world["users"]["carol"], "sub-carol")
        assert {c["email"] for c in report["changes"]} == {"carol@example.test"}

    def test_bearer_hook_is_cached_60s_per_sub(self, world):
        carol = world["users"]["carol"]
        hooks.on_bearer_authenticated(carol, "sub-carol")
        calls = len(world["fake"].calls)
        hooks.on_bearer_authenticated(carol, "sub-carol")
        assert len(world["fake"].calls) == calls
        assert ws_row(world["workspace"], carol).is_active

    def test_web_login_hook_always_runs(self, world):
        carol = world["users"]["carol"]
        hooks.on_web_login(carol, "sub-carol")
        calls = len(world["fake"].calls)
        hooks.on_web_login(carol, "sub-carol")
        assert len(world["fake"].calls) > calls

    def test_hooks_off_mode_no_calls(self, world):
        world["set_mode"]("off")
        hooks.on_bearer_authenticated(world["users"]["carol"], "sub-carol")
        hooks.on_web_login(world["users"]["carol"], "sub-carol")
        assert world["fake"].calls == []

    def test_hooks_never_raise(self, world, monkeypatch):
        world["fake"].fail = "timeout"
        assert hooks.on_bearer_authenticated(world["users"]["carol"], "sub-carol") is None
        assert hooks.on_web_login(world["users"]["carol"], "sub-carol") is None
        from plane.dumont.access import sync as sync_module

        def boom(*args, **kwargs):
            raise RuntimeError("bug")

        monkeypatch.setattr(sync_module, "build_snapshot", boom)
        world["fake"].fail = None
        assert hooks.on_web_login(world["users"]["carol"], "sub-carol") is None
        assert not WorkspaceMember.objects.filter(member=world["users"]["carol"]).exists()

    def test_hook_with_cache_down_skips(self, world, monkeypatch):
        def broken(*args, **kwargs):
            raise ConnectionError("redis down")

        monkeypatch.setattr(hooks.cache, "add", broken)
        hooks.on_bearer_authenticated(world["users"]["carol"], "sub-carol")
        assert world["fake"].calls == []

    def test_dry_run_user_sync_writes_nothing(self, world):
        world["set_mode"]("dry-run")
        report = run_user_sync(world["users"]["carol"], "sub-carol")
        assert report["status"] == "dry_run" and report["changes"]
        assert not WorkspaceMember.objects.filter(member=world["users"]["carol"]).exists()

    def test_celery_task(self, world):
        from plane.dumont.access.tasks import dumont_access_full_sync

        assert dumont_access_full_sync.run()["status"] == "applied"
        world["set_mode"]("off")
        calls = len(world["fake"].calls)
        assert dumont_access_full_sync.run() == {"status": "off"}
        assert len(world["fake"].calls) == calls
