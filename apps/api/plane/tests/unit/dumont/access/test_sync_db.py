# Dumont addition: the reconciler against real models and a fake ZITADEL. Not upstream Plane.

import logging

import pytest
from django.core.cache import cache

from plane.db.models import ProjectMember, ProjectUserProperty, WorkspaceMember
from plane.dumont.access import hooks
from plane.dumont.access.sync import (
    MANAGED_STATE_KEY,
    ZITADEL_BACKOFF_KEY,
    ZITADEL_BACKOFF_TTL,
    run_full_sync,
    run_user_sync,
)
from plane.license.models import Instance, InstanceAdmin
from plane.tests.unit.dumont.access.conftest import (
    ORG_ID,
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

    def test_zero_grants_with_managed_scopes_is_an_error(self, world, monkeypatch):
        # ZITADEL suddenly answers "no grants at all" (an explicit, empty `result`), even under the limit
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "50")
        world["fake"].grants.clear()
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "error" and report["error"] == "managed scopes but zero grants"
        # alice, bob and admin would lose access (the owner is protected): 3 people, 6 rows
        assert report["counts"]["users_losing_access"] == 3
        assert state(world) == before

    def test_zero_grants_needs_the_explicit_override(self, world):
        world["fake"].grants.clear()
        report = run_full_sync(max_removals=3)
        assert report["status"] == "applied", report
        assert ws_row(world["workspace"], world["users"]["alice"]).is_active is False

    def test_absolute_brake(self, world, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "0")
        before = state(world)
        report = run_full_sync()  # bob only: 1 of 4 workspace members, 1 of 3 in MO
        assert report["status"] == "aborted_brake" and report.get("relative_brake") in (None, [])
        assert state(world) == before

    def test_brake_counts_people_not_rows(self, world, monkeypatch):
        # bob loses 3 rows (workspace, MO, OPS by cascade): that is ONE person
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "0")
        report = run_full_sync()
        assert report["status"] == "aborted_brake"
        assert report["counts"] == {**report["counts"], "users_losing_access": 1, "deactivations": 3}
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "1")
        assert run_full_sync()["status"] == "applied"

    def test_brake_counts_demotions(self, world, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "1")
        for grant in world["fake"].grants:
            if grant["userId"] == "sub-alice":
                grant["roleKeys"] = ["hangar.workspace.guest", "hangar.project.mo.guest"]
        report = run_full_sync()  # bob removed + alice demoted = 2 people
        assert report["status"] == "aborted_brake"
        assert report["counts"]["users_losing_access"] == 2

    def test_max_removals_override_for_one_run(self, world, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "0")
        assert run_full_sync(max_removals=1)["status"] == "applied"
        assert run_full_sync(max_removals=-1)["status"] == "error"

    def test_cascade_is_logged_and_reported(self, world, caplog):
        caplog.set_level(logging.WARNING, logger="plane.dumont.access")
        bob = world["users"]["bob"]
        report = run_full_sync()
        assert report["status"] == "applied"
        assert [(c["scope"], c["user_id"], c["action"]) for c in report["cascaded"]] == [
            ("OPS", str(bob.id), "deactivate")
        ]
        lines = [r.getMessage() for r in caplog.records if "cascade" in r.getMessage()]
        assert len(lines) == 1
        assert "cascade applied: deactivate project=OPS" in lines[0]
        assert f"project_id={world['ops'].id}" in lines[0] and f"user_id={bob.id}" in lines[0]
        assert "bob@example.test" not in lines[0]

    def test_cascade_logged_in_dry_run_too(self, world, caplog):
        world["set_mode"]("dry-run")
        caplog.set_level(logging.WARNING, logger="plane.dumont.access")
        run_full_sync()
        assert any("cascade planned (dry-run, not written)" in r.getMessage() for r in caplog.records)

    def test_missing_result_changes_nothing(self, world):
        world["fake"].drop_result_on = "grants"
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "error" and "no 'result'" in report["error"]
        assert state(world) == before

    def test_truncated_pages_change_nothing(self, world):
        world["fake"].page_cap = 2
        world["fake"].truncate_after = 2  # 4 grants, totalResult 4, then empty pages
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "error" and "empty page" in report["error"]
        assert state(world) == before

    def test_users_search_silently_empty_changes_nothing(self, world):
        # reviewer probe: users/_search answers 200 with no rows (permission-filtered)
        world["fake"].filter_users = True
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "error" and "permission too narrow" in report["error"]
        assert state(world) == before

    def test_admin_handover_writes_the_new_admin_first(self, world):
        # MO: `admin` is the only admin; ZITADEL moves MO admin to alice. The upgrade must be written
        # before the removal, or the write-time last-admin check would refuse the removal.
        for grant in world["fake"].grants:
            if grant["userId"] == "sub-alice":
                grant["roleKeys"] = ["hangar.workspace.member", "hangar.project.mo.admin"]
            if grant["userId"] == "sub-admin":
                grant["roleKeys"] = ["hangar.workspace.admin"]
        # MO loses 2 of its 3 members (bob and admin): the relative brake stops the beat, so this is
        # the explicit one-run override an operator gives after the dry-run
        assert run_full_sync()["status"] == "aborted_brake"
        report = run_full_sync(max_removals=5)
        assert report["status"] == "applied", report
        assert report["stale"] == [], report["stale"]
        assert pr_row(world["mo"], world["users"]["alice"]).role == 20
        assert pr_row(world["mo"], world["users"]["admin"]).is_active is False

    def test_last_admin_rechecked_at_write_time(self, world, monkeypatch):
        from plane.dumont.access import sync as sync_module

        owner = world["owner"]
        pr_member(world["mo"], owner, 20)  # the owner is protected: the plan counts on this admin
        for grant in world["fake"].grants:
            if grant["userId"] == "sub-admin":
                grant["roleKeys"] = ["hangar.workspace.admin"]  # admin loses MO admin
        real_apply = sync_module.apply_plan

        def racing_apply(plan, workspace):
            # between plan and write, the owner leaves MO by hand: `admin` is now the last MO admin
            ProjectMember.objects.filter(project=world["mo"], member=owner).update(is_active=False)
            return real_apply(plan, workspace)

        monkeypatch.setattr(sync_module, "apply_plan", racing_apply)
        report = run_full_sync()
        assert [(s["scope"], s["reason"]) for s in report["stale"]] == [
            ("MO", "would leave the scope without an active admin")
        ]
        assert pr_row(world["mo"], world["users"]["admin"]).is_active is True

    def test_brake_not_applied_to_dry_run(self, world):
        world["set_mode"]("dry-run")
        world["fake"].grants.clear()
        report = run_full_sync()
        assert report["status"] == "dry_run"
        assert report["would_refuse"] == [
            "managed scopes but zero grants",
            "relative brake: more than half of a managed scope would lose access",
        ]
        assert {item["scope"] for item in report["relative_brake"]} == {"workspace", "MO"}

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

    @pytest.mark.parametrize("mode", ["dry-run", "enforce"])
    def test_org_id_is_required_before_any_call(self, world, monkeypatch, mode):
        world["set_mode"](mode)
        monkeypatch.delenv("DUMONT_ZITADEL_ORG_ID")
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "error" and "DUMONT_ZITADEL_ORG_ID" in report["error"]
        report = run_user_sync(world["users"]["carol"], "sub-carol")
        assert report["status"] == "error" and "DUMONT_ZITADEL_ORG_ID" in report["error"]
        assert world["fake"].calls == []
        assert state(world) == before

    def test_grants_outside_the_dumont_org_are_ignored(self, world):
        fake = world["fake"]
        # bob's only grant came through a project grant to another org: he is removed as without a grant
        fake.grant(
            "sub-bob", "hangar.workspace.admin", "hangar.project.mo.admin", grant_org="999", project_grant_id="pg"
        )
        # erin signed in to Hangar with a user of another org; a grant in the Dumont project gives nothing
        make_user("erin@example.test", sub="sub-erin")
        fake.grant("sub-erin", "hangar.workspace.admin", user_org="999")
        report = run_full_sync()
        assert report["status"] == "applied", report
        s = state(world)
        assert s[("ws", "bob@example.test")] == (15, False)
        assert ("ws", "erin@example.test") not in s
        assert {(i["user_id"], i["reason"]) for i in report["ignored_grants"]} == {
            ("sub-bob", "project_grant"),
            ("sub-erin", "user_outside_org"),
        }
        assert report["counts"]["ignored_grants"] == 2
        assert all(p["zitadel_user_id"] not in ("sub-erin", "sub-bob") for p in report["pending"])

    def test_user_lookup_failure_changes_nothing(self, world):
        world["fake"].fail = 403  # e.g. the service user may read grants but not users
        world["fake"].fail_on = "users/_search"
        before = state(world)
        report = run_full_sync()
        assert report["status"] == "error" and "users/_search" in report["error"]
        assert state(world) == before

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

    def test_user_sync_of_a_user_from_another_org_changes_nothing(self, world):
        world["fake"].org_users["sub-alice"] = "999"  # alice's ZITADEL user is owned by another org
        before = state(world)
        report = run_user_sync(world["users"]["alice"], "sub-alice")
        assert report["status"] == "skipped", report
        assert "outside the Dumont organisation" in report["error"]
        assert state(world) == before
        assert world["fake"].api_calls("grants") == []  # not even asked

    def test_user_sync_never_removes_or_demotes(self, world):
        bob = world["users"]["bob"]  # no grant at all: the full sync removes him, the per-user sync must not
        for grant in world["fake"].grants:
            if grant["userId"] == "sub-alice":
                grant["roleKeys"] = ["hangar.workspace.guest"]
        world["fake"].org_users["sub-bob"] = ORG_ID  # bob is a Dumont user, just without grants
        before = state(world)
        report = run_user_sync(bob, "sub-bob")
        assert report["status"] == "applied" and report["changes"] == []
        assert {(c["scope"], c["action"]) for c in report["deferred_to_full_sync"]} == {
            ("workspace", "deactivate"),
            ("MO", "deactivate"),
        }
        assert report["cascaded"] == []  # OPS is never touched by a per-user sync
        report = run_user_sync(world["users"]["alice"], "sub-alice")
        assert report["changes"] == []
        assert {(c["scope"], c["action"], c["to_role"]) for c in report["deferred_to_full_sync"]} == {
            ("workspace", "update_role", "guest"),
            ("MO", "deactivate", None),
        }
        assert state(world) == before

    def test_second_dumont_account_of_another_org_cannot_evict(self, world):
        # reviewer probe: Plane links a second ZITADEL user (another org, same verified e-mail) to alice.
        from plane.db.models import Account

        alice = world["users"]["alice"]
        Account.objects.create(user=alice, provider="dumont", provider_account_id="sub-alice-other", access_token="x")
        world["fake"].org_users["sub-alice-other"] = "999"
        before = state(world)
        hooks.on_web_login(alice, "sub-alice-other")
        assert state(world) == before
        report = run_full_sync()
        assert report["status"] == "applied"
        assert ws_row(world["workspace"], alice).is_active and pr_row(world["mo"], alice).is_active

    def test_grants_of_all_linked_accounts_count(self, world):
        from plane.db.models import Account

        alice = world["users"]["alice"]
        Account.objects.create(user=alice, provider="dumont", provider_account_id="sub-alice-2", access_token="x")
        world["fake"].grant("sub-alice-2", "hangar.project.mo.admin")
        world["fake"].org_users["sub-alice-other"] = "999"
        Account.objects.create(user=alice, provider="dumont", provider_account_id="sub-alice-other", access_token="x")
        # logging in with the account that only holds the MO admin grant keeps the workspace membership
        # of the other account and upgrades MO
        report = run_user_sync(alice, "sub-alice-2")
        assert report["status"] == "applied", report
        assert report["deferred_to_full_sync"] == []
        assert report["ignored_grants"] == [{"user_id": "sub-alice-other", "reason": "user_outside_org"}]
        assert ws_row(world["workspace"], alice).is_active
        assert pr_row(world["mo"], alice).role == 20
        # the full sync sees the same union
        assert run_full_sync()["status"] == "applied"
        assert pr_row(world["mo"], alice).role == 20 and ws_row(world["workspace"], alice).is_active

    def test_user_sync_login_sub_must_belong_to_the_user(self, world):
        report = run_user_sync(world["users"]["alice"], "sub-bob")
        assert report["status"] == "error" and "not linked" in report["error"]
        assert world["fake"].calls == []

    def test_user_sync_users_search_silently_empty_changes_nothing(self, world):
        world["fake"].filter_users = True
        before = state(world)
        report = run_user_sync(world["users"]["alice"], "sub-alice")
        assert report["status"] == "skipped"
        assert state(world) == before

    def test_user_sync_missing_result_changes_nothing(self, world):
        # reviewer probe: grants answer without `result` used to read as "no grants" -> eviction
        world["fake"].drop_result_on = "grants"
        before = state(world)
        report = run_user_sync(world["users"]["alice"], "sub-alice")
        assert report["status"] == "error" and "no 'result'" in report["error"]
        assert state(world) == before

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
        cache.delete(ZITADEL_BACKOFF_KEY)
        assert hooks.on_web_login(world["users"]["carol"], "sub-carol") is None
        cache.delete(ZITADEL_BACKOFF_KEY)
        from plane.dumont.access import sync as sync_module

        def boom(*args, **kwargs):
            raise RuntimeError("bug")

        monkeypatch.setattr(sync_module, "build_snapshot", boom)
        world["fake"].fail = None
        calls = len(world["fake"].calls)
        assert hooks.on_web_login(world["users"]["carol"], "sub-carol") is None
        assert len(world["fake"].calls) > calls  # the sync really ran into the bug
        assert not WorkspaceMember.objects.filter(member=world["users"]["carol"]).exists()

    def test_zitadel_error_backs_off_all_hooks_for_60s(self, world):
        carol, alice = world["users"]["carol"], world["users"]["alice"]
        world["fake"].fail = "timeout"
        hooks.on_web_login(carol, "sub-carol")
        assert cache.get(ZITADEL_BACKOFF_KEY) and cache.ttl(ZITADEL_BACKOFF_KEY) <= ZITADEL_BACKOFF_TTL
        world["fake"].fail = None
        calls = len(world["fake"].calls)
        # another user, and even a forced web login: no ZITADEL call while the flag is set
        hooks.on_bearer_authenticated(alice, "sub-alice")
        hooks.on_web_login(carol, "sub-carol")
        assert len(world["fake"].calls) == calls
        assert not WorkspaceMember.objects.filter(member=carol).exists()
        cache.delete(ZITADEL_BACKOFF_KEY)  # the 60 s are over
        hooks.on_web_login(carol, "sub-carol")
        assert len(world["fake"].calls) > calls
        assert ws_row(world["workspace"], carol).is_active

    def test_full_sync_error_also_starts_the_backoff(self, world):
        world["fake"].fail = 503
        assert run_full_sync()["status"] == "error"
        assert cache.get(ZITADEL_BACKOFF_KEY)

    def test_config_error_does_not_start_the_backoff(self, world, monkeypatch):
        monkeypatch.delenv("DUMONT_ACCESS_ZITADEL_KEY_JSON")
        assert run_user_sync(world["users"]["carol"], "sub-carol")["status"] == "error"
        assert not cache.get(ZITADEL_BACKOFF_KEY)

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

    @pytest.mark.parametrize("variable,value", [("DUMONT_ACCESS_SYNC", "enfroce"), ("DUMONT_ACCESS_MAX_REMOVALS", "x")])
    def test_celery_task_config_typo_is_loud(self, world, monkeypatch, caplog, variable, value):
        from plane.dumont.access.tasks import dumont_access_full_sync

        monkeypatch.setenv(variable, value)
        caplog.set_level(logging.ERROR, logger="plane.dumont.access")
        before = state(world)
        result = dumont_access_full_sync.run()
        assert result["status"] == "error" and variable in result["error"]
        assert any("configuration error" in r.getMessage() and r.levelno == logging.ERROR for r in caplog.records)
        assert world["fake"].calls == [] and state(world) == before


@pytest.fixture
def small_world(db, workspace, create_user, fake_zitadel, access_env):
    """Second-round reviewer world: an admin plus four members, all granted; OPS is unmanaged."""
    fake = fake_zitadel
    fake.roles = WS_ROLES + MO_ROLES
    mo = make_project(workspace, "MO", create_user)
    ops = make_project(workspace, "OPS", create_user)
    admin = make_user("admin@example.test", sub="sub-admin")
    ws_member(workspace, admin, 20)
    pr_member(mo, admin, 20)
    fake.grant("sub-admin", "hangar.workspace.admin", "hangar.project.mo.admin")
    people = []
    for i in range(4):
        person = make_user(f"u{i}@example.test", sub=f"sub-u{i}")
        ws_member(workspace, person, 15)
        pr_member(mo, person, 15)
        pr_member(ops, person, 15)  # unmanaged project: reached only by the cascade
        fake.grant(f"sub-u{i}", "hangar.workspace.member", "hangar.project.mo.member")
        people.append(person)
    return {"fake": fake, "ws": workspace, "mo": mo, "ops": ops, "people": people, "admin": admin}


def _small_state(w):
    return [
        (ws_row(w["ws"], p).is_active, pr_row(w["mo"], p).is_active, pr_row(w["ops"], p).is_active) for p in w["people"]
    ]


@pytest.mark.unit
@pytest.mark.django_db
class TestNoSilentWipe:
    """Second-round review: answers that used to wipe a small workspace now write nothing."""

    def test_grants_answer_without_result_and_total_is_an_error(self, small_world):
        # reviewer probe: grants/_search answers 200 {"details": {"viewTimestamp": ...}}
        small_world["fake"].raw_body_on = ("grants", {"details": {"viewTimestamp": "2026-09-28T00:00:00Z"}})
        report = run_full_sync()
        assert report["status"] == "error" and "no 'result'" in report["error"]
        assert _small_state(small_world) == [(True, True, True)] * 4

    def test_second_page_without_result_and_total_is_an_error(self, small_world, monkeypatch):
        # reviewer probe: PAGE_SIZE=2, page 1 says totalResult=5, page 2 omits result and totalResult
        from plane.dumont.access import zitadel as Z
        from plane.tests.unit.dumont.access.conftest import _response

        monkeypatch.setattr(Z, "PAGE_SIZE", 2)
        real_page = small_world["fake"]._page

        def page(request, parsed, rows):
            if "grants" in request.url and int(parsed.get("query", {}).get("offset", "0")) > 0:
                return _response(request, 200, {"details": {"viewTimestamp": "x"}})
            return real_page(request, parsed, rows)

        monkeypatch.setattr(small_world["fake"], "_page", page)
        for mode in ("dry-run", None):
            report = run_full_sync(mode=mode)
            assert report["status"] == "error", report
        assert _small_state(small_world) == [(True, True, True)] * 4

    def test_second_page_empty_before_total_is_an_error(self, small_world, monkeypatch):
        from plane.dumont.access import zitadel as Z

        monkeypatch.setattr(Z, "PAGE_SIZE", 2)
        small_world["fake"].truncate_after = 2  # 5 grants announced, only 2 ever served
        report = run_full_sync()
        assert report["status"] == "error" and "empty page at offset 2 of totalResult" in report["error"]
        assert _small_state(small_world) == [(True, True, True)] * 4

    def test_four_member_wipe_is_refused_under_the_absolute_limit(self, small_world):
        # all four members lose their grants: 4 people <= DUMONT_ACCESS_MAX_REMOVALS=5, but it is
        # 4 of 6 workspace members and 4 of 5 MO members: the relative brake stops it
        fake = small_world["fake"]
        fake.grants = [g for g in fake.grants if not g["userId"].startswith("sub-u")]
        report = run_full_sync()
        assert report["status"] == "aborted_brake", report
        assert {(i["scope"], i["losing"], i["members"]) for i in report["relative_brake"]} == {
            ("workspace", 4, 6),
            ("MO", 4, 5),
        }
        assert _small_state(small_world) == [(True, True, True)] * 4

    def test_relative_brake_counts_demotions(self, small_world):
        fake = small_world["fake"]
        for grant in fake.grants:
            if grant["userId"] in ("sub-u0", "sub-u1", "sub-u2"):
                grant["roleKeys"] = ["hangar.workspace.member", "hangar.project.mo.guest"]
        report = run_full_sync()  # MO: 3 of 5 downgraded
        assert report["status"] == "aborted_brake"
        assert [(i["scope"], i["losing"]) for i in report["relative_brake"]] == [("MO", 3)]

    def test_half_is_not_more_than_half(self, small_world):
        fake = small_world["fake"]
        for grant in fake.grants:
            if grant["userId"] in ("sub-u0", "sub-u1"):
                grant["roleKeys"] = ["hangar.workspace.member"]  # lose MO only: 2 of 5
        assert run_full_sync()["status"] == "applied"

    def test_explicit_override_lifts_the_relative_brake(self, small_world):
        fake = small_world["fake"]
        fake.grants = [g for g in fake.grants if not g["userId"].startswith("sub-u")]
        report = run_full_sync(max_removals=4)
        assert report["status"] == "applied", report
        assert _small_state(small_world) == [(False, False, False)] * 4
