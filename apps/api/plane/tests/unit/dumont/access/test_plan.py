# Dumont addition: pure tests of the membership diff (no database). Not upstream Plane.

import pytest

from plane.dumont.access.plan import (
    CREATE,
    DEACTIVATE,
    REACTIVATE,
    UPDATE_ROLE,
    Grant,
    Membership,
    PlaneUser,
    ProjectRef,
    Snapshot,
    compute_plan,
    managed_scopes,
)

WS = "ws-1"
MO = ProjectRef(id="p-mo", identifier="MO")
HGR = ProjectRef(id="p-hgr", identifier="HGR")
OPS = ProjectRef(id="p-ops", identifier="OPS")  # never has roles: unmanaged

ALL_WS_ROLES = {"hangar.workspace.admin", "hangar.workspace.member", "hangar.workspace.guest"}
MO_ROLES = {"hangar.project.mo.admin", "hangar.project.mo.member", "hangar.project.mo.guest"}


def user(uid, **kw):
    kw.setdefault("linked", True)
    kw.setdefault("email", f"{uid}@example.test")
    return PlaneUser(id=uid, **kw)


def active(role):
    return Membership(role=role, is_active=True)


def inactive(role):
    return Membership(role=role, is_active=False)


def snap(
    role_keys=(),
    grants=(),
    users=(),
    ws=None,
    projects_members=None,
    projects=(MO, HGR, OPS),
    only=None,
    accounts=None,
):
    users = {u.id: u for u in users}
    if accounts is None:
        accounts = {f"sub-{u.id}": u.id for u in users.values() if u.linked}
    return Snapshot(
        workspace_id=WS,
        workspace_slug="dumont",
        role_keys=frozenset(role_keys),
        grants=list(grants),
        projects=list(projects),
        accounts=accounts,
        users=users,
        workspace_members=ws or {},
        project_members=projects_members or {},
        only_user_ids=frozenset(only) if only is not None else None,
    )


def g(uid, *keys, email=None):
    return Grant(zitadel_user_id=f"sub-{uid}", role_keys=tuple(keys), email=email)


def summary(plan):
    return sorted((c.label, c.user_id, c.action, c.to_role) for c in plan.changes)


def kinds(plan):
    return sorted((n["kind"], n.get("user_id"), n.get("scope")) for n in plan.notes)


@pytest.mark.unit
class TestManagedScopes:
    def test_marker_and_projects(self):
        ws, managed, unknown, invalid = managed_scopes(
            {
                "hangar.workspace.member",
                "hangar.project.mo.guest",
                "hangar.project.zz.admin",
                "hangar.project.BAD.x",
                "hangar_reader",
            },
            {"mo", "hgr"},
        )
        assert ws is True
        assert managed == ["mo"]
        assert unknown == ["zz"]
        assert invalid == ["hangar.project.BAD.x"]

    def test_workspace_needs_member_marker(self):
        ws, *_ = managed_scopes({"hangar.workspace.admin", "hangar.workspace.guest"}, set())
        assert ws is False

    def test_nothing_managed_nothing_planned(self):
        plan = compute_plan(
            snap(
                role_keys={"hangar_reader"},
                users=[user("a")],
                ws={"a": active(15)},
                projects_members={"p-mo": {"a": active(15)}},
            )
        )
        assert plan.changes == [] and not plan.managed_workspace and plan.managed_projects == {}


@pytest.mark.unit
class TestWorkspace:
    def test_create_reactivate_update_deactivate(self):
        users = [user("new"), user("back"), user("promo"), user("gone"), user("same"), user("admin")]
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[
                    g("new", "hangar.workspace.member"),
                    g("back", "hangar.workspace.guest"),
                    g("promo", "hangar.workspace.admin"),
                    g("same", "hangar.workspace.member"),
                    g("admin", "hangar.workspace.admin"),
                ],
                users=users,
                ws={
                    "back": inactive(15),
                    "promo": active(15),
                    "gone": active(15),
                    "same": active(15),
                    "admin": active(20),
                },
            )
        )
        assert summary(plan) == [
            ("workspace", "back", REACTIVATE, 5),
            ("workspace", "gone", DEACTIVATE, None),
            ("workspace", "new", CREATE, 15),
            ("workspace", "promo", UPDATE_ROLE, 20),
        ]
        assert len(plan.deactivations) == 1

    def test_highest_role_wins_across_keys_and_grants(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[
                    g("a", "hangar.workspace.guest", "hangar.workspace.admin"),
                    g("a", "hangar.workspace.member"),
                ],
                users=[user("a")],
            )
        )
        assert summary(plan) == [("workspace", "a", CREATE, 20)]

    def test_mcp_gate_roles_are_not_memberships(self):
        plan = compute_plan(
            snap(role_keys=ALL_WS_ROLES | {"hangar_writer"}, grants=[g("a", "hangar_writer")], users=[user("a")])
        )
        assert plan.changes == []

    def test_unmanaged_workspace_is_untouched(self):
        plan = compute_plan(
            snap(
                role_keys={"hangar.workspace.admin"},  # no hangar.workspace.member marker
                grants=[g("a", "hangar.workspace.admin")],
                users=[user("a"), user("b")],
                ws={"b": active(15)},
            )
        )
        assert plan.changes == [] and not plan.managed_workspace

    def test_inactive_rows_without_grant_stay(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                users=[user("a"), user("x")],
                grants=[g("x", "hangar.workspace.admin")],
                ws={"a": inactive(15), "x": active(20)},
            )
        )
        assert plan.changes == []

    def test_bots_never_touched(self):
        bot = user("bot", is_bot=True)
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("bot", "hangar.workspace.admin"), g("x", "hangar.workspace.admin")],
                users=[bot, user("x")],
                ws={"bot": active(5), "x": active(20)},
            )
        )
        assert plan.changes == []
        assert ("bot_grant_ignored", "bot", None) in kinds(plan)

    def test_protected_users_keep_access_but_can_gain(self):
        owner = user("owner", protected=True)
        admin2 = user("ia", protected=True)
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("ia", "hangar.workspace.admin"), g("x", "hangar.workspace.admin")],
                users=[owner, admin2, user("x")],
                ws={"owner": active(20), "ia": active(15), "x": active(20)},
            )
        )
        # owner has no grant but is protected; ia is promoted (gaining is allowed)
        assert summary(plan) == [("workspace", "ia", UPDATE_ROLE, 20)]
        assert ("protected_kept", "owner", "workspace") in kinds(plan)

    def test_protected_user_not_demoted(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("ia", "hangar.workspace.guest")],
                users=[user("ia", protected=True)],
                ws={"ia": active(20)},
            )
        )
        assert plan.changes == []

    def test_inactive_plane_user_gets_nothing_new(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("a", "hangar.workspace.member"), g("x", "hangar.workspace.admin")],
                users=[user("a", is_active=False), user("x")],
                ws={"x": active(20)},
            )
        )
        assert plan.changes == []
        assert ("plane_user_inactive", "a", "workspace") in kinds(plan)

    def test_last_admin_is_kept(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("a", "hangar.workspace.member")],
                users=[user("a"), user("b")],
                ws={"a": active(20), "b": active(20)},
            )
        )
        # both admins would lose admin: both removals/demotions are dropped
        assert plan.changes == []
        assert [n["kind"] for n in plan.notes].count("last_admin_kept") == 2

    def test_admin_handover_is_allowed(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("new", "hangar.workspace.admin")],
                users=[user("old"), user("new")],
                ws={"old": active(20)},
            )
        )
        assert summary(plan) == [("workspace", "new", CREATE, 20), ("workspace", "old", DEACTIVATE, None)]


@pytest.mark.unit
class TestPending:
    def test_unlinked_grant_is_pending(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES | MO_ROLES,
                grants=[g("ghost", "hangar.workspace.member", "hangar.project.mo.member", email="ghost@x.test")],
                users=[],
            )
        )
        assert plan.changes == []
        assert plan.pending == [
            {
                "zitadel_user_id": "sub-ghost",
                "email": "ghost@x.test",
                "display_name": None,
                "roles": ["hangar.project.mo.member", "hangar.workspace.member"],
            }
        ]

    def test_unlinked_member_with_pending_grant_is_kept(self):
        legacy = user("legacy", linked=False, email="Legacy@X.test")
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES | MO_ROLES,
                grants=[
                    g("zlegacy", "hangar.workspace.member", "hangar.project.mo.member", email="legacy@x.test"),
                    g("x", "hangar.workspace.admin", "hangar.project.mo.admin"),
                ],
                users=[legacy, user("x")],
                ws={"legacy": active(15), "x": active(20)},
                projects_members={"p-mo": {"legacy": active(15), "x": active(20)}},
                accounts={"sub-x": "x"},
            )
        )
        assert plan.changes == []
        assert ("awaiting_dumont_login", "legacy", "workspace") in kinds(plan)
        assert ("awaiting_dumont_login", "legacy", "MO") in kinds(plan)

    def test_unlinked_member_without_grant_is_removed(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("x", "hangar.workspace.admin")],
                users=[user("legacy", linked=False), user("x")],
                ws={"legacy": active(15), "x": active(20)},
                accounts={"sub-x": "x"},
            )
        )
        assert summary(plan) == [("workspace", "legacy", DEACTIVATE, None)]


@pytest.mark.unit
class TestProjects:
    def base(self, **kw):
        kw.setdefault("role_keys", ALL_WS_ROLES | MO_ROLES)
        return snap(**kw)

    def test_project_managed_only_with_roles(self):
        plan = compute_plan(
            self.base(
                grants=[g("a", "hangar.workspace.member", "hangar.project.mo.member")],
                users=[user("a"), user("z")],
                ws={"a": active(15), "z": active(20)},
                projects_members={"p-ops": {"a": active(20)}, "p-mo": {"z": active(20)}},
            )
        )
        assert plan.managed_projects == {"p-mo": "MO"}
        # z loses the workspace (no grant) -> cascade to OPS? z has no OPS row; MO: z has no MO grant.
        # z is the only MO admin -> kept.
        assert ("MO", "a", CREATE, 15) in summary(plan)
        assert ("last_admin_kept", "z", "MO") in kinds(plan)
        assert all(c.label != "OPS" or c.user_id != "a" for c in plan.changes)

    def test_project_grant_needs_workspace_membership(self):
        plan = compute_plan(
            self.base(
                grants=[
                    g("a", "hangar.project.mo.member"),
                    g("x", "hangar.workspace.admin", "hangar.project.mo.admin"),
                ],
                users=[user("a"), user("x")],
                ws={"x": active(20)},
                projects_members={"p-mo": {"x": active(20)}},
            )
        )
        assert summary(plan) == []
        assert ("no_workspace_membership", "a", "MO") in kinds(plan)

    def test_project_grant_with_unmanaged_workspace_uses_actual_membership(self):
        plan = compute_plan(
            snap(
                role_keys=MO_ROLES,
                grants=[g("a", "hangar.project.mo.member"), g("b", "hangar.project.mo.admin")],
                users=[user("a"), user("b")],
                ws={"a": active(15)},  # b is not in the workspace
                projects_members={"p-mo": {}},
            )
        )
        assert summary(plan) == [("MO", "a", CREATE, 15)]
        assert ("no_workspace_membership", "b", "MO") in kinds(plan)

    def test_workspace_guest_is_capped(self):
        plan = compute_plan(
            self.base(
                grants=[
                    g("a", "hangar.workspace.guest", "hangar.project.mo.admin"),
                    g("x", "hangar.workspace.admin", "hangar.project.mo.admin"),
                ],
                users=[user("a"), user("x")],
                ws={"x": active(20)},
                projects_members={"p-mo": {"x": active(20)}},
            )
        )
        assert ("MO", "a", CREATE, 5) in summary(plan)
        assert ("capped_to_guest", "a", "MO") in kinds(plan)

    def test_removed_from_managed_project(self):
        plan = compute_plan(
            self.base(
                grants=[g("a", "hangar.workspace.member"), g("x", "hangar.workspace.admin", "hangar.project.mo.admin")],
                users=[user("a"), user("x")],
                ws={"a": active(15), "x": active(20)},
                projects_members={"p-mo": {"a": active(15), "x": active(20)}},
            )
        )
        assert summary(plan) == [("MO", "a", DEACTIVATE, None)]

    def test_project_last_admin_kept(self):
        plan = compute_plan(
            self.base(
                grants=[
                    g("a", "hangar.workspace.member", "hangar.project.mo.member"),
                    g("x", "hangar.workspace.admin"),
                ],
                users=[user("a"), user("x")],
                ws={"a": active(15), "x": active(20)},
                projects_members={"p-mo": {"a": active(20)}},
            )
        )
        assert summary(plan) == []
        assert ("last_admin_kept", "a", "MO") in kinds(plan)

    def test_unknown_project_roles_reported(self):
        plan = compute_plan(snap(role_keys={"hangar.project.nope.member"}))
        assert plan.unknown_project_roles == ["nope"] and plan.managed_projects == {}


@pytest.mark.unit
class TestCascade:
    def test_workspace_removal_deactivates_unmanaged_projects(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("x", "hangar.workspace.admin")],
                users=[user("a"), user("x")],
                ws={"a": active(15), "x": active(20)},
                projects_members={"p-ops": {"a": active(15), "x": active(20)}, "p-hgr": {"a": inactive(15)}},
            )
        )
        assert summary(plan) == [("OPS", "a", DEACTIVATE, None), ("workspace", "a", DEACTIVATE, None)]
        assert [c.cascade for c in plan.changes if c.label == "OPS"] == [True]

    def test_cascade_keeps_last_project_admin(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("x", "hangar.workspace.admin")],
                users=[user("a"), user("x")],
                ws={"a": active(15), "x": active(20)},
                projects_members={"p-ops": {"a": active(20)}},
            )
        )
        assert summary(plan) == [("workspace", "a", DEACTIVATE, None)]
        assert ("last_admin_kept", "a", "OPS") in kinds(plan)

    def test_demotion_to_guest_caps_unmanaged_projects(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("a", "hangar.workspace.guest"), g("x", "hangar.workspace.admin")],
                users=[user("a"), user("x")],
                ws={"a": active(15), "x": active(20)},
                projects_members={"p-ops": {"a": active(15), "x": active(20)}},
            )
        )
        assert summary(plan) == [("OPS", "a", UPDATE_ROLE, 5), ("workspace", "a", UPDATE_ROLE, 5)]


@pytest.mark.unit
class TestPerUser:
    def test_only_the_user_changes(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES | MO_ROLES,
                grants=[g("a", "hangar.workspace.member", "hangar.project.mo.member")],
                users=[user("a"), user("b")],
                ws={"b": active(20)},  # b has no grant in this (per-user) view: must stay
                projects_members={"p-mo": {"b": active(20)}},
                only={"a"},
            )
        )
        assert summary(plan) == [("MO", "a", CREATE, 15), ("workspace", "a", CREATE, 15)]

    def test_last_admin_counts_other_members(self):
        # a is one of two admins; per-user sync demoting a is fine because b stays admin
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("a", "hangar.workspace.member")],
                users=[user("a"), user("b")],
                ws={"a": active(20), "b": active(20)},
                only={"a"},
            )
        )
        assert summary(plan) == [("workspace", "a", UPDATE_ROLE, 15)]

    def test_user_without_grants_loses_managed_access(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES | MO_ROLES,
                grants=[],
                users=[user("a"), user("b")],
                ws={"a": active(15), "b": active(20)},
                projects_members={"p-mo": {"a": active(15), "b": active(20)}},
                only={"a"},
            )
        )
        assert summary(plan) == [("MO", "a", DEACTIVATE, None), ("workspace", "a", DEACTIVATE, None)]


@pytest.mark.unit
class TestAdditiveOnly:
    """The per-user sync (login / bearer hooks) never removes or reduces access."""

    def test_removals_and_demotions_are_deferred(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES | MO_ROLES,
                grants=[g("a", "hangar.workspace.guest")],
                users=[user("a"), user("b")],
                ws={"a": active(15), "b": active(20)},
                projects_members={"p-mo": {"a": active(15), "b": active(20)}},
                only={"a"},
            ),
            additive_only=True,
        )
        assert plan.changes == []
        assert sorted((c.label, c.action, c.to_role) for c in plan.deferred) == [
            ("MO", DEACTIVATE, None),
            ("workspace", UPDATE_ROLE, 5),
        ]

    def test_additions_are_kept(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES | MO_ROLES,
                grants=[g("a", "hangar.workspace.admin", "hangar.project.mo.member")],
                users=[user("a")],
                ws={"a": active(15)},
                projects_members={"p-mo": {"a": inactive(5)}},
                only={"a"},
            ),
            additive_only=True,
        )
        assert summary(plan) == [("MO", "a", REACTIVATE, 15), ("workspace", "a", UPDATE_ROLE, 20)]
        assert plan.deferred == []

    def test_never_cascades(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES,
                grants=[g("x", "hangar.workspace.admin")],
                users=[user("a"), user("x")],
                ws={"a": active(15), "x": active(20)},
                projects_members={"p-ops": {"a": active(15)}},
                only={"a"},
            ),
            additive_only=True,
        )
        assert plan.changes == [] and plan.cascaded == []
        assert [(c.label, c.action) for c in plan.deferred] == [("workspace", DEACTIVATE)]

    def test_no_project_role_on_a_workspace_membership_about_to_go(self):
        # a has an MO grant but no workspace grant any more: the full sync removes the workspace row,
        # so the per-user sync must not create the MO row on top of it.
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES | MO_ROLES,
                grants=[g("a", "hangar.project.mo.member"), g("x", "hangar.workspace.admin")],
                users=[user("a"), user("x")],
                ws={"a": active(15), "x": active(20)},
                only={"a"},
            ),
            additive_only=True,
        )
        assert plan.changes == []
        assert [(c.label, c.action) for c in plan.deferred] == [("workspace", DEACTIVATE)]


@pytest.mark.unit
class TestUsersLosingAccess:
    def test_counts_people_not_rows(self):
        plan = compute_plan(
            snap(
                role_keys=ALL_WS_ROLES | MO_ROLES,
                grants=[g("x", "hangar.workspace.admin", "hangar.project.mo.admin"), g("b", "hangar.workspace.guest")],
                users=[user("a"), user("b"), user("x")],
                ws={"a": active(15), "b": active(15), "x": active(20)},
                projects_members={
                    "p-mo": {"a": active(15), "x": active(20)},
                    "p-ops": {"a": active(15), "b": active(15)},
                    "p-hgr": {"a": active(15)},
                },
            )
        )
        # a: workspace + MO + OPS + HGR rows (cascade included); b: demoted to guest (+ OPS capped)
        assert len(plan.deactivations) == 4
        assert plan.users_losing_access == ["a", "b"]
        assert {c.label for c in plan.cascaded} == {"OPS", "HGR"}


@pytest.mark.unit
class TestIdentifiers:
    def test_collision_leaves_both_projects_unmanaged(self):
        mo_upper = ProjectRef(id="p-mo-1", identifier="MO")
        mo_space = ProjectRef(id="p-mo-2", identifier="MO ")
        plan = compute_plan(
            snap(
                role_keys=MO_ROLES,
                grants=[g("a", "hangar.project.mo.admin")],
                users=[user("a")],
                projects=(mo_upper, mo_space, OPS),
                projects_members={"p-mo-1": {"b": active(15)}},
            )
        )
        assert plan.managed_projects == {} and plan.changes == []
        assert plan.identifier_collisions == [{"key_part": "mo", "identifiers": ["MO", "MO "]}]
        assert ("identifier_collision", None, "mo") in kinds(plan)
        assert plan.unknown_project_roles == []  # the part has projects; it is just ambiguous

    def test_look_alike_identifier_is_not_managed(self):
        kelvin = ProjectRef(id="p-k", identifier="KMO")  # KELVIN SIGN lowercases to ASCII "k"
        plan = compute_plan(snap(role_keys={"hangar.project.kmo.admin"}, projects=(kelvin,), users=[user("a")]))
        assert plan.managed_projects == {} and plan.unknown_project_roles == ["kmo"]


@pytest.mark.unit
def test_change_as_dict_is_readable():
    plan = compute_plan(snap(role_keys=ALL_WS_ROLES, grants=[g("a", "hangar.workspace.admin")], users=[user("a")]))
    as_dict = plan.changes[0].as_dict({"a": user("a")})
    assert as_dict == {
        "scope": "workspace",
        "scope_type": "workspace",
        "scope_id": WS,
        "user_id": "a",
        "email": "a@example.test",
        "action": "create",
        "from_role": None,
        "to_role": "admin",
        "cascade": False,
    }
