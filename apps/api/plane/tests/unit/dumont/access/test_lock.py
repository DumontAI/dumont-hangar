# Dumont addition: membership endpoints are locked for ZITADEL-managed scopes (enforce only).
# Not upstream Plane. Real views, real models, fake ZITADEL.

import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

from plane.db.models import ProjectMemberInvite, WorkspaceMember, WorkspaceMemberInvite
from plane.dumont.access.guard import ERROR_CODE, UNAVAILABLE_CODE
from plane.dumont.access.sync import MANAGED_STATE_KEY
from plane.tests.unit.dumont.access.conftest import make_project, make_user, pr_member, ws_member

SLUG = "test-workspace"
ROLES = [
    "hangar.workspace.admin",
    "hangar.workspace.member",
    "hangar.workspace.guest",
    "hangar.project.mo.admin",
    "hangar.project.mo.member",
    "hangar.project.mo.guest",
]


@pytest.fixture
def setup(db, workspace, create_user, api_token, fake_zitadel, access_env):
    fake_zitadel.roles = list(ROLES)
    mo = make_project(workspace, "MO", create_user)
    ops = make_project(workspace, "OPS", create_user)
    pr_member(mo, create_user, 20)
    pr_member(ops, create_user, 20)
    alice = make_user("alice@example.test", sub="sub-alice")
    alice_ws = ws_member(workspace, alice, 15)
    alice_mo = pr_member(mo, alice, 15)
    alice_ops = pr_member(ops, alice, 15)
    ws_invite = WorkspaceMemberInvite.objects.create(workspace=workspace, email="new@example.test", token="t1", role=15)
    mo_invite = ProjectMemberInvite.objects.create(
        workspace=workspace, project=mo, email="test@plane.so", token="t2", role=15
    )
    session = APIClient()
    session.force_authenticate(user=create_user)
    alice_session = APIClient()
    alice_session.force_authenticate(user=alice)
    v1 = APIClient()
    v1.credentials(HTTP_X_API_KEY=api_token.token)
    return {
        "mo": mo,
        "ops": ops,
        "alice": alice,
        "alice_ws": alice_ws,
        "alice_mo": alice_mo,
        "alice_ops": alice_ops,
        "ws_invite": ws_invite,
        "mo_invite": mo_invite,
        "clients": {"session": session, "alice": alice_session, "v1": v1},
        "set_mode": access_env,
        "fake": fake_zitadel,
    }


def _mo(s):
    return s["mo"].id


# (id, client, method, url builder, body) - every HTTP path that creates/changes/removes a membership
LOCKED_CASES = [
    (
        "app project member add",
        "session",
        "post",
        lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/members/",
        lambda s: {"members": [{"member_id": str(s["alice"].id), "role": 20}]},
    ),
    (
        "app project member role",
        "session",
        "patch",
        lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/members/{s['alice_mo'].id}/",
        lambda s: {"role": 5},
    ),
    (
        "app project member deactivate",
        "session",
        "patch",
        lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/members/{s['alice_mo'].id}/",
        lambda s: {"is_active": False},
    ),
    (
        "app project member remove",
        "session",
        "delete",
        lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/members/{s['alice_mo'].id}/",
        None,
    ),
    ("app project leave", "alice", "post", lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/members/leave/", None),
    (
        "app project invite",
        "session",
        "post",
        lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/invitations/",
        lambda s: {"emails": [{"email": "x@example.test", "role": 15}]},
    ),
    (
        "app join projects",
        "alice",
        "post",
        lambda s: f"/api/users/me/workspaces/{SLUG}/projects/invitations/",
        lambda s: {"project_ids": [str(s["mo"].id)]},
    ),
    (
        "app accept project invite",
        "session",
        "post",
        lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/join/{s['mo_invite'].id}/",
        lambda s: {"token": "t2", "accepted": True},
    ),
    (
        "app project identifier rename",
        "session",
        "patch",
        lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/",
        lambda s: {"identifier": "MOX"},
    ),
    (
        "app workspace member role",
        "session",
        "patch",
        lambda s: f"/api/workspaces/{SLUG}/members/{s['alice_ws'].id}/",
        lambda s: {"role": 20},
    ),
    (
        "app workspace member remove",
        "session",
        "delete",
        lambda s: f"/api/workspaces/{SLUG}/members/{s['alice_ws'].id}/",
        None,
    ),
    ("app workspace leave", "alice", "post", lambda s: f"/api/workspaces/{SLUG}/members/leave/", None),
    (
        "app workspace invite",
        "session",
        "post",
        lambda s: f"/api/workspaces/{SLUG}/invitations/",
        lambda s: {"emails": [{"email": "y@example.test", "role": 15}]},
    ),
    (
        "app workspace invite role",
        "session",
        "patch",
        lambda s: f"/api/workspaces/{SLUG}/invitations/{s['ws_invite'].id}/",
        lambda s: {"role": 20},
    ),
    (
        "app accept workspace invite",
        "session",
        "post",
        lambda s: f"/api/workspaces/{SLUG}/invitations/{s['ws_invite'].id}/join/",
        lambda s: {"token": "t1"},
    ),
    (
        "app accept my invites",
        "session",
        "post",
        lambda s: "/api/users/me/workspaces/invitations/",
        lambda s: {"invitations": [str(s["ws_invite"].id)]},
    ),
    (
        "v1 project member add",
        "v1",
        "post",
        lambda s: f"/api/v1/workspaces/{SLUG}/projects/{_mo(s)}/members/",
        lambda s: {"member": str(s["alice"].id), "role": 20},
    ),
    (
        "v1 project member update",
        "v1",
        "patch",
        lambda s: f"/api/v1/workspaces/{SLUG}/projects/{_mo(s)}/members/{s['alice_mo'].id}/",
        lambda s: {"role": 5},
    ),
    (
        "v1 project member remove",
        "v1",
        "delete",
        lambda s: f"/api/v1/workspaces/{SLUG}/projects/{_mo(s)}/members/{s['alice_mo'].id}/",
        None,
    ),
    (
        "v1 workspace invite",
        "v1",
        "post",
        lambda s: f"/api/v1/workspaces/{SLUG}/invitations/",
        lambda s: {"email": "z@example.test", "role": 15},
    ),
    (
        "v1 workspace invite role",
        "v1",
        "patch",
        lambda s: f"/api/v1/workspaces/{SLUG}/invitations/{s['ws_invite'].id}/",
        lambda s: {"role": 20},
    ),
    (
        "v1 project identifier rename",
        "v1",
        "patch",
        lambda s: f"/api/v1/workspaces/{SLUG}/projects/{_mo(s)}/",
        lambda s: {"identifier": "MOX"},
    ),
]


def _call(setup, client, method, url, body):
    c = setup["clients"][client]
    kwargs = {"format": "json"}
    if body is not None:
        kwargs["data"] = body(setup)
    return getattr(c, method)(url(setup), **kwargs)


@pytest.mark.unit
@pytest.mark.django_db
class TestLock:
    @pytest.mark.parametrize("case", LOCKED_CASES, ids=[c[0] for c in LOCKED_CASES])
    def test_managed_scope_is_locked_in_enforce(self, setup, case):
        _, client, method, url, body = case
        response = _call(setup, client, method, url, body)
        assert response.status_code == 403, (response.status_code, getattr(response, "data", None))
        assert response.data["error_code"] == ERROR_CODE
        assert "Dumont Auth (ZITADEL)" in response.data["error"]
        # nothing changed underneath
        setup["alice_mo"].refresh_from_db()
        setup["alice_ws"].refresh_from_db()
        assert (setup["alice_mo"].role, setup["alice_mo"].is_active) == (15, True)
        assert (setup["alice_ws"].role, setup["alice_ws"].is_active) == (15, True)

    def test_message_names_the_role_to_ask_for(self, setup):
        response = _call(setup, *LOCKED_CASES[0][1:])
        assert "hangar.project.mo.admin" in response.data["error"]
        response = _call(setup, *LOCKED_CASES[9][1:])
        assert "hangar.workspace.admin" in response.data["error"]

    @pytest.mark.parametrize("mode", ["off", "dry-run"])
    def test_not_locked_outside_enforce(self, setup, mode):
        setup["set_mode"](mode)
        response = _call(
            setup,
            "session",
            "patch",
            lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/members/{s['alice_mo'].id}/",
            lambda s: {"role": 5},
        )
        assert response.status_code == 200
        setup["alice_mo"].refresh_from_db()
        assert setup["alice_mo"].role == 5
        assert setup["fake"].calls == []  # the lock never asks ZITADEL outside enforce

    def test_unmanaged_project_not_locked(self, setup):
        response = _call(
            setup,
            "session",
            "patch",
            lambda s: f"/api/workspaces/{SLUG}/projects/{s['ops'].id}/members/{s['alice_ops'].id}/",
            lambda s: {"role": 5},
        )
        assert response.status_code == 200
        response = _call(
            setup, "alice", "post", lambda s: f"/api/workspaces/{SLUG}/projects/{s['ops'].id}/members/leave/", None
        )
        assert response.status_code == 204

    def test_preference_patch_not_locked(self, setup):
        response = _call(
            setup,
            "session",
            "patch",
            lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/members/{s['alice_mo'].id}/",
            lambda s: {"view_props": {"x": 1}},
        )
        assert response.status_code == 200

    def test_project_rename_without_identifier_change_not_locked(self, setup):
        response = _call(
            setup,
            "session",
            "patch",
            lambda s: f"/api/workspaces/{SLUG}/projects/{_mo(s)}/",
            lambda s: {"name": "Moveezi", "identifier": "mo"},
        )
        assert response.status_code == 200, response.data

    def test_unmanaged_workspace_not_locked(self, setup):
        setup["fake"].roles = [r for r in ROLES if not r.startswith("hangar.workspace")]
        response = _call(
            setup,
            "session",
            "patch",
            lambda s: f"/api/workspaces/{SLUG}/members/{s['alice_ws'].id}/",
            lambda s: {"role": 5},
        )
        assert response.status_code == 200
        assert WorkspaceMember.objects.get(pk=setup["alice_ws"].pk).role == 5

    def test_state_unknown_and_zitadel_down_is_503(self, setup):
        cache.delete(MANAGED_STATE_KEY)
        setup["fake"].fail = 500
        response = _call(setup, *LOCKED_CASES[1][1:])
        assert response.status_code == 503
        assert response.data["error_code"] == UNAVAILABLE_CODE

    def test_cached_state_used_without_zitadel(self, setup):
        _call(setup, *LOCKED_CASES[1][1:])  # warms the cache from the fake ZITADEL
        setup["fake"].fail = 500
        calls = len(setup["fake"].calls)
        response = _call(setup, *LOCKED_CASES[1][1:])
        assert response.status_code == 403 and len(setup["fake"].calls) == calls

    def test_other_workspace_never_locked(self, setup, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_WORKSPACE_SLUG", "another-workspace")
        response = _call(setup, *LOCKED_CASES[1][1:])
        assert response.status_code == 200
        assert setup["fake"].calls == []

    def test_unauthorised_caller_gets_plane_answer_first(self, setup):
        outsider = make_user("outsider@example.test")
        client = APIClient()
        client.force_authenticate(user=outsider)
        response = client.patch(
            f"/api/workspaces/{SLUG}/projects/{setup['mo'].id}/members/{setup['alice_mo'].id}/",
            {"role": 5},
            format="json",
        )
        assert response.status_code == 403
        assert "error_code" not in response.data  # Plane's own permission answer, not the lock
        assert setup["fake"].calls == []

    @pytest.mark.parametrize("variable,value", [("DUMONT_ACCESS_SYNC", "enfroce"), ("DUMONT_ACCESS_MAX_REMOVALS", "x")])
    @pytest.mark.parametrize("case", LOCKED_CASES[:3], ids=[c[0] for c in LOCKED_CASES[:3]])
    def test_invalid_config_fails_closed(self, setup, monkeypatch, case, variable, value):
        # a typo must not read as `off` and open the membership endpoints
        monkeypatch.setenv(variable, value)
        response = _call(setup, *case[1:])
        assert response.status_code == 503, response.content
        assert response.data["error_code"] == UNAVAILABLE_CODE
        assert setup["fake"].calls == []

    def test_invalid_config_leaves_other_workspaces_alone(self, setup, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_SYNC", "enfroce")
        monkeypatch.setenv("DUMONT_ACCESS_WORKSPACE_SLUG", "another-workspace")
        response = _call(setup, *LOCKED_CASES[0][1:])
        assert response.status_code != 503

    def test_enforce_without_org_id_fails_closed(self, setup, monkeypatch):
        # DUMONT_ZITADEL_ORG_ID is required: without it the lock cannot learn the managed scopes
        # and answers 503 instead of letting a change through; ZITADEL is never called.
        cache.delete(MANAGED_STATE_KEY)
        monkeypatch.delenv("DUMONT_ZITADEL_ORG_ID")
        response = _call(setup, *LOCKED_CASES[1][1:])
        assert response.status_code == 503
        assert setup["fake"].calls == []


NEW_ROLES = ["hangar.project.new.admin", "hangar.project.new.member"]


@pytest.fixture
def queued(monkeypatch):
    from plane.dumont.access import tasks

    calls = []
    monkeypatch.setattr(tasks.dumont_access_full_sync, "delay", lambda *a, **k: calls.append(1))
    return calls


def _create(setup, client, body):
    url = f"/api/v1/workspaces/{SLUG}/projects/" if client == "v1" else f"/api/workspaces/{SLUG}/projects/"
    return setup["clients"][client].post(url, body, format="json")


@pytest.mark.unit
@pytest.mark.django_db
class TestProjectCreateSideEffects:
    """Plane makes the creator (and a different project lead) admin of a new project."""

    @pytest.mark.parametrize("client", ["session", "v1"])
    def test_different_lead_refused_for_managed_identifier(self, setup, queued, client):
        from plane.db.models import Project

        setup["fake"].roles = ROLES + NEW_ROLES
        response = _create(setup, client, {"name": "New", "identifier": "NEW", "project_lead": str(setup["alice"].id)})
        assert response.status_code == 403, response.data
        assert response.data["error_code"] == ERROR_CODE
        assert "hangar.project.new.admin" in response.data["error"]
        assert not Project.objects.filter(identifier="NEW").exists()
        assert queued == []

    @pytest.mark.parametrize("client", ["session", "v1"])
    def test_create_managed_identifier_queues_a_full_sync(
        self, setup, queued, client, django_capture_on_commit_callbacks
    ):
        setup["fake"].roles = ROLES + NEW_ROLES
        with django_capture_on_commit_callbacks(execute=True):
            response = _create(setup, client, {"name": "New", "identifier": "NEW"})
        assert response.status_code == 201, response.data
        assert queued == [1]

    def test_lead_allowed_for_unmanaged_identifier(self, setup, queued, django_capture_on_commit_callbacks):
        with django_capture_on_commit_callbacks(execute=True):
            response = _create(
                setup, "session", {"name": "Free", "identifier": "FREE", "project_lead": str(setup["alice"].id)}
            )
        assert response.status_code == 201, response.data

    def test_lead_with_zitadel_down_is_503(self, setup, queued):
        cache.delete(MANAGED_STATE_KEY)
        setup["fake"].fail = 500
        response = _create(
            setup, "session", {"name": "New", "identifier": "NEW", "project_lead": str(setup["alice"].id)}
        )
        assert response.status_code == 503

    @pytest.mark.parametrize("mode", ["off", "dry-run"])
    def test_nothing_outside_enforce(self, setup, queued, mode, django_capture_on_commit_callbacks):
        setup["set_mode"](mode)
        setup["fake"].roles = ROLES + NEW_ROLES
        with django_capture_on_commit_callbacks(execute=True):
            response = _create(
                setup, "session", {"name": "New", "identifier": "NEW", "project_lead": str(setup["alice"].id)}
            )
        assert response.status_code == 201, response.data
        assert queued == [] and setup["fake"].calls == []
