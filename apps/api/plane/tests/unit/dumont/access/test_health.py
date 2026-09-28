# Dumont addition: health endpoint of the ZITADEL -> Hangar full sync. Not upstream Plane.

import time

import pytest
from django.core.cache import cache
from django.test import Client

from plane.dumont.access import health as H
from plane.dumont.access.sync import run_full_sync
from plane.tests.unit.dumont.access.conftest import make_project, make_user, ws_member

URL = "/api/dumont/access-sync/status/"
WS_ROLES = ["hangar.workspace.admin", "hangar.workspace.member", "hangar.workspace.guest"]


@pytest.fixture
def world(db, workspace, create_user, fake_zitadel, access_env):
    fake_zitadel.roles = WS_ROLES + ["hangar.project.mo.member"]
    make_project(workspace, "MO", create_user)
    for i in range(3):
        person = make_user(f"p{i}@example.test", sub=f"sub-p{i}")
        ws_member(workspace, person, 15)
        fake_zitadel.grant(f"sub-p{i}", "hangar.workspace.member")
    cache.delete(H.LAST_FULL_SYNC_KEY)
    yield {"fake": fake_zitadel, "set_mode": access_env, "workspace": workspace}
    cache.delete(H.LAST_FULL_SYNC_KEY)


def _get():
    response = Client().get(URL)  # anonymous: no session, no API key
    return response.status_code, response.json()


@pytest.mark.unit
@pytest.mark.django_db
class TestHealthEndpoint:
    def test_enforce_without_any_run_is_503(self, world):
        assert _get() == (503, {"mode": "enforce", "healthy": False, "reason": "no_run_recorded"})

    def test_healthy_after_an_applied_run(self, world):
        assert run_full_sync()["status"] == "applied"
        status, body = _get()
        assert status == 200 and body["healthy"] is True
        assert body["last_status"] == "applied" and body["last_reason"] == "ok"
        assert body["consecutive_failures"] == 0 and body["age_seconds"] <= 5

    def test_body_is_minimal(self, world):
        run_full_sync()
        _, body = _get()
        assert set(body) == {
            "mode",
            "healthy",
            "last_status",
            "last_reason",
            "last_run_at",
            "age_seconds",
            "consecutive_failures",
        }
        assert "example.test" not in str(body) and "sub-" not in str(body)

    def test_one_failure_is_tolerated_two_alert(self, world):
        world["fake"].fail = 503  # ZITADEL down
        assert run_full_sync()["status"] == "error"
        status, body = _get()
        assert status == 200 and body["consecutive_failures"] == 1
        assert run_full_sync()["status"] == "error"
        status, body = _get()
        assert status == 503
        assert body["reason"] == "zitadel_error" and body["consecutive_failures"] == 2
        world["fake"].fail = None
        assert run_full_sync()["status"] == "applied"
        assert _get()[0] == 200  # one good run clears it

    def test_brake_reason(self, world, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "0")
        world["fake"].grants = [g for g in world["fake"].grants if g["userId"] != "sub-p0"]
        for _ in range(2):
            assert run_full_sync()["status"] == "aborted_brake"
        status, body = _get()
        assert status == 503 and body["reason"] == "brake_absolute"

    def test_zero_grants_reason(self, world):
        world["fake"].grants.clear()
        for _ in range(2):
            assert run_full_sync()["status"] == "error"
        assert _get()[1]["reason"] == "zero_grants"

    def test_zero_role_keys_reason(self, world):
        world["fake"].roles = []
        for _ in range(2):
            assert run_full_sync()["status"] == "error"
        status, body = _get()
        assert status == 503 and body["reason"] == "zero_role_keys"

    def test_stale_run_is_503(self, world, monkeypatch):
        run_full_sync()
        later = time.time() + H.STALE_AFTER_SECONDS + 60
        monkeypatch.setattr(H.time, "time", lambda: later)
        status, body = _get()
        assert status == 503 and body["reason"] == "stale"

    def test_manual_dry_run_does_not_hide_a_stuck_enforce(self, world):
        world["fake"].fail = 503
        run_full_sync()
        run_full_sync()
        world["fake"].fail = None
        assert run_full_sync(mode="dry-run")["status"] == "dry_run"
        assert _get()[0] == 503

    @pytest.mark.parametrize("mode", ["off", "dry-run"])
    def test_off_and_dry_run_are_200(self, world, mode):
        world["set_mode"](mode)
        status, body = _get()
        assert status == 200 and body["mode"] == mode and body["healthy"] is True

    def test_mode_typo_is_503(self, world, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_SYNC", "enfroce")
        assert _get() == (503, {"mode": "invalid", "healthy": False, "reason": "config_error"})

    def test_enforce_with_bad_max_is_503_but_off_is_not(self, world, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "five")
        assert _get()[1]["reason"] == "config_error" and _get()[0] == 503
        world["set_mode"]("off")
        assert _get() == (200, {"mode": "off", "healthy": True, "config_error": True})

    def test_beat_config_error_is_recorded(self, world, monkeypatch):
        from plane.dumont.access.tasks import dumont_access_full_sync

        monkeypatch.setenv("DUMONT_ACCESS_MAX_REMOVALS", "five")
        dumont_access_full_sync.run()
        assert cache.get(H.LAST_FULL_SYNC_KEY)["reason"] == "config_error"

    def test_cache_down_is_503_in_enforce(self, world, monkeypatch):
        def broken(*args, **kwargs):
            raise ConnectionError("redis down")

        monkeypatch.setattr(H.cache, "get", broken)
        assert _get()[1]["reason"] == "state_unavailable"

    def test_never_throttled(self, world):
        run_full_sync()
        client = Client()
        codes = {client.get(URL).status_code for _ in range(60)}  # DRF's anon rate is 30/minute
        assert codes == {200}

    def test_only_get(self, world):
        assert Client().post(URL).status_code == 405

    def test_cheap_no_zitadel_call(self, world):
        run_full_sync()
        calls = len(world["fake"].calls)
        _get()
        assert len(world["fake"].calls) == calls
