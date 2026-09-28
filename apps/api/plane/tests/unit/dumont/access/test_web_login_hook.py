# Dumont addition: the Dumont web login callback runs the per-user sync and never breaks login.
# Not upstream Plane. The OIDC provider is replaced by a stub: no network.

from importlib import import_module

import pytest
from django.conf import settings
from django.test import RequestFactory

from plane.authentication.views.app import dumont as dumont_view
from plane.db.models import WorkspaceMember
from plane.dumont.access import sync as sync_module
from plane.tests.unit.dumont.access.conftest import make_user


class _StubProvider:
    user = None

    def __init__(self, request, code=None, callback=None, **kwargs):
        self.user_data = {"email": self.user.email, "user": {"provider_id": "sub-login"}}

    def authenticate(self):
        return self.user


def _callback(user, monkeypatch):
    _StubProvider.user = user
    monkeypatch.setattr(dumont_view, "DumontOAuthProvider", _StubProvider)
    request = RequestFactory().get("/auth/dumont/callback/", {"code": "c", "state": "s"})
    request.session = import_module(settings.SESSION_ENGINE).SessionStore()
    request.session["state"] = "s"
    request.session["next_path"] = "/somewhere"
    request.user = None
    return dumont_view.DumontCallbackEndpoint.as_view()(request)


@pytest.mark.unit
@pytest.mark.django_db
class TestWebLoginHook:
    def test_login_applies_grants(self, workspace, fake_zitadel, access_env, monkeypatch):
        user = make_user("login@example.test", sub="sub-login")
        fake_zitadel.roles = ["hangar.workspace.member"]
        fake_zitadel.grant("sub-login", "hangar.workspace.member")
        response = _callback(user, monkeypatch)
        assert response.status_code == 302 and "error_code" not in response["Location"]
        assert WorkspaceMember.objects.get(workspace=workspace, member=user).role == 15

    def test_login_survives_zitadel_down(self, workspace, fake_zitadel, access_env, monkeypatch):
        user = make_user("login@example.test", sub="sub-login")
        fake_zitadel.fail = "timeout"
        response = _callback(user, monkeypatch)
        assert response.status_code == 302 and "error_code" not in response["Location"]

    def test_login_survives_sync_bug(self, workspace, fake_zitadel, access_env, monkeypatch):
        user = make_user("login@example.test", sub="sub-login")

        def boom(*args, **kwargs):
            raise RuntimeError("bug")

        monkeypatch.setattr(sync_module, "run_user_sync", boom)
        response = _callback(user, monkeypatch)
        assert response.status_code == 302 and "error_code" not in response["Location"]

    def test_login_off_mode_no_zitadel(self, workspace, fake_zitadel, access_env, monkeypatch):
        access_env("off")
        user = make_user("login@example.test", sub="sub-login")
        response = _callback(user, monkeypatch)
        assert response.status_code == 302
        assert fake_zitadel.calls == []
