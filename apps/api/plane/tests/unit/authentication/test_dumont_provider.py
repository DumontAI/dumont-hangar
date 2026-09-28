# Dumont addition: covers the Dumont Auth (ZITADEL) OIDC provider mapping.
# Not upstream Plane.

from datetime import datetime, timedelta

import pytest
import pytz

from plane.authentication.adapter.error import AUTHENTICATION_ERROR_CODES, AuthenticationException
from plane.authentication.provider.oauth.dumont import DumontOAuthProvider


@pytest.fixture(autouse=True)
def _no_org_check_unless_asked(monkeypatch):
    # The org check reads DUMONT_WEB_LOGIN_ORG_CHECK / DUMONT_ZITADEL_ORG_ID per login; the process env
    # (e.g. a feature-on test run) must not leak into tests that are about something else.
    monkeypatch.delenv("DUMONT_WEB_LOGIN_ORG_CHECK", raising=False)
    monkeypatch.delenv("DUMONT_ZITADEL_ORG_ID", raising=False)


def _provider(userinfo=None, token=None):
    """Build the provider without __init__ so the test never touches config or the network."""
    provider = object.__new__(DumontOAuthProvider)
    provider.provider = DumontOAuthProvider.provider
    provider.code = "auth-code"
    provider.client_id = "client-id"
    provider.client_secret = "client-secret"
    provider.redirect_uri = "https://hangar.getdumont.ai/auth/dumont/callback/"
    provider.get_user_response = lambda: userinfo or {}
    provider.get_user_token = lambda data, headers=None: token or {}
    return provider


@pytest.mark.unit
class TestDumontUserData:
    def test_maps_zitadel_claims(self):
        provider = _provider(
            {
                "sub": "385793755363475461",
                "email": "carlos@shipeezi.com",
                "email_verified": True,
                "given_name": "Carlos",
                "family_name": "Dumont",
                "picture": "https://auth.getdumont.ai/avatar.png",
            }
        )
        provider.set_user_data()

        assert provider.user_data["email"] == "carlos@shipeezi.com"
        # sub, not id: ZITADEL has no "id" claim, and a wrong key silently creates a second
        # Account row on every sign-in.
        assert provider.user_data["user"]["provider_id"] == "385793755363475461"
        assert provider.user_data["user"]["first_name"] == "Carlos"
        assert provider.user_data["user"]["is_password_autoset"] is True

    def test_absent_email_verified_is_rejected(self):
        """Fail closed like upstream (GHSA-7j95-vh8g-f365): absent is not verified."""
        provider = _provider({"sub": "1", "email": "carlos@shipeezi.com"})
        with pytest.raises(AuthenticationException):
            provider.set_user_data()

    def test_explicit_unverified_email_is_rejected(self):
        provider = _provider({"sub": "1", "email": "attacker@example.com", "email_verified": False})
        with pytest.raises(AuthenticationException):
            provider.set_user_data()

    def test_missing_email_is_rejected(self):
        provider = _provider({"sub": "1"})
        with pytest.raises(AuthenticationException):
            provider.set_user_data()


@pytest.mark.unit
class TestDumontTokenData:
    def test_expires_in_is_a_duration_not_a_timestamp(self):
        provider = _provider(token={"access_token": "at", "expires_in": 3600, "id_token": "it"})
        provider.set_token_data()

        expires_at = provider.token_data["access_token_expired_at"]
        expected = datetime.now(tz=pytz.utc) + timedelta(seconds=3600)
        # Upstream's Google provider reads expires_in as an epoch timestamp, which lands in 1970.
        assert abs((expires_at - expected).total_seconds()) < 60

    def test_missing_expiry_is_none(self):
        provider = _provider(token={"access_token": "at"})
        provider.set_token_data()
        assert provider.token_data["access_token_expired_at"] is None


ORG = "200000000000000001"
CLAIM = "urn:zitadel:iam:user:resourceowner:id"


def _userinfo(**extra):
    return {"sub": "385793755363475461", "email": "carlos@shipeezi.com", "email_verified": True, **extra}


def _enable(monkeypatch, org=ORG, flag="1"):
    monkeypatch.setenv("DUMONT_WEB_LOGIN_ORG_CHECK", flag)
    if org is not None:
        monkeypatch.setenv("DUMONT_ZITADEL_ORG_ID", org)


@pytest.mark.unit
class TestDumontOrgBoundary:
    """Dumont addition: DUMONT_WEB_LOGIN_ORG_CHECK=1 restricts the web login to DUMONT_ZITADEL_ORG_ID."""

    def test_matching_org_passes(self, monkeypatch):
        _enable(monkeypatch)
        provider = _provider(_userinfo(**{CLAIM: ORG}))
        provider.set_user_data()
        assert provider.user_data["user"]["provider_id"] == "385793755363475461"

    @pytest.mark.parametrize("claim", ["999999999999999999", None, "", ORG + " "])
    def test_foreign_or_missing_org_is_refused(self, monkeypatch, claim):
        _enable(monkeypatch)
        info = _userinfo() if claim is None else _userinfo(**{CLAIM: claim})
        provider = _provider(info)
        with pytest.raises(AuthenticationException) as exc:
            provider.set_user_data()
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["DUMONT_ORG_NOT_ALLOWED"] == 5116
        assert not hasattr(provider, "user_data")

    @pytest.mark.parametrize("flag", [None, "0", ""])
    def test_flag_off_means_no_check_even_with_org_set(self, monkeypatch, flag):
        # the bearer auth needs DUMONT_ZITADEL_ORG_ID; setting it must not change the web login by itself
        monkeypatch.setenv("DUMONT_ZITADEL_ORG_ID", ORG)
        if flag is not None:
            monkeypatch.setenv("DUMONT_WEB_LOGIN_ORG_CHECK", flag)
        provider = _provider(_userinfo(**{CLAIM: "999999999999999999"}))
        provider.set_user_data()
        assert provider.user_data["email"] == "carlos@shipeezi.com"

    def test_unset_means_no_check(self):
        provider = _provider(_userinfo())  # no claim at all, as before this check existed
        provider.set_user_data()
        assert provider.user_data["email"] == "carlos@shipeezi.com"

    @pytest.mark.parametrize(
        "flag,org",
        [
            ("1", None),  # enabled without an org
            ("1", ""),
            ("1", "2000:1"),  # enabled with a malformed org
            ("true", ORG),  # strict parse: only "1" enables
            ("yes", ORG),
            ("2", ORG),
        ],
    )
    def test_misconfigured_check_fails_closed(self, monkeypatch, flag, org):
        _enable(monkeypatch, org=org, flag=flag)
        provider = _provider(_userinfo(**{CLAIM: ORG}))
        with pytest.raises(AuthenticationException) as exc:
            provider.set_user_data()
        assert exc.value.error_code == AUTHENTICATION_ERROR_CODES["DUMONT_NOT_CONFIGURED"] == 5113

    def test_code_is_unique(self):
        codes = list(AUTHENTICATION_ERROR_CODES.values())
        assert codes.count(5116) == 1


@pytest.mark.unit
@pytest.mark.django_db
class TestDumontOrgBoundaryScope:
    """The resourceowner scope is requested only when the check is on: the default changes nothing."""

    def _new(self, monkeypatch):
        from django.test import RequestFactory

        monkeypatch.setenv("DUMONT_CLIENT_ID", "client-id")
        monkeypatch.setenv("DUMONT_CLIENT_SECRET", "client-secret")
        request = RequestFactory().get("/auth/dumont/")
        return DumontOAuthProvider(request=request, state="s")

    def test_default_scope_is_unchanged(self, monkeypatch):
        monkeypatch.setenv("DUMONT_ZITADEL_ORG_ID", ORG)  # set for the bearer auth; flag unset
        provider = self._new(monkeypatch)
        assert provider.scope == "openid email profile"
        assert "resourceowner" not in provider.get_auth_url()

    def test_scope_with_check_on(self, monkeypatch):
        _enable(monkeypatch)
        provider = self._new(monkeypatch)
        assert provider.scope.split() == ["openid", "email", "profile", "urn:zitadel:iam:user:resourceowner"]
        assert "urn%3Azitadel%3Aiam%3Auser%3Aresourceowner" in provider.get_auth_url()

    def test_login_start_fails_closed_when_misconfigured(self, monkeypatch):
        _enable(monkeypatch, org=None)
        with pytest.raises(AuthenticationException) as exc:
            self._new(monkeypatch)
        assert exc.value.error_code == 5113


@pytest.mark.unit
@pytest.mark.django_db
class TestDumontOrgBoundaryBeforeAnyUser:
    """The refusal happens before Plane looks up, creates or links any user (no e-mail match)."""

    def _authenticate(self, userinfo, monkeypatch):
        provider = _provider(userinfo, token={"access_token": "at", "expires_in": 60})
        reached = []

        def complete_login_or_signup():
            reached.append(True)
            return "logged-in"

        monkeypatch.setattr(provider, "complete_login_or_signup", complete_login_or_signup, raising=False)
        return provider, reached

    def test_foreign_org_never_reaches_user_lookup(self, monkeypatch):
        from plane.db.models import Account, User

        # a Hangar user with the same verified e-mail already exists: e-mail matching must not happen
        User.objects.create(email="carlos@shipeezi.com", username="carlos")
        users, accounts = User.objects.count(), Account.objects.count()
        _enable(monkeypatch)
        provider, reached = self._authenticate(_userinfo(**{CLAIM: "999999999999999999"}), monkeypatch)
        with pytest.raises(AuthenticationException):
            provider.authenticate()
        assert reached == []
        assert (User.objects.count(), Account.objects.count()) == (users, accounts)

    def test_matching_org_reaches_the_login(self, monkeypatch):
        _enable(monkeypatch)
        provider, reached = self._authenticate(_userinfo(**{CLAIM: ORG}), monkeypatch)
        assert provider.authenticate() == "logged-in" and reached == [True]

    def test_unset_reaches_the_login_without_the_claim(self, monkeypatch):
        provider, reached = self._authenticate(_userinfo(), monkeypatch)
        assert provider.authenticate() == "logged-in" and reached == [True]


class _FakeResponse:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


@pytest.mark.unit
class TestDumontUserAgent:
    """Cloudflare in front of Dumont Auth blocks some library-default User-Agents."""

    def test_token_and_userinfo_requests_send_the_explicit_user_agent(self, monkeypatch):
        from plane.authentication.adapter import oauth as oauth_module
        from plane.dumont.auth.config import USER_AGENT

        seen = []
        monkeypatch.setattr(
            oauth_module.requests,
            "post",
            lambda url, data=None, headers=None: seen.append(("post", url, dict(headers))) or _FakeResponse({}),
        )
        monkeypatch.setattr(
            oauth_module.requests,
            "get",
            lambda url, headers=None: seen.append(("get", url, dict(headers))) or _FakeResponse({}),
        )
        provider = object.__new__(DumontOAuthProvider)
        provider.get_user_token(data={"code": "x"})
        provider.token_data = {"access_token": "at"}
        provider.get_user_response()
        assert [(method, headers.get("User-Agent")) for method, _, headers in seen] == [
            ("post", USER_AGENT),
            ("get", USER_AGENT),
        ]
        assert seen[1][2]["Authorization"] == "Bearer at"

    def test_upstream_providers_are_unchanged(self):
        from plane.authentication.adapter.oauth import OauthAdapter
        from plane.authentication.provider.oauth.github import GitHubOAuthProvider

        assert OauthAdapter.request_headers == {}
        assert GitHubOAuthProvider.request_headers == {}
