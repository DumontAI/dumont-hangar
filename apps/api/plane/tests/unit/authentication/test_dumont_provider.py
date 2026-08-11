# Dumont addition: covers the Dumont Auth (ZITADEL) OIDC provider mapping.
# Not upstream Plane.

from datetime import datetime, timedelta

import pytest
import pytz

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oauth.dumont import DumontOAuthProvider


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
