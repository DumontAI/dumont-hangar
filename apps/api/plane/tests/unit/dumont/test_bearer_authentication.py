# Dumont addition: ZitadelBearerAuthentication, end to end through a real API v1 endpoint.
# Not upstream Plane. No network: see conftest.py.

import base64
import json
import time

import pytest
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework.request import Request

from plane.db.models import Account, User
from plane.dumont.auth import jwks as jwks_module
from plane.dumont.auth.authentication import AuthContext, ZitadelBearerAuthentication

from .conftest import AUDIENCE, DROP, LINKED_SUB, OTHER_AUDIENCE, WEB_URL, base_claims, make_config, public_jwk

ME = "/api/v1/users/me/"


def bearer_client(token):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


def assert_invalid(response, token=None):
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.content
    assert response["WWW-Authenticate"].startswith("Bearer")
    assert response.json()["error_code"] == "DUMONT_INVALID_TOKEN"
    if token:
        assert token not in response.content.decode()


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@pytest.mark.unit
@pytest.mark.django_db
class TestBearerAccepted:
    def test_reader_token_reads_me(self, bearer_enabled, linked_account, make_token, create_user):
        response = bearer_client(make_token()).get(ME)
        assert response.status_code == status.HTTP_200_OK, response.content
        assert response.json()["id"] == str(create_user.id)

    def test_auth_context_is_not_the_token(self, bearer_enabled, linked_account, make_token, create_user):
        token = make_token(jti="jti-123")
        request = Request(APIRequestFactory().get(ME, HTTP_AUTHORIZATION=f"Bearer {token}"))
        user, auth = ZitadelBearerAuthentication().authenticate(request)
        assert user == create_user
        assert isinstance(auth, AuthContext)
        assert auth == AuthContext(sub=LINKED_SUB, roles=("hangar_reader",), token_id="jti-123")
        assert token not in repr(auth)

    def test_token_id_without_jti_is_a_fingerprint(self, bearer_enabled, linked_account, make_token):
        token = make_token(jti=DROP)
        request = Request(APIRequestFactory().get(ME, HTTP_AUTHORIZATION=f"Bearer {token}"))
        _, auth = ZitadelBearerAuthentication().authenticate(request)
        assert auth.token_id.startswith("sha256:") and len(auth.token_id) == len("sha256:") + 16

    def test_second_configured_audience(self, bearer_enabled, linked_account, make_token):
        token = make_token(
            aud=OTHER_AUDIENCE,
            **{
                f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": DROP,
                "my:zitadel:grants": [f"{OTHER_AUDIENCE}:hangar_reader"],
            },
        )
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK

    def test_nbf_within_leeway(self, bearer_enabled, linked_account, make_token):
        token = make_token(nbf=int(time.time()) + 20)
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK

    def test_scheme_is_case_insensitive(self, bearer_enabled, linked_account, make_token):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"bearer {make_token()}")
        assert client.get(ME).status_code == status.HTTP_200_OK

    def test_keys_are_cached(self, bearer_enabled, linked_account, make_token, fake_jwks):
        for _ in range(3):
            assert bearer_client(make_token()).get(ME).status_code == status.HTTP_200_OK
        assert fake_jwks.calls == 1

    def test_hook_called_with_user_and_sub(self, bearer_enabled, linked_account, make_token, monkeypatch, create_user):
        from plane.dumont.access import hooks

        calls = []
        monkeypatch.setattr(hooks, "on_bearer_authenticated", lambda user, sub: calls.append((user, sub)))
        assert bearer_client(make_token()).get(ME).status_code == status.HTTP_200_OK
        assert calls == [(create_user, LINKED_SUB)]

    def test_hook_crash_does_not_lock_out(self, bearer_enabled, linked_account, make_token, monkeypatch):
        from plane.dumont.access import hooks

        def boom(user, sub):
            raise RuntimeError("sync down")

        monkeypatch.setattr(hooks, "on_bearer_authenticated", boom)
        assert bearer_client(make_token()).get(ME).status_code == status.HTTP_200_OK

    def test_hook_can_refuse(self, bearer_enabled, linked_account, make_token, monkeypatch):
        from plane.dumont.access import hooks

        def refuse(user, sub):
            raise PermissionDenied("no")

        monkeypatch.setattr(hooks, "on_bearer_authenticated", refuse)
        assert bearer_client(make_token()).get(ME).status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.unit
@pytest.mark.django_db
class TestBearerRejected:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"exp": int(time.time()) - 1},
            {"exp": DROP},
            {"exp": True},
            {"exp": "9999999999"},
            {"nbf": int(time.time()) + 3600},
            {"nbf": "0"},
            {"iss": "https://evil.test"},
            {"iss": "https://issuer.test/"},
            {"iss": DROP},
            {"aud": "someone-else"},
            {"aud": ["someone-else"]},
            {"aud": DROP},
            {"sub": DROP},
            {"sub": ""},
            {"sub": 123},
            {"nonce": "n-1"},
            {"at_hash": "abc"},
        ],
        ids=lambda o: ",".join(f"{k}={'DROP' if v is DROP else v}" for k, v in o.items()),
    )
    def test_claim_rejections(self, bearer_enabled, linked_account, make_token, overrides):
        # Time values are computed at collection; the margins keep them invalid for the whole run.
        token = make_token(**overrides)
        assert_invalid(bearer_client(token).get(ME), token)

    def test_signed_by_unknown_key_with_known_kid(self, bearer_enabled, linked_account, make_token, other_key):
        token = make_token(key=other_key)
        assert_invalid(bearer_client(token).get(ME), token)

    def test_tampered_payload(self, bearer_enabled, linked_account, make_token):
        header, _, signature = make_token().split(".")
        forged = ".".join([header, b64(base_claims(sub="someone-else")), signature])
        assert_invalid(bearer_client(forged).get(ME), forged)

    def test_hs256_never_reaches_jwks(self, bearer_enabled, linked_account, fake_jwks):
        import jwt

        token = jwt.encode(
            base_claims(), "shared-secret-for-test-only-32bytes!", algorithm="HS256", headers={"kid": "kid-1"}
        )
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_jwks.calls == 0

    def test_alg_none(self, bearer_enabled, linked_account, fake_jwks):
        token = ".".join([b64({"alg": "none", "kid": "kid-1"}), b64(base_claims()), "sig"])
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_jwks.calls == 0

    def test_jwe_shape(self, bearer_enabled, linked_account, fake_jwks):
        token = ".".join([b64({"alg": "RSA-OAEP", "enc": "A256GCM"}), "a", "b", "c", "d"])
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_jwks.calls == 0

    def test_enc_header_on_three_parts(self, bearer_enabled, linked_account, make_token, fake_jwks):
        token = make_token(headers={"enc": "A256GCM"})
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_jwks.calls == 0

    def test_opaque_token(self, bearer_enabled, linked_account, fake_jwks):
        token = "k6Q3dm9hcGF0aHRva2VuLXRlc3Q"
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_jwks.calls == 0

    def test_non_json_header(self, bearer_enabled, linked_account):
        token = "bm90anNvbg.e30.c2ln"
        assert_invalid(bearer_client(token).get(ME), token)

    def test_oversized_token(self, bearer_enabled, linked_account, make_token, fake_jwks):
        token = make_token(padding="x" * (16 * 1024))
        assert_invalid(bearer_client(token).get(ME))
        assert fake_jwks.calls == 0

    def test_malformed_header(self, bearer_enabled, linked_account, make_token):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {make_token()} extra")
        assert_invalid(client.get(ME))

    def test_empty_bearer(self, bearer_enabled, linked_account):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Bearer")
        assert_invalid(client.get(ME))

    def test_missing_kid(self, bearer_enabled, linked_account, make_token, fake_jwks):
        token = make_token(kid=None)
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_jwks.calls == 0

    def test_unknown_kid_refetch_is_bounded(self, bearer_enabled, linked_account, make_token, fake_jwks):
        assert bearer_client(make_token()).get(ME).status_code == status.HTTP_200_OK
        assert fake_jwks.calls == 1
        for i in range(5):
            token = make_token(kid=f"random-{i}")
            assert_invalid(bearer_client(token).get(ME), token)
        # One forced refresh for the first unknown kid, none for the rest within the interval.
        assert fake_jwks.calls == 2

    def test_rotated_key_is_picked_up(self, bearer_enabled, linked_account, make_token, fake_jwks, other_key):
        assert bearer_client(make_token()).get(ME).status_code == status.HTTP_200_OK
        fake_jwks.keys.append(public_jwk(other_key, "kid-2"))
        token = make_token(key=other_key, kid="kid-2")
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK
        assert fake_jwks.calls == 2

    def test_jwks_down_is_503_not_401(self, bearer_enabled, linked_account, make_token, fake_jwks):
        fake_jwks.fail = True
        token = make_token()
        response = bearer_client(token).get(ME)
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert response.json()["error_code"] == "DUMONT_AUTH_UNAVAILABLE"
        assert token not in response.content.decode()
        # Backoff: the next request does not call the issuer again.
        assert bearer_client(token).get(ME).status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert fake_jwks.calls == 1

    def test_no_hangar_role(self, bearer_enabled, linked_account, make_token):
        token = make_token(**{f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": {"other_role": {}}})
        response = bearer_client(token).get(ME)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["error_code"] == "DUMONT_HANGAR_ROLE_REQUIRED"

    def test_role_of_unconfigured_project(self, bearer_enabled, linked_account, make_token):
        token = make_token(
            **{
                f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": DROP,
                "urn:zitadel:iam:org:project:999:roles": {"hangar_writer": {}},
                "my:zitadel:grants": ["999:hangar_writer"],
            }
        )
        assert bearer_client(token).get(ME).status_code == status.HTTP_403_FORBIDDEN

    def test_account_not_linked(self, bearer_enabled, create_user, make_token):
        # create_user exists with an email, but has no Dumont Account: no email fallback.
        token = make_token(email=create_user.email, email_verified=True)
        response = bearer_client(token).get(ME)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response["WWW-Authenticate"].startswith("Bearer")
        assert response.json() == {
            "error_code": "DUMONT_ACCOUNT_NOT_LINKED",
            "error": f"Sign in once at {WEB_URL} with Dumont login",
        }

    def test_account_of_another_provider_does_not_count(self, bearer_enabled, create_user, make_token):
        Account.objects.create(user=create_user, provider="google", provider_account_id=LINKED_SUB, access_token="x")
        response = bearer_client(make_token()).get(ME)
        assert response.json()["error_code"] == "DUMONT_ACCOUNT_NOT_LINKED"

    def test_inactive_user(self, bearer_enabled, linked_account, make_token, create_user):
        create_user.is_active = False
        create_user.save()
        response = bearer_client(make_token()).get(ME)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["error_code"] == "DUMONT_USER_NOT_ALLOWED"

    def test_bot_user(self, bearer_enabled, create_bot_user, make_token):
        Account.objects.create(
            user=create_bot_user, provider="dumont", provider_account_id=LINKED_SUB, access_token="x"
        )
        response = bearer_client(make_token()).get(ME)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["error_code"] == "DUMONT_USER_NOT_ALLOWED"

    def test_both_headers_are_ambiguous(self, bearer_enabled, linked_account, make_token, api_token):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {make_token()}", HTTP_X_API_KEY=api_token.token)
        response = client.get(ME)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["error_code"] == "DUMONT_AMBIGUOUS_CREDENTIALS"


@pytest.mark.unit
@pytest.mark.django_db
class TestBearerDisabledAndApiKeyUnchanged:
    def test_disabled_ignores_bearer(self, settings, fake_jwks, linked_account, make_token):
        settings.DUMONT_API_BEARER = make_config(enabled=False)
        response = bearer_client(make_token()).get(ME)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "WWW-Authenticate" not in response
        assert fake_jwks.calls == 0

    def test_disabled_with_both_headers_uses_api_key(self, settings, fake_jwks, api_token, make_token):
        settings.DUMONT_API_BEARER = make_config(enabled=False)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {make_token()}", HTTP_X_API_KEY=api_token.token)
        assert client.get(ME).status_code == status.HTTP_200_OK

    def test_api_key_still_works_when_enabled(self, bearer_enabled, api_key_client, fake_jwks):
        assert api_key_client.get(ME).status_code == status.HTTP_200_OK
        assert fake_jwks.calls == 0

    def test_bad_api_key_keeps_its_403_without_bearer_challenge(self, bearer_enabled):
        client = APIClient()
        client.credentials(HTTP_X_API_KEY="not-a-key")
        response = client.get(ME)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "WWW-Authenticate" not in response

    def test_other_authorization_scheme_is_not_ours(self, bearer_enabled, fake_jwks):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz")
        response = client.get(ME)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "WWW-Authenticate" not in response
        assert fake_jwks.calls == 0

    def test_no_credentials(self, bearer_enabled):
        assert APIClient().get(ME).status_code == status.HTTP_401_UNAUTHORIZED

    def test_users_are_not_created(self, bearer_enabled, make_token, db):
        before = User.objects.count()
        bearer_client(make_token(sub="brand-new-sub")).get(ME)
        assert User.objects.count() == before

    def test_client_cache_is_per_process(self, bearer_enabled):
        assert jwks_module.get_jwks_client("https://issuer.test/oauth/v2/keys") is jwks_module.get_jwks_client(
            "https://issuer.test/oauth/v2/keys"
        )
