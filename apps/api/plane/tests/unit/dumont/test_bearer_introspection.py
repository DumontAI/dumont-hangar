# Dumont addition: opaque ZITADEL access tokens on API v1 through RFC 7662 introspection.
# Not upstream Plane. No network: the introspection endpoint is an in-process fake that
# replaces plane.dumont.auth.introspection._http_post (one test drives the real HTTP code
# against a loopback server started in the test).

import base64
import http.server
import json
import logging
import secrets
import threading
import time
from urllib.parse import parse_qs

import pytest
from django.core.cache import cache
from rest_framework import status
from rest_framework.request import Request
from rest_framework.test import APIClient, APIRequestFactory

from plane.db.models import APIActivityLog
from plane.dumont.auth import introspection as introspection_module
from plane.dumont.auth.authentication import AuthContext, ZitadelBearerAuthentication

from .conftest import (
    AUDIENCE,
    DROP,
    FOREIGN_ORG_ID,
    ISSUER,
    LINKED_SUB,
    ORG_ID,
    RESOURCE_OWNER,
    base_claims,
    make_config,
    writer_roles,
)

ME = "/api/v1/users/me/"
INVALID_TOKEN_CHALLENGE = 'Bearer realm="api", error="invalid_token"'
INTROSPECTION_URL = "https://issuer.test/oauth/v2/introspect"
CLIENT_ID = "390213468206137347@hangar-api"
# Characters that must be form-encoded before Basic (RFC 6749 section 2.3.1), as in the MCP.
CLIENT_SECRET = "intro:Secret+value/for-tests-only"
LOGGER_NAME = "plane.authentication.dumont_bearer"


def opaque_token():
    return "opq_" + secrets.token_urlsafe(32)


def zitadel_jwe_token():
    # The 5-part shape ZITADEL issues as opaque access token (alg A256GCMKW / enc A256GCM).
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "A256GCMKW", "enc": "A256GCM", "kid": "k", "iv": "A" * 16, "tag": "A" * 22}).encode()
    )
    return ".".join([header.rstrip(b"=").decode(), "B" * 43, "C" * 16, secrets.token_urlsafe(24), "D" * 22])


def introspection_claims(**overrides):
    claims = base_claims(**{"token_type": "Bearer", "client_id": "client@project", "scope": "openid"})
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not DROP}


class FakeIntrospection:
    """Stands in for the issuer's /oauth/v2/introspect. Answers per token; counts calls."""

    def __init__(self):
        self.active = {}  # token -> claims returned with "active": true
        self.calls = []
        self.fail = False
        self.status = 200
        # When set, returned as the body instead of the JSON answer.
        self.raw = None

    def __call__(self, url, body, headers, timeout):
        form = parse_qs(body.decode("ascii"), strict_parsing=True)
        self.calls.append({"url": url, "form": form, "headers": dict(headers), "timeout": timeout})
        if self.fail:
            raise OSError("fake introspection endpoint down")
        if self.raw is not None:
            return self.status, self.raw
        token = form["token"][0]
        claims = self.active.get(token)
        payload = {"active": True, **claims} if claims is not None else {"active": False}
        return self.status, json.dumps(payload).encode()


def introspection_config(**overrides):
    values = {
        "introspection_url": INTROSPECTION_URL,
        "introspection_client_id": CLIENT_ID,
        "introspection_client_secret": CLIENT_SECRET,
    }
    values.update(overrides)
    return make_config(**values)


@pytest.fixture
def fake_introspection(monkeypatch):
    fake = FakeIntrospection()
    monkeypatch.setattr(introspection_module, "_http_post", fake)
    return fake


@pytest.fixture
def introspection_enabled(settings, fake_jwks, fake_introspection):
    settings.DUMONT_API_BEARER = introspection_config()
    cache.clear()
    yield settings
    cache.clear()


@pytest.fixture
def issue(fake_introspection):
    """issue(**claim_overrides) -> a fresh opaque token the fake reports as active with those claims."""

    def _issue(token=None, **overrides):
        token = token or opaque_token()
        fake_introspection.active[token] = introspection_claims(**overrides)
        return token

    return _issue


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def text(self):
        return "\n".join(f"{r.getMessage()} {r.__dict__!r}" for r in self.records)


@pytest.fixture
def log_records():
    handler = _Records()
    targets = [logging.getLogger(LOGGER_NAME), logging.getLogger()]
    old_level = targets[0].level
    targets[0].setLevel(logging.DEBUG)
    for target in targets:
        target.addHandler(handler)
    yield handler
    for target in targets:
        target.removeHandler(handler)
    targets[0].setLevel(old_level)


def bearer_client(token):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


def assert_invalid(response, token):
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.content
    assert response["WWW-Authenticate"] == INVALID_TOKEN_CHALLENGE
    assert response.json()["error_code"] == "DUMONT_INVALID_TOKEN"
    assert token not in response.content.decode()


def assert_unavailable(response, token):
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE, response.content
    assert response.json()["error_code"] == "DUMONT_AUTH_UNAVAILABLE"
    # A 503 must never look like a bad token: no invalid_token challenge, so no relogin loop.
    assert "invalid_token" not in response.get("WWW-Authenticate", "")
    body = response.content.decode()
    assert token not in body and CLIENT_SECRET not in body


def authenticate(token, method="get"):
    request = Request(getattr(APIRequestFactory(), method)(ME, HTTP_AUTHORIZATION=f"Bearer {token}"))
    return ZitadelBearerAuthentication().authenticate(request)


@pytest.mark.unit
@pytest.mark.django_db
class TestIntrospectionAccepted:
    def test_active_token_with_our_org_role(self, introspection_enabled, linked_account, issue, create_user):
        response = bearer_client(issue()).get(ME)
        assert response.status_code == status.HTTP_200_OK, response.content
        assert response.json()["id"] == str(create_user.id)

    def test_request_shape(self, introspection_enabled, linked_account, issue, fake_introspection):
        token = issue()
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK
        [call] = fake_introspection.calls
        assert call["url"] == INTROSPECTION_URL
        assert call["form"] == {"token": [token], "token_type_hint": ["access_token"]}
        assert call["timeout"] == 5
        assert call["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        scheme, _, encoded = call["headers"]["Authorization"].partition(" ")
        assert scheme == "Basic"
        # client_id and secret are form-encoded, then joined with ':' (as the MCP does).
        assert base64.b64decode(encoded).decode() == (
            "390213468206137347%40hangar-api:intro%3ASecret%2Bvalue%2Ffor-tests-only"
        )

    def test_zitadel_jwe_shaped_token(self, introspection_enabled, linked_account, issue, fake_introspection):
        token = issue(token=zitadel_jwe_token())
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK
        assert len(fake_introspection.calls) == 1

    @pytest.mark.parametrize("token_type", [DROP, "Bearer", "bearer", "access_token"])
    def test_access_token_types(self, introspection_enabled, linked_account, issue, token_type):
        assert bearer_client(issue(token_type=token_type)).get(ME).status_code == status.HTTP_200_OK

    def test_string_audience(self, introspection_enabled, linked_account, issue):
        assert bearer_client(issue(aud=AUDIENCE)).get(ME).status_code == status.HTTP_200_OK

    def test_auth_context_uses_a_fingerprint_even_with_jti(self, introspection_enabled, linked_account, issue):
        token = issue(jti="zitadel-token-id")
        user, auth = authenticate(token)
        assert isinstance(auth, AuthContext)
        assert auth.sub == LINKED_SUB and auth.roles == ("hangar_reader",)
        assert auth.token_id.startswith("sha256:") and len(auth.token_id) == len("sha256:") + 16
        assert token not in repr(auth)

    def test_writer_can_write_reader_cannot(self, introspection_enabled, linked_account, issue):
        reader = bearer_client(issue()).patch(ME, {"first_name": "X"}, format="json")
        assert reader.status_code == status.HTTP_403_FORBIDDEN
        assert reader.json()["error_code"] == "DUMONT_WRITER_ROLE_REQUIRED"
        writer = issue(**writer_roles())
        # /users/me/ has no PATCH: getting past the auth gate to the route's 405 is the proof.
        _, auth = authenticate(writer, method="patch")
        assert auth.roles == ("hangar_reader", "hangar_writer")
        assert bearer_client(writer).patch(ME, {"first_name": "X"}, format="json").status_code == (
            status.HTTP_405_METHOD_NOT_ALLOWED
        )

    def test_hook_called(self, introspection_enabled, linked_account, issue, monkeypatch, create_user):
        from plane.dumont.access import hooks

        calls = []
        monkeypatch.setattr(hooks, "on_bearer_authenticated", lambda user, sub: calls.append((user, sub)))
        assert bearer_client(issue()).get(ME).status_code == status.HTTP_200_OK
        assert calls == [(create_user, LINKED_SUB)]

    def test_jws_tokens_never_reach_introspection(
        self, introspection_enabled, linked_account, make_token, fake_introspection, fake_jwks
    ):
        assert bearer_client(make_token()).get(ME).status_code == status.HTTP_200_OK
        id_token = make_token(nonce="n-1")
        assert_invalid(bearer_client(id_token).get(ME), id_token)
        assert fake_introspection.calls == []
        assert fake_jwks.calls == 1


@pytest.mark.unit
@pytest.mark.django_db
class TestIntrospectionRejected:
    def test_inactive(self, introspection_enabled, linked_account, fake_introspection):
        token = opaque_token()
        assert_invalid(bearer_client(token).get(ME), token)
        assert len(fake_introspection.calls) == 1

    @pytest.mark.parametrize("active", [DROP, False, "true", 1, None])
    def test_only_active_true_counts(self, introspection_enabled, linked_account, fake_introspection, active):
        claims = introspection_claims()
        if active is not DROP:
            claims["active"] = active
        fake_introspection.raw = json.dumps(claims).encode()
        token = opaque_token()
        assert_invalid(bearer_client(token).get(ME), token)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"iss": "https://evil.test"},
            {"iss": ISSUER + "/"},
            {"iss": DROP},
            {"aud": "someone-else"},
            {"aud": ["someone-else"]},
            {"aud": DROP},
            {"exp": int(time.time()) - 1},
            {"exp": DROP},
            {"exp": "9999999999"},
            {"exp": True},
            {"nbf": int(time.time()) + 3600},
            {"sub": DROP},
            {"sub": ""},
            {"sub": 123},
            {"nonce": "n-1"},
            {"at_hash": "abc"},
            {"token_type": "id_token"},
            {"token_type": "urn:ietf:params:oauth:token-type:id_token"},
            {"token_type": "refresh_token"},
            {"token_type": 1},
            {"token_type": None},
        ],
        ids=lambda o: ",".join(f"{k}={'DROP' if v is DROP else v}" for k, v in o.items()),
    )
    def test_claim_rejections(self, introspection_enabled, linked_account, issue, overrides):
        token = issue(**overrides)
        assert_invalid(bearer_client(token).get(ME), token)

    @pytest.mark.parametrize("exp", [float("inf"), float("nan")])
    def test_non_finite_exp(self, introspection_enabled, linked_account, fake_introspection, exp):
        # json.dumps writes Infinity/NaN and json.loads reads them back; neither is a timestamp.
        fake_introspection.raw = json.dumps({"active": True, **introspection_claims(exp=exp)}).encode()
        token = opaque_token()
        assert_invalid(bearer_client(token).get(ME), token)

    def test_foreign_org_role_map(self, introspection_enabled, linked_account, issue):
        # Our project granted to another org: same aud, same claim name, but the role is that org's.
        token = issue(
            **{
                f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": {
                    "hangar_reader": {FOREIGN_ORG_ID: "other.example"},
                    "hangar_writer": {FOREIGN_ORG_ID: "other.example"},
                },
                RESOURCE_OWNER: FOREIGN_ORG_ID,
            }
        )
        response = bearer_client(token).get(ME)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["error_code"] == "DUMONT_HANGAR_ROLE_REQUIRED"

    @pytest.mark.parametrize("owner", [DROP, FOREIGN_ORG_ID])
    def test_bare_roles_need_our_resource_owner(self, introspection_enabled, linked_account, issue, owner):
        token = issue(
            **{
                f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": DROP,
                "roles": ["hangar_writer"],
                "org_id": ORG_ID,
                RESOURCE_OWNER: owner,
            }
        )
        response = bearer_client(token).get(ME)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["error_code"] == "DUMONT_HANGAR_ROLE_REQUIRED"

    def test_bare_roles_with_our_resource_owner(self, introspection_enabled, linked_account, issue):
        token = issue(
            **{
                f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": DROP,
                "roles": ["hangar_reader"],
                RESOURCE_OWNER: ORG_ID,
            }
        )
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK

    def test_no_role_claims(self, introspection_enabled, linked_account, issue):
        response = bearer_client(issue(**{f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": DROP})).get(ME)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["error_code"] == "DUMONT_HANGAR_ROLE_REQUIRED"

    def test_account_not_linked(self, introspection_enabled, create_user, issue):
        response = bearer_client(issue()).get(ME)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response["WWW-Authenticate"] == 'Bearer realm="api"'
        assert response.json()["error_code"] == "DUMONT_ACCOUNT_NOT_LINKED"

    def test_inactive_plane_user(self, introspection_enabled, linked_account, issue, create_user):
        create_user.is_active = False
        create_user.save()
        response = bearer_client(issue()).get(ME)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["error_code"] == "DUMONT_USER_NOT_ALLOWED"

    @pytest.mark.parametrize("token", ["bad!token", "tok,en", 'tok"en', "=abc", "abc=def"])
    def test_malformed_opaque_token_never_reaches_issuer(
        self, introspection_enabled, linked_account, fake_introspection, token
    ):
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_introspection.calls == []

    def test_oversized_opaque_token_never_reaches_issuer(
        self, introspection_enabled, linked_account, fake_introspection
    ):
        token = "a" * (16 * 1024 + 1)
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_introspection.calls == []


@pytest.mark.unit
@pytest.mark.django_db
class TestIntrospectionUnavailable:
    @pytest.mark.parametrize(
        "setup",
        [
            {"fail": True},
            {"status": 500},
            {"status": 401},
            {"status": 400},
            {"status": 302},
            {"status": 201},
            {"raw": b"<html>garbage</html>"},
            {"raw": b""},
            {"raw": b"[1, 2]"},
            {"raw": b'"active"'},
            {"raw": b"\xff\xfe"},
            {"raw": b"{" + b" " * (64 * 1024 + 1) + b"}"},
        ],
        ids=[
            "down",
            "500",
            "401",
            "400",
            "302",
            "201",
            "html",
            "empty",
            "list",
            "string",
            "not-utf8",
            "too-large",
        ],
    )
    def test_is_503_and_not_cached(self, introspection_enabled, linked_account, issue, fake_introspection, setup):
        token = issue()
        for name, value in setup.items():
            setattr(fake_introspection, name, value)
        assert_unavailable(bearer_client(token).get(ME), token)
        assert_unavailable(bearer_client(token).get(ME), token)
        # Never cached: each request asked the issuer again.
        assert len(fake_introspection.calls) == 2
        assert cache.get(introspection_module._cache_key(token)) is None
        # Issuer back: the same token works at once.
        fake_introspection.fail, fake_introspection.status, fake_introspection.raw = False, 200, None
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK

    def test_real_http_client_refuses_redirects_and_errors(self):
        """_http_post itself against a loopback server: redirects are not followed, errors keep their status."""
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append(self.path)
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/ok")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif self.path == "/error":
                    body = b'{"error": "invalid_client"}'
                    self.send_response(401)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    body = b'{"active": false}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            post = introspection_module._http_post
            assert post(f"{base}/ok", b"token=x", {}, 5) == (200, b'{"active": false}')
            assert post(f"{base}/redirect", b"token=x", {}, 5) == (302, b"")
            assert post(f"{base}/error", b"token=x", {}, 5) == (401, b"")
            assert seen == ["/ok", "/redirect", "/error"]  # the redirect target was never requested
        finally:
            server.shutdown()
            server.server_close()


@pytest.mark.unit
@pytest.mark.django_db
class TestIntrospectionCache:
    def test_cache_hit_avoids_second_call(self, introspection_enabled, linked_account, issue, fake_introspection):
        token = issue()
        for _ in range(3):
            assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK
        assert len(fake_introspection.calls) == 1

    def test_cached_claims_are_checked_again(self, introspection_enabled, linked_account, issue, settings):
        token = issue()
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK
        # Same cached answer, stricter config: the claim checks run on the hit too.
        settings.DUMONT_API_BEARER = introspection_config(audiences=("300000000000000077",))
        assert_invalid(bearer_client(token).get(ME), token)

    def test_different_tokens_never_share_cache(
        self, introspection_enabled, linked_account, issue, fake_introspection, create_user
    ):
        good = issue()
        other = issue(sub="sub-someone-else")
        assert bearer_client(good).get(ME).status_code == status.HTTP_200_OK
        response = bearer_client(other).get(ME)
        assert response.json()["error_code"] == "DUMONT_ACCOUNT_NOT_LINKED"
        dead = opaque_token()
        assert_invalid(bearer_client(dead).get(ME), dead)
        assert bearer_client(good).get(ME).status_code == status.HTTP_200_OK
        assert [c["form"]["token"][0] for c in fake_introspection.calls] == [good, other, dead]

    def test_inactive_is_cached_for_30_seconds(self, introspection_enabled, linked_account, fake_introspection):
        token = opaque_token()
        for _ in range(3):
            assert_invalid(bearer_client(token).get(ME), token)
        assert len(fake_introspection.calls) == 1
        key = introspection_module._cache_key(token)
        assert cache.get(key) == {"active": False}
        assert 0 < cache.ttl(key) <= 30

    def test_positive_ttl_is_min_of_60s_and_exp(self, introspection_enabled, linked_account, issue):
        long_lived = issue()
        short_lived = issue(exp=int(time.time()) + 10)
        assert bearer_client(long_lived).get(ME).status_code == status.HTTP_200_OK
        assert bearer_client(short_lived).get(ME).status_code == status.HTTP_200_OK
        assert 50 <= cache.ttl(introspection_module._cache_key(long_lived)) <= 60
        assert 0 < cache.ttl(introspection_module._cache_key(short_lived)) <= 10

    def test_active_answer_with_unusable_exp_is_not_cached(
        self, introspection_enabled, linked_account, issue, fake_introspection
    ):
        token = issue(exp=int(time.time()) - 5)
        assert_invalid(bearer_client(token).get(ME), token)
        assert cache.get(introspection_module._cache_key(token)) is None

    def test_cache_key_does_not_contain_the_token(self, introspection_enabled, linked_account, issue):
        token = issue()
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK
        key = introspection_module._cache_key(token)
        assert token not in key
        assert key == introspection_module.CACHE_KEY_PREFIX + introspection_module.token_fingerprint(token)
        stored_keys = list(cache.keys("*"))
        assert key in stored_keys
        assert not any(token in k for k in stored_keys)

    def test_cache_outage_does_not_decide(
        self, introspection_enabled, linked_account, issue, fake_introspection, monkeypatch
    ):
        class BrokenCache:
            def get(self, *args, **kwargs):
                raise ConnectionError("cache down")

            set = get

        monkeypatch.setattr(introspection_module, "cache", BrokenCache())
        token = issue()
        assert bearer_client(token).get(ME).status_code == status.HTTP_200_OK
        dead = opaque_token()
        assert_invalid(bearer_client(dead).get(ME), dead)
        assert len(fake_introspection.calls) == 2


@pytest.mark.unit
@pytest.mark.django_db
class TestIntrospectionSecrecy:
    def test_secret_not_in_repr(self):
        config = introspection_config()
        assert CLIENT_SECRET not in repr(config)
        assert CLIENT_SECRET not in str(config)
        assert CLIENT_ID in repr(config)

    def test_token_and_secret_never_logged(
        self, introspection_enabled, linked_account, issue, fake_introspection, log_records
    ):
        good = issue()
        assert bearer_client(good).get(ME).status_code == status.HTTP_200_OK
        dead = opaque_token()
        assert_invalid(bearer_client(dead).get(ME), dead)
        foreign = issue(**{f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": {"hangar_reader": {FOREIGN_ORG_ID: "x"}}})
        bearer_client(foreign).get(ME)
        fake_introspection.fail = True
        down = issue()
        assert_unavailable(bearer_client(down).get(ME), down)
        fake_introspection.fail = False
        fake_introspection.status = 500
        down2 = issue()
        assert_unavailable(bearer_client(down2).get(ME), down2)

        text = log_records.text()
        assert "introspection unavailable" in text
        basic = fake_introspection.calls[0]["headers"]["Authorization"].partition(" ")[2]
        for needle in (good, dead, foreign, down, down2, CLIENT_SECRET, basic):
            assert needle not in text

    def test_audit_log_has_fingerprint_not_token(
        self, introspection_enabled, linked_account, issue, workspace, monkeypatch
    ):
        from plane.bgtasks import logger_task
        from plane.middleware import logger as logger_middleware

        monkeypatch.setattr(
            logger_middleware.process_logs,
            "delay",
            lambda log_data: logger_task.process_logs(log_data=log_data),
        )
        token = issue(jti="zitadel-token-id", **writer_roles())
        url = f"/api/v1/workspaces/{workspace.slug}/projects/"
        response = bearer_client(token).post(url, {"name": "Audited", "identifier": "AUD"}, format="json")
        assert response.status_code == status.HTTP_201_CREATED, response.content
        row = APIActivityLog.objects.get(path=url, method="POST")
        fingerprint = introspection_module.token_fingerprint(token)[:16]
        assert row.token_identifier == f"dumont:{LINKED_SUB}:sha256:{fingerprint}"
        stored = " ".join(
            str(getattr(row, field))
            for field in ("token_identifier", "headers", "body", "response_body", "query_params")
        )
        assert token not in stored


@pytest.mark.unit
@pytest.mark.django_db
class TestIntrospectionUnconfigured:
    @pytest.mark.parametrize("token", ["opq_abcdef0123456789", zitadel_jwe_token()])
    def test_opaque_token_is_401(self, bearer_enabled, linked_account, fake_introspection, token):
        assert_invalid(bearer_client(token).get(ME), token)
        assert fake_introspection.calls == []

    def test_disabled_feature_never_introspects(self, settings, fake_jwks, fake_introspection, linked_account):
        settings.DUMONT_API_BEARER = introspection_config(enabled=False)
        response = bearer_client(opaque_token()).get(ME)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "WWW-Authenticate" not in response
        assert fake_introspection.calls == []
