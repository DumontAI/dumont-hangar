# Dumont addition: fixtures for the ZITADEL bearer tests. Not upstream Plane.
#
# No network: tokens are signed with RSA keys generated here and the JWKS "endpoint"
# is an in-process fake that replaces plane.dumont.auth.jwks._fetch_jwks.

import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.cache import cache
from jwt.algorithms import RSAAlgorithm

from plane.db.models import Account
from plane.dumont.auth import jwks as jwks_module
from plane.dumont.auth.config import BearerConfig

ISSUER = "https://issuer.test"
JWKS_URL = "https://issuer.test/oauth/v2/keys"
AUDIENCE = "300000000000000001"
OTHER_AUDIENCE = "300000000000000002"
ORG_ID = "200000000000000001"
FOREIGN_ORG_ID = "200000000000000099"
RESOURCE_OWNER = "urn:zitadel:iam:user:resourceowner:id"
WEB_URL = "https://hangar.example.test"
LINKED_SUB = "sub-linked-0001"


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def signing_key():
    return _new_key()


@pytest.fixture(scope="session")
def other_key():
    return _new_key()


def public_jwk(private_key, kid):
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


class FakeJwks:
    """Stands in for the issuer's /oauth/v2/keys; counts fetches, can fail on demand."""

    def __init__(self):
        self.keys = []
        self.calls = 0
        self.fail = False
        # When set, returned as-is instead of {"keys": [...]} (malformed or unusable answers).
        self.document = None

    def __call__(self, uri, timeout):
        self.calls += 1
        assert uri == JWKS_URL
        if self.fail:
            raise OSError("fake JWKS down")
        if self.document is not None:
            return self.document
        return {"keys": list(self.keys)}


class FakeClock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(jwks_module, "_now", fake)
    return fake


@pytest.fixture
def fake_jwks(monkeypatch, signing_key):
    fake = FakeJwks()
    fake.keys.append(public_jwk(signing_key, "kid-1"))
    jwks_module.reset_jwks_clients()
    monkeypatch.setattr(jwks_module, "_fetch_jwks", fake)
    yield fake
    jwks_module.reset_jwks_clients()


def make_config(**overrides):
    values = {
        "enabled": True,
        "issuer": ISSUER,
        "jwks_url": JWKS_URL,
        "audiences": (AUDIENCE, OTHER_AUDIENCE),
        "allowed_org_id": ORG_ID,
        "reader_role": "hangar_reader",
        "writer_role": "hangar_writer",
        "rate_limit": "1000/minute",
        "web_url": WEB_URL,
    }
    values.update(overrides)
    return BearerConfig(**values)


@pytest.fixture
def bearer_enabled(settings, fake_jwks):
    settings.DUMONT_API_BEARER = make_config()
    cache.clear()
    yield settings
    cache.clear()


def base_claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": [AUDIENCE, "client-id@project"],
        "sub": LINKED_SUB,
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "jti": uuid.uuid4().hex,
        f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": {"hangar_reader": {ORG_ID: "dumont.example"}},
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not _DROP}


_DROP = object()
DROP = _DROP


@pytest.fixture
def make_token(signing_key):
    def _make(claims=None, key=None, kid="kid-1", algorithm="RS256", headers=None, **overrides):
        payload = claims if claims is not None else base_claims(**overrides)
        extra_headers = {"kid": kid} if kid is not None else {}
        extra_headers.update(headers or {})
        return jwt.encode(payload, key or signing_key, algorithm=algorithm, headers=extra_headers)

    return _make


def writer_roles():
    return {
        f"urn:zitadel:iam:org:project:{AUDIENCE}:roles": {
            "hangar_reader": {ORG_ID: "dumont.example"},
            "hangar_writer": {ORG_ID: "dumont.example"},
        }
    }


@pytest.fixture
def linked_account(db, create_user):
    return Account.objects.create(
        user=create_user,
        provider="dumont",
        provider_account_id=LINKED_SUB,
        access_token="not-a-real-token",
    )
