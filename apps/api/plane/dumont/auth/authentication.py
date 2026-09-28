# Dumont addition: accept ZITADEL (Dumont Auth) access tokens on the Plane API v1.
# Not upstream Plane. Wired into plane/api/views/base.py ahead of APIKeyAuthentication.
#
# The token string is never logged, never put in an error and never stored on the
# request: request.auth is an AuthContext, not the raw token.

import base64
import binascii
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass

import jwt
from django.conf import settings
from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import APIException, AuthenticationFailed, PermissionDenied
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from plane.dumont.auth.jwks import get_jwks_client
from plane.dumont.auth.roles import granted_roles

logger = logging.getLogger("plane.dumont.auth")

MAX_BEARER_BYTES = 16 * 1024
NOT_BEFORE_LEEWAY_SECONDS = 30
BEARER_HEADER = re.compile(r"^Bearer[ \t]+([^ \t]+)$", re.IGNORECASE)
BEARER_SCHEME = re.compile(r"^Bearer(?:[ \t]|$)", re.IGNORECASE)
BASE64URL_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

ERROR_INVALID_TOKEN = "DUMONT_INVALID_TOKEN"
ERROR_ACCOUNT_NOT_LINKED = "DUMONT_ACCOUNT_NOT_LINKED"
ERROR_USER_NOT_ALLOWED = "DUMONT_USER_NOT_ALLOWED"
ERROR_ROLE_REQUIRED = "DUMONT_HANGAR_ROLE_REQUIRED"
ERROR_WRITER_ROLE_REQUIRED = "DUMONT_WRITER_ROLE_REQUIRED"
ERROR_AMBIGUOUS_CREDENTIALS = "DUMONT_AMBIGUOUS_CREDENTIALS"
ERROR_AUTH_UNAVAILABLE = "DUMONT_AUTH_UNAVAILABLE"


@dataclass(frozen=True)
class AuthContext:
    """What request.auth holds for a ZITADEL bearer request. Carries no token material."""

    sub: str
    roles: tuple
    token_id: str

    def has_role(self, role):
        return role in self.roles


class AmbiguousCredentials(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = {
        "error_code": ERROR_AMBIGUOUS_CREDENTIALS,
        "error": "Send either Authorization: Bearer or X-Api-Key, not both.",
    }
    default_code = "ambiguous_credentials"


class AuthUnavailable(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = {
        "error_code": ERROR_AUTH_UNAVAILABLE,
        "error": "Dumont Auth signing keys are temporarily unavailable. Retry shortly.",
    }
    default_code = "auth_unavailable"


def _invalid(reason):
    # `reason` is a fixed code chosen here, never token content.
    logger.info("dumont bearer rejected", extra={"reason": reason})
    return AuthenticationFailed({"error_code": ERROR_INVALID_TOKEN, "error": "Invalid or expired Dumont access token."})


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _decode_header(segment):
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        header = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return header if isinstance(header, dict) else None


def _config():
    return settings.DUMONT_API_BEARER


def _bearer_header(request):
    """The raw Authorization value when it uses the Bearer scheme, else None (not ours)."""
    value = request.headers.get("Authorization") or ""
    return value if BEARER_SCHEME.match(value) else None


class ZitadelBearerAuthentication(BaseAuthentication):
    """`Authorization: Bearer <ZITADEL JWT access token>` for API v1.

    Returns None (so X-Api-Key keeps working unchanged) when the feature is off or the
    request has no Bearer Authorization header.
    """

    www_authenticate_realm = "api"

    def authenticate_header(self, request):
        # Only answer with a Bearer challenge for Bearer requests: X-Api-Key failures keep
        # their upstream behaviour (DRF turns AuthenticationFailed into 403 without a challenge).
        if not _config().enabled or _bearer_header(request) is None:
            return None
        return f'Bearer realm="{self.www_authenticate_realm}"'

    def authenticate(self, request):
        config = _config()
        if not config.enabled:
            return None
        header = _bearer_header(request)
        if header is None:
            return None
        if request.headers.get("X-Api-Key"):
            raise AmbiguousCredentials()

        match = BEARER_HEADER.match(header)
        if not match:
            raise _invalid("malformed_header")
        token = match.group(1)
        claims = self._verify(token, config)

        roles = granted_roles(claims, config.audiences, config.reader_role, config.writer_role)
        if not roles:
            raise PermissionDenied(
                {
                    "error_code": ERROR_ROLE_REQUIRED,
                    "error": f"Token lacks the {config.reader_role} or {config.writer_role} role.",
                }
            )

        sub = claims["sub"]
        user = self._resolve_user(sub, config)

        if config.writer_role not in roles and request.method.upper() not in SAFE_METHODS:
            raise PermissionDenied(
                {
                    "error_code": ERROR_WRITER_ROLE_REQUIRED,
                    "error": f"The {config.writer_role} role is required for {request.method.upper()} requests.",
                }
            )

        self._run_hook(user, sub)
        return (user, AuthContext(sub=sub, roles=roles, token_id=self._token_id(claims, token)))

    def _verify(self, token, config):
        if len(token.encode("utf-8")) > MAX_BEARER_BYTES:
            raise _invalid("too_large")
        parts = token.split(".")
        # Only compact JWS (3 segments). JWE (5 segments), opaque tokens and anything else stop here.
        if len(parts) != 3 or not all(BASE64URL_SEGMENT.match(part) for part in parts):
            raise _invalid("not_jws")
        header = _decode_header(parts[0])
        if header is None or header.get("alg") != "RS256" or "enc" in header:
            raise _invalid("bad_header")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise _invalid("no_kid")

        try:
            signing_key = get_jwks_client(config.jwks_url).get_signing_key(kid)
        except PyJWKClientConnectionError:
            logger.warning("dumont bearer: JWKS unavailable")
            raise AuthUnavailable()
        except PyJWKClientError:
            raise _invalid("unknown_kid")

        try:
            # Signature only; the claim checks below mirror mcp/src/auth.ts evaluateAccessClaims.
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                    "verify_jti": False,
                    "require": [],
                },
            )
        except jwt.PyJWTError:
            raise _invalid("bad_signature")
        if not isinstance(claims, dict):
            raise _invalid("bad_payload")

        now = int(time.time())
        if claims.get("iss") != config.issuer:
            raise _invalid("issuer")
        aud = claims.get("aud")
        token_audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if not any(isinstance(a, str) and a in config.audiences for a in token_audiences):
            raise _invalid("audience")
        exp = claims.get("exp")
        if not _is_number(exp) or exp <= now:
            raise _invalid("expired")
        if "nbf" in claims and (not _is_number(claims["nbf"]) or claims["nbf"] > now + NOT_BEFORE_LEEWAY_SECONDS):
            raise _invalid("not_yet_valid")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise _invalid("no_sub")
        # `nonce`/`at_hash` only appear in ID tokens; never accept one as an access token.
        if "nonce" in claims or "at_hash" in claims:
            raise _invalid("id_token")
        return claims

    def _resolve_user(self, sub, config):
        # Imported here so this module stays importable before the app registry is ready.
        from plane.db.models import Account

        accounts = list(Account.objects.filter(provider="dumont", provider_account_id=sub).select_related("user")[:2])
        if not accounts:
            where = f" at {config.web_url}" if config.web_url else " in the Hangar web app"
            raise AuthenticationFailed(
                {
                    "error_code": ERROR_ACCOUNT_NOT_LINKED,
                    "error": f"Sign in once{where} with Dumont login",
                }
            )
        user = accounts[0].user
        if len(accounts) != 1 or not user.is_active or user.is_bot:
            logger.info("dumont bearer rejected", extra={"reason": "user_not_allowed"})
            raise AuthenticationFailed(
                {"error_code": ERROR_USER_NOT_ALLOWED, "error": "This Hangar user cannot use the API."}
            )
        return user

    @staticmethod
    def _run_hook(user, sub):
        from plane.dumont.access import hooks

        try:
            hooks.on_bearer_authenticated(user, sub)
        except APIException:
            raise
        except Exception:
            # Fail safe: a membership-sync problem must not lock users out of the API.
            logger.exception("dumont bearer: on_bearer_authenticated hook failed")

    @staticmethod
    def _token_id(claims, token):
        jti = claims.get("jti")
        if isinstance(jti, str) and 0 < len(jti) <= 128:
            return jti
        # A short one-way fingerprint for correlation; the token itself is never kept.
        return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
