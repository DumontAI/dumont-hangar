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
import math
import re
import time
from dataclasses import dataclass

import jwt
from django.conf import settings
from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import APIException, AuthenticationFailed, PermissionDenied

from plane.dumont.auth.introspection import (
    IntrospectionUnavailable,
    introspect,
    is_zitadel_opaque_token,
    token_fingerprint,
)
from plane.dumont.auth.jwks import UnknownKid, get_jwks_client
from plane.dumont.auth.roles import granted_roles

# A child of "plane.authentication", so it inherits the handler and level that
# plane/settings/production.py and local.py configure there.
logger = logging.getLogger("plane.authentication.dumont_bearer")

MAX_BEARER_BYTES = 16 * 1024
NOT_BEFORE_LEEWAY_SECONDS = 30
BEARER_HEADER = re.compile(r"^Bearer[ \t]+([^ \t]+)$", re.IGNORECASE)
BEARER_SCHEME = re.compile(r"^Bearer(?:[ \t]|$)", re.IGNORECASE)
BASE64URL_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
# `token_type` values an introspection answer may carry for an access token (as in the MCP).
ACCESS_TOKEN_TYPES = frozenset({"bearer", "access_token", "urn:ietf:params:oauth:token-type:access_token"})
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


class InvalidBearerToken(AuthenticationFailed):
    """401 DUMONT_INVALID_TOKEN; answered with `error="invalid_token"` in the Bearer challenge (RFC 6750)."""


# Set on the DRF request when authenticate() rejected the token itself, so
# authenticate_header() can add `error="invalid_token"` to the challenge.
_INVALID_TOKEN_FLAG = "_dumont_bearer_invalid_token"


def _invalid(reason):
    # `reason` is a fixed code chosen here, never token content.
    logger.info("dumont bearer rejected", extra={"reason": reason})
    return InvalidBearerToken({"error_code": ERROR_INVALID_TOKEN, "error": "Invalid or expired Dumont access token."})


def _is_number(value):
    # json.loads accepts NaN and Infinity; neither is a usable timestamp.
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


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
    """`Authorization: Bearer <ZITADEL access token>` for API v1.

    JWT access tokens are verified locally against the JWKS. Opaque access tokens are checked
    with RFC 7662 introspection when DUMONT_API_INTROSPECTION_CLIENT_ID/_SECRET are set, and
    rejected otherwise. Both paths then run the same claim checks and org-bound role gate.

    Returns None (so X-Api-Key keeps working unchanged) when the feature is off or the
    request has no Bearer Authorization header.
    """

    www_authenticate_realm = "api"

    def authenticate_header(self, request):
        # Only answer with a Bearer challenge for Bearer requests: X-Api-Key failures keep
        # their upstream behaviour (DRF turns AuthenticationFailed into 403 without a challenge).
        if not _config().enabled or _bearer_header(request) is None:
            return None
        if getattr(request, _INVALID_TOKEN_FLAG, False):
            return f'Bearer realm="{self.www_authenticate_realm}", error="invalid_token"'
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

        try:
            match = BEARER_HEADER.match(header)
            if not match:
                raise _invalid("malformed_header")
            token = match.group(1)
            claims, token_id = self._verify(token, config)
        except InvalidBearerToken:
            setattr(request, _INVALID_TOKEN_FLAG, True)
            raise

        roles = granted_roles(claims, config.audiences, config.reader_role, config.writer_role, config.allowed_org_id)
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
        return (user, AuthContext(sub=sub, roles=roles, token_id=token_id))

    def _verify(self, token, config):
        """(claims, token_id) of a valid access token. Raises InvalidBearerToken or AuthUnavailable."""
        if len(token.encode("utf-8")) > MAX_BEARER_BYTES:
            raise _invalid("too_large")
        parts = token.split(".")
        # Compact JWS (3 segments) is only ever verified locally, so a JWT (an ID token, a forged
        # token) never reaches the issuer. Anything else (ZITADEL opaque tokens, JWE) is only
        # accepted through introspection, when it is configured.
        if len(parts) == 3 and all(BASE64URL_SEGMENT.match(part) for part in parts):
            claims = self._verify_jws(token, parts, config)
            return claims, self._token_id(claims, token)
        if not config.introspection_enabled:
            raise _invalid("not_jws")
        if not is_zitadel_opaque_token(token):
            # Only ZITADEL's opaque shape is worth an issuer call; anything else is invalid here.
            raise _invalid("not_zitadel_opaque")
        return self._verify_by_introspection(token, config)

    def _verify_by_introspection(self, token, config):
        try:
            claims = introspect(token, config)
        except IntrospectionUnavailable:
            # We could not check the token, which is not the caller's fault: 503 so clients retry
            # instead of starting a new login. Never 401, never 500.
            raise AuthUnavailable(
                {
                    "error_code": ERROR_AUTH_UNAVAILABLE,
                    "error": "Dumont Auth token introspection is temporarily unavailable. Retry shortly.",
                }
            ) from None
        if claims is None:
            raise _invalid("inactive")
        token_type = claims.get("token_type")
        if "token_type" in claims and not (isinstance(token_type, str) and token_type.lower() in ACCESS_TOKEN_TYPES):
            raise _invalid("token_type")
        self._check_claims(claims, config)
        # Always the fingerprint here (never the token): the audit id of an introspected token.
        return claims, "sha256:" + token_fingerprint(token)[:16]

    def _verify_jws(self, token, parts, config):
        header = _decode_header(parts[0])
        if header is None or header.get("alg") != "RS256" or "enc" in header:
            raise _invalid("bad_header")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise _invalid("no_kid")

        try:
            signing_key = get_jwks_client(config.jwks_url).get_signing_key(kid)
        except UnknownKid:
            # The key set is current and has no such kid: the token is invalid.
            raise _invalid("unknown_kid")
        except jwt.PyJWTError:
            # Anything else (fetch failure, unusable key set) means we could not check the
            # token, which is not the caller's fault: 503, never 401 or 500.
            logger.warning("dumont bearer: JWKS unavailable")
            raise AuthUnavailable()

        try:
            # Signature only; _check_claims mirrors mcp/src/auth.ts evaluateAccessClaims.
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
        self._check_claims(claims, config)
        return claims

    @staticmethod
    def _check_claims(claims, config):
        """The claim checks shared by JWS and introspected tokens (mirror of the MCP's evaluateAccessClaims)."""
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

    def _resolve_user(self, sub, config):
        # Imported here so this module stays importable before the app registry is ready.
        from plane.db.models import Account

        # (provider, provider_account_id) is unique_together on Account: at most one row.
        account = Account.objects.filter(provider="dumont", provider_account_id=sub).select_related("user").first()
        if account is None:
            where = f" at {config.web_url}" if config.web_url else " in the Hangar web app"
            raise AuthenticationFailed(
                {
                    "error_code": ERROR_ACCOUNT_NOT_LINKED,
                    "error": f"Sign in once{where} with Dumont login",
                }
            )
        user = account.user
        if not user.is_active or user.is_bot:
            # The token is fine; this user may not use the API. 403, so clients do not re-login.
            logger.info("dumont bearer rejected", extra={"reason": "user_not_allowed"})
            raise PermissionDenied(
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
