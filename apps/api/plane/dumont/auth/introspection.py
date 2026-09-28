# Dumont addition: RFC 7662 introspection of opaque ZITADEL access tokens for API v1 bearer auth.
# Not upstream Plane.
#
# Mirrors the Hangar MCP's introspection client (mcp/src/introspection.ts, client_secret_basic
# path): POST `token` + `token_type_hint=access_token`, HTTP Basic client authentication with
# form-encoded id and secret, no redirects, bounded response, only HTTP 200 with a JSON object
# counts as an answer, and only `"active": true` counts as active.
#
# The token is sent only to the configured introspection URL (same origin as the issuer). It is
# never logged, never put in an error and never used as a cache key: the Django cache is keyed
# by its SHA-256. The client secret is never logged either.

import base64
import hashlib
import json
import logging
import math
import time
import urllib.error
import urllib.parse
import urllib.request

from django.core.cache import cache

from plane.dumont.auth.config import USER_AGENT

logger = logging.getLogger("plane.authentication.dumont_bearer")

INTROSPECTION_TIMEOUT_SECONDS = 5
MAX_INTROSPECTION_BYTES = 64 * 1024
# An active answer is reused for at most this long (and never past the token's `exp`), so a
# token revoked in ZITADEL stops working here within this many seconds.
POSITIVE_CACHE_SECONDS = 60
# An inactive answer is reused for this long, so a client retrying a dead token does not turn
# every retry into a call to the issuer.
NEGATIVE_CACHE_SECONDS = 30
CACHE_KEY_PREFIX = "dumont_bearer:introspection:v1:"

_INACTIVE = {"active": False}


class IntrospectionUnavailable(Exception):
    """The issuer could not answer usably (network, timeout, non-200, bad body). Maps to 503.

    Carries a fixed reason code only; never the token, the secret or the response body.
    """

    def __init__(self, reason, http_status=None):
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The URL is pinned to the issuer origin; a redirect is an error, never followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _http_post(url, body, headers, timeout):
    """POST and return (status, body bytes, capped at MAX_INTROSPECTION_BYTES + 1).

    Tests replace this function; production calls the issuer. Network errors propagate.
    """
    request = urllib.request.Request(url=url, data=body, headers=headers, method="POST")
    try:
        with _opener.open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_INTROSPECTION_BYTES + 1)
    except urllib.error.HTTPError as error:
        # Non-2xx (and a refused redirect). The body is not read: nothing from it is used.
        status = error.code
        error.close()
        return status, b""


def _form_encode(value):
    # RFC 6749 section 2.3.1: client_id and client_secret are form-encoded before Basic.
    return urllib.parse.quote_plus(value, safe="")


def _basic_auth(client_id, client_secret):
    raw = f"{_form_encode(client_id)}:{_form_encode(client_secret)}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def token_fingerprint(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _cache_key(token):
    return CACHE_KEY_PREFIX + token_fingerprint(token)


def _cache_get(key):
    try:
        return cache.get(key)
    except Exception:
        # A cache outage only costs an extra issuer call; it never decides the outcome.
        logger.warning("dumont bearer: introspection cache read failed")
        return None


def _cache_set(key, value, ttl):
    try:
        cache.set(key, value, ttl)
    except Exception:
        logger.warning("dumont bearer: introspection cache write failed")


def _call_issuer(token, config):
    """One introspection request. Returns the response object; raises IntrospectionUnavailable."""
    body = urllib.parse.urlencode({"token": token, "token_type_hint": "access_token"}).encode("ascii")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        # Explicit: Cloudflare in front of Dumont Auth answers 403 to urllib's default User-Agent.
        "User-Agent": USER_AGENT,
        "Authorization": _basic_auth(config.introspection_client_id, config.introspection_client_secret),
    }
    try:
        status, raw = _http_post(config.introspection_url, body, headers, INTROSPECTION_TIMEOUT_SECONDS)
    except Exception:
        # Deliberately no exc_info: frame locals hold the token and the Basic credentials.
        raise IntrospectionUnavailable("request_failed") from None
    if status != 200:
        raise IntrospectionUnavailable("http_error", status)
    if len(raw) > MAX_INTROSPECTION_BYTES:
        raise IntrospectionUnavailable("too_large", status)
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise IntrospectionUnavailable("invalid_response", status) from None
    if not isinstance(payload, dict):
        raise IntrospectionUnavailable("invalid_response", status)
    return payload


def _positive_ttl(claims, now):
    """Seconds an active answer may be reused: min(60, exp - now), 0 when `exp` is unusable."""
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
        return 0
    return int(min(POSITIVE_CACHE_SECONDS, exp - now))


def introspect(token, config):
    """The introspection claims when ZITADEL says the token is active, None when it is not.

    Raises IntrospectionUnavailable when the issuer could not answer usably; that outcome is
    never cached. The caller still runs every claim check on the returned claims (issuer,
    audience, lifetime, subject, org-bound roles), on a cache hit too.
    """
    key = _cache_key(token)
    cached = _cache_get(key)
    if isinstance(cached, dict):
        return cached if cached.get("active") is True else None

    try:
        payload = _call_issuer(token, config)
    except IntrospectionUnavailable as error:
        logger.warning(
            "dumont bearer: introspection unavailable",
            extra={"reason": error.reason, "http_status": error.http_status},
        )
        raise

    if payload.get("active") is not True:
        _cache_set(key, _INACTIVE, NEGATIVE_CACHE_SECONDS)
        return None
    ttl = _positive_ttl(payload, time.time())
    if ttl >= 1:
        _cache_set(key, payload, ttl)
    return payload
