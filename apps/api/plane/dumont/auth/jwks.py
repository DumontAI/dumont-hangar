# Dumont addition: cached ZITADEL JWKS lookup for API v1 bearer tokens.
# Not upstream Plane.
#
# Own cache instead of PyJWKClient's, for three properties PyJWKClient does not give:
# - a response is validated (PyJWKSet.from_dict, at least one usable RS256 signing key)
#   BEFORE it replaces the cached set, so a broken answer never evicts good keys;
# - after a failed refresh the last good set keeps serving the kids it knows, for up to
#   MAX_STALE_SECONDS, so a short issuer outage does not take the API down;
# - unknown `kid`s and failures are rate limited, so random tokens cannot hammer the issuer.

import json
import threading
import time
import urllib.request

from jwt import PyJWKSet
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from plane.dumont.auth.config import USER_AGENT

JWKS_TIMEOUT_SECONDS = 5
# How long a fetched key set is used before it is fetched again.
JWKS_LIFESPAN_SECONDS = 300
# A token with an unknown `kid` may force a refetch (key rotation), but at most this often,
# so random `kid`s cannot turn every request into a call to the issuer.
UNKNOWN_KID_REFRESH_INTERVAL_SECONDS = 60
# After a failed fetch, do not call the issuer again for this long.
FETCH_FAILURE_BACKOFF_SECONDS = 10
# While refreshes fail, the last good set still verifies the kids it contains for this long
# (counted from the last successful fetch). After that, every token gets 503.
MAX_STALE_SECONDS = 24 * 60 * 60
MAX_JWKS_BYTES = 256 * 1024


class UnknownKid(PyJWKClientError):
    """The key set is current and has no key for the token's `kid`: the token is invalid (401)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The JWKS URL is pinned to the issuer origin; never follow a redirect elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _now():
    return time.monotonic()


def _fetch_jwks(uri, timeout):
    """Fetch and parse the key set. Tests replace this function; production calls the issuer."""
    # Explicit User-Agent: Cloudflare in front of Dumont Auth answers 403 to urllib's default one.
    request = urllib.request.Request(url=uri, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    with _opener.open(request, timeout=timeout) as response:
        body = response.read(MAX_JWKS_BYTES + 1)
    if len(body) > MAX_JWKS_BYTES:
        raise ValueError("JWKS response too large")
    return json.loads(body)


def _usable_keys(data):
    """{kid: PyJWK} of the RS256 signing keys in a JWKS document. Raises ValueError when there are none."""
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise ValueError("JWKS document is not an object with a keys array")
    jwk_set = PyJWKSet.from_dict(data)  # raises PyJWKSetError when no key is usable
    keys = {}
    for key in jwk_set.keys:
        if (
            isinstance(key.key_id, str)
            and key.key_id
            and key.key_type == "RSA"
            and key.public_key_use in (None, "sig")
            and key.algorithm_name == "RS256"
        ):
            keys[key.key_id] = key
    if not keys:
        raise ValueError("JWKS has no RS256 signing key with a kid")
    return keys


class BoundedJWKClient:
    """Per-process JWKS cache for one issuer. `get_signing_key(kid)` is the only entry point."""

    def __init__(self, uri):
        self.uri = uri
        self.timeout = JWKS_TIMEOUT_SECONDS
        self._lock = threading.Lock()
        self._keys = {}
        self._fetched_at = None  # monotonic time of the last successful fetch
        self._last_failure = float("-inf")
        self._last_forced_refresh = float("-inf")
        self._refresh_failing = False

    def _refresh(self, now):
        """Try to replace the key set. Never raises; returns True on success."""
        if now - self._last_failure < FETCH_FAILURE_BACKOFF_SECONDS:
            self._refresh_failing = True
            return False
        try:
            keys = _usable_keys(_fetch_jwks(self.uri, self.timeout))
        except Exception:
            # Nothing from the response is kept or logged; the caller decides between stale keys and 503.
            self._last_failure = _now()
            self._refresh_failing = True
            return False
        self._keys = keys
        self._fetched_at = _now()
        self._refresh_failing = False
        return True

    def _drop_expired(self, now):
        if self._fetched_at is not None and now - self._fetched_at >= MAX_STALE_SECONDS:
            self._keys = {}
            self._fetched_at = None

    def get_signing_key(self, kid):
        with self._lock:
            now = _now()
            refreshed = False
            if self._fetched_at is None or now - self._fetched_at >= JWKS_LIFESPAN_SECONDS:
                refreshed = self._refresh(now)
                self._drop_expired(now)

            key = self._keys.get(kid)
            if key is None and not refreshed and self._fetched_at is not None:
                if now - self._last_forced_refresh >= UNKNOWN_KID_REFRESH_INTERVAL_SECONDS:
                    self._last_forced_refresh = now
                    self._refresh(now)
                    key = self._keys.get(kid)

            if key is not None:
                return key
            if self._fetched_at is None or self._refresh_failing:
                # Never fetched, too old, or the latest refresh failed: we cannot tell
                # whether this kid is real, so this is "unavailable", not "invalid".
                raise PyJWKClientConnectionError("JWKS unavailable")
            raise UnknownKid("No signing key matches the token kid")


_clients = {}
_clients_lock = threading.Lock()


def get_jwks_client(uri):
    """One client per JWKS URL per process, so the key cache is shared by all requests."""
    with _clients_lock:
        client = _clients.get(uri)
        if client is None:
            client = BoundedJWKClient(uri)
            _clients[uri] = client
        return client


def reset_jwks_clients():
    """Drop every cached client (tests)."""
    with _clients_lock:
        _clients.clear()
