# Dumont addition: cached ZITADEL JWKS lookup for API v1 bearer tokens.
# Not upstream Plane.

import json
import threading
import time
import urllib.request

from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

JWKS_TIMEOUT_SECONDS = 5
# How long a fetched key set is trusted before it is fetched again.
JWKS_LIFESPAN_SECONDS = 300
# A token with an unknown `kid` may force a refetch (key rotation), but at most this often,
# so random `kid`s cannot turn every request into a call to the issuer.
UNKNOWN_KID_REFRESH_INTERVAL_SECONDS = 60
# After a failed fetch, answer "unavailable" without calling the issuer again for this long.
FETCH_FAILURE_BACKOFF_SECONDS = 10
MAX_JWKS_BYTES = 256 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The JWKS URL is pinned to the issuer origin; never follow a redirect elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _fetch_jwks(uri, timeout):
    """Fetch and parse the key set. Tests replace this function; production calls the issuer."""
    request = urllib.request.Request(url=uri, headers={"Accept": "application/json"})
    with _opener.open(request, timeout=timeout) as response:
        body = response.read(MAX_JWKS_BYTES + 1)
    if len(body) > MAX_JWKS_BYTES:
        raise ValueError("JWKS response too large")
    return json.loads(body)


class BoundedJWKClient(PyJWKClient):
    """PyJWKClient with a JWK Set cache, a bounded refetch on unknown `kid` and a failure backoff."""

    def __init__(self, uri):
        super().__init__(
            uri,
            cache_keys=False,
            cache_jwk_set=True,
            lifespan=JWKS_LIFESPAN_SECONDS,
            timeout=JWKS_TIMEOUT_SECONDS,
        )
        self._lock = threading.Lock()
        self._last_forced_refresh = float("-inf")
        self._last_failure = float("-inf")

    def fetch_data(self):
        now = time.monotonic()
        if now - self._last_failure < FETCH_FAILURE_BACKOFF_SECONDS:
            raise PyJWKClientConnectionError("JWKS fetch recently failed; backing off")
        try:
            jwk_set = _fetch_jwks(self.uri, self.timeout)
        except Exception as exc:
            self._last_failure = time.monotonic()
            # The message names only the failure class: never the token, never the response.
            raise PyJWKClientConnectionError(f"JWKS fetch failed ({type(exc).__name__})") from exc
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        return jwk_set

    def get_signing_key(self, kid):
        with self._lock:
            signing_key = self.match_kid(self.get_signing_keys(), kid)
            if signing_key is None:
                now = time.monotonic()
                if now - self._last_forced_refresh >= UNKNOWN_KID_REFRESH_INTERVAL_SECONDS:
                    self._last_forced_refresh = now
                    signing_key = self.match_kid(self.get_signing_keys(refresh=True), kid)
        if signing_key is None:
            raise PyJWKClientError("No signing key matches the token kid")
        return signing_key


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
