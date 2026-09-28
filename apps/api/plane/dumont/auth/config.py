# Dumont addition: configuration of ZITADEL bearer tokens on the Plane API v1.
# Not upstream Plane.
#
# Stdlib only (plus Django's exception class) on purpose: plane.settings.common calls load_bearer_config() while
# Django settings are loading, so a misconfiguration stops the process at startup
# with a clear message instead of failing on the first request.

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

DEFAULT_AUTH_HOST = "https://auth.getdumont.ai"
DEFAULT_READER_ROLE = "hangar_reader"
DEFAULT_WRITER_ROLE = "hangar_writer"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# A bare ZITADEL id: no ':' (that would make `<aud>:<role>` grants ambiguous) and no whitespace of any kind.
_NOT_BARE_ID = re.compile(r"[:\s]")


class BearerConfigError(ImproperlyConfigured):
    """Raised at startup when DUMONT_API_BEARER_ENABLED=1 but the rest of the config is unusable."""


@dataclass(frozen=True)
class BearerConfig:
    enabled: bool
    issuer: str = ""
    jwks_url: str = ""
    audiences: tuple = ()
    allowed_org_id: str = ""
    reader_role: str = DEFAULT_READER_ROLE
    writer_role: str = DEFAULT_WRITER_ROLE
    rate_limit: str = "60/minute"
    web_url: str = ""
    # RFC 7662 introspection for opaque (non-JWS) access tokens. All three are "" unless both
    # DUMONT_API_INTROSPECTION_CLIENT_ID and _CLIENT_SECRET are set. The secret is kept out of
    # repr() so it never shows up in a log line, a traceback or Django's debug page.
    introspection_url: str = ""
    introspection_client_id: str = ""
    introspection_client_secret: str = field(default="", repr=False)

    @property
    def introspection_enabled(self):
        return bool(self.introspection_url and self.introspection_client_id and self.introspection_client_secret)


def _canonical_url(value, name):
    """`origin + path` without a trailing slash, the same shape the MCP compares `iss` against."""
    parts = urlsplit(value)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise BearerConfigError(f"{name} must be an absolute http(s) URL")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        raise BearerConfigError(f"{name} must use https (plain http is only allowed for localhost)")
    if parts.query or parts.fragment or parts.username or parts.password:
        raise BearerConfigError(f"{name} must not carry credentials, a query or a fragment")
    path = parts.path.rstrip("/")
    return f"{parts.scheme}://{parts.netloc.lower()}{path}"


def _origin(url):
    parts = urlsplit(url)
    return (parts.scheme, parts.netloc.lower())


def _validate_rate(rate):
    # Same format DRF's SimpleRateThrottle.parse_rate accepts: "<int>/<s|m|h|d...>".
    num, sep, period = rate.partition("/")
    if not sep or not num.isdigit() or int(num) <= 0 or not period or period[0] not in "smhd":
        raise BearerConfigError('DUMONT_API_BEARER_RATE_LIMIT must look like "60/minute"')


def _enabled(raw):
    value = (raw or "").strip()
    if value in ("", "0"):
        return False
    if value == "1":
        return True
    raise BearerConfigError('DUMONT_API_BEARER_ENABLED must be "1" (on) or "0"/unset (off)')


ORG_ID_ENV = "DUMONT_ZITADEL_ORG_ID"


def parse_zitadel_org_id(environ):
    """DUMONT_ZITADEL_ORG_ID as a bare id, or "" when unset. Raises BearerConfigError when malformed.

    One value, one set of rules for every consumer: the bearer role gate (this module), the
    membership sync (plane/dumont/access) and the web login org check (provider/oauth/dumont.py).
    """
    value = (environ.get(ORG_ID_ENV) or "").strip()
    if value and _NOT_BARE_ID.search(value):
        raise BearerConfigError(f"{ORG_ID_ENV} must be a bare ZITADEL organization id (no ':' or whitespace)")
    return value


def _introspection(environ, auth_host, issuer):
    """(url, client_id, client_secret) for RFC 7662 introspection, or three "" when it is off.

    On only when both the client id and the secret are set. One without the other, or a URL
    without credentials, is a half-done setup and refuses to start. Error messages name the
    variable, never its value.
    """
    client_id = (environ.get("DUMONT_API_INTROSPECTION_CLIENT_ID") or "").strip()
    client_secret = (environ.get("DUMONT_API_INTROSPECTION_CLIENT_SECRET") or "").strip()
    url = (environ.get("DUMONT_API_INTROSPECTION_URL") or "").strip()
    if not client_id and not client_secret:
        if url:
            raise BearerConfigError(
                "DUMONT_API_INTROSPECTION_URL is set but DUMONT_API_INTROSPECTION_CLIENT_ID and "
                "DUMONT_API_INTROSPECTION_CLIENT_SECRET are not"
            )
        return "", "", ""
    if not client_id:
        raise BearerConfigError(
            "DUMONT_API_INTROSPECTION_CLIENT_ID is required with DUMONT_API_INTROSPECTION_CLIENT_SECRET"
        )
    if not client_secret:
        raise BearerConfigError(
            "DUMONT_API_INTROSPECTION_CLIENT_SECRET is required with DUMONT_API_INTROSPECTION_CLIENT_ID"
        )
    if re.search(r"\s", client_id):
        raise BearerConfigError("DUMONT_API_INTROSPECTION_CLIENT_ID must be one value without whitespace")
    if re.search(r"\s", client_secret):
        raise BearerConfigError("DUMONT_API_INTROSPECTION_CLIENT_SECRET must be one value without whitespace")
    url = _canonical_url(url or f"{auth_host}/oauth/v2/introspect", "DUMONT_API_INTROSPECTION_URL")
    if _origin(url) != _origin(issuer):
        raise BearerConfigError(
            "DUMONT_API_INTROSPECTION_URL must have the same origin (scheme, host, port) as the issuer"
        )
    return url, client_id, client_secret


def load_bearer_config(environ, default_rate="60/minute"):
    """Parse the DUMONT_API_BEARER_* / DUMONT_AUTH_* variables. Raises BearerConfigError when enabled but invalid."""
    enabled = _enabled(environ.get("DUMONT_API_BEARER_ENABLED"))
    if not enabled:
        # Off means off: the bearer rate override is ignored, so a bad value can never
        # break X-Api-Key requests (DumontBearerRateThrottle is still instantiated on them).
        return BearerConfig(enabled=False, rate_limit=default_rate)
    rate_limit = (environ.get("DUMONT_API_BEARER_RATE_LIMIT") or "").strip() or default_rate

    auth_host = (environ.get("DUMONT_AUTH_HOST") or "").strip() or DEFAULT_AUTH_HOST
    auth_host = _canonical_url(auth_host, "DUMONT_AUTH_HOST")
    issuer = (environ.get("DUMONT_AUTH_ISSUER") or "").strip()
    issuer = _canonical_url(issuer, "DUMONT_AUTH_ISSUER") if issuer else auth_host
    jwks_url = (environ.get("DUMONT_AUTH_JWKS_URL") or "").strip() or f"{auth_host}/oauth/v2/keys"
    jwks_url = _canonical_url(jwks_url, "DUMONT_AUTH_JWKS_URL")
    if _origin(jwks_url) != _origin(issuer):
        raise BearerConfigError("DUMONT_AUTH_JWKS_URL must have the same origin (scheme, host, port) as the issuer")

    audiences = tuple(
        dict.fromkeys(a.strip() for a in (environ.get("DUMONT_API_AUDIENCES") or "").split(",") if a.strip())
    )
    if not audiences:
        raise BearerConfigError(
            "DUMONT_API_AUDIENCES is required when DUMONT_API_BEARER_ENABLED=1 "
            "(comma-separated ZITADEL project ids accepted in the token `aud`)"
        )
    if any(_NOT_BARE_ID.search(a) for a in audiences):
        raise BearerConfigError("DUMONT_API_AUDIENCES entries must be bare ZITADEL project ids (no ':' or whitespace)")

    allowed_org_id = parse_zitadel_org_id(environ)
    if not allowed_org_id:
        raise BearerConfigError(
            "DUMONT_ZITADEL_ORG_ID is required when DUMONT_API_BEARER_ENABLED=1 "
            "(the ZITADEL organization id whose role grants Hangar accepts)"
        )

    reader_role = (environ.get("DUMONT_API_READER_ROLE") or "").strip() or DEFAULT_READER_ROLE
    writer_role = (environ.get("DUMONT_API_WRITER_ROLE") or "").strip() or DEFAULT_WRITER_ROLE
    if reader_role == writer_role:
        raise BearerConfigError("DUMONT_API_READER_ROLE and DUMONT_API_WRITER_ROLE must differ")

    _validate_rate(rate_limit)

    web_url = (environ.get("WEB_URL") or environ.get("APP_BASE_URL") or "").strip().rstrip("/")

    introspection_url, introspection_client_id, introspection_client_secret = _introspection(environ, auth_host, issuer)

    return BearerConfig(
        enabled=True,
        issuer=issuer,
        jwks_url=jwks_url,
        audiences=audiences,
        allowed_org_id=allowed_org_id,
        reader_role=reader_role,
        writer_role=writer_role,
        rate_limit=rate_limit,
        web_url=web_url,
        introspection_url=introspection_url,
        introspection_client_id=introspection_client_id,
        introspection_client_secret=introspection_client_secret,
    )
