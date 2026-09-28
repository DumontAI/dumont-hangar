# Dumont addition: configuration of ZITADEL bearer tokens on the Plane API v1.
# Not upstream Plane.
#
# Stdlib only (plus Django's exception class) on purpose: plane.settings.common calls load_bearer_config() while
# Django settings are loading, so a misconfiguration stops the process at startup
# with a clear message instead of failing on the first request.

from dataclasses import dataclass
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured

DEFAULT_AUTH_HOST = "https://auth.getdumont.ai"
DEFAULT_READER_ROLE = "hangar_reader"
DEFAULT_WRITER_ROLE = "hangar_writer"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class BearerConfigError(ImproperlyConfigured):
    """Raised at startup when DUMONT_API_BEARER_ENABLED=1 but the rest of the config is unusable."""


@dataclass(frozen=True)
class BearerConfig:
    enabled: bool
    issuer: str = ""
    jwks_url: str = ""
    audiences: tuple = ()
    reader_role: str = DEFAULT_READER_ROLE
    writer_role: str = DEFAULT_WRITER_ROLE
    rate_limit: str = "60/minute"
    web_url: str = ""


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


def load_bearer_config(environ, default_rate="60/minute"):
    """Parse the DUMONT_API_BEARER_* / DUMONT_AUTH_* variables. Raises BearerConfigError when enabled but invalid."""
    enabled = _enabled(environ.get("DUMONT_API_BEARER_ENABLED"))
    rate_limit = (environ.get("DUMONT_API_BEARER_RATE_LIMIT") or "").strip() or default_rate
    if not enabled:
        return BearerConfig(enabled=False, rate_limit=rate_limit)

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
    if any(":" in a or " " in a for a in audiences):
        raise BearerConfigError("DUMONT_API_AUDIENCES entries must be bare ZITADEL project ids (no ':' or spaces)")

    reader_role = (environ.get("DUMONT_API_READER_ROLE") or "").strip() or DEFAULT_READER_ROLE
    writer_role = (environ.get("DUMONT_API_WRITER_ROLE") or "").strip() or DEFAULT_WRITER_ROLE
    if reader_role == writer_role:
        raise BearerConfigError("DUMONT_API_READER_ROLE and DUMONT_API_WRITER_ROLE must differ")

    _validate_rate(rate_limit)

    web_url = (environ.get("WEB_URL") or environ.get("APP_BASE_URL") or "").strip().rstrip("/")

    return BearerConfig(
        enabled=True,
        issuer=issuer,
        jwks_url=jwks_url,
        audiences=audiences,
        reader_role=reader_role,
        writer_role=writer_role,
        rate_limit=rate_limit,
        web_url=web_url,
    )
