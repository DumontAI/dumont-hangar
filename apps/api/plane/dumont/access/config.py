# Dumont addition: configuration of the ZITADEL -> Hangar membership sync.
# Not upstream Plane. Read from the environment at call time (not at import), so a
# misconfiguration can never break Django startup and tests can change it per test.

import json
import os
from dataclasses import dataclass, field

from plane.dumont.auth.config import ORG_ID_ENV, BearerConfigError, parse_zitadel_org_id

MODE_OFF = "off"
MODE_DRY_RUN = "dry-run"
MODE_ENFORCE = "enforce"
MODES = (MODE_OFF, MODE_DRY_RUN, MODE_ENFORCE)

DEFAULT_MAX_REMOVALS = 5
# Same issuer as the web login provider (plane/authentication/provider/oauth/dumont.py).
DEFAULT_AUTH_HOST = "https://auth.getdumont.ai"


class AccessConfigError(Exception):
    """The sync is enabled but its configuration is unusable. Never carries secret values."""


@dataclass(frozen=True)
class ServiceKey:
    """A ZITADEL service-user key (JWT profile). `private_key` is never logged or printed."""

    key_id: str
    user_id: str
    private_key: str

    def __repr__(self):  # keep the private key out of tracebacks and logs
        return f"ServiceKey(key_id={self.key_id!r}, user_id={self.user_id!r}, private_key=<redacted>)"


@dataclass(frozen=True)
class AccessConfig:
    mode: str
    workspace_slug: str | None
    base_url: str
    project_id: str | None
    org_id: str | None
    # The key JSON (or a path to it): never part of repr, so it cannot leak through a log or traceback.
    key_source: str | None = field(repr=False)
    max_removals: int
    # A malformed DUMONT_ZITADEL_ORG_ID is reported by require_complete(), not at load time: loading
    # must keep the mode, so that in enforce the endpoint lock fails closed (503) instead of the whole
    # feature reading as `off`.
    org_id_error: str | None = None

    @property
    def enabled(self):
        return self.mode in (MODE_DRY_RUN, MODE_ENFORCE)

    @property
    def enforce(self):
        return self.mode == MODE_ENFORCE

    def require_complete(self):
        """Raise AccessConfigError (names only, no values) when something needed for a sync is missing."""
        if self.org_id_error:
            raise AccessConfigError(self.org_id_error)
        missing = [
            name
            for name, value in (
                ("DUMONT_ACCESS_WORKSPACE_SLUG", self.workspace_slug),
                ("DUMONT_ACCESS_ZITADEL_PROJECT_ID", self.project_id),
                (ORG_ID_ENV, self.org_id),
                ("DUMONT_ACCESS_ZITADEL_KEY_JSON", self.key_source),
            )
            if not value
        ]
        if missing:
            raise AccessConfigError("missing configuration: " + ", ".join(missing))

    def load_service_key(self):
        return parse_service_key(self.key_source)


def parse_service_key(source):
    """Parse DUMONT_ACCESS_ZITADEL_KEY_JSON: the key file's JSON content, or a path to that file.

    Expected shape (ZITADEL "service user" key, JSON type):
    {"type": "serviceaccount", "keyId": "...", "key": "-----BEGIN RSA PRIVATE KEY-----...", "userId": "..."}
    """
    if not source:
        raise AccessConfigError("DUMONT_ACCESS_ZITADEL_KEY_JSON is not set")
    text = source.strip()
    if not text.startswith("{"):
        try:
            with open(text, encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            raise AccessConfigError(
                f"DUMONT_ACCESS_ZITADEL_KEY_JSON is neither JSON nor a readable file ({exc.__class__.__name__})"
            ) from None
    try:
        data = json.loads(text)
    except ValueError:
        raise AccessConfigError("DUMONT_ACCESS_ZITADEL_KEY_JSON is not valid JSON") from None
    if not isinstance(data, dict):
        raise AccessConfigError("DUMONT_ACCESS_ZITADEL_KEY_JSON must be a JSON object")
    key_id, user_id, private_key = data.get("keyId"), data.get("userId"), data.get("key")
    if not (isinstance(key_id, str) and key_id and isinstance(user_id, str) and user_id):
        raise AccessConfigError("DUMONT_ACCESS_ZITADEL_KEY_JSON needs keyId and userId (a service-user key)")
    if not (isinstance(private_key, str) and "PRIVATE KEY" in private_key):
        raise AccessConfigError("DUMONT_ACCESS_ZITADEL_KEY_JSON has no PEM private key in 'key'")
    return ServiceKey(key_id=key_id, user_id=user_id, private_key=private_key)


def load_access_config(env=None):
    """Build the config from the environment. An unknown mode raises; everything else is lazy."""
    env = os.environ if env is None else env
    mode = (env.get("DUMONT_ACCESS_SYNC") or MODE_OFF).strip().lower()
    if mode not in MODES:
        raise AccessConfigError(f"DUMONT_ACCESS_SYNC must be one of {', '.join(MODES)}")
    raw_max = (env.get("DUMONT_ACCESS_MAX_REMOVALS") or "").strip()
    if raw_max:
        try:
            max_removals = int(raw_max)
        except ValueError:
            raise AccessConfigError("DUMONT_ACCESS_MAX_REMOVALS must be an integer") from None
        if max_removals < 0:
            raise AccessConfigError("DUMONT_ACCESS_MAX_REMOVALS must be >= 0")
    else:
        max_removals = DEFAULT_MAX_REMOVALS
    org_id_error = None
    try:
        # Shared with the bearer auth and the web login check: one value, one set of rules.
        org_id = parse_zitadel_org_id(env) or None
    except BearerConfigError as exc:
        org_id, org_id_error = None, str(exc)
    return AccessConfig(
        org_id_error=org_id_error,
        mode=mode,
        workspace_slug=(env.get("DUMONT_ACCESS_WORKSPACE_SLUG") or "").strip() or None,
        base_url=(env.get("DUMONT_AUTH_HOST") or DEFAULT_AUTH_HOST).strip().rstrip("/"),
        project_id=(env.get("DUMONT_ACCESS_ZITADEL_PROJECT_ID") or "").strip() or None,
        org_id=org_id,
        key_source=env.get("DUMONT_ACCESS_ZITADEL_KEY_JSON") or None,
        max_removals=max_removals,
    )


def current_mode():
    """The configured mode, treating an invalid value as `off` (fail safe for request paths)."""
    try:
        return load_access_config().mode
    except AccessConfigError:
        return MODE_OFF
