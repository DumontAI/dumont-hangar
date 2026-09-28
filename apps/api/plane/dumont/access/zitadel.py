# Dumont addition: minimal, read-only ZITADEL Management API client for the membership sync.
# Not upstream Plane.
#
# ALL endpoint / field assumptions live in this file. They follow the ZITADEL v2/v3/v4 docs for
# the (still supported) Management API v1 REST gateway; the exact ZITADEL version running at
# auth.getdumont.ai has NOT been verified from this code base:
#   - JWT profile for service users (private_key_jwt):
#       https://zitadel.com/docs/guides/integrate/service-users/private-key-jwt
#   - Scope that yields a token accepted by the ZITADEL APIs:
#       https://zitadel.com/docs/apis/openidoauth/scopes  (urn:zitadel:iam:org:project:id:zitadel:aud)
#   - Search project roles:  POST /management/v1/projects/{projectId}/roles/_search
#       https://zitadel.com/docs/apis/resources/mgmt/management-service-list-project-roles
#   - Search user grants:    POST /management/v1/users/grants/_search
#       https://zitadel.com/docs/apis/resources/mgmt/management-service-list-user-grants
#   - Organisation context header: x-zitadel-orgid
#       https://zitadel.com/docs/apis/introduction#organization-context
#   - List query shape {"query": {"offset", "limit", "asc"}} and response {"details": {"totalResult"}, "result": []}
#       https://zitadel.com/docs/apis/resources/mgmt  (ListQuery / ListDetails)
#
# The client never writes to ZITADEL, never logs tokens or the private key, and raises
# ZitadelError for every failure so callers can fail safe (change nothing).

import logging
import threading
import time

import jwt
import requests

logger = logging.getLogger("plane.dumont.access")

TIMEOUT_SECONDS = 5
PAGE_SIZE = 100
MAX_PAGES = 500  # 50k rows: far beyond this instance; stops a misbehaving server from looping forever
TOKEN_REFRESH_MARGIN_SECONDS = 60
ASSERTION_LIFETIME_SECONDS = 300

TOKEN_PATH = "/oauth/v2/token"
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_SCOPE = "openid urn:zitadel:iam:org:project:id:zitadel:aud"
ROLES_SEARCH_PATH = "/management/v1/projects/{project_id}/roles/_search"
GRANTS_SEARCH_PATH = "/management/v1/users/grants/_search"
ORG_HEADER = "x-zitadel-orgid"
GRANT_STATE_ACTIVE = "USER_GRANT_STATE_ACTIVE"
# ZITADEL omits zero-value enums in JSON; an absent/unspecified state therefore means "active".
GRANT_STATES_ACCEPTED = {GRANT_STATE_ACTIVE, "USER_GRANT_STATE_UNSPECIFIED", None, ""}


class ZitadelError(Exception):
    """ZITADEL could not be reached or answered something unusable. Message never carries secrets."""


class ZitadelGrant:
    __slots__ = ("user_id", "role_keys", "email", "login_name", "display_name")

    def __init__(self, user_id, role_keys, email=None, login_name=None, display_name=None):
        self.user_id = user_id
        self.role_keys = tuple(role_keys)
        self.email = email
        self.login_name = login_name
        self.display_name = display_name

    def __repr__(self):
        return f"ZitadelGrant(user_id={self.user_id!r}, role_keys={self.role_keys!r})"


def new_session():
    """Seam for tests: they replace this with a session whose transport is a fake ZITADEL."""
    return requests.Session()


# Access tokens are cached per (base_url, key_id) in-process until shortly before they expire.
_token_cache = {}
_token_lock = threading.Lock()


def reset_token_cache():
    with _token_lock:
        _token_cache.clear()


class ZitadelClient:
    def __init__(self, base_url, org_id, service_key, session=None, timeout=TIMEOUT_SECONDS):
        self.base_url = base_url.rstrip("/")
        self.org_id = org_id
        self.service_key = service_key
        self.session = session or new_session()
        self.timeout = timeout

    # --- token -------------------------------------------------------------------------------

    def _assertion(self):
        now = int(time.time())
        claims = {
            "iss": self.service_key.user_id,
            "sub": self.service_key.user_id,
            "aud": self.base_url,
            "iat": now,
            "exp": now + ASSERTION_LIFETIME_SECONDS,
        }
        try:
            return jwt.encode(
                claims, self.service_key.private_key, algorithm="RS256", headers={"kid": self.service_key.key_id}
            )
        except Exception as exc:  # bad PEM etc.; never include the key in the message
            raise ZitadelError(f"cannot sign the JWT profile assertion ({exc.__class__.__name__})") from None

    def access_token(self):
        cache_key = (self.base_url, self.service_key.key_id)
        now = time.time()
        with _token_lock:
            cached = _token_cache.get(cache_key)
            if cached and cached[1] - TOKEN_REFRESH_MARGIN_SECONDS > now:
                return cached[0]
        data = self._request(
            "POST",
            TOKEN_PATH,
            form={"grant_type": JWT_BEARER_GRANT, "scope": TOKEN_SCOPE, "assertion": self._assertion()},
            authenticated=False,
        )
        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            raise ZitadelError("token endpoint returned no access_token")
        try:
            expires_in = int(data.get("expires_in") or 0)
        except (TypeError, ValueError):
            expires_in = 0
        if expires_in <= 0:
            expires_in = 300
        with _token_lock:
            _token_cache[cache_key] = (token, now + expires_in)
        return token

    # --- transport ---------------------------------------------------------------------------

    def _request(self, method, path, json_body=None, form=None, authenticated=True):
        headers = {"Accept": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self.access_token()}"
            headers[ORG_HEADER] = self.org_id
        url = self.base_url + path
        try:
            response = self.session.request(
                method, url, json=json_body, data=form, headers=headers, timeout=self.timeout, allow_redirects=False
            )
        except requests.RequestException as exc:
            raise ZitadelError(f"{method} {path}: {exc.__class__.__name__}") from None
        if response.status_code == 401 and authenticated:
            # A revoked/rotated token: drop it so the next run fetches a fresh one.
            with _token_lock:
                _token_cache.pop((self.base_url, self.service_key.key_id), None)
        if not 200 <= response.status_code < 300:
            raise ZitadelError(f"{method} {path}: HTTP {response.status_code} {_error_message(response)}".strip())
        try:
            data = response.json()
        except ValueError:
            raise ZitadelError(f"{method} {path}: response is not JSON") from None
        if not isinstance(data, dict):
            raise ZitadelError(f"{method} {path}: response is not a JSON object")
        return data

    def _search(self, path, queries=None):
        """Run a paginated _search and return all `result` rows."""
        rows = []
        offset = 0
        for _ in range(MAX_PAGES):
            body = {"query": {"offset": str(offset), "limit": PAGE_SIZE, "asc": True}}
            if queries:
                body["queries"] = queries
            data = self._request("POST", path, json_body=body)
            page = data.get("result") or []
            if not isinstance(page, list):
                raise ZitadelError(f"POST {path}: 'result' is not a list")
            rows.extend(page)
            total = _total_result(data)
            offset += len(page)
            if not page:
                return rows
            # Trust totalResult when the server sends it (a server-side limit below PAGE_SIZE must not
            # truncate the list, which would look like mass revocation); otherwise a short page ends it.
            if total is not None:
                if offset >= total:
                    return rows
            elif len(page) < PAGE_SIZE:
                return rows
        raise ZitadelError(f"POST {path}: more than {MAX_PAGES} pages, refusing to continue")

    # --- API ---------------------------------------------------------------------------------

    def list_project_role_keys(self, project_id):
        rows = self._search(ROLES_SEARCH_PATH.format(project_id=project_id))
        keys = []
        for row in rows:
            key = row.get("key") if isinstance(row, dict) else None
            if not isinstance(key, str):
                raise ZitadelError("project role without a 'key'")
            keys.append(key)
        return keys

    def list_user_grants(self, project_id, user_id=None):
        """Active user grants of the project (optionally of one user)."""
        queries = [{"projectIdQuery": {"projectId": project_id}}]
        if user_id:
            queries.append({"userIdQuery": {"userId": user_id}})
        grants = []
        for row in self._search(GRANTS_SEARCH_PATH, queries=queries):
            if not isinstance(row, dict):
                raise ZitadelError("user grant is not an object")
            # Defence in depth: never trust that the server applied our filters.
            if row.get("projectId") not in (None, project_id):
                continue
            if user_id and row.get("userId") != user_id:
                continue
            if row.get("state") not in GRANT_STATES_ACCEPTED:
                continue
            grant_user_id = row.get("userId")
            role_keys = row.get("roleKeys") or []
            if not isinstance(grant_user_id, str) or not grant_user_id or not isinstance(role_keys, list):
                raise ZitadelError("user grant without userId/roleKeys")
            grants.append(
                ZitadelGrant(
                    user_id=grant_user_id,
                    role_keys=[key for key in role_keys if isinstance(key, str)],
                    email=row.get("email") or None,
                    login_name=row.get("preferredLoginName") or row.get("userName") or None,
                    display_name=row.get("displayName") or None,
                )
            )
        return grants


def _total_result(data):
    details = data.get("details")
    if not isinstance(details, dict) or details.get("totalResult") in (None, ""):
        return None
    try:
        return int(details["totalResult"])
    except (TypeError, ValueError):
        return None


def _error_message(response):
    """ZITADEL's error message (never contains our credentials), trimmed for logs."""
    try:
        data = response.json()
    except ValueError:
        return ""
    message = data.get("message") if isinstance(data, dict) else None
    return str(message)[:200] if message else ""
