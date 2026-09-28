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
#   - Search users (org-scoped by x-zitadel-orgid), query inUserIdsQuery {"userIds": [...]}:
#       POST /management/v1/users/_search
#       https://zitadel.com/docs/apis/resources/mgmt/management-service-list-users
#   - List query shape {"query": {"offset", "limit", "asc"}} and response {"details": {"totalResult"}, "result": []}
#       https://zitadel.com/docs/apis/resources/mgmt  (ListQuery / ListDetails)
#   - UserGrant fields used: userId, projectId, roleKeys, state, orgId, projectGrantId, details.resourceOwner,
#       email, preferredLoginName, displayName. User fields used: id, details.resourceOwner.
#
# Organisation boundary: the ZITADEL instance is shared with other products' production, so only
# grants AND users of the configured Dumont organisation (DUMONT_ZITADEL_ORG_ID) count. A
# grant is ignored when it came through a project grant (projectGrantId set), when its orgId or
# details.resourceOwner names another org, or when its user is not a user of the Dumont org (checked
# with an org-scoped users/_search). Absent fields are not treated as foreign (older/newer versions
# may omit them); the org-scoped user check still applies.
#
# The client never writes to ZITADEL, never logs tokens or the private key, and raises
# ZitadelError for every failure so callers can fail safe (change nothing). Answers that look like
# success but are incomplete are failures too: a search answer without `result` (unless
# `details.totalResult` is present and 0), an empty page while any page's `totalResult` says more rows
# exist, and grants whose users the org-scoped users/_search does not
# return at all (a silently filtered HTTP 200).

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
USERS_SEARCH_PATH = "/management/v1/users/_search"
USER_IDS_PER_QUERY = 100
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
        self.ignored_grants = []

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
        expected = None  # the largest totalResult any page announced
        for _ in range(MAX_PAGES):
            body = {"query": {"offset": str(offset), "limit": PAGE_SIZE, "asc": True}}
            if queries:
                body["queries"] = queries
            data = self._request("POST", path, json_body=body)
            total = _total_result(data, path)
            if "result" not in data:
                # ZITADEL's gateway may omit empty repeated fields and zero numbers (proto3 JSON without
                # EmitUnpopulated). An omitted `result` is an empty list ONLY when the answer says so
                # explicitly: `details.totalResult` present and 0. Anything else without `result` is a
                # changed or partial answer, and reading it as empty would look like a mass revocation.
                if total != 0:
                    raise ZitadelError(f"POST {path}: response has no 'result' (API shape changed?)")
                page = []
            else:
                page = data["result"]
            if not isinstance(page, list):
                raise ZitadelError(f"POST {path}: 'result' is not a list")
            if total is not None:
                expected = total if expected is None else max(expected, total)
            rows.extend(page)
            offset += len(page)
            if expected is not None:
                # Once any page announced a total, it is the only way to end: a page that brings
                # nothing new while rows are still owed is a truncated answer. A short but non-empty
                # page (a server-side limit below PAGE_SIZE) keeps paging.
                if offset >= expected:
                    return rows
                if not page:
                    raise ZitadelError(f"POST {path}: empty page at offset {offset} of totalResult {expected}")
            elif len(page) < PAGE_SIZE:
                # No page ever carried a total: a short page ends the list.
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

    def user_ids_in_org(self, user_ids):
        """The subset of `user_ids` that are users of the configured organisation."""
        wanted = sorted({uid for uid in user_ids if uid})
        found = set()
        for start in range(0, len(wanted), USER_IDS_PER_QUERY):
            chunk = wanted[start : start + USER_IDS_PER_QUERY]
            for row in self._search(USERS_SEARCH_PATH, queries=[{"inUserIdsQuery": {"userIds": chunk}}]):
                if not isinstance(row, dict):
                    raise ZitadelError("user is not an object")
                row_id = row.get("id")
                # Defence in depth: the org header scopes the search, and the owner must match when present.
                if row_id in chunk and _resource_owner(row) in (None, self.org_id):
                    found.add(row_id)
        return found

    def list_user_grants(self, project_id, user_id=None):
        """Active user grants of the project (optionally of one user), inside the configured org only.

        Grants dropped because of the organisation boundary are recorded in `self.ignored_grants`
        as {"user_id", "reason"} (ids only, no e-mails).
        """
        self.ignored_grants = []
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
            reason = _grant_outside_org(row, self.org_id)
            if reason:
                self.ignored_grants.append({"user_id": grant_user_id, "reason": reason})
                continue
            grants.append(
                ZitadelGrant(
                    user_id=grant_user_id,
                    role_keys=[key for key in role_keys if isinstance(key, str)],
                    email=row.get("email") or None,
                    login_name=row.get("preferredLoginName") or row.get("userName") or None,
                    display_name=row.get("displayName") or None,
                )
            )
        if not grants:
            return grants
        in_org = self.user_ids_in_org(grant.user_id for grant in grants)
        if not in_org:
            # Grants exist but the org-scoped user search knows none of their users. That is what a
            # permission that silently filters users/_search (HTTP 200, empty result) looks like;
            # dropping every grant would read as "everyone lost access". Fail safe instead.
            raise ZitadelError(
                f"POST {USERS_SEARCH_PATH}: none of the {len({g.user_id for g in grants})} grantee(s) was found "
                "in the organisation (service user permission too narrow?)"
            )
        kept = []
        for grant in grants:
            if grant.user_id in in_org:
                kept.append(grant)
            else:
                self.ignored_grants.append({"user_id": grant.user_id, "reason": "user_outside_org"})
        return kept


def _resource_owner(row):
    details = row.get("details")
    owner = details.get("resourceOwner") if isinstance(details, dict) else None
    return owner or None


def _grant_outside_org(row, org_id):
    """Why a grant row is outside the configured organisation, or None when it is inside."""
    if row.get("projectGrantId"):
        return "project_grant"
    if row.get("orgId") not in (None, "", org_id):
        return "grant_org"
    if _resource_owner(row) not in (None, org_id):
        return "grant_resource_owner"
    return None


def _total_result(data, path=""):
    """details.totalResult as an int, None when absent. A present but unreadable value is an error."""
    details = data.get("details")
    if not isinstance(details, dict) or "totalResult" not in details:
        return None
    value = details["totalResult"]
    if isinstance(value, bool):
        raise ZitadelError(f"POST {path}: unreadable details.totalResult")
    try:
        total = int(value)
    except (TypeError, ValueError):
        raise ZitadelError(f"POST {path}: unreadable details.totalResult") from None
    if total < 0:
        raise ZitadelError(f"POST {path}: unreadable details.totalResult")
    return total


def _error_message(response):
    """ZITADEL's error message (never contains our credentials), trimmed for logs."""
    try:
        data = response.json()
    except ValueError:
        return ""
    message = data.get("message") if isinstance(data, dict) else None
    return str(message)[:200] if message else ""
