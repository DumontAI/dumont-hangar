# Dumont addition: fixtures for the ZITADEL -> Hangar membership sync tests. Not upstream Plane.
#
# No network, ever: every requests.Session the client creates gets a FakeZitadel transport
# mounted on http:// and https://, so an unexpected URL fails loudly instead of leaving the box.

import json
import re
import uuid
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.cache import cache

from plane.db.models import Account, Project, ProjectMember, User, WorkspaceMember
from plane.dumont.access import zitadel as zitadel_module

BASE_URL = "https://zitadel.test"
PROJECT_ID = "300000000000000042"
ORG_ID = "200000000000000001"
KEY_ID = "key-0001"
SERVICE_USER_ID = "svc-hangar-sync"


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def key_json(rsa_key):
    pem = rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    ).decode()
    return json.dumps({"type": "serviceaccount", "keyId": KEY_ID, "key": pem, "userId": SERVICE_USER_ID})


def _response(request, status, body):
    response = requests.models.Response()
    response.status_code = status
    response._content = body if isinstance(body, bytes) else json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    response.url = request.url
    response.request = request
    return response


class FakeZitadel(requests.adapters.BaseAdapter):
    """In-process stand-in for the ZITADEL token endpoint and the management v1 search endpoints."""

    def __init__(self, public_key):
        super().__init__()
        self.public_key = public_key
        self.roles = []  # role keys
        self.grants = []  # raw grant rows as ZITADEL returns them
        self.users = []  # raw user rows (users/_search by e-mail, bootstrap tests)
        self.org_users = {}  # user id -> owning org id (users/_search by id, org-scoped)
        self.writes = []  # write calls received (bootstrap script tests)
        self.calls = []  # (method, path, parsed body)
        self.timeouts = []
        self.user_agents = []  # User-Agent header of every request received
        self.token_requests = 0
        self.issued = set()
        self.fail = None  # None | int status | "timeout" | "badjson"
        self.fail_on = None  # substring of the path that fails; None = every call
        self.page_cap = None  # simulate a server that returns fewer rows than asked
        self.omit_total = False
        self.drop_result_on = None  # path substring: answer 200 without the `result` key
        self.truncate_after = None  # rows served before pages come back empty (totalResult stays honest)
        self.filter_users = False  # users/_search by id answers 200 with no rows (permission-filtered)
        self.raw_body_on = None  # (path substring, body): answer 200 with exactly this JSON body
        self.expires_in = 43199

    # helpers for tests
    def grant(
        self,
        user_id,
        *role_keys,
        email=None,
        state="USER_GRANT_STATE_ACTIVE",
        project_id=PROJECT_ID,
        grant_org=ORG_ID,
        user_org=ORG_ID,
        project_grant_id=None,
    ):
        """Add a grant row. `user_org` registers the user in that org's directory (users/_search)."""
        row = {
            "id": uuid.uuid4().hex,
            "details": {"resourceOwner": grant_org},
            "userId": user_id,
            "projectId": project_id,
            "roleKeys": list(role_keys),
            "email": email,
            "displayName": email or user_id,
            "orgId": grant_org,
        }
        if project_grant_id:
            row["projectGrantId"] = project_grant_id
        if state is not None:
            row["state"] = state
        self.org_users.setdefault(user_id, user_org)
        self.grants.append(row)
        return row

    def api_calls(self, fragment=""):
        return [c for c in self.calls if c[1] != "/oauth/v2/token" and fragment in c[1]]

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        path = urlparse(request.url).path
        body = request.body
        if isinstance(body, bytes):
            body = body.decode()
        self.timeouts.append(timeout)
        self.user_agents.append(request.headers.get("User-Agent"))
        if not request.url.startswith(BASE_URL + "/"):
            raise AssertionError(f"unexpected outbound URL {request.url}")
        if self.fail is not None and (self.fail_on is None or self.fail_on in path):
            self.calls.append((request.method, path, body))
            if self.fail == "timeout":
                raise requests.exceptions.ConnectTimeout("fake timeout")
            if self.fail == "badjson":
                return _response(request, 200, b"<html>not json</html>")
            return _response(request, self.fail, {"code": 7, "message": "fake failure"})
        if path == "/oauth/v2/token":
            form = {k: v[0] for k, v in parse_qs(body).items()}
            self.calls.append((request.method, path, {k: v for k, v in form.items() if k != "assertion"}))
            return self._token(request, form)
        auth = request.headers.get("Authorization", "")
        parsed = json.loads(body) if body else {}
        self.calls.append((request.method, path, parsed))
        if not auth.startswith("Bearer ") or auth[7:] not in self.issued:
            return _response(request, 401, {"code": 16, "message": "no valid token"})
        if request.headers.get("x-zitadel-orgid") != ORG_ID:
            return _response(request, 403, {"code": 7, "message": "wrong org"})
        match = re.fullmatch(r"/management/v1/projects/([^/]+)/roles/_search", path)
        if match:
            if match.group(1) != PROJECT_ID:
                return _response(request, 404, {"code": 5, "message": "project not found"})
            return self._page(request, parsed, [{"key": key, "displayName": key} for key in self.roles])
        if path == "/management/v1/users/grants/_search":
            rows = self.grants
            for query in parsed.get("queries", []):
                if "projectIdQuery" in query:
                    rows = [r for r in rows if r["projectId"] == query["projectIdQuery"]["projectId"]]
                if "userIdQuery" in query:
                    rows = [r for r in rows if r["userId"] == query["userIdQuery"]["userId"]]
            return self._page(request, parsed, rows)
        # --- write/admin endpoints, used by the bootstrap script tests only --------------------
        if path == "/management/v1/users/_search" and any("inUserIdsQuery" in q for q in parsed.get("queries", [])):
            # Org-scoped like ZITADEL: only users owned by the org in x-zitadel-orgid are returned.
            wanted = set()
            for query in parsed["queries"]:
                wanted |= set(query.get("inUserIdsQuery", {}).get("userIds", []))
            rows = [
                {"id": uid, "details": {"resourceOwner": org}, "state": "USER_STATE_ACTIVE"}
                for uid, org in sorted(self.org_users.items())
                if uid in wanted and org == ORG_ID and not self.filter_users
            ]
            return self._page(request, parsed, rows)
        if path == "/management/v1/users/_search":
            rows = self.users
            for query in parsed.get("queries", []):
                if "emailQuery" in query:
                    wanted = query["emailQuery"]["emailAddress"].lower()
                    rows = [r for r in rows if r["human"]["email"]["email"].lower() == wanted]
            return self._page(request, parsed, rows)
        match = re.fullmatch(r"/management/v1/projects/([^/]+)/roles", path)
        if match and request.method == "POST":
            if parsed["roleKey"] in self.roles:
                return _response(request, 409, {"code": 6, "message": "role already exists"})
            self.roles.append(parsed["roleKey"])
            self.writes.append(("add_role", parsed))
            return _response(request, 200, {"details": {}})
        match = re.fullmatch(r"/management/v1/users/([^/]+)/grants", path)
        if match and request.method == "POST":
            # ZITADEL's UserGrant carries the user's e-mail (field `email`); mirror that.
            email = next((u["human"]["email"]["email"] for u in self.users if u["id"] == match.group(1)), None)
            row = self.grant(match.group(1), *parsed["roleKeys"], project_id=parsed["projectId"], email=email)
            self.writes.append(("add_grant", match.group(1), parsed))
            return _response(request, 200, {"userGrantId": row["id"]})
        match = re.fullmatch(r"/management/v1/users/([^/]+)/grants/([^/]+)", path)
        if match and request.method == "PUT":
            for row in self.grants:
                if row["id"] == match.group(2) and row["userId"] == match.group(1):
                    row["roleKeys"] = list(parsed["roleKeys"])
                    self.writes.append(("update_grant", match.group(1), parsed))
                    return _response(request, 200, {"details": {}})
            return _response(request, 404, {"code": 5, "message": "grant not found"})
        return _response(request, 404, {"code": 5, "message": "not found"})

    def add_user(self, user_id, email, org=ORG_ID, verified=True, leak=False):
        """Register a ZITADEL user. The e-mail search is org-scoped like ZITADEL's, unless `leak`
        (a server that ignores the org header) lists a user of another org too."""
        self.org_users[user_id] = org
        if org == ORG_ID or leak:
            self.users.append(
                {
                    "id": user_id,
                    "state": "USER_STATE_ACTIVE",
                    "details": {"resourceOwner": org},
                    "human": {"email": {"email": email, "isEmailVerified": verified}},
                }
            )

    def _token(self, request, form):
        assert form.get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assert form.get("scope") == "openid urn:zitadel:iam:org:project:id:zitadel:aud"
        header = jwt.get_unverified_header(form["assertion"])
        assert header.get("kid") == KEY_ID and header.get("alg") == "RS256"
        claims = jwt.decode(form["assertion"], self.public_key, algorithms=["RS256"], audience=BASE_URL)
        assert claims["iss"] == SERVICE_USER_ID and claims["sub"] == SERVICE_USER_ID
        self.token_requests += 1
        token = f"fake-access-token-{self.token_requests}"
        self.issued.add(token)
        return _response(request, 200, {"access_token": token, "token_type": "Bearer", "expires_in": self.expires_in})

    def _page(self, request, parsed, rows):
        query = parsed.get("query", {})
        offset = int(query.get("offset", "0"))
        limit = int(query.get("limit", 1000))
        if self.page_cap:
            limit = min(limit, self.page_cap)
        served = rows if self.truncate_after is None else rows[: self.truncate_after]
        body = {"result": served[offset : offset + limit]}
        if not self.omit_total:
            body["details"] = {"totalResult": str(len(rows))}
        if self.drop_result_on and self.drop_result_on in urlparse(request.url).path:
            body.pop("result")
        if self.raw_body_on and self.raw_body_on[0] in urlparse(request.url).path:
            body = self.raw_body_on[1]  # an exact response body, for response-shape tests
        return _response(request, 200, body)

    def close(self):
        pass


@pytest.fixture
def fake_zitadel(rsa_key, monkeypatch):
    fake = FakeZitadel(rsa_key.public_key())

    def new_session():
        session = requests.Session()
        session.mount("https://", fake)
        session.mount("http://", fake)
        return session

    monkeypatch.setattr(zitadel_module, "new_session", new_session)
    zitadel_module.reset_token_cache()
    yield fake
    zitadel_module.reset_token_cache()


def _clear_access_cache():
    try:
        keys = cache.keys("dumont_access:*")
        if keys:
            cache.delete_many(keys)
    except Exception:
        pass


@pytest.fixture
def access_env(monkeypatch, key_json, fake_zitadel):
    """Configure the sync against the fake ZITADEL. Returns a setter for the mode."""
    monkeypatch.setenv("DUMONT_AUTH_HOST", BASE_URL)
    monkeypatch.setenv("DUMONT_ACCESS_WORKSPACE_SLUG", "test-workspace")
    monkeypatch.setenv("DUMONT_ACCESS_ZITADEL_PROJECT_ID", PROJECT_ID)
    monkeypatch.setenv("DUMONT_ZITADEL_ORG_ID", ORG_ID)
    monkeypatch.setenv("DUMONT_ACCESS_ZITADEL_KEY_JSON", key_json)
    monkeypatch.delenv("DUMONT_ACCESS_MAX_REMOVALS", raising=False)
    monkeypatch.setenv("DUMONT_ACCESS_SYNC", "enforce")
    _clear_access_cache()

    def set_mode(mode):
        monkeypatch.setenv("DUMONT_ACCESS_SYNC", mode)

    yield set_mode
    _clear_access_cache()


# --- DB helpers ---------------------------------------------------------------------------------


def make_user(email, sub=None, is_bot=False):
    user = User.objects.create(email=email, username=email.split("@")[0] + uuid.uuid4().hex[:6], is_bot=is_bot)
    if sub:
        Account.objects.create(user=user, provider="dumont", provider_account_id=sub, access_token="x")
    return user


def ws_member(workspace, user, role, is_active=True):
    return WorkspaceMember.objects.create(workspace=workspace, member=user, role=role, is_active=is_active)


def make_project(workspace, identifier, creator=None):
    return Project.objects.create(
        name=f"Project {identifier}", identifier=identifier, workspace=workspace, created_by=creator
    )


def pr_member(project, user, role, is_active=True):
    return ProjectMember.objects.create(
        workspace=project.workspace, project=project, member=user, role=role, is_active=is_active
    )


def ws_row(workspace, user):
    return WorkspaceMember.objects.get(workspace=workspace, member=user)


def pr_row(project, user):
    return ProjectMember.objects.get(project=project, member=user)
