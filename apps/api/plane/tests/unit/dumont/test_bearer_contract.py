# Dumont addition: API v1 contract with a ZITADEL bearer token (projects + rate limit).
# Not upstream Plane. No network: see conftest.py.

from uuid import uuid4

import pytest
from rest_framework import status
from rest_framework.test import APIClient

from plane.api.rate_limit import ApiKeyRateThrottle
from plane.db.models import Account, APIActivityLog, Project, ProjectMember, User

from .conftest import make_config, writer_roles


def bearer_client(token):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


def projects_url(workspace):
    return f"/api/v1/workspaces/{workspace.slug}/projects/"


@pytest.fixture
def project(workspace, create_user):
    created = Project.objects.create(name="Existing", identifier="EX", workspace=workspace, created_by=create_user)
    ProjectMember.objects.create(project=created, member=create_user, workspace=workspace, role=20)
    return created


@pytest.mark.contract
@pytest.mark.django_db
class TestProjectsWithBearer:
    def test_linked_reader_lists_projects(self, bearer_enabled, linked_account, workspace, project, make_token):
        response = bearer_client(make_token()).get(projects_url(workspace))
        assert response.status_code == status.HTTP_200_OK, response.content
        assert [p["identifier"] for p in response.json()["results"]] == ["EX"]

    def test_reader_cannot_create(self, bearer_enabled, linked_account, workspace, make_token):
        response = bearer_client(make_token()).post(
            projects_url(workspace), {"name": "Nope", "identifier": "NOPE"}, format="json"
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["error_code"] == "DUMONT_WRITER_ROLE_REQUIRED"
        assert not Project.objects.filter(identifier="NOPE").exists()

    @pytest.mark.parametrize("method", ["patch", "delete"])
    def test_reader_cannot_use_other_unsafe_methods(
        self, bearer_enabled, linked_account, workspace, project, make_token, method
    ):
        url = f"{projects_url(workspace)}{project.id}/"
        response = getattr(bearer_client(make_token()), method)(url, {"name": "Renamed"}, format="json")
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["error_code"] == "DUMONT_WRITER_ROLE_REQUIRED"
        project.refresh_from_db()
        assert project.name == "Existing" and project.deleted_at is None

    def test_writer_creates_as_the_user(self, bearer_enabled, linked_account, workspace, make_token, create_user):
        token = make_token(**writer_roles())
        response = bearer_client(token).post(
            projects_url(workspace), {"name": "Mine", "identifier": "MINE"}, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED, response.content
        created = Project.objects.get(id=response.json()["id"])
        assert created.created_by_id == create_user.id

    def test_unlinked_user_gets_401(self, bearer_enabled, create_user, workspace, make_token):
        response = bearer_client(make_token()).get(projects_url(workspace))
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["error_code"] == "DUMONT_ACCOUNT_NOT_LINKED"

    def test_plane_permissions_still_apply(self, bearer_enabled, workspace, make_token):
        # Linked and holding hangar_writer, but not a member of the workspace.
        outsider = User.objects.create(email=f"out-{uuid4().hex[:8]}@plane.so", username=f"out_{uuid4().hex[:8]}")
        Account.objects.create(user=outsider, provider="dumont", provider_account_id="sub-outsider", access_token="x")
        token = make_token(sub="sub-outsider", **writer_roles())
        client = bearer_client(token)
        assert client.get(projects_url(workspace)).status_code == status.HTTP_403_FORBIDDEN
        response = client.post(projects_url(workspace), {"name": "X", "identifier": "XX"}, format="json")
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert not Project.objects.filter(identifier="XX").exists()

    def test_viewset_routes_accept_bearer(self, bearer_enabled, linked_account, workspace, make_token):
        # BaseViewSet (stickies, invitations) is wired the same way as BaseAPIView.
        url = f"/api/v1/workspaces/{workspace.slug}/stickies/"
        assert bearer_client(make_token()).get(url).status_code == status.HTTP_200_OK
        response = bearer_client(make_token()).post(url, {"name": "note"}, format="json")
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["error_code"] == "DUMONT_WRITER_ROLE_REQUIRED"

    def test_viewset_routes_are_throttled_per_sub(self, bearer_enabled, linked_account, workspace, make_token):
        bearer_enabled.DUMONT_API_BEARER = make_config(rate_limit="1/minute")
        url = f"/api/v1/workspaces/{workspace.slug}/stickies/"
        client = bearer_client(make_token())
        assert client.get(url).status_code == status.HTTP_200_OK
        assert client.get(url).status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.contract
@pytest.mark.django_db
class TestBearerAuditLog:
    def test_bearer_post_is_logged_without_the_token(
        self, bearer_enabled, linked_account, workspace, make_token, monkeypatch
    ):
        # Run the celery task inline so the row is written by the real task code.
        from plane.bgtasks import logger_task
        from plane.middleware import logger as logger_middleware

        monkeypatch.setattr(
            logger_middleware.process_logs,
            "delay",
            lambda log_data: logger_task.process_logs(log_data=log_data),
        )
        token = make_token(jti="jti-audit-1", **writer_roles())
        response = bearer_client(token).post(
            projects_url(workspace), {"name": "Audited", "identifier": "AUD"}, format="json"
        )
        assert response.status_code == status.HTTP_201_CREATED, response.content

        row = APIActivityLog.objects.get(path=projects_url(workspace), method="POST")
        assert row.token_identifier == "dumont:sub-linked-0001:jti-audit-1"
        assert row.response_code == status.HTTP_201_CREATED
        assert "[REDACTED]" in row.headers
        stored = " ".join(
            str(getattr(row, field))
            for field in ("token_identifier", "headers", "body", "response_body", "query_params")
        )
        assert token not in stored
        # No piece of the token either (header, payload or signature segment).
        for segment in token.split("."):
            assert segment not in stored

    def test_failed_bearer_request_is_not_logged_as_bearer(self, bearer_enabled, workspace, make_token, monkeypatch):
        from plane.middleware import logger as logger_middleware

        calls = []
        monkeypatch.setattr(logger_middleware.process_logs, "delay", lambda log_data: calls.append(log_data))
        response = bearer_client(make_token()).get(projects_url(workspace))  # no linked account
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert calls == []


@pytest.mark.contract
@pytest.mark.django_db
class TestBearerRateLimit:
    def test_throttled_per_sub_with_headers(self, bearer_enabled, linked_account, workspace, make_token):
        bearer_enabled.DUMONT_API_BEARER = make_config(rate_limit="2/minute")
        client = bearer_client(make_token())
        first = client.get(projects_url(workspace))
        assert first.status_code == status.HTTP_200_OK
        assert first["X-RateLimit-Remaining"] == "1"
        assert "X-RateLimit-Reset" in first
        assert client.get(projects_url(workspace)).status_code == status.HTTP_200_OK
        third = client.get(projects_url(workspace))
        assert third.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert third["X-RateLimit-Remaining"] == "0"

        # Another subject has its own bucket.
        other = User.objects.create(email=f"o-{uuid4().hex[:8]}@plane.so", username=f"o_{uuid4().hex[:8]}")
        Account.objects.create(user=other, provider="dumont", provider_account_id="sub-other", access_token="x")
        other_response = bearer_client(make_token(sub="sub-other")).get("/api/v1/users/me/")
        assert other_response.status_code == status.HTTP_200_OK

    def test_api_key_headers_are_not_overwritten(self, bearer_enabled, api_key_client, workspace):
        bearer_enabled.DUMONT_API_BEARER = make_config(rate_limit="2/minute")
        response = api_key_client.get(projects_url(workspace))
        assert response.status_code == status.HTTP_200_OK
        assert int(response["X-RateLimit-Remaining"]) == ApiKeyRateThrottle().num_requests - 1
