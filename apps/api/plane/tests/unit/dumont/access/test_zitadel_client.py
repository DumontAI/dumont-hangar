# Dumont addition: the read-only ZITADEL client against a fake ZITADEL. Not upstream Plane.

import pytest

from plane.dumont.access import zitadel as Z
from plane.dumont.access.config import parse_service_key
from plane.tests.unit.dumont.access.conftest import BASE_URL, ORG_ID, PROJECT_ID


@pytest.fixture
def client(fake_zitadel, key_json):
    return Z.ZitadelClient(BASE_URL, ORG_ID, parse_service_key(key_json))


@pytest.mark.unit
class TestZitadelClient:
    def test_token_is_jwt_profile_and_cached(self, client, fake_zitadel):
        fake_zitadel.roles = ["hangar.workspace.member"]
        assert client.list_project_role_keys(PROJECT_ID) == ["hangar.workspace.member"]
        assert client.list_project_role_keys(PROJECT_ID) == ["hangar.workspace.member"]
        assert fake_zitadel.token_requests == 1  # the fake verified signature, kid, iss/sub and aud
        assert set(fake_zitadel.timeouts) == {5}

    def test_token_refreshed_when_near_expiry(self, client, fake_zitadel):
        fake_zitadel.expires_in = 30  # below the refresh margin: never reused
        client.list_project_role_keys(PROJECT_ID)
        client.list_project_role_keys(PROJECT_ID)
        assert fake_zitadel.token_requests == 2

    def test_pagination_and_org_header(self, client, fake_zitadel):
        fake_zitadel.roles = [f"hangar.project.p{i}.member" for i in range(250)]
        keys = client.list_project_role_keys(PROJECT_ID)
        assert len(keys) == 250
        offsets = [call[2]["query"]["offset"] for call in fake_zitadel.api_calls("roles")]
        assert offsets == ["0", "100", "200"]

    def test_server_side_limit_below_page_size_is_followed_via_total(self, client, fake_zitadel):
        fake_zitadel.page_cap = 40
        for i in range(130):
            fake_zitadel.grant(f"u{i}", "hangar.workspace.member")
        assert len(client.list_user_grants(PROJECT_ID)) == 130

    def test_without_total_a_short_page_ends(self, client, fake_zitadel):
        fake_zitadel.omit_total = True
        for i in range(120):
            fake_zitadel.grant(f"u{i}", "hangar.workspace.member")
        assert len(client.list_user_grants(PROJECT_ID)) == 120

    def test_grant_filters(self, client, fake_zitadel):
        fake_zitadel.grant("a", "hangar.workspace.member", email="a@x.test")
        fake_zitadel.grant("b", "hangar.workspace.member", state="USER_GRANT_STATE_INACTIVE")
        fake_zitadel.grant("c", "hangar.workspace.admin", state=None)  # zero-value enum omitted
        fake_zitadel.grant("d", "hangar.workspace.admin", project_id="other")
        grants = client.list_user_grants(PROJECT_ID)
        assert sorted(g.user_id for g in grants) == ["a", "c"]
        assert [g.email for g in grants if g.user_id == "a"] == ["a@x.test"]
        only_a = client.list_user_grants(PROJECT_ID, user_id="a")
        assert [g.user_id for g in only_a] == ["a"]
        body = fake_zitadel.api_calls("grants")[-1][2]
        assert {"userIdQuery": {"userId": "a"}} in body["queries"]
        assert {"projectIdQuery": {"projectId": PROJECT_ID}} in body["queries"]

    @pytest.mark.parametrize("failure", [500, 403, 404, "timeout", "badjson"])
    def test_failures_raise_zitadel_error(self, client, fake_zitadel, failure):
        fake_zitadel.fail = failure
        with pytest.raises(Z.ZitadelError) as exc:
            client.list_project_role_keys(PROJECT_ID)
        assert "fake-access-token" not in str(exc.value) and "PRIVATE" not in str(exc.value)

    def test_wrong_project_is_an_error(self, fake_zitadel, key_json):
        client = Z.ZitadelClient(BASE_URL, ORG_ID, parse_service_key(key_json))
        with pytest.raises(Z.ZitadelError):
            client.list_project_role_keys("not-the-project")

    def test_401_drops_cached_token(self, client, fake_zitadel):
        client.list_project_role_keys(PROJECT_ID)
        fake_zitadel.issued.clear()  # token revoked server-side
        with pytest.raises(Z.ZitadelError):
            client.list_project_role_keys(PROJECT_ID)
        client.list_project_role_keys(PROJECT_ID)
        assert fake_zitadel.token_requests == 2

    def test_bad_private_key(self, fake_zitadel):
        from plane.dumont.access.config import ServiceKey

        client = Z.ZitadelClient(BASE_URL, ORG_ID, ServiceKey("k", "u", "-----BEGIN RSA PRIVATE KEY-----\nnope\n"))
        with pytest.raises(Z.ZitadelError) as exc:
            client.list_project_role_keys(PROJECT_ID)
        assert "nope" not in str(exc.value)
