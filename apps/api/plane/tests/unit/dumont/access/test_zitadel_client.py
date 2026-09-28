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

    def test_only_grants_and_users_of_the_dumont_org(self, client, fake_zitadel):
        other = "999999999999999999"
        fake_zitadel.grant("in-org", "hangar.workspace.member")
        fake_zitadel.grant("via-project-grant", "hangar.workspace.admin", project_grant_id="pg-1")
        fake_zitadel.grant("grant-other-org", "hangar.workspace.admin", grant_org=other)
        fake_zitadel.grant("user-other-org", "hangar.workspace.admin", user_org=other)
        row = fake_zitadel.grant("owner-only-other", "hangar.workspace.admin")
        row.pop("orgId")
        row["details"]["resourceOwner"] = other
        grants = client.list_user_grants(PROJECT_ID)
        assert [g.user_id for g in grants] == ["in-org"]
        assert sorted((i["user_id"], i["reason"]) for i in client.ignored_grants) == [
            ("grant-other-org", "grant_org"),
            ("owner-only-other", "grant_resource_owner"),
            ("user-other-org", "user_outside_org"),
            ("via-project-grant", "project_grant"),
        ]
        user_search = fake_zitadel.api_calls("users/_search")[-1][2]
        assert user_search["queries"] == [{"inUserIdsQuery": {"userIds": ["in-org", "user-other-org"]}}]

    def test_org_fields_absent_still_needs_user_in_org(self, client, fake_zitadel):
        for user_id, org in (("a", ORG_ID), ("b", "999")):
            row = fake_zitadel.grant(user_id, "hangar.workspace.member", user_org=org)
            row.pop("orgId")
            row.pop("details")
        assert [g.user_id for g in client.list_user_grants(PROJECT_ID)] == ["a"]

    def test_user_check_ignores_rows_of_other_orgs_even_if_returned(self, client, fake_zitadel, monkeypatch):
        fake_zitadel.grant("a", "hangar.workspace.member")
        fake_zitadel.grant("b", "hangar.workspace.member", user_org="999")
        real_search = Z.ZitadelClient._search

        def leaky(self, path, queries=None):
            rows = real_search(self, path, queries)
            if path == Z.USERS_SEARCH_PATH:  # a server that ignores the org scope
                rows = rows + [{"id": "b", "details": {"resourceOwner": "999"}}]
            return rows

        monkeypatch.setattr(Z.ZitadelClient, "_search", leaky)
        assert [g.user_id for g in client.list_user_grants(PROJECT_ID)] == ["a"]

    def test_user_ids_are_checked_in_chunks(self, client, fake_zitadel):
        for i in range(Z.USER_IDS_PER_QUERY + 5):
            fake_zitadel.grant(f"u{i:03d}", "hangar.workspace.member")
        assert len(client.list_user_grants(PROJECT_ID)) == Z.USER_IDS_PER_QUERY + 5
        chunks = [len(c[2]["queries"][0]["inUserIdsQuery"]["userIds"]) for c in fake_zitadel.api_calls("users/_search")]
        assert chunks == [Z.USER_IDS_PER_QUERY, 5]

    def test_no_grants_no_user_lookup(self, client, fake_zitadel):
        # an explicit "result": [] is the only way to say "nothing"
        assert client.list_user_grants(PROJECT_ID) == []
        assert fake_zitadel.api_calls("users/_search") == []

    @pytest.mark.parametrize("path", ["roles", "grants", "users/_search"])
    def test_answer_without_result_is_an_error(self, client, fake_zitadel, path):
        fake_zitadel.roles = ["hangar.workspace.member"]
        fake_zitadel.grant("a", "hangar.workspace.member")
        fake_zitadel.drop_result_on = path
        with pytest.raises(Z.ZitadelError) as exc:
            client.list_project_role_keys(PROJECT_ID)
            client.list_user_grants(PROJECT_ID)
        assert "no 'result'" in str(exc.value)

    def test_short_page_with_total_keeps_paging(self, client, fake_zitadel):
        # the server hands out 30 rows per page although we asked for 100; totalResult says 75
        fake_zitadel.page_cap = 30
        fake_zitadel.roles = [f"hangar.project.p{i}.member" for i in range(75)]
        assert len(client.list_project_role_keys(PROJECT_ID)) == 75
        offsets = [call[2]["query"]["offset"] for call in fake_zitadel.api_calls("roles")]
        assert offsets == ["0", "30", "60"]

    def test_empty_page_before_total_is_an_error(self, client, fake_zitadel):
        # 150 grants exist (totalResult 150) but the server stops handing rows out after 100
        for i in range(150):
            fake_zitadel.grant(f"u{i:03d}", "hangar.workspace.member")
        fake_zitadel.truncate_after = 100
        with pytest.raises(Z.ZitadelError) as exc:
            client.list_user_grants(PROJECT_ID)
        assert "empty page at offset 100 of totalResult 150" in str(exc.value)

    def test_filtered_200_on_users_search_is_an_error(self, client, fake_zitadel):
        # a permission that filters users/_search answers 200 with no rows: every grant would look
        # like it belongs to another org, i.e. "everyone lost access". Fail safe instead.
        fake_zitadel.grant("a", "hangar.workspace.member")
        fake_zitadel.grant("b", "hangar.workspace.admin")
        fake_zitadel.filter_users = True
        with pytest.raises(Z.ZitadelError) as exc:
            client.list_user_grants(PROJECT_ID)
        assert "permission too narrow" in str(exc.value)

    def test_user_ids_in_org_itself_does_not_fail_on_empty(self, client, fake_zitadel):
        # the per-user sync asks "is this login sub in the org?"; "no" is an answer, not an error
        fake_zitadel.org_users["x"] = "999"
        assert client.user_ids_in_org(["x"]) == set()

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
