# Dumont addition: role claim semantics (mcp/src/auth.ts hasRole + org binding). Not upstream Plane.

import pytest

from plane.dumont.auth.roles import granted_roles, has_role

AUD = "300000000000000001"
AUD2 = "300000000000000002"
AUDS = (AUD, AUD2)
ORG = "200000000000000001"
FOREIGN = "200000000000000099"
OWNER = "urn:zitadel:iam:user:resourceowner:id"
IN_ORG = {OWNER: ORG}


@pytest.mark.unit
class TestHasRole:
    @pytest.mark.parametrize(
        "claims",
        [
            # Object form of the project claims names the granting org: no resource owner needed.
            {"urn:zitadel:iam:org:project:roles": {"hangar_reader": {ORG: "dumont.example"}}},
            {f"urn:zitadel:iam:org:project:{AUD}:roles": {"hangar_reader": {ORG: "dumont.example"}}},
            {f"urn:zitadel:iam:org:project:{AUD2}:roles": {"hangar_reader": {FOREIGN: "x", ORG: "y"}}},
            # Forms without the granting org count only for users of our org.
            {**IN_ORG, "roles": ["hangar_reader"]},
            {**IN_ORG, "roles": {"hangar_reader": {"org": "x"}}},
            {**IN_ORG, "urn:zitadel:iam:org:project:roles": ["hangar_reader"]},
            {**IN_ORG, f"urn:zitadel:iam:org:project:{AUD}:roles": ["hangar_reader"]},
            {**IN_ORG, "my:zitadel:grants": [f"{AUD}:hangar_reader"]},
            {**IN_ORG, "my:zitadel:grants": ["other", f"{AUD2}:hangar_reader"]},
        ],
    )
    def test_accepted_sources(self, claims):
        assert has_role(claims, AUDS, "hangar_reader", ORG) is True

    @pytest.mark.parametrize(
        "claims",
        [
            {},
            {**IN_ORG, "roles": "hangar_reader"},  # a bare string is neither array nor object
            {**IN_ORG, "roles": ["hangar_writer"]},
            {**IN_ORG, "roles": [["hangar_reader"]]},  # nested arrays do not count (JS ===)
            {**IN_ORG, "roles": None},
            {**IN_ORG, "urn:zitadel:iam:org:project:999:roles": {"hangar_reader": {ORG: "x"}}},  # not our audience
            {**IN_ORG, "urn:zitadel:iam:org:project:roles:extra": {"hangar_reader": {ORG: "x"}}},
            {**IN_ORG, "role": ["hangar_reader"]},
            {**IN_ORG, "my:zitadel:grants": ["hangar_reader"]},  # bare role is never enough
            {**IN_ORG, "my:zitadel:grants": ["999:hangar_reader"]},  # another project
            {**IN_ORG, "my:zitadel:grants": f"{AUD}:hangar_reader"},  # must be an array
            {**IN_ORG, "my:zitadel:grants": [{f"{AUD}:hangar_reader": True}]},
        ],
    )
    def test_rejected_sources(self, claims):
        assert has_role(claims, AUDS, "hangar_reader", ORG) is False

    @pytest.mark.parametrize(
        "claims",
        [
            # Role map of our project, granted by a foreign org (project grant).
            {f"urn:zitadel:iam:org:project:{AUD}:roles": {"hangar_reader": {FOREIGN: "other.example"}}},
            {"urn:zitadel:iam:org:project:roles": {"hangar_reader": {FOREIGN: "other.example"}}},
            # Object form never falls back to the resource owner.
            {**IN_ORG, f"urn:zitadel:iam:org:project:{AUD}:roles": {"hangar_reader": {FOREIGN: "x"}}},
            {**IN_ORG, f"urn:zitadel:iam:org:project:{AUD}:roles": {"hangar_reader": {}}},
            {**IN_ORG, f"urn:zitadel:iam:org:project:{AUD}:roles": {"hangar_reader": True}},
            {**IN_ORG, f"urn:zitadel:iam:org:project:{AUD}:roles": {"hangar_reader": [ORG]}},
            # Forms without the granting org, from a user of another org or with no resource owner.
            {"roles": ["hangar_reader"]},
            {OWNER: FOREIGN, "roles": ["hangar_reader"]},
            {OWNER: FOREIGN, f"urn:zitadel:iam:org:project:{AUD}:roles": ["hangar_reader"]},
            {OWNER: FOREIGN, "my:zitadel:grants": [f"{AUD}:hangar_reader"]},
            {"my:zitadel:grants": [f"{AUD}:hangar_reader"]},
            # Only the exact resource owner claim, as the exact string, counts.
            {"org_id": ORG, "roles": ["hangar_reader"]},
            {"urn:zitadel:iam:org:id": ORG, "roles": ["hangar_reader"]},
            {OWNER: int(ORG), "roles": ["hangar_reader"]},
            {OWNER: [ORG], "roles": ["hangar_reader"]},
            {OWNER: f" {ORG}", "roles": ["hangar_reader"]},
        ],
    )
    def test_foreign_or_unbound_org_is_rejected(self, claims):
        assert has_role(claims, AUDS, "hangar_reader", ORG) is False

    def test_grants_need_an_audience(self):
        assert has_role({**IN_ORG, "my:zitadel:grants": [":hangar_reader"]}, (), "hangar_reader", ORG) is False

    @pytest.mark.parametrize("allowed", ["", None])
    def test_no_allowed_org_accepts_nothing(self, allowed):
        claims = {OWNER: "", f"urn:zitadel:iam:org:project:{AUD}:roles": {"hangar_reader": {"": "x"}}}
        assert has_role(claims, AUDS, "hangar_reader", allowed) is False


@pytest.mark.unit
class TestGrantedRoles:
    def test_reader_only(self):
        claims = {**IN_ORG, "roles": ["hangar_reader"]}
        assert granted_roles(claims, AUDS, "hangar_reader", "hangar_writer", ORG) == ("hangar_reader",)

    def test_writer_only(self):
        claims = {**IN_ORG, "roles": {"hangar_writer": {}}}
        assert granted_roles(claims, AUDS, "hangar_reader", "hangar_writer", ORG) == ("hangar_writer",)

    def test_both_in_order(self):
        claims = {**IN_ORG, "roles": ["hangar_writer", "hangar_reader"]}
        assert granted_roles(claims, AUDS, "hangar_reader", "hangar_writer", ORG) == ("hangar_reader", "hangar_writer")

    def test_none(self):
        assert granted_roles({**IN_ORG, "roles": ["other"]}, AUDS, "hangar_reader", "hangar_writer", ORG) == ()

    def test_our_reader_plus_foreign_writer_is_only_reader(self):
        claims = {
            f"urn:zitadel:iam:org:project:{AUD}:roles": {
                "hangar.workspace.guest": {ORG: "dumont.example"},
                "hangar_reader": {ORG: "dumont.example"},
                "hangar_writer": {FOREIGN: "other.example"},
            }
        }
        assert granted_roles(claims, AUDS, "hangar_reader", "hangar_writer", ORG) == ("hangar_reader",)
