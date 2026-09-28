# Dumont addition: role claim semantics, kept identical to mcp/src/auth.ts hasRole. Not upstream Plane.

import pytest

from plane.dumont.auth.roles import granted_roles, has_role

AUD = "300000000000000001"
AUD2 = "300000000000000002"
AUDS = (AUD, AUD2)


@pytest.mark.unit
class TestHasRole:
    @pytest.mark.parametrize(
        "claims",
        [
            {"roles": ["hangar_reader"]},
            {"roles": {"hangar_reader": {"org": "x"}}},
            {"urn:zitadel:iam:org:project:roles": {"hangar_reader": {}}},
            {"urn:zitadel:iam:org:project:roles": ["hangar_reader"]},
            {f"urn:zitadel:iam:org:project:{AUD}:roles": {"hangar_reader": {}}},
            {f"urn:zitadel:iam:org:project:{AUD2}:roles": {"hangar_reader": {}}},
            {"my:zitadel:grants": [f"{AUD}:hangar_reader"]},
            {"my:zitadel:grants": ["other", f"{AUD2}:hangar_reader"]},
        ],
    )
    def test_accepted_sources(self, claims):
        assert has_role(claims, AUDS, "hangar_reader") is True

    @pytest.mark.parametrize(
        "claims",
        [
            {},
            {"roles": "hangar_reader"},  # a bare string is neither array nor object
            {"roles": ["hangar_writer"]},
            {"roles": [["hangar_reader"]]},  # nested arrays do not count (JS ===)
            {"roles": None},
            {"urn:zitadel:iam:org:project:999:roles": {"hangar_reader": {}}},  # not a configured audience
            {"urn:zitadel:iam:org:project:roles:extra": {"hangar_reader": {}}},
            {"role": ["hangar_reader"]},
            {"my:zitadel:grants": ["hangar_reader"]},  # bare role is never enough
            {"my:zitadel:grants": ["999:hangar_reader"]},  # another project
            {"my:zitadel:grants": f"{AUD}:hangar_reader"},  # must be an array
            {"my:zitadel:grants": [{f"{AUD}:hangar_reader": True}]},
        ],
    )
    def test_rejected_sources(self, claims):
        assert has_role(claims, AUDS, "hangar_reader") is False

    def test_grants_need_an_audience(self):
        assert has_role({"my:zitadel:grants": [":hangar_reader"]}, (), "hangar_reader") is False


@pytest.mark.unit
class TestGrantedRoles:
    def test_reader_only(self):
        assert granted_roles({"roles": ["hangar_reader"]}, AUDS, "hangar_reader", "hangar_writer") == ("hangar_reader",)

    def test_writer_only(self):
        assert granted_roles({"roles": {"hangar_writer": {}}}, AUDS, "hangar_reader", "hangar_writer") == (
            "hangar_writer",
        )

    def test_both_in_order(self):
        claims = {"roles": ["hangar_writer", "hangar_reader"]}
        assert granted_roles(claims, AUDS, "hangar_reader", "hangar_writer") == ("hangar_reader", "hangar_writer")

    def test_none(self):
        assert granted_roles({"roles": ["other"]}, AUDS, "hangar_reader", "hangar_writer") == ()
