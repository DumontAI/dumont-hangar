# Dumont addition: role-key parsing and configuration. Not upstream Plane.

import json

import pytest

from plane.dumont.access import roles as R
from plane.dumont.access.config import (
    AccessConfigError,
    current_mode,
    load_access_config,
    parse_service_key,
)


@pytest.mark.unit
class TestRoleKeys:
    @pytest.mark.parametrize(
        "key,expected",
        [
            ("hangar.workspace.admin", ("workspace", None, 20)),
            ("hangar.workspace.member", ("workspace", None, 15)),
            ("hangar.workspace.guest", ("workspace", None, 5)),
            ("hangar.project.mo.admin", ("project", "mo", 20)),
            ("hangar.project.mo.member", ("project", "mo", 15)),
            ("hangar.project.hgr_2.guest", ("project", "hgr_2", 5)),
        ],
    )
    def test_valid(self, key, expected):
        parsed = R.parse_role_key(key)
        assert (parsed.scope, parsed.identifier, parsed.role) == expected
        assert parsed.key == key

    @pytest.mark.parametrize(
        "key",
        [
            "hangar_reader",
            "hangar_writer",
            "hangar.workspace.owner",
            "hangar.workspace",
            "hangar.project.mo",
            "hangar.project.MO.member",  # not canonical
            "hangar.project.m-o.member",
            "hangar.project.mo.member.extra",
            "hangar.project..member",
            "hangar.project.abcdefghijklm.member",  # 13 chars, Plane allows 12
            "Hangar.workspace.member",
            "hangar.project.mo\n.member",  # `$` would have accepted the trailing newline
            "hangar.workspace.member\n",
            "hangar.project.Kmo.member",  # KELVIN SIGN, not ASCII
            "",
            None,
            42,
        ],
    )
    def test_invalid(self, key):
        assert R.parse_role_key(key) is None

    def test_identifier_to_key_part(self):
        assert R.identifier_to_key_part("MO") == "mo"
        assert R.identifier_to_key_part(" HGR ") == "hgr"
        assert R.identifier_to_key_part("A B") is None
        assert R.identifier_to_key_part("ÉCO") is None
        assert R.identifier_to_key_part("") is None
        # Non-ASCII is refused BEFORE lowercasing: "K".lower() == "k" would otherwise map a
        # look-alike identifier onto the role keys of project "KMO".
        assert "KMO".lower() == "kmo"
        assert R.identifier_to_key_part("KMO") is None
        assert R.identifier_to_key_part("MO\n") == "mo"  # surrounding whitespace is stripped first
        assert R.identifier_to_key_part("M\nO") is None

    def test_role_key_roundtrip(self):
        assert R.role_key("project", "mo", R.MEMBER) == "hangar.project.mo.member"
        assert R.role_key("workspace", None, R.ADMIN) == "hangar.workspace.admin"


@pytest.mark.unit
class TestConfig:
    def test_defaults_off(self):
        cfg = load_access_config({})
        assert cfg.mode == "off" and not cfg.enabled and cfg.max_removals == 5
        assert cfg.base_url == "https://auth.getdumont.ai"

    def test_invalid_mode(self):
        with pytest.raises(AccessConfigError):
            load_access_config({"DUMONT_ACCESS_SYNC": "yes"})

    def test_invalid_mode_is_off_for_request_paths(self, monkeypatch):
        monkeypatch.setenv("DUMONT_ACCESS_SYNC", "bogus")
        assert current_mode() == "off"

    @pytest.mark.parametrize("value", ["x", "-1"])
    def test_invalid_max_removals(self, value):
        with pytest.raises(AccessConfigError):
            load_access_config({"DUMONT_ACCESS_MAX_REMOVALS": value})

    def test_require_complete_names_missing_keys_only(self):
        cfg = load_access_config({"DUMONT_ACCESS_SYNC": "dry-run", "DUMONT_ACCESS_ZITADEL_KEY_JSON": "{secret}"})
        with pytest.raises(AccessConfigError) as exc:
            cfg.require_complete()
        message = str(exc.value)
        assert "DUMONT_ACCESS_WORKSPACE_SLUG" in message and "secret" not in message

    def test_repr_has_no_key(self, key_json):
        cfg = load_access_config({"DUMONT_ACCESS_SYNC": "enforce", "DUMONT_ACCESS_ZITADEL_KEY_JSON": key_json})
        assert cfg.key_source == key_json
        text = repr(cfg) + str(cfg)
        assert "PRIVATE KEY" not in text and "key_source" not in text and "key-0001" not in text

    def test_org_id_is_the_shared_variable(self):
        cfg = load_access_config({"DUMONT_ZITADEL_ORG_ID": " 200000000000000001 "})
        assert cfg.org_id == "200000000000000001"
        # the old per-feature name is gone: one value governs bearer auth, sync and web login
        assert load_access_config({"DUMONT_ACCESS_ZITADEL_ORG_ID": "1"}).org_id is None

    @pytest.mark.parametrize("value", ["2000:1", "2000 1", "2000\t1"])
    def test_org_id_same_rules_as_bearer_auth(self, value):
        cfg = load_access_config({"DUMONT_ACCESS_SYNC": "enforce", "DUMONT_ZITADEL_ORG_ID": value})
        # The mode survives (so the lock fails closed with 503), and every sync refuses to run.
        assert cfg.mode == "enforce" and cfg.org_id is None
        with pytest.raises(AccessConfigError) as exc:
            cfg.require_complete()
        assert "DUMONT_ZITADEL_ORG_ID" in str(exc.value) and "bare" in str(exc.value)

    def test_service_key_from_json_and_file(self, key_json, tmp_path):
        key = parse_service_key(key_json)
        assert key.key_id == "key-0001" and key.user_id == "svc-hangar-sync"
        assert "PRIVATE KEY" not in repr(key)
        path = tmp_path / "key.json"
        path.write_text(key_json)
        assert parse_service_key(str(path)).key_id == "key-0001"

    @pytest.mark.parametrize(
        "source",
        [
            "",
            "{not json",
            "/nonexistent/key.json",
            json.dumps({"keyId": "k", "key": "-----BEGIN RSA PRIVATE KEY-----x"}),
            json.dumps({"keyId": "k", "userId": "u", "key": "nope"}),
            json.dumps(["list"]),
        ],
    )
    def test_service_key_rejections_do_not_leak(self, source):
        with pytest.raises(AccessConfigError) as exc:
            parse_service_key(source)
        assert "BEGIN" not in str(exc.value)
