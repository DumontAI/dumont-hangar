# Dumont addition: DUMONT_API_BEARER_* parsing. Not upstream Plane.

import pytest

from plane.dumont.auth.config import BearerConfigError, load_bearer_config

ENABLED = {
    "DUMONT_API_BEARER_ENABLED": "1",
    "DUMONT_API_AUDIENCES": "300000000000000001",
    "DUMONT_ZITADEL_ORG_ID": "200000000000000001",
}


@pytest.mark.unit
class TestBearerConfig:
    def test_disabled_by_default(self):
        config = load_bearer_config({}, default_rate="60/minute")
        assert config.enabled is False
        assert config.rate_limit == "60/minute"

    @pytest.mark.parametrize("value", ["", "0", " 0 "])
    def test_explicitly_disabled(self, value):
        assert load_bearer_config({"DUMONT_API_BEARER_ENABLED": value}).enabled is False

    def test_disabled_ignores_other_invalid_settings(self):
        # Off means off: a half-written config must not stop a deployment that does not use it.
        config = load_bearer_config({"DUMONT_API_BEARER_ENABLED": "0", "DUMONT_AUTH_JWKS_URL": "ftp://x"})
        assert config.enabled is False

    @pytest.mark.parametrize("value", ["true", "yes", "on", "2"])
    def test_unrecognised_flag_fails_fast(self, value):
        with pytest.raises(BearerConfigError, match="DUMONT_API_BEARER_ENABLED"):
            load_bearer_config({"DUMONT_API_BEARER_ENABLED": value})

    def test_defaults_when_enabled(self):
        config = load_bearer_config(ENABLED, default_rate="60/minute")
        assert config.enabled is True
        assert config.issuer == "https://auth.getdumont.ai"
        assert config.jwks_url == "https://auth.getdumont.ai/oauth/v2/keys"
        assert config.audiences == ("300000000000000001",)
        assert config.reader_role == "hangar_reader"
        assert config.writer_role == "hangar_writer"
        assert config.rate_limit == "60/minute"

    def test_issuer_and_jwks_follow_auth_host(self):
        config = load_bearer_config({**ENABLED, "DUMONT_AUTH_HOST": "https://auth.staging.test/"})
        assert config.issuer == "https://auth.staging.test"
        assert config.jwks_url == "https://auth.staging.test/oauth/v2/keys"

    def test_explicit_issuer_and_jwks(self):
        config = load_bearer_config(
            {
                **ENABLED,
                "DUMONT_AUTH_ISSUER": "https://id.test",
                "DUMONT_AUTH_JWKS_URL": "https://id.test/keys",
            }
        )
        assert config.issuer == "https://id.test"
        assert config.jwks_url == "https://id.test/keys"

    def test_audiences_are_required(self):
        with pytest.raises(BearerConfigError, match="DUMONT_API_AUDIENCES is required"):
            load_bearer_config({"DUMONT_API_BEARER_ENABLED": "1", "DUMONT_API_AUDIENCES": " , "})

    def test_audiences_csv_trimmed_and_deduplicated(self):
        config = load_bearer_config({**ENABLED, "DUMONT_API_AUDIENCES": " a1 ,a2,, a1 "})
        assert config.audiences == ("a1", "a2")

    @pytest.mark.parametrize("value", ["a1:hangar_reader", "a1 a2", "a1\ta2", "a1 a2", "a1,a\x0bb"])
    def test_audience_must_be_bare_project_id(self, value):
        with pytest.raises(BearerConfigError, match="bare ZITADEL project ids"):
            load_bearer_config({**ENABLED, "DUMONT_API_AUDIENCES": value})

    def test_allowed_org_is_required(self):
        env = {k: v for k, v in ENABLED.items() if k != "DUMONT_ZITADEL_ORG_ID"}
        with pytest.raises(BearerConfigError, match="DUMONT_ZITADEL_ORG_ID is required"):
            load_bearer_config(env)
        with pytest.raises(BearerConfigError, match="DUMONT_ZITADEL_ORG_ID is required"):
            load_bearer_config({**env, "DUMONT_ZITADEL_ORG_ID": "  "})

    @pytest.mark.parametrize("value", ["org:1", "200 001", "200\t001", "200\n001", "200 001"])
    def test_allowed_org_must_be_bare_id(self, value):
        with pytest.raises(BearerConfigError, match="bare ZITADEL organization id"):
            load_bearer_config({**ENABLED, "DUMONT_ZITADEL_ORG_ID": value})

    def test_allowed_org_is_kept(self):
        assert load_bearer_config(ENABLED).allowed_org_id == "200000000000000001"

    def test_disabled_ignores_bad_rate_override(self):
        # A bad override must not reach the throttle, which also runs on X-Api-Key requests.
        config = load_bearer_config(
            {"DUMONT_API_BEARER_ENABLED": "0", "DUMONT_API_BEARER_RATE_LIMIT": "fast"}, default_rate="60/minute"
        )
        assert config.enabled is False
        assert config.rate_limit == "60/minute"

    def test_jwks_must_share_issuer_origin(self):
        with pytest.raises(BearerConfigError, match="same origin"):
            load_bearer_config({**ENABLED, "DUMONT_AUTH_JWKS_URL": "https://evil.test/oauth/v2/keys"})

    def test_jwks_port_counts_as_origin(self):
        with pytest.raises(BearerConfigError, match="same origin"):
            load_bearer_config({**ENABLED, "DUMONT_AUTH_JWKS_URL": "https://auth.getdumont.ai:8443/oauth/v2/keys"})

    @pytest.mark.parametrize("url", ["http://auth.example.test", "ftp://auth.example.test", "not a url"])
    def test_issuer_must_be_https(self, url):
        with pytest.raises(BearerConfigError):
            load_bearer_config({**ENABLED, "DUMONT_AUTH_ISSUER": url})

    def test_plain_http_allowed_for_localhost(self):
        config = load_bearer_config({**ENABLED, "DUMONT_AUTH_HOST": "http://localhost:8080"})
        assert config.issuer == "http://localhost:8080"

    def test_roles_must_differ(self):
        with pytest.raises(BearerConfigError, match="must differ"):
            load_bearer_config({**ENABLED, "DUMONT_API_READER_ROLE": "x", "DUMONT_API_WRITER_ROLE": "x"})

    def test_custom_roles(self):
        config = load_bearer_config({**ENABLED, "DUMONT_API_READER_ROLE": "r", "DUMONT_API_WRITER_ROLE": "w"})
        assert (config.reader_role, config.writer_role) == ("r", "w")

    @pytest.mark.parametrize("rate", ["fast", "0/minute", "10/fortnight", "10"])
    def test_bad_rate_fails_fast(self, rate):
        with pytest.raises(BearerConfigError, match="DUMONT_API_BEARER_RATE_LIMIT"):
            load_bearer_config({**ENABLED, "DUMONT_API_BEARER_RATE_LIMIT": rate})

    def test_rate_override(self):
        config = load_bearer_config({**ENABLED, "DUMONT_API_BEARER_RATE_LIMIT": "30/minute"}, default_rate="60/minute")
        assert config.rate_limit == "30/minute"

    def test_web_url_for_the_not_linked_message(self):
        config = load_bearer_config({**ENABLED, "WEB_URL": "https://hangar.example.test/"})
        assert config.web_url == "https://hangar.example.test"
