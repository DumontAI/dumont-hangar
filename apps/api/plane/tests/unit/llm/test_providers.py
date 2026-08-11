# Dumont addition: covers the DeepSeek provider wiring.
# Not upstream Plane.

import pytest

from plane.app.views.external import base as llm_base


class _FakeCompletions:
    def create(self, model, messages):
        class _Msg:
            content = "pong"

        class _Choice:
            message = _Msg()

        class _Resp:
            choices = [_Choice()]

        return _Resp()


class _FakeChat:
    completions = _FakeCompletions()


class _FakeOpenAI:
    """Captures how the client was constructed."""

    calls = []

    def __init__(self, api_key, base_url=None):
        type(self).calls.append({"api_key": api_key, "base_url": base_url})
        self.chat = _FakeChat()


@pytest.fixture(autouse=True)
def fake_openai(monkeypatch):
    _FakeOpenAI.calls = []
    monkeypatch.setattr(llm_base, "OpenAI", _FakeOpenAI)
    return _FakeOpenAI


@pytest.mark.unit
class TestDeepSeekProvider:
    def test_registered_with_models(self):
        provider = llm_base.SUPPORTED_PROVIDERS.get("deepseek")
        assert provider is not None, "LLM_PROVIDER=deepseek would be rejected as unsupported"
        # get_llm_config rejects any model not in this list, so a typo here disables the feature.
        assert "deepseek-chat" in provider.models
        assert provider.default_model in provider.models

    def test_request_goes_to_deepseek_not_openai(self, fake_openai):
        text, error = llm_base.get_llm_response("task", "prompt", "sk-test", "deepseek-chat", "deepseek")
        assert (text, error) == ("pong", None)
        # Without base_url the key would be sent to api.openai.com and fail as invalid.
        assert fake_openai.calls[-1]["base_url"] == "https://api.deepseek.com"

    def test_openai_keeps_the_sdk_default_host(self, fake_openai):
        llm_base.get_llm_response("task", "prompt", "sk-test", "gpt-4o-mini", "openai")
        assert fake_openai.calls[-1]["base_url"] is None
