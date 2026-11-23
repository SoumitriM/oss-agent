"""Prompt caching: only the tool list and system prompt are cached. No network, no real key."""
from oss_agent import llm, tools
from oss_agent.prompts import SYSTEM_PROMPT


def test_api_request_caches_only_tools_and_system_prompt(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # never sent: the payload is only built
    model = llm.get_model(tools.LC_TOOLS)
    payload = model.bound._get_request_payload([llm.system_message(SYSTEM_PROMPT), ("user", "a question")], **model.kwargs)
    assert payload["system"][-1]["cache_control"] == llm.CACHE  # tools + system prompt, reused on every call
    assert "cache_control" not in payload                         # the conversation itself is not cached
    assert payload["system"][-1]["text"] == SYSTEM_PROMPT         # frozen text: nothing per-request in the prefix


def test_cli_backend_reads_the_cached_system_block_as_plain_text():
    assert llm._text(llm.system_message("hello").content) == "hello"
    assert llm._text("plain") == "plain"
