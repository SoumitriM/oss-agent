"""LLM backends. The graph only calls get_model() and invoke().

LLM_PROVIDER:
  claude_cli  (default) - ChatClaudeCLI below: Claude Code in headless mode (`claude -p`)
                used as a plain model. All its built-in tools are disabled, so it can
                only reply with JSON; the graph decides what runs.
  anthropic   - ChatAnthropic (Messages API, native tool calling, needs an API key).
Both return a LangChain AIMessage with .tool_calls, so graph.py is provider-agnostic.
"""
import json
import os
import subprocess
import tempfile
import time

from langchain_anthropic.chat_models import convert_to_anthropic_tool
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_TOKENS = 8000
CLI_TIMEOUT_S = 180


class LLMError(Exception):
    """Raised with a short, human-readable message (no secrets, no stack trace)."""


def get_model(tools: list):
    """Chat model with tools bound, one tool call per step."""
    provider = os.getenv("LLM_PROVIDER", "claude_cli")
    model = os.getenv("LLM_MODEL", DEFAULT_MODEL)
    if provider == "claude_cli":
        return ChatClaudeCLI(model=model).bind_tools(tools)
    if provider == "anthropic":
        if not os.getenv("ANTHROPIC_API_KEY"):
            raise LLMError("ANTHROPIC_API_KEY is not set (copy .env.example to .env and fill it in)")
        from langchain_anthropic import ChatAnthropic
        # No temperature: Sonnet 5.5 rejects non-default sampling values.
        chat = ChatAnthropic(
            model=model, max_tokens=MAX_TOKENS, max_retries=1,  # SDK retries once with backoff
            # On a safety-classifier decline, the API reruns the request on a fallback model.
            betas=["server-side-fallback-2026-07-01"], model_kwargs={"fallbacks": "default"},
        )
        return chat.bind_tools(tools, parallel_tool_calls=False)
    raise LLMError(f"unknown LLM_PROVIDER '{provider}' (use claude_cli or anthropic)")


def invoke(model, messages: list) -> AIMessage:
    """model.invoke() with provider errors turned into one short LLMError."""
    import anthropic
    try:
        return model.invoke(messages)
    except anthropic.AuthenticationError:
        raise LLMError("Anthropic API key invalid (check ANTHROPIC_API_KEY in .env)")
    except anthropic.RateLimitError:
        raise LLMError("Anthropic rate limit hit; wait a minute and retry")
    except anthropic.APIError as e:
        raise LLMError(f"Anthropic API error: {type(e).__name__}")


# ---------- claude_cli backend ----------

REPLY_SCHEMA = {
    "type": "object",
    "properties": {
        "text": {"type": "string"},
        "tool_calls": {
            "type": "array", "maxItems": 1,  # one action per step
            "items": {"type": "object", "properties": {"name": {"type": "string"}, "input": {"type": "object"}},
                      "required": ["name", "input"]},
        },
    },
    "required": ["text", "tool_calls"],
}


class ChatClaudeCLI(BaseChatModel):
    """Minimal LangChain chat model on top of `claude -p`. Each call is stateless."""

    model: str = DEFAULT_MODEL

    @property
    def _llm_type(self) -> str:
        return "claude-cli"

    def bind_tools(self, tools, **kwargs):
        return self.bind(tools=[convert_to_anthropic_tool(t) for t in tools])

    def _generate(self, messages, stop=None, run_manager=None, tools=None, **kwargs) -> ChatResult:
        tools = tools or []
        system = "\n".join(m.content for m in messages if isinstance(m, SystemMessage))
        out = _run_cli(_cli_system_prompt(system, tools), _render_transcript(messages), _reply_schema(tools), self.model)
        reply = out["structured_output"]
        calls = [{"name": c["name"], "args": c["input"], "id": f"call_{int(time.time() * 1000)}_{i}", "type": "tool_call"}
                 for i, c in enumerate(reply["tool_calls"])]
        u = out.get("usage", {})
        in_tok = u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) + u.get("cache_read_input_tokens", 0)
        msg = AIMessage(content=reply["text"], tool_calls=calls, usage_metadata={
            "input_tokens": in_tok, "output_tokens": u.get("output_tokens", 0),
            "total_tokens": in_tok + u.get("output_tokens", 0)})
        return ChatResult(generations=[ChatGeneration(message=msg)])


def _render_transcript(messages: list) -> str:
    """Flatten the conversation into text, because each CLI call is stateless."""
    lines = []
    for m in messages:
        if isinstance(m, HumanMessage):
            lines.append(f"[USER]\n{m.content}")
        elif isinstance(m, AIMessage):
            if m.content:
                lines.append(f"[ASSISTANT]\n{m.content}")
            lines += [f"[ASSISTANT TOOL CALL id={c['id']}]\n{c['name']}({json.dumps(c['args'])})" for c in m.tool_calls]
        elif isinstance(m, ToolMessage):
            lines.append(f"[TOOL RESULT id={m.tool_call_id}]\n{m.content}")
    return "\n\n".join(lines)


def _cli_system_prompt(system: str, tools: list) -> str:
    if not tools:
        return system + "\n\nReply with your answer in `text` and an empty `tool_calls` list."
    specs = json.dumps([{k: t[k] for k in ("name", "description", "input_schema")} for t in tools], indent=1)
    return (
        f"{system}\n\n# Actions (requested, not called)\nThe 'tools' named above are ACTIONS run by "
        "an outside program, not functions you can invoke. Your ONLY callable function is the "
        "structured-output one: call it once per turn. To request an action, put it in its "
        "`tool_calls` field as {name, input}. The program runs it and shows the result as "
        "[TOOL RESULT] in the next turn. A requested action is never 'unavailable' unless a "
        f"[TOOL RESULT] says so.\n\nAvailable actions:\n{specs}\n\n"
        "# How to reply\nRequest exactly ONE action per reply. Put any short explanation in "
        "`text`. Leave `tool_calls` empty only for a direct answer that needs no repo data."
    )


def _reply_schema(tools: list) -> dict:
    """Action names go into the reply schema as an enum: the one place the model may 'call' them."""
    schema = json.loads(json.dumps(REPLY_SCHEMA))  # deep copy
    names = [t["name"] for t in tools]
    item = schema["properties"]["tool_calls"]["items"]
    item["properties"]["name"] = {"type": "string", "enum": names} if names else {"type": "string"}
    schema["properties"]["tool_calls"]["description"] = "At most one action for the program to run: " + ", ".join(names)
    return schema


def _run_cli(system: str, transcript: str, schema: dict, model: str) -> dict:
    cmd = [
        "claude", "-p", "--output-format", "json", "--model", model,
        "--system-prompt", system, "--json-schema", json.dumps(schema),
        # Lock it down: no built-in tools, no MCP servers, no user/project settings or skills.
        "--tools", "", "--strict-mcp-config", "--setting-sources", "", "--disable-slash-commands",
        "--no-session-persistence",
    ]
    # Our API tokens are not passed to the CLI: it doesn't need them.
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "NVD_API_KEY")}
    out = None
    for attempt in (1, 2):  # one retry, e.g. for a transient network or overload error
        try:
            # Run in a temp dir so no project CLAUDE.md is pulled into the prompt.
            proc = subprocess.run(cmd, input=transcript, capture_output=True, text=True,
                                  timeout=CLI_TIMEOUT_S, env=env, cwd=tempfile.gettempdir())
            out = json.loads(proc.stdout)
            # A good reply takes 2 CLI turns (think + structured output). More means the model
            # tried to invoke an action natively and got confused, so retry it.
            if not out.get("is_error") and out.get("structured_output") is not None and out.get("num_turns", 2) <= 2:
                return out
        except FileNotFoundError:
            raise LLMError("`claude` CLI not found; install Claude Code or use LLM_PROVIDER=anthropic")
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            out = None
        if attempt == 1:
            time.sleep(2)
    if out and not out.get("is_error") and out.get("structured_output") is not None:
        return out  # after the retry, accept a reply that took extra turns
    raise LLMError(f"Claude CLI call failed: {str((out or {}).get('result') or 'no valid reply')[:200]}")
