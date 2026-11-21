"""LLM adapter: the agent loop only ever calls chat().

Two backends behind one interface (LLM_PROVIDER):
  claude_cli  (default) - Claude Code in headless mode (`claude -p`) used as a
                plain model: all its built-in tools are disabled, so it can
                only answer with JSON; the agent loop stays ours.
  anthropic   - the Messages API with native tool calling (needs an API key).

Messages use the Anthropic shape for both backends: user/assistant turns,
assistant content with "tool_use" blocks, user content with "tool_result" blocks.
"""
import json
import os
import subprocess
import tempfile
import time

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_TOKENS = 8000
CLI_TIMEOUT_S = 180

# The CLI backend returns this shape; --json-schema makes the CLI validate it.
CLI_REPLY_SCHEMA = {
    "type": "object",
    "properties": {
        "text": {"type": "string"},
        "tool_calls": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"name": {"type": "string"}, "input": {"type": "object"}},
                "required": ["name", "input"],
            },
        },
    },
    "required": ["text", "tool_calls"],
}


class LLMError(Exception):
    """Raised with a short, human-readable message (no secrets, no stack trace)."""


def chat(system: str, messages: list, tools: list | None = None) -> dict:
    """One LLM turn.

    Returns {
      "text": str,                       # any prose the model wrote
      "tool_calls": [{"id", "name", "input"}],
      "assistant_message": dict,         # append this to messages unchanged
      "stop_reason": str,
      "usage": {"input_tokens", "output_tokens"},
      "seconds": float,
    }
    """
    provider = os.getenv("LLM_PROVIDER", "claude_cli")
    model = os.getenv("LLM_MODEL", DEFAULT_MODEL)
    started = time.time()
    if provider == "claude_cli":
        result = _chat_cli(system, messages, tools or [], model)
    elif provider == "anthropic":
        result = _chat_anthropic(system, messages, tools or [], model)
    else:
        raise LLMError(f"unknown LLM_PROVIDER '{provider}' (use claude_cli or anthropic)")
    result["seconds"] = round(time.time() - started, 2)
    return result


# ---------- claude_cli backend ----------

def _render_transcript(messages: list) -> str:
    """Flatten the conversation into text, because each CLI call is stateless."""
    lines = []
    for msg in messages:
        blocks = msg["content"] if isinstance(msg["content"], list) else [{"type": "text", "text": msg["content"]}]
        for b in blocks:
            if b["type"] == "text" and b["text"]:
                lines.append(f"[{msg['role'].upper()}]\n{b['text']}")
            elif b["type"] == "tool_use":
                lines.append(f"[ASSISTANT TOOL CALL id={b['id']}]\n{b['name']}({json.dumps(b['input'])})")
            elif b["type"] == "tool_result":
                lines.append(f"[TOOL RESULT id={b['tool_use_id']}]\n{b['content']}")
    return "\n\n".join(lines)


def _cli_system_prompt(system: str, tools: list) -> str:
    if not tools:
        return system + "\n\nReply with your answer in `text` and an empty `tool_calls` list."
    specs = json.dumps([{k: t[k] for k in ("name", "description", "input_schema")} for t in tools], indent=1)
    return (
        f"{system}\n\n# Actions (requested, not called)\nThe 'tools' named above are ACTIONS run by "
        "an outside program, not functions you can invoke. Your ONLY callable function is the "
        "structured-output one: call it once per turn. To request actions, list them in its "
        "`tool_calls` field as {name, input}. The program runs them and shows each result as "
        "[TOOL RESULT] in the next turn. A requested action is never 'unavailable' unless a "
        f"[TOOL RESULT] says so.\n\nAvailable actions:\n{specs}\n\n"
        "# How to reply\nYou may request several independent actions at once. Put any short "
        "explanation in `text`. Leave `tool_calls` empty only for a direct answer that needs no "
        "repo data."
    )


def _reply_schema(tools: list) -> dict:
    """Action names go into the reply schema as an enum: the one place the model may 'call' them."""
    schema = json.loads(json.dumps(CLI_REPLY_SCHEMA))  # deep copy
    names = [t["name"] for t in tools]
    item = schema["properties"]["tool_calls"]["items"]
    item["properties"]["name"] = {"type": "string", "enum": names} if names else {"type": "string"}
    schema["properties"]["tool_calls"]["description"] = "Actions for the program to run: " + ", ".join(names)
    return schema


def _chat_cli(system: str, messages: list, tools: list, model: str) -> dict:
    cmd = [
        "claude", "-p", "--output-format", "json",
        "--model", model,
        "--system-prompt", _cli_system_prompt(system, tools),
        "--json-schema", json.dumps(_reply_schema(tools)),
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
            proc = subprocess.run(cmd, input=_render_transcript(messages), capture_output=True, text=True,
                                  timeout=CLI_TIMEOUT_S, env=env, cwd=tempfile.gettempdir())
            out = json.loads(proc.stdout)
            # A good reply takes 2 CLI turns (think + structured output). More means the model
            # tried to invoke an action natively and got confused, so retry it.
            if not out.get("is_error") and out.get("structured_output") is not None and out.get("num_turns", 2) <= 2:
                break
        except FileNotFoundError:
            raise LLMError("`claude` CLI not found; install Claude Code or use LLM_PROVIDER=anthropic")
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            out = None
        if attempt == 1:
            time.sleep(2)
    if not out or out.get("is_error") or out.get("structured_output") is None:  # after retry, accept >2 turns
        reason = (out or {}).get("result") or "no valid reply"
        raise LLMError(f"Claude CLI call failed: {str(reason)[:200]}")

    reply = out["structured_output"]
    tool_calls = [{"id": f"call_{i}_{int(time.time() * 1000)}", "name": c["name"], "input": c["input"]}
                  for i, c in enumerate(reply["tool_calls"])]
    content = ([{"type": "text", "text": reply["text"]}] if reply["text"] else [])
    content += [{"type": "tool_use", **c} for c in tool_calls]
    u = out.get("usage", {})
    return {
        "text": reply["text"],
        "tool_calls": tool_calls,
        "assistant_message": {"role": "assistant", "content": content},
        "stop_reason": "tool_use" if tool_calls else "end_turn",
        "usage": {
            "input_tokens": u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0)
            + u.get("cache_read_input_tokens", 0),
            "output_tokens": u.get("output_tokens", 0),
        },
    }


# ---------- anthropic backend ----------

def _chat_anthropic(system: str, messages: list, tools: list, model: str) -> dict:
    import anthropic  # imported here so the CLI backend works without an API key

    if not os.getenv("ANTHROPIC_API_KEY"):
        raise LLMError("ANTHROPIC_API_KEY is not set (copy .env.example to .env and fill it in)")
    # max_retries=1: the SDK retries once with backoff on 429/5xx/connection errors.
    client = anthropic.Anthropic(max_retries=1)
    try:
        resp = client.beta.messages.create(
            model=model, max_tokens=MAX_TOKENS, system=system, messages=messages, tools=tools,
            # If a safety classifier declines, the API retries on a fallback model
            # inside the same call instead of returning an empty answer.
            betas=["server-side-fallback-2026-07-01"], fallbacks="default",
        )
    except anthropic.AuthenticationError:
        raise LLMError("Anthropic API key invalid (check ANTHROPIC_API_KEY in .env)")
    except anthropic.RateLimitError:
        raise LLMError("Anthropic rate limit hit; wait a minute and retry")
    except anthropic.APIStatusError as e:
        raise LLMError(f"Anthropic API error {e.status_code}")
    except anthropic.APIConnectionError:
        raise LLMError("could not reach the Anthropic API (network problem)")

    return {
        "text": "".join(b.text for b in resp.content if b.type == "text"),
        "tool_calls": [{"id": b.id, "name": b.name, "input": b.input} for b in resp.content if b.type == "tool_use"],
        # Content is passed back exactly as received (incl. thinking blocks), as the API requires.
        "assistant_message": {"role": "assistant", "content": resp.content},
        "stop_reason": resp.stop_reason,
        "usage": {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens},
    }
