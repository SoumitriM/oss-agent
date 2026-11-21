# M0 report: setup, HTTP layer, LLM adapter

**Status:** done · **Date:** 2026-11-21 · **Package code:** ~250 lines

## Goal
Lay the foundation the agent loop will sit on: a safe way to reach the
internet (`http.py`), a swappable way to reach the model (`llm.py`), and a
CLI that proves both work with one LLM call and no tools.

## What was built

| File | Purpose |
|---|---|
| `requirements.txt` | anthropic, requests, python-dotenv, packaging, pytest |
| `.env.example` / `.env` | config template / real secrets (`.env` is git-ignored) |
| `oss_agent/http.py` | the only network gateway |
| `oss_agent/llm.py` | `chat(system, messages, tools)` with two backends |
| `oss_agent/main.py`, `__main__.py` | CLI: `python -m oss_agent "question" [--offline]` |
| `tests/test_http.py` | 5 offline tests for the HTTP layer |

### http.py: one `get()` with guard rails
- **Allowlist:** https only, and only to `api.github.com`, `raw.githubusercontent.com`,
  `services.nvd.nist.gov` and `endoflife.date`. Anything else is refused before any request is made.
- **Limits:** 15 s timeout, one retry on 5xx or timeout, 2 MB size cap (streamed, so a huge file is cut off early).
- **Never raises:** it returns `{"ok": true, "data": ...}` or `{"ok": false, "error": "<short reason>"}`.
  404 becomes "not found", and 403/429 become "rate limited or forbidden".
- **Disk cache = offline fixtures:** each response is stored under the SHA-256 of its URL in
  `tests/fixtures/http_cache/`. Online it is reused for 24 h. With `--offline` only the cache is used.
- **Secrets:** GitHub and NVD tokens are added at request time and are never part of
  the cache filename, so fixtures can't contain them.

### llm.py: provider-neutral adapter
`chat()` returns `{text, tool_calls, assistant_message, stop_reason, usage, seconds}`.
The loop never sees provider details. Messages use the Anthropic shape for every backend.

| `LLM_PROVIDER` | How it works |
|---|---|
| `claude_cli` (default) | Runs `claude -p` (Claude Code in headless mode) as a **plain model**. It uses the developer's Claude login, so no API key is needed. |
| `anthropic` | Messages API with native tool calling. Needs `ANTHROPIC_API_KEY`. Server-side refusal fallback is enabled. |

How the `claude_cli` backend keeps the loop ours:
- **Locked down:** `--tools ""` (no built-in tools), `--strict-mcp-config`, `--setting-sources ""` and
  `--disable-slash-commands`. It runs from a temp folder so no project `CLAUDE.md` gets into the prompt.
  The model can only reply; it can't execute anything.
- **Tool calls as checked JSON:** tool schemas go into the system prompt. `--json-schema` forces the reply
  `{text, tool_calls:[{name, input}]}`, and `llm.py` turns that into `tool_use` blocks.
- **Stateless calls:** each call starts from nothing, so the conversation is flattened into a text transcript every turn.
- **Errors:** GitHub and NVD tokens are removed from the subprocess environment. A failed call is retried once, then a short `LLMError` is raised.

## How to run
```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m oss_agent "Is MIT or GPL better for a commercial product?"
```

## Verified output
```
github auth ok, limit = 5000
5 passed in 0.05s

For a commercial product, MIT is generally the safer and more flexible choice: ...
(1488 in / 307 out tokens · 4.52 s · stop=end_turn)
```

## Decisions and trade-offs
- **Claude Code CLI instead of OpenRouter (for now):** no API key or credits needed. OpenRouter (M8) becomes a third backend in the same file.
- **The CLI backend costs about 3–5 s per step:** a process starts each time, and Claude Code adds about 1.5K cached overhead tokens, which are included in the reported input tokens.
- **No native tool-use blocks from the CLI:** schema-valid JSON is the next best thing. `agent.py` still checks every tool name and argument, as the spec requires.
- **System `python3` is 3.9:** the project uses `.venv` with Python 3.11.

## Known issues
- A real GitHub token was briefly in `.env.example`. It has been replaced with a placeholder
  (the real token now lives only in `.env`). It was shared in a chat, so creating a new token is advised.
