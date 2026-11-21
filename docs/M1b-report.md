# M1b report: migration to LangGraph

**Status:** done (awaiting OK) · **Date:** 2026-11-21 · **Package code:** 808 lines · **No new features**

## Files changed
| File | Change |
|---|---|
| `oss_agent/graph.py` | **new**: State, nodes `agent` / `tools` / `force_report` / `checks`, `route_after_agent`, `route_after_tools`, `build_graph(model=None)` |
| `oss_agent/agent.py` | **deleted** (still in commit `ac20988`) |
| `oss_agent/llm.py` | the adapter is replaced by `get_model(tools)` plus `invoke()`. `claude_cli` is now a LangChain `BaseChatModel` (`ChatClaudeCLI`); `anthropic` is `ChatAnthropic`. |
| `oss_agent/tools.py` | the plain functions are unchanged; thin `StructuredTool` wrappers (`LC_TOOLS`) added |
| `oss_agent/main.py` | runs the compiled graph; `--show-graph` added; `--trace` shows each node |
| `tests/test_graph.py` | **new**: 5 offline routing tests with a scripted fake model |
| `requirements.txt` | + `langgraph`, `langchain-anthropic` |
| `docs/SPEC.md` | **new**: full v2 spec |
| unchanged | `http.py`, `rules.py`, `report.py`, `prompts.py` |

## Old loop → new graph
| Old `agent.py` (commit `ac20988`) | New `graph.py` |
|---|---|
| L38–42 `run()` with local variables `messages`, `trace`, `repo_info`, `report`, `report_retries` | `State` TypedDict + `initial_state()`. Fields that build up (`trace`, `tool_outputs`, `messages`) use reducers (`operator.add`, `add_messages`). |
| L44 `for step in range(1, MAX_STEPS + 1)` | the `tools → agent` edge, plus the `steps` counter in State |
| L45 `llm.chat(SYSTEM_PROMPT, messages, TOOL_SCHEMAS)` | **`agent` node** (L76): `llm.invoke(model, [SystemMessage, *messages])`, with tools bound once in `get_model()` |
| L48–51 `if not reply["tool_calls"]: return answer` | **`route_after_agent`** → `END`; the answer is stored in `state["answer"]` |
| L54–75 `for call in tool_calls`: validate, run, submit_report check, trace | **`tools` node** (L88), with the same guardrails (`_validate_call`, `_wrap`, `_summary` copied over unchanged) |
| L77–78 `if report is not None: break` | **`route_after_tools`** → `checks` |
| L79–81 `if report_retries > 1: minimal_report` | **`route_after_tools`** → `force_report` |
| L82 `messages.append(tool results)` | the `tools` node returns `ToolMessage`s; the `add_messages` reducer appends them |
| L83–84 `for … else: minimal_report` (MAX_STEPS) | **`route_after_agent`** (steps ≥ 10) → **`force_report` node** (L113) |
| L86 `rep.post_process(report, repo_info)` | **`checks` node** (L119), then `checks → END` |

| *(new, SPEC review change 1)*: the old loop returned any reply without tool calls as a "direct answer" | **`route_after_agent`**: no tool calls and no tools used → `END`. After tools have been used → **`nudge`** node ("Finish by calling submit_report") → `agent`, once; the second time → `force_report`. |

## Verified output
- `pytest`: 12 passed. The 7 graph tests cover: a direct answer, the repo-info → report → checks path, an unknown tool being rejected, nudge then report, nudge twice → `force_report`, two invalid reports → `force_report`, and MAX_STEPS → `force_report`.
- Flask: 1 tool call, the same report format, overall 🟢, 12.8 s.
- "MIT vs GPL": direct answer, 0 tool calls.

```
TRACE
   1 agent        → get_repo_info                                   3877 tok  2.84s
   1 tools        get_repo_info {"repo": "pallets/flask"}                     0.77s  repo=pallets/flask, ...
   2 agent        → submit_report                                   6576 tok  9.17s
   2 tools        submit_report {"report": {...}}                             0.0s
   2 checks       overall=green
```

## Deviations from the request
- **No `temperature=0`:** `ChatAnthropic` itself raises `ValueError` for `claude-sonnet-5-5` at any non-default temperature, because the model rejects it. Repeatability comes from the deterministic `checks` node instead. The CLI backend has no temperature setting either.
- **One tool call per step:** `parallel_tool_calls=False` for `ChatAnthropic`; `maxItems: 1` in the CLI reply schema.
- **`anthropic` provider not tested live** (there's no API key). The request payload was checked offline: it uses the `server-side-fallback` beta with `fallbacks: "default"` and `disable_parallel_tool_use: true`.

## Known issue (carried into M2)
The evidence for some areas is a raw JSON fragment (`"licence_spdx": "BSD-3-Clause"`) linked to the repo homepage. M2's `evidence.py` (quote verification, pinned links) is the fix.
