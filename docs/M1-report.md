# M1 report: agent loop, get_repo_info, submit_report, rendering

**Status:** done · **Date:** 2026-11-21 · **Package code:** ~740 lines (see "Line budget")

## What was built

| File | Purpose |
|---|---|
| `agent.py` | The loop: LLM picks a tool → code validates it, runs it and wraps the result → repeat until `submit_report` or `MAX_STEPS = 10` |
| `tools.py` | `get_repo_info` + the tool schemas (`get_repo_info`, `submit_report`) |
| `prompts.py` | System prompt: evidence rules, untrusted-data rule, plain language |
| `rules.py` | Licence table by SPDX id, overall verdict = worst area |
| `report.py` | Validate the report → deterministic post-processing → terminal rendering |
| `main.py` | `python -m oss_agent "question" [--trace] [--offline] [--json out.json]` |

### The loop (agent.py)
1. Send the system prompt, the conversation so far and the tool schemas to `llm.chat()`.
2. No tool calls means a direct answer (e.g. "MIT vs GPL?"). Print it and stop.
3. For each tool call:
   - Check the name and required arguments.
   - Run the tool, or accept the report if it was `submit_report`.
   - Truncate the result to 4,000 characters and wrap it in `<untrusted_data>` tags.
4. An invalid report gets one retry, with the validation error sent back to the model. A second failure, or reaching 10 steps, produces a minimal report with every area marked "not checked".
5. Every tool call is logged (step, tool, args, short result, tokens, seconds). `--trace` prints the log.

### get_repo_info
- Uses the GitHub API to fetch: description, archived flag, HEAD commit SHA and date, stars, open issues and the SPDX licence id.
- Licence file: the first 60 lines, with a link pinned to the HEAD commit (`/blob/<sha>/LICENSE.txt`).
- SECURITY.md: checks `SECURITY.md`, `.github/SECURITY.md` and `docs/SECURITY.md`, then the **org-wide default in `{owner}/.github`**. That's how GitHub itself resolves it, and it's where Pallets keeps theirs.
- SKILL.md paths come from **code search**, not the git tree API. n8n's recursive tree is 14 MB, over the 2 MB cap.

### Deterministic post-processing (code overrides the LLM)
- `repo` and `commit` come from the API result, not from the LLM's text.
- Licence status comes from the SPDX table when the id is known. Custom or `NOASSERTION` licences are left to the LLM, which reads the licence text.
- An archived repo makes maintenance red.
- Areas the LLM skipped are marked `not_checked`.
- Overall = the worst area status.

## How to run
```bash
.venv/bin/python -m oss_agent "Can we use pallets/flask in a commercial product?" --trace
.venv/bin/python -m oss_agent "MIT vs GPL: which is safer for us?"      # 0 tool calls
.venv/bin/python -m oss_agent "Is pallets/flaskk safe to use?" --trace  # typo
```

## Verified output (Flask demo)
```
pallets/flask @ 49943b5 · checked 2026-11-21
Overall: 🟢 OK to use
Assumed: Question is about licence terms for commercial use only; other areas not checked. · ...

LICENCE      🟢 BSD-3-Clause is permissive and allows commercial use with conditions.
              "Redistribution and use in source and binary forms, with or without modification, are permi…"
              → https://github.com/pallets/flask/blob/49943b5a.../LICENSE.txt
SECURITY     ⚪ Not assessed for this licence question.
...
(1 tool calls · 11.7 s · --trace for details)

TRACE
   1. get_repo_info   {"repo": "pallets/flask"}    3864 tok  2.58s  repo=pallets/flask, ...
   2. submit_report   {"report": {...}}             6589 tok   9.1s
```
The typo case first tries `pallets/flaskk` (404), then `pallets/flask`, and says so: *"Assessed pallets/flask instead of pallets/flaskk (pallets/flaskk returned 404 not found)."*

## Problems found and fixed
| Problem | Cause | Fix |
|---|---|---|
| Model said "the lookup tool was unavailable" without calling anything (4 of 6 runs) | With the CLI backend, the model tried to invoke `get_repo_info` natively inside Claude Code and got "No such tool available" | Tools are described as *actions you request*. Their names are an `enum` inside the reply's JSON schema. A reply that used more than 2 CLI turns is retried. Result: 8 of 8 good runs |
| False "no SECURITY.md" for Flask | The policy is in `pallets/.github` | Added the org-level fallback |
| Long summaries, multi-line quotes | No length guidance | "Max 15 words" in the schema; quotes shown on one line |

## Line budget
The package is about 740 lines, already near the 600–800 target, and 4 tools are still to come.
The biggest items are the `submit_report` schema (~70 lines) and the two LLM backends in
`llm.py` (~190). Options for later: drop the `anthropic` backend if it won't be shown, or
treat the schema as data rather than logic. To decide before M3.

## Not yet done (by design, later milestones)
- Quote verification and the "⚠ unverified" label (M2).
- Maintenance currently cites the raw JSON (`"archived": false`) and the repo homepage. M2's evidence rules will make this cleaner.
