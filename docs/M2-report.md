# M2 report: read_file, search_code, quote verification, pinned links

**Status:** done (awaiting OK) · **Date:** 2026-11-21 · **Package code:** 1,038 lines

## What was built
| File | Change |
|---|---|
| `tools.py` | **`read_file(repo, path, start_line, end_line)`**: the file at the HEAD commit, numbered lines, max 200 lines and ~3,500 characters (so the 4,000-character cap never cuts a line silently), a "call again with start_line=N" note, and a pinned link. Rejects absolute paths and `..`. **`search_code(repo, query)`**: GitHub code search limited to the repo, max 10 hits with up to 3 fragments each. Rejects `repo:`/`org:`/`user:` in the query, so the search can't leave the repo. Both are added to `DATA_TOOLS` and the tool schemas. `conditions` is added to the `submit_report` schema. |
| `evidence.py` | **new**: `verify(findings, tool_outputs)`, called by the `checks` node |
| `graph.py` | the `checks` node runs `evidence.verify()` before `post_process()` and traces `quotes verified n/m` |
| `report.py` | `✔` or `⚠ unverified` after each link; prefers a verified, line-pinned finding per area; shows `Conditions:`; at most 3 conditions and 3 open questions shown (`+N more in --json`) |
| `prompts.py` | when to use `read_file` and `search_code`; quote without the `"   30| "` prefix; at most 3 conditions and 3 open questions |
| `tests/test_evidence.py` | **new**: 6 tests |

### How evidence verification works (code, not the LLM)
1. **Is the quote real?** The quote and everything the tools returned in this run are whitespace-normalised. Wrapping quotes, a trailing `…`, and line-number prefixes are ignored. If the quote isn't found → `verified: false` → shown as `⚠ unverified`.
2. **Which link?** The LLM's URL is replaced by where the quote was **actually** found:
   1. in a file excerpt (`read_file`, or the licence/SECURITY.md excerpts from `get_repo_info`) → the exact line range, `/blob/<sha>/<path>#L32-L33`;
   2. in a code-search fragment → that file's link;
   3. only in repo metadata (e.g. `"archived": false`) → the repo page.

   This fixed a real bug seen during the demo: the LLM attached the LICENSE.md link to the "archived: false" fact.

## How to run
```bash
.venv/bin/python -m oss_agent "Can we self-host n8n-io/n8n for workflows with customer data?" --trace
.venv/bin/python -m pytest -q       # 18 passed
```

## Verified output (n8n demo)
```
n8n-io/n8n @ d7177ef · checked 2026-11-21
Overall: 🟡 Usable with conditions
LICENCE      🟡 Custom Sustainable Use License: internal business use allowed, reselling or hosting for others is not.
              "You may use or modify the software only for your own internal business purposes or for non…"
              → https://github.com/n8n-io/n8n/blob/d7177ef…/LICENSE.md#L32-L33 ✔
PRIVACY      🟡 Anonymous telemetry is ON by default. It can be turned off with a setting.
              "enabled: boolean = true;"
              → https://github.com/n8n-io/n8n/blob/d7177ef…/packages/@n8n/config/src/configs/diagnostics.config.ts#L18 ✔
Conditions: Use only for our own internal business, not resold or offered to customers as a service. · Set N8N_DIAGNOSTICS_ENABLED=false and block outbound telemetry ... · Avoid .ee features ...
(4 tool calls · 53.8 s)

TRACE: get_repo_info → read_file LICENSE.md → search_code N8N_DIAGNOSTICS_ENABLED → read_file diagnostics.config.ts → submit_report
       checks: quotes verified 6/6, overall=yellow
```
Flask still gives 1 tool call and the same report.

## Notes and trade-offs
- **Matching is whitespace-normalised, not fuzzy.** A paraphrase counts as unverified, on purpose.
- **Quotes are matched against everything the tools returned.** A quote from a part of a long file that was cut off for the LLM could still be verified. That's safe, because the text really is at that commit.
- **The run takes 40–55 s with the `claude_cli` backend.** The final `submit_report` step alone takes 17–40 s, because the whole report is written as one JSON reply. Expect `anthropic` to be faster.
- **Line budget:** 1,038 lines, above the ~900 target. The tool schemas in `tools.py` are about 120 lines of that.
- The n8n HTTP responses are now cached in `tests/fixtures/http_cache/`, ready for `--offline` in M5 and M6.
- **Not in M2:** the GDPR mapping ("(GDPR Art. 25)" next to telemetry) comes in M3.
