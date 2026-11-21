# M4 report: human in the loop (ask, approve, register, lookup_register)

**Status:** done (awaiting OK) · **Date:** 2026-11-21 · **Package code:** 1,451 lines · **Tests:** 32 passed
Following the priority rule (SPEC section 11), `scan_skill` was moved out of M4 to the end (M4b).

## What was built
| File | Change |
|---|---|
| `register.py` | **new**: `lookup_register(repo)` (latest earlier record or `found: false`; a missing or corrupt file → empty + `warning`) and `append(record)` for `register.jsonl` (git-ignored) |
| `graph.py` | new nodes **`ask`**, **`approve`**, **`register`** using `interrupt()`; `MemorySaver` checkpointer; `run(app, question, answer_fn)` resumes with `Command(resume=…)` until there are no more interrupts; State gains `questions_asked` and `decision` |
| `tools.py` | schemas for `lookup_register` and `ask_user`; `lookup_register` added to `DATA_TOOLS` |
| `report.py` | re-check view: unchanged-and-not-rechecked areas are carried over `[from <date>]`, `changed_areas` is computed, and the render shows only the changes |
| `main.py` | `make_answer_fn()`: interactive `input()`, or a script `{"ask": [...], "approve": "..."}`; `--answer` and `--approve`; Ctrl+C or Ctrl+D → "Cancelled: nothing saved."; the record is shown before the approval prompt |
| `prompts.py` | call `lookup_register` first; on a re-check, focus on changes; ask only when the answer would change a verdict; ask (instead of guessing) when a repo isn't found |
| tests | `test_graph.py` rewritten for interrupts (+4 human-in-the-loop tests), `test_register.py` new (4 tests) |

### Graph
```
agent ─→ ask (interrupt: question) ─→ agent
checks ─→ approve (interrupt: record) ─┬─ yes → register (append) → END
                                       └─ no  → END (shown, not saved)
```

### Rules enforced in code
| Rule | Where |
|---|---|
| Max 2 questions; the 3rd returns `"question limit reached, state an assumption"` without pausing | `ask` node, `MAX_QUESTIONS` |
| An empty or unclear answer (`""`, `?`, `idk`, …) → `UNKNOWN … State an assumption` | `ask` node, `UNCLEAR` |
| Nothing is saved without an explicit yes | `approve` → `register` edge |
| Scripted defaults: ask → `""`, approve → `no` | `make_answer_fn` |
| Ctrl+C or Ctrl+D while waiting → clean exit, nothing saved (saving only happens in `register`, after approval) | `main.py` |

## Demos (live, `claude_cli` backend)
**Typo → ask instead of guess:** `"Is pallets/flaskk safe to use?" --answer "pallets/flask" --approve no`
```
❓ I could not find "pallets/flaskk" on GitHub. Which repo did you mean? For example, did you mean "pallets/flask" (the Python web framework)?
> pallets/flask   (scripted)
pallets/flask @ 49943b5 … Overall: 🟡 Usable with conditions … quotes verified 5/5
Save this record to the register? [yes/no, optional comment after it] > no   (scripted)
Not saved (rejected).
```

**Run 1:** `"Can we self-host n8n-io/n8n for workflows with customer data?" --approve "yes approved for internal use, telemetry off"` → 7 tool calls, 55 s, `Saved to register.jsonl.`

**Run 2:** `"Re-check n8n-io/n8n"` → **3 tool calls, 23 s**
```
Re-check of 2026-11-21 (same commit, previous overall 🟡)
Changed: nothing
Unchanged since last check: LICENCE 🟡 · SECURITY 🟡 · MAINTENANCE 🟢 · PRIVACY 🟡 · SKILLS ⚪
Recommendation: Nothing has changed since the earlier approval. Keep it for internal use with telemetry off ...
TRACE: lookup_register (found=True) → get_repo_info → check_vulnerabilities → submit_report → checks → approve
```

## Known issues
- **The 24 h HTTP cache hides new commits on a re-check.** "Same commit" in run 2 came partly from the cached HEAD commit. Fix: a short cache lifetime (or no cache) for `commits/HEAD` when online. This is a small change in `http.py`, not done yet.
- **Ctrl+C during a live prompt was not tested automatically.** The code path is a plain `except (KeyboardInterrupt, EOFError)`.
- **Line budget:** 1,451 lines. M4 added about 180 (graph ~70, register ~60, main ~30, report ~20).
