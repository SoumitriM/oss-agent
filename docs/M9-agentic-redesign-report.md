# M9: Agentic redesign (simple, evidence-first, no overfitting)

## Why we changed it
An audit (`docs/AUDIT-evidence-and-leakage.md`) found three problems:
- **Overfitting.** Rules, regular expressions and prompt examples had been tuned to the test cases. Some prompt examples were the test answers themselves. That would not hold up over hundreds of new questions.
- **Approvals without evidence.** In some situations the agent could say "Recommended" even though security had not been checked.
- **Too much hard-coded logic.** It made the agent harder to explain and broke on new phrasings, for example a question that quoted an attack phrase.

## How it works now (one paragraph for stakeholders)
The agent reads the question and writes down what it understood: the component, the version and what you want to know. If something is unclear or looks like a typo, it asks you. It then plans which facts it needs, fetches them from public sources (GitHub, the OSV, GitHub and NVD vulnerability databases, the npm registry, endoflife.date), and fetches more if a result raises a new question. Finally it answers. Every claim carries a quote and a link to its source, and the answer states the agent's confidence. All sources are read-only: nothing is installed, run or sent.

## What code still enforces (and why each rule exists)
| Rule | Why it is not left to the AI |
|---|---|
| Every rated area needs a verified quote from this run, otherwise it becomes "not checked". The agent gets one chance to fix this. | An answer must never rest on an unchecked claim. |
| A published malicious release means red and "Do not adopt". | Approving malware is the worst possible mistake. |
| Security that wasn't actually checked (a source was down, a different package was checked, or no check ran) is never an approval. | "Nothing found" must never look like "clean". |
| A "confirmed" skill threat must quote lines the agent actually read. | A pattern match alone is a hint, not proof. |
| The decision line is derived from the area ratings, and confidence can only be lowered. | The headline can never contradict the evidence. |
| Read-only tools, a list of allowed websites, and tool output treated as data, never as instructions. | Security of the agent itself. |

The AI now handles everything else: understanding the question, licence judgement, severity and applicability, end of life, privacy, skills and comparisons.

## Keeping it general
- `tests/test_leakage.py` fails if any name, ID, version, path or expected phrase from the test sets appears in text the AI sees (the prompt, tool descriptions and tool notes). The prompt uses only general principles and neutral placeholders.
- Removed: the regex query parser (`query.py`), the coverage rules (`coverage.py`), the licence tables, the severity and end-of-life rules, the skill-quote regexes, and the guard's topic regexes. Product code went from about 2,940 to about 2,320 lines.
- The regex in the skill scanner that had been copied from a test file was rewritten from the category's definition. It now flags a hidden `.env` theft that it used to miss, and it no longer flags a harmless sentence it used to flag.

## Cost
- One question costs one AI call per step: understand and plan, gather, and answer. There is at most one extra call to fix evidence and at most 10 steps.
- Tool results are capped at 4,000 characters each.
- Smoke run: "Can we keep minimist 1.2.5?" took 1 tool call, about 29K tokens and 23 s. The answer was red, with the CVE, two verified quotes, the fixed version and high confidence.

## Tests
- 89 offline tests pass. They cover the safety rules, the evidence checks, the tools, the security layer and the leak check.
- Tests that checked verdicts code used to force (CVE severity, licence verdicts, skill downgrades) were removed. Those are now the agent's judgement and are measured live.

## Next (M10)
1. Live development evals (`tests/eval.py`, `tests/e2e_eval.py`), 3 runs per case, giving pass rates. Failures are fixed only with general principles.
2. A held-out set written by someone who hasn't seen the code. Only its score is reported.
3. Known gaps to watch:
   - comparisons, which have no per-candidate structure yet;
   - looking up a PyPI package's repository;
   - an end-of-life product id that the agent must choose itself.
