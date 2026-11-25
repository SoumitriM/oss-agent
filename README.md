# OSS Due-Diligence Agent

Ask in plain words whether an open-source component is safe to use. The agent checks its **licence, security, maintenance and privacy** and returns a decision with a verified quote and a source link for every finding.

Built with LangGraph for decision makers who aren't engineers. It is a prototype.

```
Can we use pallets/flask in a commercial product?

🟢 Recommended · Confidence: high
Yes. Flask is under the permissive BSD-3-Clause licence, which allows commercial use.
You only need to keep the copyright notice and licence text. The latest version 3.1.3
has no known vulnerabilities and the project is actively maintained.

What to do next
 1. Include the Flask copyright notice and BSD-3-Clause licence text in your product.
    Source: "Redistribution and use in source and binary forms, with or without
    modification, are permitted…" → github.com/pallets/flask/blob/49943b5…/LICENSE.txt#L3-L5
```
*(A real answer from the web chat, shortened.)*

## Quick start

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env     # set LLM_PROVIDER and its key; GITHUB_TOKEN recommended
```

```bash
.venv/bin/python -m oss_agent.server                 # web chat on http://127.0.0.1:8000
.venv/bin/python -m oss_agent "Is axios@1.14.1 safe?" --trace
```

| `.env` | Purpose |
|---|---|
| `LLM_PROVIDER` | `openrouter`, `anthropic` or `claude_cli` (uses your Claude Code login) |
| `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` | the key for that provider |
| `GITHUB_TOKEN`, `NVD_API_KEY` | optional, read-only; raise the rate limits |

**Model:** Sonnet 5.5 by default (recommended, as the prompt was tuned on it). Add `--haiku` for Haiku 5.5, which is about 20× cheaper per token and has its own prompt with stricter "when to stop" rules.

## How it works

- **The model plans:** it reads the question, chooses its tools, asks the user at most twice and writes the report.
- **Code checks the result:** every quote must appear in a tool result, a status without verified evidence becomes "not checked", and safety rules can only make a verdict stricter. For example, a known malicious release is always red.
- **Read-only and allowlisted:** it never runs or installs what it assesses, and talks only to GitHub, OSV, NVD, endoflife.date and the npm, PyPI, Packagist, crates.io and RubyGems registries.
- Out-of-scope and general questions get one fixed reply from code, never an answer from the model's memory.

Details: [ARCHITECTURE.md](ARCHITECTURE.md).

## Evaluation

Both evals call the real model and cost API credit.

```bash
.venv/bin/python tests/eval.py --record        # case eval
.venv/bin/python -m tests.robustness.run       # robustness eval
```

- **Case eval:** 10 real questions (`tests/test_cases.json`), each with an expected verdict. Every run is checked by code: the verdict and area statuses, which tools were and weren't called, step and call limits, that every quote is verified, and that key facts (such as an advisory id) appear.
- **Robustness eval:** 6 questions, each asked in 5 wordings (paraphrase, typo, German, extra noise), plus injected faults (a database that's down, prompt injection in tool results). It runs against a frozen data snapshot, so the decision must stay the same, and a fault must never lead to an unsafe approval.
