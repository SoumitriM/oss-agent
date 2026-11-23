# OSS Due-Diligence Agent

Ask a question in plain words about an open-source component, such as *"Can we add dayjs to our new web app?"*. The agent checks the component's **licence, security, maintenance, privacy** and, for AI-agent skills, the **skill file itself**. The answer gives a decision, a confidence level and evidence for every finding.

It is a prototype (MVP) for decision makers who are not engineers. Every claim in an answer has a quote from a public source and a link to it. Anything the agent could not verify is left out or listed as a limitation.

## What an answer looks like

| Part | What it says |
|---|---|
| **Decision** | 🟢 Recommended · 🟡 Usable with conditions · 🔴 Do not adopt · ⚪ Insufficient evidence to approve · ℹ️ Answer (for a single question, such as one about a licence) |
| **Confidence** | high / medium / low, with a one-line reason |
| **Summary** | the agent's answer in a few sentences |
| **What to do next** | actions, each tied to a verified finding and its source link |
| **Limitations** | only checks that were needed but failed (for example, a vulnerability database that did not answer) |
| **Follow-up** | a question to refine the answer, if any |
| **Show evidence** | quotes, links, the tools called (☑ used / ☐ not used) and the full trace |

Questions outside this scope get fixed replies written by code, never an answer from the model's memory:
- **General questions** ("What does copyleft mean?") get a fixed reply: the agent doesn't answer from memory and helps with specific components only.
- **Out-of-scope requests** ("Build me an app…") get a polite refusal.

## Quick start

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env          # then fill it in; never commit .env
```

`.env` settings:

| Variable | Needed? | Purpose |
|---|---|---|
| `LLM_PROVIDER` | yes | `claude_cli` (uses your Claude Code login) or `anthropic` (API key) |
| `LLM_MODEL` | yes | default `claude-sonnet-5-5` |
| `ANTHROPIC_API_KEY` | only with `anthropic` | |
| `GITHUB_TOKEN` | recommended | read-only, no scopes; raises the GitHub rate limit |
| `NVD_API_KEY` | optional | raises the NVD rate limit |

## Run it

```bash
# Web chat on http://127.0.0.1:8000 (localhost only, no login; never saves to the register)
.venv/bin/python -m oss_agent.server

# Command line (asks you before saving a record to register.jsonl)
.venv/bin/python -m oss_agent "Is axios@1.14.1 safe to install in our production backend?" --trace

# Other CLI options
#   --offline         use cached HTTP responses only
#   --json out.json   write the full record (report, trace, tool outputs)
#   --show-graph      print the agent graph as Mermaid
#   --answer TEXT     scripted answer to the agent's question (repeatable)
#   --approve TEXT    scripted approval, e.g. "yes internal only" or "no"
```

## Tests and evaluation

```bash
.venv/bin/python -m pytest -q                 # 140 offline tests: no network, no LLM
.venv/bin/python -m tests.robustness.run      # robustness eval (calls the LLM; resumable)
```

| What | Where |
|---|---|
| Unit and regression tests, including a **leak test** that fails if any test-case name, version or phrase appears in the agent's instructions | `tests/test_*.py` |
| **Robustness eval**: 6 cases × (base, paraphrase, typo, German, noise) plus injected faults (tool down, prompt injection), run against a frozen data snapshot | `tests/robustness/`, results in [docs/eval/ROBUSTNESS.md](docs/eval/ROBUSTNESS.md) and [docs/eval/robustness.xlsx](docs/eval/robustness.xlsx) |
| **Evaluation plan v2**: 25 labelled cases, 4 independent reviewer agents, 5 sealed held-out cases | [docs/EVAL-PLAN.md](docs/EVAL-PLAN.md), `tests/eval_cases_v2.json` |

Last robustness run: 30 of the 36 planned runs finished and all 30 passed, with 0 hard fails. The other 6 were not run. See the report for details.

## Safety by design

- **Read-only.** The agent never clones, installs or executes anything from the repository it assesses. A tool that is not on the read-only list stops the agent at start-up.
- **Allowlisted hosts only:** the external APIs listed below. Any other host is refused.
- **Fetched content is data, not instructions.** Text that tries to instruct an AI agent is flagged and reported, never followed.
- **No secrets in prompts, logs or cached responses.** Tokens are added to the request header at the last moment.

## Supported package registries

The registry, not the model, says which repository a package comes from, which versions exist, and whether the package exists at all. Covered for now:

| Ecosystem | Registry | Package → repo | Versions with dates | Package exists |
|---|---|---|---|---|
| JavaScript | npm | ✅ | ✅ | ✅ |
| PHP | Packagist | ✅ | ✅ | ✅ |
| Python | PyPI | ✅ if the package lists its GitHub source | ✅ | ✅ |
| Rust | crates.io | ✅ | ✅ | ✅ |
| Ruby | RubyGems | ✅ if the gem lists its GitHub source | ✅ | ✅ |
| Go | none: the module path (`github.com/owner/name`) names the repo | ✅ | from GitHub releases | ✅ (the repo exists) |
| Java (Maven), .NET (NuGet) | **not yet** | ❌ give the repository instead | ❌ | ❌ |

Vulnerability databases (OSV, GitHub advisories) cover all of these ecosystems, Maven and NuGet included. A package the registry could not confirm can't be rated green, because a misspelled name also finds "no advisories".

## External APIs

All calls are read-only (GET, plus one POST to the OSV query endpoint) and go through one function in `oss_agent/http.py`, which refuses every other host.

| Host | Used for | Key |
|---|---|---|
| api.github.com | repository facts, commits, licence, files, code search, releases, GitHub security advisories | `GITHUB_TOKEN`, optional |
| raw.githubusercontent.com | file contents at a pinned commit | — |
| api.osv.dev | vulnerabilities and malicious releases (OSV) | — |
| services.nvd.nist.gov | CVEs by CPE (NVD) | `NVD_API_KEY`, optional |
| endoflife.date | end-of-life dates of runtimes and products | — |
| registry.npmjs.org | npm packages | — |
| repo.packagist.org | PHP packages (Packagist) | — |
| pypi.org | Python packages | — |
| crates.io | Rust crates | — |
| rubygems.org | Ruby gems | — |

Every endpoint, the calls per tool and a real sample response are in [docs/APIS.md](docs/APIS.md).

## Repository map

| Path | Contents |
|---|---|
| `oss_agent/` | the agent ([ARCHITECTURE.md](ARCHITECTURE.md) explains each file) |
| `oss_agent/web/index.html` | the chat page |
| `tests/` | tests, eval cases, HTTP fixtures, robustness eval |
| `docs/` | spec, milestone reports, audits, eval plan and results, slides |

## Further reading

- [ARCHITECTURE.md](ARCHITECTURE.md): how it works and why it was built that way
- [docs/SPEC.md](docs/SPEC.md): the original specification
- [docs/M9-agentic-redesign-report.md](docs/M9-agentic-redesign-report.md): the move to an agentic design
- [docs/AUDIT-evidence-and-leakage.md](docs/AUDIT-evidence-and-leakage.md): evidence and overfitting audit
