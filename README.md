# OSS Due-Diligence Agent

Ask a question in plain words about an open-source component, such as *"Can we add dayjs to our new web app?"*. The agent checks the component's **licence, security, maintenance and privacy**. The answer gives a decision, a confidence level and evidence for every finding.

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

Questions outside this scope get **one fixed reply written by code**, never an answer from the model's memory. That covers general questions ("What does copyleft mean?"), out-of-scope requests ("Build me an app…") and attempts to change the agent's role.

## Quick start

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env          # then fill it in; never commit .env
```

`.env` settings:

| Variable | Needed? | Purpose |
|---|---|---|
| `LLM_PROVIDER` | yes | `claude_cli` (uses your Claude Code login), `anthropic` (API key) or `openrouter` (OpenRouter API key) |
| `LLM_MODEL` | for `tests/eval.py` only | the CLI and the web chat ignore it and pick Sonnet, or Haiku with `--haiku`. With `openrouter`, an OpenRouter id such as `anthropic/claude-haiku-5.5` |
| `ANTHROPIC_API_KEY` | only with `anthropic` | |
| `OPENROUTER_API_KEY` | only with `openrouter` | `LLM_MODEL` must then be an OpenRouter id (with a `/`) |
| `PROMPT` | optional | `haiku` forces the Haiku prompt for any model, e.g. to test Sonnet with it in the eval |
| `GITHUB_TOKEN` | recommended | read-only, no scopes; raises the GitHub rate limit |
| `NVD_API_KEY` | optional | raises the NVD rate limit |

## Run it

**We recommend Sonnet 5.5**, the default. The prompt was developed and tuned on it, and the robustness eval was run on it.

**Haiku 5.5 works well too** if you want a smaller, cheaper model (about 20× less per token). Add `--haiku`: it switches to Haiku and to `prompts_haiku.py`, the same prompt with stricter rules on when to stop gathering, because Haiku tends to check more than a question needs. In the 10-case eval it reached the expected verdict in every case (see Tests and evaluation).

```bash
# Web chat on http://127.0.0.1:8000 (localhost only, no login)
.venv/bin/python -m oss_agent.server            # Sonnet 5.5 + prompts.py (recommended)
.venv/bin/python -m oss_agent.server --haiku    # Haiku 5.5 + prompts_haiku.py

# Command line
.venv/bin/python -m oss_agent "Is axios@1.14.1 safe to install in our production backend?" --trace

# Other CLI options
#   --offline         use cached HTTP responses only
#   --json out.json   write the full record (report, trace, tool outputs)
#   --show-graph      print the agent graph as Mermaid
#   --answer TEXT     scripted answer to the agent's question (repeatable)
#   --haiku           Haiku 5.5 and its prompt instead of Sonnet 5.5
```

## Tests and evaluation

Both evaluations run the real model, so they cost API credit. There are no offline unit tests.

```bash
.venv/bin/python tests/eval.py --case php-81-eol --record   # one case, live HTTP
.venv/bin/python tests/eval.py --case php-81-eol --runs 1   # one case, recorded HTTP (tests/fixtures, local only)
.venv/bin/python -m tests.robustness.run                    # robustness eval (resumable)
```

| What | Where |
|---|---|
| **Case eval**: 10 questions with an expected verdict and checks (verdict, area statuses, required and forbidden tools, step and call limits, questions asked, verified quotes, required finding) | `tests/eval.py`, `tests/test_cases.json` |
| **Robustness eval**: 6 cases × (base, paraphrase, typo, German, noise) plus injected faults (tool down, prompt injection), run against a frozen data snapshot | `tests/robustness/` (code, cases and snapshot) |

**Case eval, 25 Nov 2026** (one run per case, online HTTP, through OpenRouter):

| Setup | Passed | Avg tokens per case |
|---|---|---|
| Haiku 5.5 + Haiku prompt | 10 / 10 | 38k |
| Sonnet 5.5 + Sonnet prompt | 9 / 10 | 43k |
| Sonnet 5.5 + Haiku prompt | 9 / 10 | 37k |

All three gave the expected verdict in every case. Sonnet's one failure (`wdio-browserstack-cve`) is the check looking for the CVE id while the answer cited the same advisory by its GHSA id. Flask counts as passed after its call limit was raised from 2 to 3; it was not re-run.

**Robustness eval** (last run before the latest changes): 30 of the 36 planned runs finished and all 30 passed, with 0 hard fails. The other 6 were not run.

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


## Repository map

| Path | Contents |
|---|---|
| `oss_agent/` | the agent ([ARCHITECTURE.md](ARCHITECTURE.md) explains each file) |
| `oss_agent/web/index.html` | the chat page |
| `tests/` | case eval, robustness eval; `tests/fixtures/` (recorded HTTP, also the live cache) is local only |
| `docs/` | local working notes (spec, reports, code walkthroughs, eval results); not in git |

## Further reading

- [ARCHITECTURE.md](ARCHITECTURE.md): how it works and why it was built that way
