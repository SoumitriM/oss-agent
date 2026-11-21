# M3 report: check_vulnerabilities + GDPR/CRA mapping

**Status:** done (awaiting OK) · **Date:** 2026-11-21 · **Package code:** 1,267 lines · **Tests:** 24 passed

## What was built
| File | Change |
|---|---|
| `vulns.py` | **new**: `check_vulnerabilities(product, vendor?, ecosystem?, version?)` combining NVD, GitHub advisories (incl. malware) and endoflife.date |
| `rules.py` | `vulnerability_rule()` (EOL → red, malware for the version → red, malware without a version → yellow); `LEGAL_MAP` + `legal_refs()` (GDPR 25/28/35/44, CRA 13(5)) |
| `report.py` | `post_process()` applies the vulnerability rules, but only to make an area worse (`_raise_status`), and adds `report["legal"]`; articles shown on area lines; `(no commit checked)` when no repo was looked up; the evidence line is the LLM's most important **verified** finding |
| `evidence.py` | link rule 2 generalised: a quote inside any item with its own `url` (CVE, advisory, endoflife, search hit) links there |
| `tools.py` | tool schema; `tags` enum on findings |
| `prompts.py` | when to call `check_vulnerabilities`; tag facts, never cite articles |
| `tests/test_rules.py` | **new**: 5 tests (EOL, malware ×2, never-better rule, legal refs only for verified findings). `test_evidence.py` +1 (CVE link). |

### Design decisions
- **NVD matching by CPE, not keyword:** "php" as a keyword matches 13,256 CVEs (mostly PHP apps); CPE `php:php` matches 760. NVD sorts oldest first, so we count, then fetch the **newest 100** (~0.7 MB). The version range check is done locally with `packaging`, so it's explainable: `versionStartIncluding ≤ v < versionEndExcluding`.
- **Most urgent first:** the result order is endoflife → GitHub (malware first) → NVD, so the 4,000-character cap can never cut the malware entry.
- **Legal mapping:** the LLM only tags *facts* on findings. Code maps tags to articles, and only for **verified** findings, so an invented quote can't trigger a legal reference.

## Demos (live runs, `claude_cli` backend)
**"Our portal runs PHP 8.1 (php/php-src). Do we need to act?"** → 1 tool call, 14 s
```
php/php-src (no commit checked) · checked 2026-11-21
Overall: 🔴 Do not adopt without review
SECURITY     🔴 PHP 8.1 is end-of-life; 44 known CVEs match, including critical ones.  (CRA Art. 13(5))
              → https://nvd.nist.gov/vuln/detail/CVE-2026-109618 ✔
MAINTENANCE  🔴 8.1 stopped receiving security fixes on 2025-12-31.
              → https://endoflife.date/php ✔
Recommendation: Yes, act. PHP 8.1 no longer gets security fixes ... Upgrade to a supported version soon ...
```

**"Can we add axios/axios to our new web app?"** → 2 tool calls, 23 s
```
SECURITY     🟡 Two malware releases and many past flaws; use a patched, verified version.  (CRA Art. 13(5))
              "Malware in axios"
              → https://github.com/advisories/GHSA-fw8c-xr5c-95f9 ✔
Conditions: Pin axios to an exact version at or above 1.20.0; never 1.14.1 or 0.30.4. · ...
```

**n8n regression** → 6 tool calls, 5/5 quotes verified, plus advisories:
```
SECURITY     🟡 Several medium-severity flaws, fixed in newer versions. ...  (CRA Art. 13(5))
              → https://github.com/advisories/GHSA-cqr2-h44g-v75v ✔
PRIVACY      🟡 Telemetry is on by default and must be switched off.  (GDPR Art. 25)
```

## Notes and trade-offs
- **Only the newest 100 product CVEs are version-checked.** Older CVEs affecting an old version can be missed. For EOL versions, the EOL rule covers this.
- **`vendor`** is a new optional argument (not in v2): CPE vendors differ from product names (e.g. `nodejs:node.js`). The LLM fills it in.
- **The EUR-Lex links point to the regulation**, not an article anchor; anchors aren't stable.
- **The PHP run didn't call `get_repo_info`,** so there's no commit. That's correct for a version question.
- **Line budget:** 1,267 lines, well above ~900. The largest files are `tools.py` (~330, half of it schemas), `llm.py` (176) and `graph.py` (172). Dropping the `claude_cli` backend from the submission would save about 120 lines.
