# External APIs

This is every external call the agent makes. All of them go through one function, `http.get` / `http.post_json` in [oss_agent/http.py](../oss_agent/http.py), which enforces the following:

- **Allowed hosts only:** api.github.com, raw.githubusercontent.com, api.osv.dev, services.nvd.nist.gov, endoflife.date, and the package registries registry.npmjs.org, repo.packagist.org, pypi.org, crates.io, rubygems.org. Any other host is refused.
- **GET only**, except POST to the one OSV query endpoint.
- **Limits:** 15 s timeout, one retry for transient errors, 2 MB response cap.
- **Disk cache:** 24 h, or 5 minutes for "latest commit" lookups. The cache is also the offline test fixture store. Auth headers are never part of the cache.
- **Auth:** `GITHUB_TOKEN` is sent only to api.github.com and `NVD_API_KEY` only to NVD. Both are optional.

A real recorded response for each endpoint is in [api-samples/](api-samples/). Long lists and strings are trimmed for reading.

## Endpoints

| # | Method and URL | Called by | Used for | Sample |
|---|---|---|---|---|
| 1 | `GET api.github.com/repos/{owner}/{repo}` | `get_repo_info` | description, default branch, archived, stars, open issues, last push, licence id | [github-repo.json](api-samples/github-repo.json) |
| 2 | `GET api.github.com/repos/{owner}/{repo}/commits/{branch \| HEAD \| tag}` | `get_repo_info`, `read_file`, `scan_skill` | pin the exact commit, last commit date, resolve a release tag to a commit | [github-commit.json](api-samples/github-commit.json) |
| 3 | `GET api.github.com/repos/{owner}/{repo}/license` | `get_repo_info` | licence detected by GitHub (SPDX id) | [github-license.json](api-samples/github-license.json) |
| 4 | `GET api.github.com/repos/{owner}/{repo}/contents[/{folder}]?ref={sha}` | `get_repo_info` (root), `scan_skill` (skill folder and sub-folders) | licence files in the root; files next to a SKILL.md | [github-contents.json](api-samples/github-contents.json) |
| 5 | `GET api.github.com/search/code?q=…+repo:{owner}/{repo}` | `get_repo_info` (`filename:SKILL.md`; `filename:LICENSE` only when the root has none), `search_code` | find skills and sub-folder licences; search the code (for example, telemetry). Latest code only. | [github-search-code.json](api-samples/github-search-code.json) |
| 6 | `GET api.github.com/repos/{owner}/{repo}/releases?per_page=100` | `find_version` (repository source) | release tags with dates (latest 100) | [github-releases.json](api-samples/github-releases.json) |
| 7 | `GET api.github.com/advisories?ecosystem=…&affects={pkg}@{ver}&type=malware\|reviewed&per_page=5` | `check_vulnerabilities` | GitHub advisories and malware entries: **2 calls per version** | [github-advisories.json](api-samples/github-advisories.json) |
| 8 | `GET raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}` | `read_file`, `scan_skill`, `get_repo_info` (SECURITY.md) | file text at a pinned commit | [raw-file.json](api-samples/raw-file.json) |
| 9 | `POST api.osv.dev/v1/query` with body `{"package": {"name", "ecosystem"}, "version"}` | `check_vulnerabilities` | OSV vulnerabilities and `MAL-*` malware entries: **1 call per version** | [osv-query.json](api-samples/osv-query.json) |
| 10 | `GET services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:{vendor}:{product}` | `check_vulnerabilities` | CVEs by CPE: one call for the total, then the newest 100 | [nvd-cves.json](api-samples/nvd-cves.json) |
| 11 | `GET registry.npmjs.org/{package}/{version \| latest}` | `get_repo_info` (package given) | package → source repository, from the registry's own metadata | [npm-version.json](api-samples/npm-version.json) |
| 12 | `GET registry.npmjs.org/{package}` | `find_version` (npm source) | every version with its publish date | [npm-package.json](api-samples/npm-package.json) |
| 13 | `GET endoflife.date/api/{product}.json` | `check_vulnerabilities`, `find_version` (product source) | release lines, end-of-life dates, latest per line | [endoflife.json](api-samples/endoflife.json) |
| 14 | `GET registry.npmjs.org/{package}/latest` | `check_vulnerabilities` (npm) | the package exists | same shape as row 11 |
| 15 | `GET repo.packagist.org/p2/{vendor}/{package}.json` | `get_repo_info`, `find_version`, `check_vulnerabilities` (composer) | source repo, every version with its date, exists | — |
| 16 | `GET pypi.org/pypi/{name}/json` | same (pypi) | GitHub link from `project_urls`, versions with upload dates (yanked left out), exists | — |
| 17 | `GET crates.io/api/v1/crates/{name}` | same (rust) | `repository`, versions with dates (yanked left out), exists | — |
| 18 | `GET rubygems.org/api/v1/gems/{name}.json` and `/api/v1/versions/{name}.json` | same (rubygems) | `source_code_uri`, versions with dates (pre-releases left out), exists | — |

Go modules need no registry call: `github.com/owner/name` names the repository, and `check_vulnerabilities` confirms it exists with row 1. Maven and NuGet have no registry lookup yet.

**How the names are chosen.** OSV, GitHub advisories, the registries and the GitHub repo use the name exactly as the user wrote it; a misspelled name is asked about, never corrected, and a name that doesn't exist fails with a 404. The NVD CPE (row 10) and the endoflife.date id (row 13) are database ids the model picks from its own knowledge. They aren't verified, so 0 CVEs or a 404 is reported as "no match" (the id may be wrong) and never counts as a clean answer.

The OSV sample shows the response only. The cache doesn't store the POST body; the body shape is given in row 9.

## Calls per tool

| Tool | Calls (typical) |
|---|---|
| `get_repo_info` | registry lookup (if a package was given: npm 11, Packagist 15, PyPI 16, crates.io 17, RubyGems 18) → repo (1) → latest commit (2) → licence (3) → root contents (4) → `filename:LICENSE` search, only if the root has no licence file (5) → SECURITY.md: the commit of `{owner}/.github` (2), then up to 4 raw reads (8) → `filename:SKILL.md` search (5). **About 7–12 calls.** |
| `check_vulnerabilities` | once: the package exists in its registry (14–18, or 1 for Go). Then per version: OSV (9) + 2 × GitHub advisories (7). Once per call: NVD × 2 (10), endoflife (13). **For 10 versions: about 33 calls.** If a malicious release is found, the patch release before it is checked too (3 more). |
| `find_version` | one of: a registry (12, 15–18), GitHub releases (6) or endoflife (13). **1 call** (2 for RubyGems). |
| `read_file` | the commit: the latest one, or for a tag, trying `ref`, then without and with a leading "v" (2); never falls back to the latest code. Then the raw file (8). **2–4 calls.** |
| `search_code` | code search (5). **1 call.** |
| `scan_skill` | latest commit (2) → folder listing and sub-folders (4) → up to 10 raw files (8). **Up to about 15 calls.** |
| `lookup_register` | none: it reads the local `register.jsonl` |

## Where real responses are stored

| Location | What |
|---|---|
| `tests/fixtures/http_cache/` | every response recorded during development (also used by the offline tests) |
| `tests/robustness/snapshot/` | the frozen snapshot replayed by the robustness eval |
| `docs/api-samples/` | one readable, trimmed example per endpoint (this page) |

In the cache, each file is named by a hash of the URL and holds `{"url", "fetched_at", "data"}`, or `{"url", "fetched_at", "error"}` for a recorded failure such as a 404.
