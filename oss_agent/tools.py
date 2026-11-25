"""Data tools the LLM can call. All are read-only and NEVER raise:
success -> {"ok": True, ...}, failure -> {"ok": False, "error": "<short reason>"}.
"""
import base64
import re
from urllib.parse import quote

from langchain_core.tools import StructuredTool

from oss_agent import http, registries, rules
from oss_agent.rules import EVIDENCE_LEVELS, LEGAL_TAGS, SKILL_CATEGORIES
from oss_agent.skills import scan_skill
from oss_agent.versions import find_version
from oss_agent.vulns import NPM_RE, check_vulnerabilities

GH = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SECURITY_PATHS = ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]


def _first_lines(text: str, n: int, max_chars: int) -> str:
    lines = text.splitlines()
    out = "\n".join(lines[:n])[:max_chars]
    if len(lines) > n or len(out) == max_chars:
        out += f"\n[... truncated, file has {len(lines)} lines]"
    return out


def _find_security_policy(repo: str, sha: str) -> dict | None:
    """SECURITY.md in the repo, else the org-wide default in {owner}/.github (GitHub's own fallback)."""
    candidates = [(repo, sha, p) for p in SECURITY_PATHS]
    org_repo = repo.split("/")[0] + "/.github"
    org_head = http.get(f"{GH}/repos/{org_repo}/commits/HEAD")
    if org_head["ok"]:
        candidates.append((org_repo, org_head["data"]["sha"], "SECURITY.md"))
    for r, ref, path in candidates:
        sec = http.get(f"{RAW}/{r}/{ref}/{path}", as_json=False)
        if sec["ok"]:
            return {
                "path": f"{r}/{path}",
                "url": f"https://github.com/{r}/blob/{ref}/{path}",
                "first_lines": _first_lines(sec["data"], 40, 1000),
            }
    return None


GITHUB_IN_URL = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


def resolve_npm_repo(package: str, version: str | None = None) -> dict:
    """Package -> source repo from the npm registry's own metadata (repository.url + .directory).
    Uses the ASKED version's metadata: a package can move repos ("latest" may point elsewhere).
    Never guessed from the npm scope."""
    if not NPM_RE.match(package or ""):
        return {"ok": False, "error": f"'{package}' is not a valid npm package name"}
    base = f"https://registry.npmjs.org/{quote(package, safe='@')}"  # @scope/name -> @scope%2Fname
    tag, note = version or "latest", None if version else "no version given: repo taken from the 'latest' release; older versions may live elsewhere"
    res = http.get(f"{base}/{quote(tag)}")
    if not res["ok"] and version and "404" in res["error"]:  # npm removes malicious versions, so fall back
        tag, res = "latest", http.get(f"{base}/latest")
        note = f"version {version} is no longer on npm (removed; this often happens to malicious releases); repo taken from 'latest'"
    if not res["ok"]:
        return {"ok": False, "error": f"npm registry has no {package}@{tag}: {res['error']}"}
    repo_field = res["data"].get("repository") or {}
    if isinstance(repo_field, str):  # "github:owner/repo", "owner/repo" or a URL
        repo_field = {"url": repo_field.removeprefix("github:")}
    raw = repo_field.get("url", "")
    m = GITHUB_IN_URL.search(raw)
    if m:  # git+https://github.com/o/r.git, git://…, git+ssh://git@github.com/o/r.git, https://github.com/o/r
        repo = f"{m.group(1)}/{m.group(2)}"
    elif REPO_RE.match(raw):  # npm shorthand "owner/repo"
        repo = raw
    else:
        return {"ok": False, "error": f"npm metadata of {package}@{tag} names no GitHub repository ({raw or 'empty'})"}
    return {"ok": True, "repo": repo, "directory": repo_field.get("directory"), "npm_version": res["data"].get("version"),
            "npm_licence": res["data"].get("license"), "registry_url": f"https://www.npmjs.com/package/{package}/v/{res['data'].get('version')}",
            **({"note": note} if note else {})}


def get_repo_info(repo: str | None = None, package: str | None = None, ecosystem: str | None = None,
                  version: str | None = None) -> dict:
    """GitHub facts for a repo, or for a package (its repo is looked up in the package registry first)."""
    resolved = None
    if package and not repo:
        eco = registries.key(ecosystem or "npm")
        if eco == "npm":
            resolved = resolve_npm_repo(package, version)
        elif eco == "go":  # a Go module path names its repository
            m = registries.GO_GITHUB.match(package)
            resolved = ({"ok": True, "repo": f"{m.group(1)}/{m.group(2)}", "registry": "Go module path"} if m else
                        {"ok": False, "error": "the module is not hosted on github.com; give the repository"})
        elif eco in registries.LOOKUPS:
            found = registries.lookup(package, eco)
            resolved = found if not found["ok"] else (
                {"ok": True, "repo": found["repo"], "registry": found["registry"], "registry_url": found["url"]} if found["repo"] else
                {"ok": False, "error": f"{found['registry']} lists no GitHub source repository ({found['source'] or 'none given'})"})
        else:
            return {"ok": False, "error": f"repo lookup for {ecosystem} packages is not supported yet"}
        if not resolved["ok"]:
            return {"ok": False, "error": f"could not find the source repo of {package}: {resolved['error']}"}
        repo = resolved["repo"]
    result = _repo_info(repo)
    if result["ok"] and resolved:
        result["resolved_from"] = {"package": package, **{k: v for k, v in resolved.items() if k != "ok"}}
        if resolved.get("directory"):  # monorepo: the package is one folder of a bigger repo
            result["package_directory"] = resolved["directory"]
            result["package_url"] = f"https://github.com/{repo}/tree/{result['head_commit']}/{resolved['directory']}"
    return result


def _repo_info(repo: str) -> dict:
    if not REPO_RE.match(repo or ""):
        return {"ok": False, "error": "repo must look like owner/name"}
    meta = http.get(f"{GH}/repos/{repo}")
    if not meta["ok"]:
        hint = " - check the spelling" if "404" in meta["error"] else ""
        return {"ok": False, "error": f"repo {repo}: {meta['error']}{hint}"}
    m = meta["data"]
    branch = m["default_branch"]
    head = http.get(f"{GH}/repos/{repo}/commits/{branch}")
    if not head["ok"]:
        return {"ok": False, "error": f"could not read HEAD commit: {head['error']}"}
    sha = head["data"]["sha"]
    result = {
        "ok": True,
        "repo": m["full_name"],
        "description": m.get("description"),
        "archived": m["archived"],
        "default_branch": branch,
        "head_commit": sha,
        "head_commit_date": head["data"]["commit"]["committer"]["date"],
        "last_push": m.get("pushed_at"),
        "stars": m["stargazers_count"],
        "open_issues": m["open_issues_count"],
        "licence_spdx": (m.get("license") or {}).get("spdx_id"),
    }

    # Licence file text: the SPDX id alone can hide custom terms (e.g. n8n).
    lic = http.get(f"{GH}/repos/{repo}/license")
    if lic["ok"]:
        path = lic["data"]["path"]
        text = base64.b64decode(lic["data"]["content"]).decode("utf-8", "replace")
        result["licence_file"] = {
            "path": path,
            "url": f"https://github.com/{repo}/blob/{sha}/{path}",
            "first_lines": _first_lines(text, 60, 2000),
        }
    else:
        result["licence_file"] = None
        if "404" not in lic["error"]:  # an outage or rate limit is not "no licence"
            result["licence_error"] = lic["error"]
    # Licence-like files in the root: GitHub's detection misses some (LICENSE.md) and shows one of several (dual licences).
    root = http.get(f"{GH}/repos/{repo}/contents", params={"ref": sha})
    if root["ok"] and isinstance(root["data"], list):
        result["root_licence_files"] = [f["name"] for f in root["data"]
                                        if f.get("type") == "file" and rules.LICENCE_FILE_RE.match(f["name"])]
        if len(result["root_licence_files"]) > 1:
            result["licence_note"] = (f"Several licence files ({', '.join(result['root_licence_files'])}): possibly "
                                      "dual- or multi-licensed; read them before deciding.")
        elif result["root_licence_files"] and not lic["ok"]:
            result["licence_note"] = (f"GitHub did not detect a licence, but {result['root_licence_files'][0]} exists: "
                                      "read it before deciding.")
    else:
        result["root_licence_files"] = None  # unknown: never read as "no licence file"
    if result["root_licence_files"] == [] and not lic["ok"]:  # monorepos and skill collections license per folder
        sub = http.get(f"{GH}/search/code", params={"q": f"filename:LICENSE repo:{repo}", "per_page": 50})
        result["sub_licence_files"] = sorted(i["path"] for i in sub["data"]["items"] if "/" in i["path"]
                                             and rules.LICENCE_FILE_RE.match(i["path"].rsplit("/", 1)[-1])) if sub["ok"] else None
        if result["sub_licence_files"]:
            result["licence_note"] = ("No licence file in the root, but in sub-folders: "
                                      f"{', '.join(result['sub_licence_files'][:5])}. Only one in the used component's "
                                      "folder (or a parent folder) applies to it.")

    result["security_policy"] = _find_security_policy(repo, sha)

    # Code search instead of the git tree: trees of big repos exceed the 2 MB cap.
    skills = http.get(f"{GH}/search/code", params={"q": f"filename:SKILL.md repo:{repo}", "per_page": 50})
    result["skill_files"] = [i["path"] for i in skills["data"]["items"]] if skills["ok"] else "search unavailable"
    return result


MAX_LINES = 200
MAX_FILE_CHARS = 3500  # stays under the 4,000-char tool-result cap, so no line is cut silently


def _head_sha(repo: str) -> dict:
    head = http.get(f"{GH}/repos/{repo}/commits/HEAD")
    return {"ok": True, "sha": head["data"]["sha"]} if head["ok"] else {"ok": False, "error": f"repo {repo}: {head['error']}"}


REF_RE = re.compile(r"^[\w.+/-]{1,100}$")


def _ref_sha(repo: str, ref: str) -> dict:
    """A version tag (or branch/commit) -> its commit. Tags are written with or without "v", so both are tried.
    Never falls back to HEAD: reading the wrong version's code would be evidence about the wrong version."""
    if not REF_RE.match(ref) or ".." in ref:
        return {"ok": False, "error": f"'{ref}' is not a valid tag or commit"}
    tried = list(dict.fromkeys([ref, ref.removeprefix("v"), "v" + ref.removeprefix("v")]))
    for candidate in tried:
        res = http.get(f"{GH}/repos/{repo}/commits/{quote(candidate, safe='')}")
        if res["ok"]:
            return {"ok": True, "sha": res["data"]["sha"], "ref": candidate}
    return {"ok": False, "error": f"{repo} has no tag or commit {' / '.join(tried)}; the code of that version was not read"}


def read_file(repo: str, path: str, start_line: int = 1, end_line: int = 120, ref: str | None = None) -> dict:
    """Lines of one file at HEAD, or at a version's tag (ref), numbered, with a pinned link to exactly those lines."""
    if not REPO_RE.match(repo or ""):
        return {"ok": False, "error": "repo must look like owner/name"}
    if not path or path.startswith("/") or ".." in path.split("/"):
        return {"ok": False, "error": "path must be relative to the repo root, without '..'"}
    head = _ref_sha(repo, str(ref).strip()) if ref else _head_sha(repo)
    if not head["ok"]:
        return head
    sha = head["sha"]
    url_path = quote(path, safe="/@")  # encode spaces etc., keep '@' readable
    raw = http.get(f"{RAW}/{repo}/{sha}/{url_path}", as_json=False)
    if not raw["ok"]:
        return {"ok": False, "error": f"{path}: {raw['error']}"}
    lines = raw["data"].splitlines()
    start = max(1, int(start_line))
    end = min(len(lines), int(end_line), start + MAX_LINES - 1)
    numbered, size = [], 0
    for n in range(start, end + 1):  # stop early if the text gets too long for the LLM
        row = f"{n:>5}| {lines[n - 1]}"
        if size + len(row) > MAX_FILE_CHARS and numbered:
            end = n - 1
            break
        numbered.append(row)
        size += len(row) + 1
    result = {
        "ok": True, "path": path, "commit": sha, "ref": head.get("ref", "HEAD (latest code)"),
        "start_line": start, "end_line": end,
        "total_lines": len(lines), "content": "\n".join(numbered),
        "url": f"https://github.com/{repo}/blob/{sha}/{url_path}#L{start}-L{end}",
    }
    if end < len(lines):
        result["note"] = f"truncated: call again with start_line={end + 1} to read more"
    return result


def search_code(repo: str, query: str) -> dict:
    """GitHub code search inside one repo: up to 10 files with matching line fragments."""
    if not REPO_RE.match(repo or ""):
        return {"ok": False, "error": "repo must look like owner/name"}
    if re.search(r"\b(repo|org|user):", query or ""):
        return {"ok": False, "error": "query must not contain repo:/org:/user: qualifiers"}
    res = http.get(f"{GH}/search/code", params={"q": f"{query} repo:{repo}", "per_page": 10},
                   headers={"Accept": "application/vnd.github.text-match+json"})  # asks for fragments
    if not res["ok"]:
        return {"ok": False, "error": f"code search: {res['error']}"}
    hits = [{"path": item["path"], "url": item["html_url"],
             "fragments": [m["fragment"][:300] for m in item.get("text_matches", [])][:3]}
            for item in res["data"]["items"][:10]]
    return {"ok": True, "query": query, "total_count": res["data"]["total_count"], "hits": hits,
            "note": "searches the LATEST code only, and fragments have no line numbers: read the file with read_file "
                    "(with ref for a specific version) to quote exact lines"}


AREAS = ["licence", "security", "maintenance", "privacy", "skills"]
STATUSES = ["green", "yellow", "red", "not_checked"]

TOOL_SCHEMAS = [
    {
        "name": "get_repo_info",
        "description": (
            "NEEDS: a repo (owner/name) OR a package name (+ ecosystem, + version). For a package, "
            "code resolves package -> repo from the registry's own metadata (npm, Packagist, PyPI, crates.io, "
            "RubyGems; a Go module path names its repo); never derived from the name or scope. "
            "RETURNS: description, archived flag, HEAD commit SHA and date, stars, open issues, licence SPDX "
            "id, first 60 lines of the licence file, licence-like files in the root (root_licence_files, licence_note when several or undetected), first 40 lines of SECURITY.md (repo or org-wide), "
            "SKILL.md paths, and for monorepos package_directory. "
            "GOOD FOR: licence, maintenance, security policy, and confirming where a package's source lives."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "owner/name: the repository the user named, one a tool returned, or a named product's official repository (confirm it with the user)"},
                "package": {"type": "string", "description": "exact package name as the user wrote it, e.g. '@scope/name'"},
                "ecosystem": {"type": "string", "description": "npm, composer, pypi, rust, rubygems or go (maven, nuget: not yet)"},
                "version": {"type": "string", "description": "the asked version: the repo can differ between versions"},
            },
            "required": [],
        },
    },
    {
        "name": "ask_user",
        "description": (
            "NEEDS: one short question for the decision maker. Pauses until they answer. Max 2 per run "
            "(enforced by code). "
            "RETURNS: their answer, or UNKNOWN if unclear. "
            "GOOD FOR: facts only the user knows (their version/lockfile, internal use vs. hosting for "
            "customers, which repo they meant if the one they named does not exist), when the answer would "
            "change a verdict. NOT for facts a tool can look up (repo location, licence)."
        ),
        "input_schema": {"type": "object", "properties": {"question": {"type": "string"}}, "required": ["question"]},
    },
    {
        "name": "find_version",
        "description": (
            "NEEDS: when ('latest', a date 'YYYY-MM-DD', 'N days/weeks/months/years ago', or a version) and ONE of: a package "
            "(+ ecosystem: npm, composer, pypi, rust, rubygems; versions from the registry), a repository (owner/name, uses its GitHub releases; if it publishes several packages, also "
            "give package) or a product name (endoflife.date, 'latest' only). Code computes dates from today. "
            "RETURNS: the exact newest stable version on that date with its release date and a source link, the "
            "latest version, and the releases published since. With a version in when and another in until: every "
            "released version from one to the other (range), from the source, never guessed. "
            "GOOD FOR: a version described instead of given ('the latest', 'installed last spring'); then check the "
            "exact versions with check_vulnerabilities, and use the releases since as evidence of maintenance."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "when": {"type": "string", "description": "'latest', 'YYYY-MM-DD', 'N months ago', or a version (start of a range)"},
                "until": {"type": "string", "description": "last version of a range, e.g. when='1.0.0', until='1.4.2'"},
                "package": {"type": "string", "description": "exact package name as the user wrote it"},
                "ecosystem": {"type": "string", "description": "npm, composer, pypi, rust or rubygems"},
                "repo": {"type": "string", "description": "owner/name"},
                "product": {"type": "string", "description": "endoflife.date product id (lowercase)"},
            },
            "required": ["when"],
        },
    },
    {
        "name": "check_vulnerabilities",
        "description": (
            "NEEDS: only the exact package/product name (+ ecosystem for packages, + versions). NO repo needed. "
            "Use the name EXACTLY as the user wrote it, including any @scope/. "
            "RETURNS, per version: OSV entries (MAL-* = published malware), GitHub advisories incl. malware / "
            "hijacked releases (both need an ecosystem), NVD CVEs (by CPE), end-of-life status, and which "
            "sources answered. Withdrawn / rejected advisories are left out (listed in withdrawn_ignored). "
            "GOOD FOR: security of specific versions, adding, keeping or upgrading a dependency, end-of-life."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "exact package or product name, e.g. '@scope/name' or 'name'"},
                "ecosystem": {"type": "string", "description": "npm, pypi, maven, go, rubygems, nuget, composer, rust (omit for runtimes and products that are not packages)"},
                "versions": {"type": "array", "items": {"type": "string"},
                             "description": "each exact version to check, e.g. ['1.0.0', '1.0.1']. At most the newest 10 "
                                            "are checked; any others come back in not_checked_versions"},
                "cpe_vendor": {"type": "string", "description": "NVD CPE vendor, if it differs from the product name"},
                "cpe_product": {"type": "string", "description": "NVD CPE product, if it differs from the package name. Also used as the endoflife.date product id"},
            },
            "required": ["package"],
        },
    },
    {
        "name": "scan_skill",
        "description": (
            "NEEDS: a repo (owner/name) and the path of a SKILL.md (or its folder). Read-only: files are fetched "
            "as text, never executed. "
            "RETURNS: the skill's declared name/description, how many lines/files were scanned, and SIGNALS: "
            "regex matches with category (instruction_override, exfiltration, secret_access, destructive, "
            "pipe_to_shell, obfuscation, agent_directive), file, exact line, short excerpt, pinned link and an "
            "'inspect' read_file window. Signals are SUSPICIOUS only, never proof. "
            "GOOD FOR: finding where to look in a large skill; then inspect the relevant lines with read_file."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"repo": {"type": "string"},
                           "skill_path": {"type": "string", "description": "e.g. 'path/to/skill/SKILL.md'"}},
            "required": ["repo", "skill_path"],
        },
    },
    {
        "name": "search_code",
        "description": (
            "NEEDS: a repo (owner/name) and search words or identifiers. "
            "RETURNS: up to 10 files with matching fragments (no line numbers), from the LATEST code only (GitHub "
            "searches the default branch). "
            "GOOD FOR: finding where data is collected or sent (telemetry, analytics, tracking, external "
            "endpoints, configuration flags). To quote exact lines, read the file with read_file."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}, "query": {"type": "string", "description": "words or identifiers"}},
            "required": ["repo", "query"],
        },
    },
    {
        "name": "read_file",
        "description": (
            "NEEDS: a repo (owner/name) and a path from the repo root; for a specific version, ref = its tag "
            "(e.g. '1.2.3' or 'v1.2.3', both are tried). Without ref it reads the latest code. "
            "RETURNS: numbered lines at that commit with a pinned link (max 200 lines / ~3,500 characters "
            "per call; a note says where to continue). "
            "GOOD FOR: quoting exact text, e.g. a custom licence (when the SPDX id is NOASSERTION), a "
            "config default found by search_code, or the CONTEXT around a scan_skill signal (use its "
            "'inspect' window, about 30 lines either side of the signal: targeted, not the whole file)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "path": {"type": "string", "description": "path from the repo root"},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer", "default": 120},
                "ref": {"type": "string", "description": "version tag or commit; omit for the latest code"},
            },
            "required": ["repo", "path"],
        },
    },
    {
        "name": "submit_report",
        "description": "Submit the final due-diligence record. Call exactly once, at the end.",
        "input_schema": {
            "type": "object",
            "properties": {
                "report": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "commit": {"type": "string"},
                        "question": {"type": "string"},
                        "kind": {"type": "string", "enum": ["decision", "answer"],
                                 "description": "decision: the user asks whether to adopt, add, install, keep or approve "
                                                "something; answer: the user asks a specific question (what a licence "
                                                "allows, what data it sends, what a file does)"},
                        "assumptions": {"type": "array", "items": {"type": "string"}},
                        "privacy_check_required": {"type": "boolean",
                                                   "description": "true if the user asks about privacy or telemetry, or the "
                                                                  "stated use involves personal, customer or user data. Then "
                                                                  "the privacy area needs a result, or not_checked with the "
                                                                  "reason the check could not be completed"},
                        "areas": {
                            "type": "object",
                            "description": "One entry per area: " + ", ".join(AREAS),
                            "properties": {
                                a: {
                                    "type": "object",
                                    "properties": {
                                        "status": {"type": "string", "enum": STATUSES},
                                        "summary": {"type": "string", "description": "one short sentence, max 15 words"},
                                    },
                                    "required": ["status", "summary"],
                                }
                                for a in AREAS
                            },
                        },
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "area": {"type": "string", "enum": AREAS},
                                    "claim": {"type": "string"},
                                    "evidence_quote": {"type": "string", "description": "short verbatim quote from a tool result"},
                                    "url": {"type": "string"},
                                    "source_tool": {"type": "string"},
                                    "tags": {"type": "array", "items": {"type": "string", "enum": LEGAL_TAGS},
                                             "description": "facts this finding shows; code maps them to legal articles"},
                                    "category": {"type": "string", "enum": SKILL_CATEGORIES,
                                                 "description": "for skill/security findings: what kind of behaviour"},
                                    "evidence_level": {"type": "string", "enum": EVIDENCE_LEVELS,
                                                       "description": "suspicious | confirmed_manipulation | confirmed_dangerous; "
                                                                      "confirmed needs an inspected quote that itself shows it"},
                                    "why": {"type": "string", "description": "one sentence: why this evidence matters"},
                                    "uncertainty": {"type": "string", "description": "what is still unknown, if anything"},
                                },
                                "required": ["area", "claim", "evidence_quote", "url", "source_tool"],
                            },
                        },
                        "conditions": {"type": "array", "maxItems": 4,
                                       "description": "concrete next actions, each with the finding it rests on",
                                       "items": {"type": "object", "properties": {
                                           "action": {"type": "string", "description": "one concrete action: which version "
                                                      "to pin or upgrade to, what to configure or verify"},
                                           "finding": {"type": "integer", "description": "number of the finding (1 = first "
                                                       "in findings) this action rests on; an action with no finding is "
                                                       "removed"}},
                                           "required": ["action", "finding"]}},
                        "open_questions": {"type": "array", "items": {"type": "string"},
                                           "description": "only facts the USER knows that could change the decision"},
                        "recommendation": {"type": "string", "description": "1-3 plain sentences that answer the question"},
                        "confidence": {"type": "object", "description": "how sure the answer is, given the evidence",
                                       "properties": {"level": {"type": "string", "enum": ["high", "medium", "low"]},
                                                      "reason": {"type": "string", "description": "one sentence: what the "
                                                                 "confidence rests on, or what is missing"}},
                                       "required": ["level", "reason"]},
                    },
                    "required": ["repo", "question", "privacy_check_required", "areas", "findings", "recommendation"],
                }
            },
            "required": ["report"],
        },
    },
]

# Name -> plain function for the data tools. submit_report and ask_user are handled by graph nodes.
DATA_TOOLS = {"get_repo_info": get_repo_info, "search_code": search_code, "read_file": read_file,
              "check_vulnerabilities": check_vulnerabilities, "scan_skill": scan_skill, "find_version": find_version}


def _handled_by_graph(**kwargs) -> dict:
    return {"ok": True}  # never run: submit_report -> tools node, ask_user -> ask node


# Thin LangChain wrappers: they only carry name, description and JSON schema to bind_tools().
# The graph calls the plain functions above, so tools stay testable without LangChain.
LC_TOOLS = [
    StructuredTool.from_function(
        func=DATA_TOOLS.get(s["name"], _handled_by_graph),
        name=s["name"], description=s["description"], args_schema=s["input_schema"],
    )
    for s in TOOL_SCHEMAS
]
