"""Data tools the LLM can call. All are read-only and NEVER raise:
success -> {"ok": True, ...}, failure -> {"ok": False, "error": "<short reason>"}.
"""
import base64
import re
from urllib.parse import quote

from langchain_core.tools import StructuredTool

from oss_agent import http

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


def get_repo_info(repo: str) -> dict:
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
        result["licence_file"] = None  # "no licence" means "no permission to use"

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


def read_file(repo: str, path: str, start_line: int = 1, end_line: int = 120) -> dict:
    """Lines of one file at the HEAD commit, numbered, with a pinned link to exactly those lines."""
    if not REPO_RE.match(repo or ""):
        return {"ok": False, "error": "repo must look like owner/name"}
    if not path or path.startswith("/") or ".." in path.split("/"):
        return {"ok": False, "error": "path must be relative to the repo root, without '..'"}
    head = _head_sha(repo)
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
        "ok": True, "path": path, "commit": sha, "start_line": start, "end_line": end,
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
            "note": "fragments have no line numbers: use read_file to quote exact lines"}


AREAS = ["licence", "security", "maintenance", "privacy", "skills"]
STATUSES = ["green", "yellow", "red", "not_checked"]

TOOL_SCHEMAS = [
    {
        "name": "get_repo_info",
        "description": (
            "GitHub facts about a repository: description, archived flag, HEAD commit SHA and date, "
            "stars, open issues, licence SPDX id, first 60 lines of the licence file, first 40 lines "
            "of SECURITY.md, and paths of SKILL.md files. Call this first for any repo question."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"repo": {"type": "string", "description": "owner/name, e.g. pallets/flask"}},
            "required": ["repo"],
        },
    },
    {
        "name": "search_code",
        "description": (
            "Search code inside one GitHub repo (max 10 files, with matching fragments). Use it to find "
            "telemetry, analytics or external endpoints, e.g. 'telemetry', 'diagnostics', 'posthog', "
            "'N8N_DIAGNOSTICS_ENABLED'. Fragments have no line numbers: use read_file to quote exact lines."
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
            "Read lines of a file at the HEAD commit, numbered, with a pinned link (max 200 lines, "
            "~3,500 characters per call). Use it to read a full licence, or a config file found by "
            "search_code, before quoting it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "path": {"type": "string", "description": "path from the repo root, e.g. LICENSE.md"},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer", "default": 120},
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
                        "assumptions": {"type": "array", "items": {"type": "string"}},
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
                                },
                                "required": ["area", "claim", "evidence_quote", "url", "source_tool"],
                            },
                        },
                        "conditions": {"type": "array", "items": {"type": "string"},
                                       "description": "what must hold for safe use, e.g. 'internal use only'"},
                        "open_questions": {"type": "array", "items": {"type": "string"}},
                        "recommendation": {"type": "string", "description": "1-2 plain-language sentences"},
                    },
                    "required": ["repo", "question", "areas", "findings", "recommendation"],
                }
            },
            "required": ["report"],
        },
    },
]

# Name -> plain function for the data tools. submit_report is handled by the tools node itself.
DATA_TOOLS = {"get_repo_info": get_repo_info, "search_code": search_code, "read_file": read_file}


def _submit_report(report: dict) -> dict:
    return {"ok": True}  # never run: the graph's tools node validates and stores the report


# Thin LangChain wrappers: they only carry name, description and JSON schema to bind_tools().
# The graph calls the plain functions above, so tools stay testable without LangChain.
LC_TOOLS = [
    StructuredTool.from_function(
        func={**DATA_TOOLS, "submit_report": _submit_report}[s["name"]],
        name=s["name"], description=s["description"], args_schema=s["input_schema"],
    )
    for s in TOOL_SCHEMAS
]
