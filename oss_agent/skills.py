"""scan_skill: deterministic scan of an AI-agent skill (SKILL.md + files in its folder).

Every match is only a SIGNAL ("suspicious"). The tool never says "malicious": the agent must
inspect the context (read_file around the line) and cite a quote that itself shows the behaviour.
Nothing from the repo is executed; files are only fetched as text.
"""
import posixpath
import re
from urllib.parse import quote

from oss_agent import http

GH, RAW = "https://api.github.com", "https://raw.githubusercontent.com"
TEXT_EXT = (".md", ".txt", ".sh", ".bash", ".py", ".js", ".ts", ".mjs", ".ps1", ".rb", ".json", ".yaml", ".yml", ".toml")
MAX_FILES, MAX_SIGNALS, WINDOW = 10, 10, 30

# category -> regex. Order = priority when signals are cut to MAX_SIGNALS.
PATTERNS = [
    ("instruction_override", r"(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|system|user'?s?|original)\b.{0,20}"
                             r"\b(instructions?|prompts?|rules|task)|do not (tell|inform|show) the user|without (telling|informing) the user"
                             r"|<!--.{0,200}\b(agent|assistant|ai|llm)\b"),
    ("exfiltration", r"(curl|wget|Invoke-WebRequest|requests\.post|fetch\(|nc )\S*.{0,80}(-d\s*@|--data(-binary)?\s*@|-F\s*\S+=@|"
                     r"upload|webhook|pastebin|ngrok|requestbin|discord\.com/api/webhooks)|\|\s*(curl|nc|wget)\b"),
    ("secret_access", r"~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.azure/(accessTokens|msal)|\.netrc|\.npmrc|\.git-credentials"
                      r"|(^|[\s/'\"])\.env\b|\bkeychain\b|/etc/(shadow|passwd)|\bprintenv\b|\benv\s*\||get-access-token|\$\{?(AWS_SECRET\w*|GITHUB_TOKEN|"
                      r"OPENAI_API_KEY|ANTHROPIC_API_KEY)\b"),
    ("destructive", r"rm\s+-rf\s+(/|~|\$HOME)(\s|$)|\bmkfs\b|\bdd\s+if=|:\(\)\s*\{\s*:\|:&\s*\};:|chmod\s+-R\s+777\s+/"),
    ("pipe_to_shell", r"(curl|wget)\s[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b"),
    ("obfuscation", r"base64\s+(-d|--decode)|\beval\s*\(|\bexec\s*\(|[A-Za-z0-9+/]{120,}={0,2}|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){8,}|[​-‏⁠]"),
    # Directives that change how an agent behaves: secrecy, persona switches, absolute rules aimed at the agent.
    ("agent_directive", r"\b(secretly|silently|covertly)\b|\bwithout (asking|telling|informing|notifying)\b|"
                        r"\b(pretend|act|behave) (to be|as)\b|\byou are (now )?(an?|the) \w+|"
                        r"\b(you|the (agent|assistant|model))\s+(must|shall) (always|never)\b"),
]
COMPILED = [(cat, re.compile(rx, re.IGNORECASE)) for cat, rx in PATTERNS]


def _frontmatter(text: str) -> dict:
    m = re.match(r"---\s*\n(.*?)\n---", text, re.S)
    fields = dict(re.findall(r"^(\w+):\s*(.+)$", m.group(1), re.M)) if m else {}
    return {"name": fields.get("name"), "description": (fields.get("description") or "")[:300]}


def _scan(text: str, path: str, url_base: str) -> list:
    signals = []
    for n, line in enumerate(text.splitlines(), 1):
        for cat, rx in COMPILED:
            if rx.search(line):
                signals.append({"category": cat, "file": path, "line": n, "excerpt": " ".join(line.split())[:160],
                                "url": f"{url_base}#L{n}",
                                "inspect": {"start_line": max(1, n - WINDOW), "end_line": n + WINDOW}})
                break  # one signal per line: the highest-priority category
    return signals


def scan_skill(repo: str, skill_path: str) -> dict:
    from oss_agent.tools import REPO_RE, _head_sha  # same validation and commit pinning as read_file
    if not REPO_RE.match(repo or ""):
        return {"ok": False, "error": "repo must look like owner/name"}
    path = skill_path.rstrip("/")
    path = path if path.endswith("SKILL.md") else f"{path}/SKILL.md"
    if path.startswith("/") or ".." in path.split("/"):
        return {"ok": False, "error": "skill_path must be relative to the repo root, without '..'"}
    head = _head_sha(repo)
    if not head["ok"]:
        return head
    sha = head["sha"]
    files = [path]
    folder = posixpath.dirname(path)
    listing = http.get(f"{GH}/repos/{repo}/contents/{quote(folder, safe='/@')}", params={"ref": sha})
    if listing["ok"] and isinstance(listing["data"], list):
        for item in listing["data"]:
            if item["type"] == "file" and item["path"] != path and item["path"].lower().endswith(TEXT_EXT):
                files.append(item["path"])
            elif item["type"] == "dir" and item["name"] in ("scripts", "bin", "src", "tools"):
                sub = http.get(f"{GH}/repos/{repo}/contents/{quote(item['path'], safe='/@')}", params={"ref": sha})
                files += [s["path"] for s in (sub["data"] if sub["ok"] else []) if s["type"] == "file"
                          and s["path"].lower().endswith(TEXT_EXT)]
    scanned, not_scanned, signals, skill, total = [], [], [], {}, 0
    for f in files[:MAX_FILES]:
        raw = http.get(f"{RAW}/{repo}/{sha}/{quote(f, safe='/@')}", as_json=False)
        if not raw["ok"]:
            not_scanned.append({"file": f, "reason": raw["error"]})
            continue
        lines = raw["data"].count("\n") + 1
        scanned.append({"file": f, "lines": lines})
        if f == path:
            skill, total = _frontmatter(raw["data"]), lines
        signals += _scan(raw["data"], f, f"https://github.com/{repo}/blob/{sha}/{quote(f, safe='/@')}")
    if path not in [s["file"] for s in scanned]:
        return {"ok": False, "error": f"could not read {path}: {not_scanned[0]['reason'] if not_scanned else 'missing'}"}
    not_scanned += [{"file": f, "reason": f"over the {MAX_FILES}-file limit"} for f in files[MAX_FILES:]]
    order = {cat: i for i, (cat, _) in enumerate(PATTERNS)}
    signals.sort(key=lambda s: (order[s["category"]], s["file"], s["line"]))
    for i, s in enumerate(signals, 1):
        s["id"] = f"S{i}"
    counts = {}
    for s in signals:
        counts[s["category"]] = counts.get(s["category"], 0) + 1
    return {
        "ok": True, "repo": repo, "commit": sha, "skill_path": path, "declared": skill, "skill_lines": total,
        "files_scanned": scanned, "files_not_scanned": not_scanned,
        "signal_counts": counts, "signals": signals[:MAX_SIGNALS], "signals_omitted": max(0, len(signals) - MAX_SIGNALS),
        "note": "Signals are regex matches = SUSPICIOUS only. Inspect each relevant one with read_file around "
                "its line ('inspect' window) before classifying it; cite the exact instruction as evidence.",
    }
