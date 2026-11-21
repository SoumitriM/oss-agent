"""Query normalising: code, not the LLM, reads names and versions out of the user's question.

"@wppconnect-team/wppconnect@2.4.1–2.4.3 this version?" ->
  packages: [{"name": "@wppconnect-team/wppconnect", "ecosystem": "npm", "versions": ["2.4.1", "2.4.2", "2.4.3"]}]
  repos:    []   (never guessed from the scope; get_repo_info(package=...) looks it up in the npm registry)
The result is shown to the LLM as facts it must use verbatim, and used by code to catch a
vulnerability check of a different package. Deterministic regexes only; nothing is guessed.
"""
import re

VERSION = r"v?\d+(?:\.\d+){1,3}"  # 8.1, 2.4.1, v1.14.1
RANGE_RE = re.compile(rf"({VERSION})\s*(?:–|—|-|\.\.|\bto\b|\bbis\b)\s*({VERSION})", re.IGNORECASE)
SCOPED_RE = re.compile(r"(@[a-z0-9-~][a-z0-9-._~]*/[a-z0-9-~][a-z0-9-._~]*)(?:@([^\s,;?]+))?", re.IGNORECASE)
REPO_RE = re.compile(r"(?<![@\w./-])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?![\w/])")
GITHUB_URL_RE = re.compile(r"(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*?)(?:\.git)?(?=[/#?\s]|$)\S*")
PKG_AT_RE = re.compile(r"(?<![@\w/])([a-z0-9][a-z0-9._-]*)@([^\s,;?]+)", re.IGNORECASE)  # axios@1.14.1
ECOSYSTEM_WORDS = {"npm": "npm", "node": "npm", "pip": "pypi", "pypi": "pypi", "python": "pypi", "maven": "maven",
                   "java": "maven", "cargo": "rust", "crates.io": "rust", "rust": "rust", "gem": "rubygems",
                   "rubygems": "rubygems", "nuget": "nuget", "composer": "composer", "go": "go"}
MAX_EXPAND = 10


def _versions(spec: str | None) -> tuple[list, str | None]:
    """'2.4.1–2.4.3' -> (['2.4.1', '2.4.2', '2.4.3'], note). Only patch ranges inside one minor are expanded."""
    if not spec:
        return [], None
    spec = spec.strip().rstrip(".")
    m = RANGE_RE.fullmatch(spec) or RANGE_RE.search(spec)
    if not m:
        return ([spec.lstrip("v")], None) if re.fullmatch(VERSION, spec) else ([], f"could not read version '{spec}'")
    lo, hi = m.group(1).lstrip("v").split("."), m.group(2).lstrip("v").split(".")
    if len(lo) == len(hi) == 3 and lo[:2] == hi[:2] and int(lo[2]) <= int(hi[2]) and int(hi[2]) - int(lo[2]) < MAX_EXPAND:
        expanded = [f"{lo[0]}.{lo[1]}.{p}" for p in range(int(lo[2]), int(hi[2]) + 1)]
        return expanded, f"range {m.group(0)} expanded to every patch release (some may not exist)"
    return [".".join(lo), ".".join(hi)], f"range {m.group(0)} too wide to expand: only both ends are checked"


def parse_query(text: str) -> dict:
    out = {"packages": [], "repos": [], "versions": [], "ecosystem_hint": None, "notes": []}
    words = re.findall(r"[a-z.]+", text.lower())
    out["ecosystem_hint"] = next((ECOSYSTEM_WORDS[w] for w in words if w in ECOSYSTEM_WORDS), None)
    rest = text

    for m in GITHUB_URL_RE.finditer(text):  # https://github.com/owner/name[/...]
        out["repos"].append({"repo": m.group(1), "how": "from a GitHub URL"})
        rest = rest.replace(m.group(0), " ")

    for m in SCOPED_RE.finditer(rest):  # npm scoped packages, with optional @version / @range
        name = m.group(1).lower()
        spec = m.group(2)
        tail = text[m.end():m.end() + 30]  # "@2.4.1 – 2.4.3" written with spaces
        if spec and RANGE_RE.match(spec + tail):
            spec = RANGE_RE.match(spec + tail).group(0)
        versions, note = _versions(spec)
        out["packages"].append({"name": name, "ecosystem": "npm", "versions": versions})
        # No repo guess from the scope: @wdio/browserstack-service lives in webdriverio/webdriverio.
        out["notes"] += [note] if note else []
        rest = rest.replace(m.group(0), " ")

    for m in PKG_AT_RE.finditer(rest):  # plain name@version, e.g. axios@1.14.1
        versions, note = _versions(m.group(2))
        out["packages"].append({"name": m.group(1).lower(), "ecosystem": out["ecosystem_hint"], "versions": versions})
        out["notes"] += [note] if note else []
        rest = rest.replace(m.group(0), " ")

    for m in REPO_RE.finditer(rest):  # owner/name that is not part of a URL path or a package
        if not re.fullmatch(VERSION, m.group(1).split("/")[0]):
            out["repos"].append({"repo": m.group(1), "how": "as written"})
            rest = rest.replace(m.group(1), " ")

    if not any(p["versions"] for p in out["packages"]):  # loose versions: "PHP 8.1", "version 2.4.1–2.4.3"
        m = RANGE_RE.search(rest)
        versions, note = _versions(m.group(0)) if m else ([v.lstrip("v") for v in re.findall(rf"\b{VERSION}\b", rest)], None)
        out["versions"] = versions[:MAX_EXPAND]
        out["notes"] += [note] if note else []
        if len(out["packages"]) == 1 and out["versions"]:  # "@wdio/browserstack-service 9.23.2": one package, so they belong to it
            out["packages"][0]["versions"], out["versions"] = out["versions"], []
    return out


def as_prompt(parsed: dict) -> str | None:
    """Short, factual block for the LLM. None if nothing was recognised."""
    if not (parsed["packages"] or parsed["repos"] or parsed["versions"]):
        return None
    lines = ["Parsed from the question by code (deterministic). Use these names and versions EXACTLY:"]
    for p in parsed["packages"]:
        lines.append(f"- package: {p['name']} (ecosystem: {p['ecosystem'] or 'unknown'}); versions to check: "
                     f"{p['versions'] or 'none given'}")
    for r in parsed["repos"]:
        lines.append(f"- GitHub repo: {r['repo']} ({r['how']})")
    if parsed["packages"] and not parsed["repos"]:
        lines.append("- GitHub repo: unknown. Look it up with get_repo_info(package=..., version=...); never guess it from the name")
    if parsed["versions"]:
        lines.append(f"- versions mentioned: {parsed['versions']}")
    lines += [f"- note: {n}" for n in parsed["notes"]]
    return "\n".join(lines)
