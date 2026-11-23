"""Package registries: the registry, not the model, says which repository a package comes from, which versions
exist (with dates), and whether the package exists at all. One GET per lookup; read-only, cached by http.py.

npm keeps its own version-specific lookup (tools.resolve_npm_repo, versions._npm); it only appears here for the
existence check. Go has no registry call: a module path like github.com/owner/name names its repository."""
import re
from urllib.parse import quote

from oss_agent import http

# Aliases the agent may use -> one registry key. Ecosystems without a lookup here (maven, nuget) are not confirmed.
ALIASES = {"npm": "npm", "composer": "composer", "packagist": "composer", "pypi": "pypi", "pip": "pypi",
           "rust": "rust", "cargo": "rust", "crates.io": "rust", "rubygems": "rubygems", "gem": "rubygems", "go": "go"}
NAMES = {"npm": "npm registry", "composer": "Packagist", "pypi": "PyPI", "rust": "crates.io", "rubygems": "RubyGems",
         "go": "GitHub (Go module path)"}
NAME_RE = {"composer": re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$", re.I), "pypi": re.compile(r"^[A-Za-z0-9._-]+$"),
           "rust": re.compile(r"^[A-Za-z0-9_-]+$"), "rubygems": re.compile(r"^[A-Za-z0-9_.-]+$")}
GO_GITHUB = re.compile(r"^github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(/.*)?$")
GITHUB_URL = re.compile(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?]|$)")


def key(ecosystem: str | None) -> str | None:
    return ALIASES.get((ecosystem or "").strip().lower())


def github_repo(url: str | None) -> str | None:
    m = GITHUB_URL.search(url or "")
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _packagist(name):
    res = http.get(f"https://repo.packagist.org/p2/{quote(name.lower(), safe='/')}.json")
    if not res["ok"]:
        return res
    entries = res["data"].get("packages", {}).get(name.lower()) or []
    source = next((e["source"].get("url") for e in entries if isinstance(e.get("source"), dict)), None)
    return {"ok": True, "source": source, "url": f"https://packagist.org/packages/{name.lower()}",
            "releases": [(e["version"], (e.get("time") or "")[:10]) for e in entries if e.get("version")]}


def _pypi(name):
    res = http.get(f"https://pypi.org/pypi/{quote(name)}/json")
    if not res["ok"]:
        return res
    info, urls = res["data"].get("info", {}), res["data"].get("info", {}).get("project_urls") or {}
    preferred = [u for k, u in urls.items() if re.search(r"source|repo|code|github", k, re.I)]
    source = next((u for u in [*preferred, *urls.values(), info.get("home_page")] if github_repo(u)), None)
    releases = []
    for version, files in res["data"].get("releases", {}).items():
        live = [f for f in files if not f.get("yanked")]
        if live:
            releases.append((version, min(f["upload_time"] for f in live)[:10]))
    return {"ok": True, "source": source, "url": f"https://pypi.org/project/{name}/#history", "releases": releases}


def _crates(name):
    res = http.get(f"https://crates.io/api/v1/crates/{quote(name)}")
    if not res["ok"]:
        return res
    return {"ok": True, "source": res["data"].get("crate", {}).get("repository"),
            "url": f"https://crates.io/crates/{name}/versions",
            "releases": [(v["num"], v["created_at"][:10]) for v in res["data"].get("versions", []) if not v.get("yanked")]}


def _rubygems(name):
    gem = http.get(f"https://rubygems.org/api/v1/gems/{quote(name)}.json")
    if not gem["ok"]:
        return gem
    source = next((u for u in (gem["data"].get("source_code_uri"), gem["data"].get("homepage_uri")) if github_repo(u)), None)
    versions = http.get(f"https://rubygems.org/api/v1/versions/{quote(name)}.json")
    if not versions["ok"]:
        return versions
    releases = list(dict.fromkeys((v["number"], v["created_at"][:10]) for v in versions["data"] if not v.get("prerelease")))
    return {"ok": True, "source": source, "url": f"https://rubygems.org/gems/{name}/versions", "releases": releases}


LOOKUPS = {"composer": _packagist, "pypi": _pypi, "rust": _crates, "rubygems": _rubygems}


def lookup(package: str, ecosystem: str | None) -> dict:
    """{"ok", "registry", "repo" (owner/name or None), "source" (as the registry wrote it), "releases", "url"}."""
    eco = key(ecosystem)
    if eco not in LOOKUPS:
        return {"ok": False, "error": f"no registry lookup for {ecosystem or 'this package'} yet"}
    if not NAME_RE[eco].match(package or ""):
        return {"ok": False, "error": f"'{package}' is not a valid {NAMES[eco]} package name"}
    res = LOOKUPS[eco](package)
    if not res["ok"]:
        missing = "404" in res["error"]
        return {"ok": False, "not_found": missing,
                "error": f"{NAMES[eco]} has no package '{package}'" if missing else f"{NAMES[eco]}: {res['error']}"}
    return {**res, "registry": NAMES[eco], "repo": github_repo(res["source"])}


def exists(package: str, ecosystem: str | None) -> bool | None:
    """True / False (the registry says it does not exist) / None (no registry for this ecosystem, or no answer)."""
    eco = key(ecosystem)
    if eco == "npm":
        res = http.get(f"https://registry.npmjs.org/{quote(package, safe='@')}/latest")
        return True if res["ok"] else (False if "404" in res["error"] else None)
    if eco == "go":
        m = GO_GITHUB.match(package or "")
        if not m:
            return None
        res = http.get(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}")
        return True if res["ok"] else (False if "404" in res["error"] else None)
    if eco in LOOKUPS:
        res = lookup(package, eco)
        return True if res["ok"] else (False if res.get("not_found") else None)
    return None
