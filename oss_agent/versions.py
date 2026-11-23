"""find_version: turn a described version ("latest", "installed 6 months ago", a date) into an exact, sourced
version, plus what was released since. The agent then checks the exact versions; nothing here is a verdict.

Sources, by what the user named: package -> its registry (npm, Packagist, PyPI, crates.io, RubyGems: every
version has a publish date);
repository -> GitHub releases; runtime/product -> endoflife.date (latest only, no history)."""
import re
from datetime import date, timedelta
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

from oss_agent import http, registries

RELATIVE_RE = re.compile(r"^(\d{1,3})\s*(day|week|month|year)s?\s+ago$", re.IGNORECASE)
DAYS = {"day": 1, "week": 7, "month": 30, "year": 365}


def _as_of(when: str) -> date | None:
    """'latest' -> today; 'YYYY-MM-DD'; 'N days/weeks/months/years ago' (computed here, not by the model)."""
    when = (when or "latest").strip().lower()
    if when == "latest":
        return date.today()
    m = RELATIVE_RE.match(when)
    if m:
        return date.today() - timedelta(days=int(m.group(1)) * DAYS[m.group(2).lower()])
    try:
        return date.fromisoformat(when)
    except ValueError:
        return None


def _stable(v: str) -> Version | None:
    try:
        parsed = Version(v.removeprefix("v"))
    except InvalidVersion:
        return None
    return None if parsed.is_prerelease or parsed.is_devrelease else parsed


def _npm(package: str) -> tuple[list, str] | str:
    res = http.get(f"https://registry.npmjs.org/{quote(package, safe='@')}")
    if not res["ok"]:
        return f"npm registry: {res['error']}"
    times = res["data"].get("time", {})
    releases = [(v, t[:10]) for v, t in times.items() if v not in ("created", "modified") and _stable(v)]
    return releases, f"https://www.npmjs.com/package/{package}?activeTab=versions"


def _github(repo: str, package: str | None = None) -> tuple[list, str, str | None] | str:
    """Releases of one package. A repository that publishes several packages tags them "name==1.2.3": keep only
    the asked package (or the one named like the repository); otherwise plain "1.2.3" tags."""
    res = http.get(f"https://api.github.com/repos/{repo}/releases", params={"per_page": 100})
    if not res["ok"]:
        return f"GitHub releases: {res['error']}"
    named, plain = {}, []
    for r in res["data"]:
        if r.get("draft") or r.get("prerelease") or not r.get("published_at"):
            continue
        tag, day = r["tag_name"], r["published_at"][:10]
        name, sep, ver = tag.partition("==")
        if sep and _stable(ver):
            named.setdefault(name.lower(), []).append((ver, day))
        elif _stable(tag):
            plain.append((tag.removeprefix("v"), day))
    want = (package or repo.split("/")[-1]).lower()
    if want in named:
        return named[want], f"https://github.com/{repo}/releases", want
    if plain:
        return plain, f"https://github.com/{repo}/releases", None
    if named:  # several packages, none matches: say which exist instead of guessing
        return f"{repo} publishes several packages ({', '.join(sorted(named)[:8])}); give the package name"
    return f"{repo} publishes no GitHub releases"


def _endoflife(product: str) -> tuple[list, str] | str:
    res = http.get(f"https://endoflife.date/api/{product}.json")
    if not res["ok"]:
        return f"endoflife.date: {res['error']}"
    releases = [(c["latest"], c.get("latestReleaseDate") or c.get("releaseDate") or "") for c in res["data"]
                if c.get("latest") and _stable(str(c["latest"]))]
    return releases, f"https://endoflife.date/{product}"


def find_version(when: str = "latest", package: str | None = None, ecosystem: str | None = None,
                 repo: str | None = None, product: str | None = None, until: str | None = None) -> dict:
    """when: 'latest', a date, 'N months ago', or a released version (the start of a range ending at `until`)."""
    as_of = _as_of(when)
    start = None if as_of else _stable(when.strip())
    if as_of is None and start is None:
        return {"ok": False, "error": f"'{when}' is not 'latest', a date (YYYY-MM-DD), 'N months ago' or a version"}
    eco = registries.key(ecosystem)
    npm = eco == "npm" or (package and not repo and not ecosystem)  # a repo wins unless a registry is named
    if package and npm:
        found, source = _npm(package), "npm registry"
    elif package and eco in registries.LOOKUPS:
        r = registries.lookup(package, eco)
        found = ([(v, d) for v, d in r["releases"] if _stable(v)], r["url"]) if r["ok"] else r["error"]
        source = r.get("registry", "registry")
    elif repo:
        found, source = _github(repo, package), "GitHub releases"
    elif product:
        if when.strip().lower() != "latest":
            return {"ok": False, "error": "endoflife.date only knows the latest version per release line; "
                                          "give the repository to look up a version by date"}
        found, source = _endoflife(product.lower()), "endoflife.date"
    else:
        return {"ok": False, "error": "give a package (+ ecosystem), a repository (owner/name) or a product name"}
    if isinstance(found, str):
        return {"ok": False, "error": found}
    releases, url = found[:2]
    matched = found[2] if len(found) > 2 else None
    releases = sorted(releases, key=lambda r: _stable(r[0]))
    oldest = min((d for _, d in releases if d), default="?")
    more = f" (only the latest releases were read, back to {oldest})" if source == "GitHub releases" else ""

    def release(v):  # a version the user named must really exist: never guessed, never "close enough"
        return next((r for r in releases if _stable(r[0]).public == v.public), None)

    if start is not None:
        found_start = release(start)
        if not found_start:
            return {"ok": False, "error": f"version {when.strip()} was not found in {source}{more}; it may not exist"}
        tag, released = found_start
    else:
        on_date = [r for r in releases if r[1] and r[1] <= as_of.isoformat()]
        if not on_date:
            return {"ok": False, "error": f"no release found on or before {as_of.isoformat()} in {source}{more}"}
        tag, released = on_date[-1]
    end = None
    if until:
        end = _stable(until.strip())
        if end is None or not release(end):
            return {"ok": False, "error": f"version {until.strip()} was not found in {source}{more}; it may not exist"}
        if end < _stable(tag):
            return {"ok": False, "error": f"{until.strip()} is older than {_stable(tag).public}: give the range oldest first"}
    newer = [r for r in releases if _stable(r[0]).public != _stable(tag).public and _stable(r[0]) > _stable(tag)]
    version = _stable(tag).public  # "1.2.3+build-1" -> "1.2.3": advisory databases match the public version
    as_of = as_of or (date.fromisoformat(released) if released else date.today())
    if start is not None:
        note = "the version given, found in the source" + ("; range = every released version from it to until" if end else "")
    elif when.strip().lower() == "latest":
        note = "newest stable release today"
    else:
        note = "the version that was the newest stable release on that date; the user may have installed an older one"
    return {"ok": True, "when": when, "as_of": as_of.isoformat(), "version": version, "released": released,
            **({"tag": tag} if tag != version else {}),
            "source": source, "url": url, **({"package": matched} if matched else {}), "latest": {"version": releases[-1][0], "released": releases[-1][1]},
            "newer_releases": len(newer), "newer": [v for v, _ in newer],
            **({"range": [_stable(tag).public] + [_stable(v).public for v, _ in newer if _stable(v) <= end],
                "until": end.public} if end else {}),
            "note": note}
