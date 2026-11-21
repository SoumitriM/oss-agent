"""check_vulnerabilities: four public sources, combined per version.

  OSV           per-version query; MAL-* entries are published malware (hijacked releases)
  GitHub        advisories for the package ecosystem, incl. type=malware
  NVD           known CVEs (matched by CPE, version ranges checked with `packaging`)
  endoflife     is this version's release cycle still supported?
The package name is checked EXACTLY as given (never "corrected"), and every source reports
whether it worked, so "nothing found" can never be confused with "could not check".
"""
import re
from datetime import date

from packaging.version import InvalidVersion, Version

from oss_agent import http

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GH_ADVISORIES = "https://api.github.com/advisories"
OSV = "https://api.osv.dev/v1/query"
NVD_PAGE = 100  # newest 100 CVEs of the product, ~0.7 MB
MAX_VERSIONS = 10

# Package-name rules per ecosystem; never the repo regex.
NPM_RE = re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
PYPI_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
GENERIC_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9._~:/@+-]*$")  # maven group:artifact, go module paths, ...
CPE_RE = re.compile(r"^[a-z0-9_.+-]+$")
# ecosystem alias -> (GitHub advisory ecosystem, OSV ecosystem)
ECOSYSTEMS = {"npm": ("npm", "npm"), "pypi": ("pip", "PyPI"), "pip": ("pip", "PyPI"), "maven": ("maven", "Maven"),
              "go": ("go", "Go"), "rubygems": ("rubygems", "RubyGems"), "nuget": ("nuget", "NuGet"),
              "composer": ("composer", "Packagist"), "packagist": ("composer", "Packagist"),
              "rust": ("rust", "crates.io"), "cargo": ("rust", "crates.io"), "crates.io": ("rust", "crates.io")}


def _version(text: str | None) -> Version | None:
    try:
        return Version(text) if text else None
    except InvalidVersion:
        return None


def _valid_name(package: str, ecosystem: str | None) -> bool:
    if not package or len(package) > 214 or ".." in package:
        return False
    rule = {"npm": NPM_RE, "pypi": PYPI_RE, "pip": PYPI_RE}.get(ecosystem or "", GENERIC_RE)
    return bool(rule.match(package))


# ---------- OSV ----------

def _osv(package: str, osv_ecosystem: str, versions: list) -> tuple[dict, list]:
    """(per-version vuln ids, items). One query per version; no version -> all known vulns."""
    per_version, items = {}, {}
    for v in versions or [None]:
        body = {"package": {"name": package, "ecosystem": osv_ecosystem}}
        if v:
            body["version"] = v
        res = http.post_json(OSV, body)
        if not res["ok"]:
            raise RuntimeError(res["error"])
        found = res["data"].get("vulns", [])
        if v:
            per_version[v] = [x["id"] for x in found]
        for x in found:
            items[x["id"]] = {
                "id": x["id"], "source": "osv", "type": "malware" if x["id"].startswith("MAL-") else "vulnerability",
                "severity": (x.get("database_specific") or {}).get("severity", "unknown"),
                "summary": (x.get("summary") or x.get("details", ""))[:110], "aliases": x.get("aliases", [])[:3],
                "affected": sorted({ver for a in x.get("affected", []) for ver in a.get("versions", [])})[:8],
                "url": f"https://osv.dev/vulnerability/{x['id']}"}
    return per_version, list(items.values())


# ---------- GitHub advisories ----------

def _github(package: str, gh_ecosystem: str, versions: list) -> tuple[dict, list]:
    per_version, items = {}, {}
    for v in versions or [None]:
        ids = []
        for kind in ("malware", "reviewed"):  # malware first: it is the most urgent
            res = http.get(GH_ADVISORIES, params={"ecosystem": gh_ecosystem, "affects": f"{package}@{v}" if v else package,
                                                  "type": kind, "per_page": 5})
            if not res["ok"]:
                raise RuntimeError(res["error"])
            for a in res["data"]:
                mine = [x for x in a["vulnerabilities"] if x["package"]["name"] == package]
                ids.append(a["ghsa_id"])
                items[a["ghsa_id"]] = {
                    "id": a["ghsa_id"], "source": "github", "type": a["type"], "severity": a["severity"],
                    "cve": a.get("cve_id"), "summary": a["summary"][:110],
                    "affected": [x.get("vulnerable_version_range") for x in mine],
                    "patched": [x["first_patched_version"] for x in mine if x.get("first_patched_version")],
                    "url": a["html_url"]}
        if v:
            per_version[v] = ids
    return per_version, list(items.values())


# ---------- NVD ----------

def _severity(cve: dict) -> tuple[str, float | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return data.get("baseSeverity") or metrics[key][0].get("baseSeverity", "?"), data.get("baseScore")
    return "unknown", None


def _affects(cve: dict, vendor: str, product: str, version: Version) -> bool:
    """True if any vulnerable CPE range for vendor:product includes the version."""
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m["criteria"].split(":")
                if not m.get("vulnerable") or parts[3:5] != [vendor, product]:
                    continue
                exact = _version(parts[5]) if parts[5] not in ("*", "-") else None
                if exact is not None:
                    if exact == version:
                        return True
                    continue
                lo_in, lo_ex = _version(m.get("versionStartIncluding")), _version(m.get("versionStartExcluding"))
                hi_in, hi_ex = _version(m.get("versionEndIncluding")), _version(m.get("versionEndExcluding"))
                if ((lo_in is None or version >= lo_in) and (lo_ex is None or version > lo_ex)
                        and (hi_in is None or version <= hi_in) and (hi_ex is None or version < hi_ex)):
                    return True
    return False


def _nvd(vendor: str, product: str, versions: list) -> tuple[dict, list, dict]:
    cpe = f"cpe:2.3:a:{vendor}:{product}"
    count = http.get(NVD, params={"virtualMatchString": cpe, "resultsPerPage": 1})
    if not count["ok"]:
        raise RuntimeError(count["error"])
    total = count["data"]["totalResults"]
    page = http.get(NVD, params={"virtualMatchString": cpe, "resultsPerPage": NVD_PAGE,
                                 "startIndex": max(0, total - NVD_PAGE)})  # NVD sorts oldest first
    if not page["ok"]:
        raise RuntimeError(page["error"])
    cves = sorted((v["cve"] for v in page["data"]["vulnerabilities"]), key=lambda c: c["published"], reverse=True)
    per_version = {}
    for v in versions:
        parsed = _version(v)
        per_version[v] = [c["id"] for c in cves if parsed and _affects(c, vendor, product, parsed)]
    shown = [c for c in cves if not versions or any(c["id"] in ids for ids in per_version.values())]
    items = []
    for c in shown[:6]:
        severity, score = _severity(c)
        items.append({"id": c["id"], "source": "nvd", "type": "vulnerability", "severity": severity, "score": score,
                      "summary": c["descriptions"][0]["value"][:110], "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}"})
    return per_version, items, {"cpe": cpe, "total_for_product": total, "checked_newest": len(cves)}


# ---------- endoflife.date ----------

def _endoflife(product: str, versions: list) -> dict:
    res = http.get(f"https://endoflife.date/api/{product}.json")
    if not res["ok"]:
        if "404" in res["error"]:
            return {"listed": False}
        raise RuntimeError(res["error"])
    today = date.today().isoformat()

    def is_eol(cycle):  # eol is a date string or a boolean
        return cycle["eol"] is True or (isinstance(cycle["eol"], str) and cycle["eol"] <= today)

    out = {"listed": True, "supported_cycles": [c["cycle"] for c in res["data"] if not is_eol(c)][:5],
           "url": f"https://endoflife.date/{product}", "per_version": {}}
    for v in versions:
        parsed = _version(v)
        for c in res["data"]:
            cycle = _version(c["cycle"])
            if parsed and cycle and parsed.release[:len(cycle.release)] == cycle.release:
                out["per_version"][v] = {"cycle": c["cycle"], "eol_date": c["eol"], "is_eol": is_eol(c),
                                         "latest_in_cycle": c.get("latest")}
                break
    return out


def _previous_release(package: str, eco: str, malware_versions: dict, asked: list) -> dict | None:
    """The patch release just before the first malicious one (2.4.1 -> 2.4.0): a candidate to pin.
    Only checked, never assumed clean: it must have no OSV/GitHub entry, and must exist in the lockfile."""
    first = min((_version(v) for v in malware_versions), key=lambda v: v)
    major, minor, patch = (list(first.release) + [0, 0])[:3]
    if patch == 0:
        return None
    prev = f"{major}.{minor}.{patch - 1}"
    if prev in asked:
        return None
    gh_eco, osv_eco = ECOSYSTEMS[eco]
    try:
        osv_ids = _osv(package, osv_eco, [prev])[0][prev]
        gh_ids = _github(package, gh_eco, [prev])[0][prev]
    except RuntimeError as e:
        return {"version": prev, "checked": False, "error": str(e)}
    return {"version": prev, "checked": True, "advisories": sorted(set(osv_ids + gh_ids))}


# ---------- the tool ----------

def check_vulnerabilities(package: str, ecosystem: str | None = None, versions: list | None = None,
                          cpe_vendor: str | None = None, cpe_product: str | None = None) -> dict:
    eco = (ecosystem or "").strip().lower() or None
    if eco and eco not in ECOSYSTEMS:
        return {"ok": False, "error": f"unknown ecosystem '{ecosystem}' (use one of {sorted(ECOSYSTEMS)})"}
    if not _valid_name(package, eco):
        return {"ok": False, "error": f"'{package}' is not a valid {eco or 'package'} name; it was not checked"}
    versions = [str(v).strip() for v in (versions or []) if str(v).strip()][:MAX_VERSIONS]
    bad = [v for v in versions if _version(v) is None]
    if bad:
        return {"ok": False, "error": f"not valid versions: {bad}. List each exact version, e.g. ['2.4.1', '2.4.2']"}

    result = {"ok": True, "package_checked": package, "ecosystem": eco, "versions_checked": versions, "sources": {}}
    if not versions:
        result["note"] = "no version given: showing known issues for any version; give exact versions for a precise check"
    per_version = {v: {"malware": [], "vulnerabilities": []} for v in versions}
    items = []

    def run(name, fn, *args):  # one failing source never hides the others
        try:
            pv, found = fn(*args)[:2]
            result["sources"][name] = "ok"
            for v, ids in pv.items():
                for i in ids:
                    kind = next((x["type"] for x in found if x["id"] == i), "vulnerability")
                    per_version[v]["malware" if kind == "malware" else "vulnerabilities"].append(i)
            items.extend(found)
        except RuntimeError as e:
            result["sources"][name] = f"unavailable: {e}"

    if eco:
        gh_eco, osv_eco = ECOSYSTEMS[eco]
        run("osv", _osv, package, osv_eco, versions)
        run("github", _github, package, gh_eco, versions)
    else:
        result["sources"]["osv"] = result["sources"]["github"] = "skipped: give an ecosystem (npm, pypi, ...)"
    product = (cpe_product or package).lower()
    vendor = (cpe_vendor or product).lower()
    if CPE_RE.match(product) and CPE_RE.match(vendor):
        run("nvd", _nvd, vendor, product, versions)
    else:
        result["sources"]["nvd"] = "skipped: give cpe_vendor/cpe_product to check NVD"
    if CPE_RE.match(product):
        try:
            eol = _endoflife(product, versions)
            result["sources"]["endoflife"] = "ok" if eol["listed"] else "not listed"
            if eol["listed"]:
                result["endoflife"] = {k: eol[k] for k in ("supported_cycles", "url")}
                for v, info in eol["per_version"].items():
                    per_version[v]["eol"] = info
        except RuntimeError as e:
            result["sources"]["endoflife"] = f"unavailable: {e}"

    # Most urgent first, so the 4,000-char cap for the LLM can only ever cut the tail.
    for v in per_version.values():  # an id found by two sources is listed once
        v["malware"] = sorted(set(v["malware"]))
        v["vulnerabilities"] = sorted(set(v["vulnerabilities"]) - set(v["malware"]))[:8]
    result["malware_versions"] = {v: d["malware"] for v, d in per_version.items() if d["malware"]}
    result["per_version"] = per_version
    if result["malware_versions"] and eco:
        result["previous_release"] = _previous_release(package, eco, result["malware_versions"], versions)
    merged = {}  # one id from two sources (OSV + GitHub): merge, so e.g. GitHub's fixed version is kept
    for x in sorted(items, key=lambda x: x["type"] != "malware"):
        if x["id"] in merged:
            merged[x["id"]].update({k: v for k, v in x.items() if v and not merged[x["id"]].get(k)})
        else:
            merged[x["id"]] = dict(x)
    result["items"] = list(merged.values())[:12]
    return result
