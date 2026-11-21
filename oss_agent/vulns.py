"""check_vulnerabilities: three public sources, each optional, combined into one answer.

  NVD           known CVEs for the product (matched by CPE, version range checked with `packaging`)
  GitHub        advisories for a package ecosystem, incl. type=malware (hijacked releases have no CVE)
  endoflife     is this version's release cycle still supported?
One failing source never hides the others; it is reported in the result instead.
"""
import re
from datetime import date

from packaging.version import InvalidVersion, Version

from oss_agent import http

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GH_ADVISORIES = "https://api.github.com/advisories"
NAME_RE = re.compile(r"^[a-z0-9_.+-]+$")
NVD_PAGE = 100  # newest 100 CVEs of the product, ~0.7 MB


def _version(text: str | None) -> Version | None:
    try:
        return Version(text) if text else None
    except InvalidVersion:
        return None


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


def _nvd(vendor: str, product: str, version: Version | None) -> dict:
    cpe = f"cpe:2.3:a:{vendor}:{product}"
    count = http.get(NVD, params={"virtualMatchString": cpe, "resultsPerPage": 1})
    if not count["ok"]:
        return {"nvd_unavailable": True, "nvd_error": count["error"]}
    total = count["data"]["totalResults"]
    page = http.get(NVD, params={"virtualMatchString": cpe, "resultsPerPage": NVD_PAGE,
                                 "startIndex": max(0, total - NVD_PAGE)})  # NVD sorts oldest first
    if not page["ok"]:
        return {"nvd_unavailable": True, "nvd_error": page["error"]}
    cves = [v["cve"] for v in page["data"]["vulnerabilities"]]
    if version:
        cves = [c for c in cves if _affects(c, vendor, product, version)]
    cves.sort(key=lambda c: c["published"], reverse=True)
    items = []
    for c in cves[:10]:
        severity, score = _severity(c)
        items.append({"id": c["id"], "published": c["published"][:10], "severity": severity, "score": score,
                      "summary": c["descriptions"][0]["value"][:110], "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}"})
    return {"nvd_cpe": cpe, "nvd_total_for_product": total, "nvd_checked": len(page["data"]["vulnerabilities"]),
            "nvd_matching": len(cves), "nvd_items": items}


def _github(ecosystem: str, package: str, version: str | None) -> dict:
    affects = f"{package}@{version}" if version else package
    items = []
    for kind in ("malware", "reviewed"):  # malware first: it is the most urgent
        res = http.get(GH_ADVISORIES, params={"ecosystem": ecosystem, "affects": affects, "type": kind, "per_page": 5})
        if not res["ok"]:
            return {"github_unavailable": True, "github_error": res["error"]}
        for a in res["data"]:
            ranges = [v.get("vulnerable_version_range") for v in a["vulnerabilities"] if v["package"]["name"] == package]
            patched = [v.get("first_patched_version") for v in a["vulnerabilities"] if v["package"]["name"] == package]
            items.append({"id": a["ghsa_id"], "type": a["type"], "severity": a["severity"], "cve": a.get("cve_id"),
                          "summary": a["summary"][:110], "affected": ranges, "patched": [p for p in patched if p],
                          "url": a["html_url"]})
    return {"github_items": items}


def _endoflife(product: str, version: Version | None) -> dict:
    res = http.get(f"https://endoflife.date/api/{product}.json")
    if not res["ok"]:
        return {"endoflife": "not listed on endoflife.date" if "404" in res["error"] else res["error"]}
    today = date.today().isoformat()

    def is_eol(cycle):  # eol is a date string or a boolean
        return cycle["eol"] is True or (isinstance(cycle["eol"], str) and cycle["eol"] <= today)

    supported = [c["cycle"] for c in res["data"] if not is_eol(c)]
    out = {"endoflife": {"supported_cycles": supported[:5], "url": f"https://endoflife.date/{product}"}}
    if version:
        for c in res["data"]:
            cycle = _version(c["cycle"])
            if cycle and version.release[:len(cycle.release)] == cycle.release:
                out["endoflife"].update({"cycle": c["cycle"], "eol_date": c["eol"], "is_eol": is_eol(c),
                                         "latest_in_cycle": c.get("latest")})
                break
    return out


def check_vulnerabilities(product: str, vendor: str | None = None, ecosystem: str | None = None,
                          version: str | None = None) -> dict:
    product, vendor = (product or "").lower(), (vendor or product or "").lower()
    if not NAME_RE.match(product) or not NAME_RE.match(vendor):
        return {"ok": False, "error": "product/vendor must be simple lowercase names, e.g. 'php', 'axios'"}
    parsed = _version(version)
    result = {"ok": True, "product": product, "version": version}
    if version and parsed is None:
        result["note"] = f"'{version}' is not a valid version; showing recent issues instead"
    elif not version:
        result["note"] = "no version given: showing recent issues only; give a version for an exact check"
    # Most urgent first, so the 4,000-char cap for the LLM can only ever cut NVD's tail.
    result.update(_endoflife(product, parsed))
    if ecosystem:
        result.update(_github(ecosystem.lower(), product, version if parsed else None))
    else:
        result["github"] = "skipped: give an ecosystem (npm, pip, maven, ...) to check GitHub advisories and malware"
    nvd = _nvd(vendor, product, parsed)
    if ecosystem and nvd.get("nvd_items"):
        nvd["nvd_items"] = nvd["nvd_items"][:6]  # leave room for the advisories
    result.update(nvd)
    return result
