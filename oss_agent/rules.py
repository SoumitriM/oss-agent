"""Deterministic rules. Code, not the LLM, decides these, so they are
repeatable and explainable."""

import re

# Base SPDX ids, upper-case. "-only", "-or-later" and "+" are stripped before lookup (normalise_spdx).
PERMISSIVE = {"MIT", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC", "0BSD", "UNLICENSE", "ZLIB", "PSF-2.0"}
WEAK_COPYLEFT = {"LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0"}
STRONG_COPYLEFT = {"GPL-2.0", "GPL-3.0"}
NETWORK_COPYLEFT = {"AGPL-3.0"}
# GitHub often reports NOASSERTION for standard texts; these first-line headers identify them exactly.
LICENCE_HEADERS = [  # order matters: "LESSER" and "AFFERO" before plain "GENERAL PUBLIC"
    (r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3", "LGPL-3.0"),
    (r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1", "LGPL-2.1"),
    (r"GNU AFFERO GENERAL PUBLIC LICENSE\s+Version 3", "AGPL-3.0"),
    (r"GNU GENERAL PUBLIC LICENSE\s+Version 3", "GPL-3.0"),
    (r"GNU GENERAL PUBLIC LICENSE\s+Version 2", "GPL-2.0"),
    (r"Apache License\s+Version 2\.0", "Apache-2.0"),
    (r"Mozilla Public License,?\s+(Version|v\.)\s*2\.0", "MPL-2.0"),
]


def normalise_spdx(spdx: str | None) -> str | None:
    """'LGPL-3.0-or-later' / 'lgpl-3.0-only' / 'LGPL-3.0+' -> 'LGPL-3.0' (upper-case base id)."""
    if not spdx:
        return None
    base = spdx.strip().upper()
    for suffix in ("-OR-LATER", "-ONLY", "+"):
        base = base.removesuffix(suffix)
    return base


def spdx_from_text(text: str | None) -> str | None:
    """Recognise a standard licence from its header (first ~60 lines), only for exact well-known texts."""
    head = " ".join((text or "").split()[:80])
    return next((spdx for pattern, spdx in LICENCE_HEADERS if re.search(pattern, head, re.IGNORECASE)), None)

RANK = {"green": 0, "not_checked": 0, "yellow": 1, "red": 2}

GDPR = "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
CRA = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
# Fact tag (set by the LLM on a finding) -> article (fixed here). The agent points to articles; it never says "compliant".
LEGAL_MAP = {
    "telemetry_on_by_default": ("GDPR Art. 25", "Data protection by design and by default", GDPR),
    "data_to_non_eu_service": ("GDPR Art. 44", "Transfers of personal data outside the EU", GDPR),
    "vendor_processes_data": ("GDPR Art. 28", "Processor: a contract is needed", GDPR),
    "large_scale_personal_data": ("GDPR Art. 35", "Data protection impact assessment", GDPR),
}
CRA_DUE_DILIGENCE = ("CRA Art. 13(5)", "Due diligence when integrating third-party (open-source) components", CRA)
LEGAL_TAGS = list(LEGAL_MAP)


def licence_rule(spdx: str | None, has_licence_file: bool, licence_text: str | None = None) -> tuple[str, str] | None:
    """(status, note) from the SPDX id (or a standard licence header), or None if the LLM must judge."""
    if not has_licence_file and spdx in (None, "NONE"):
        return "red", "No licence file: by default there is no permission to use the code."
    base, source = normalise_spdx(spdx), spdx
    if base in (None, "NOASSERTION", "OTHER") and spdx_from_text(licence_text):
        source = spdx_from_text(licence_text) + " (recognised from the licence file header)"
        base = normalise_spdx(spdx_from_text(licence_text))
    if base in PERMISSIVE:
        return "green", f"{source} is a permissive licence (keep the copyright notice)."
    if base in WEAK_COPYLEFT:
        return "green", (f"{source} is weak copyleft: you may use it in closed products, but changes to the "
                         "library itself must be shared (and, for LGPL, users must be able to replace the library).")
    if base in STRONG_COPYLEFT:
        return "yellow", f"{source} is strong copyleft: distributing your product may require releasing its source."
    if base in NETWORK_COPYLEFT:
        return "yellow", f"{source} is network copyleft: offering it as a service may require releasing your source."
    return None  # NOASSERTION, custom or source-available: the LLM must read the licence file


MALWARE_HEADLINE = "Do not use: malicious release"
UNVERIFIED_HEADLINE = "Security could not be verified"
SCOPED_NPM_RE = re.compile(r"@[a-z0-9-~][a-z0-9-._~]*/[a-z0-9-~][a-z0-9-._~]*")


def wrong_package(asked_text: str, package: str) -> bool:
    """Did the tool check something other than what the user asked about? (never trust a "corrected" name)"""
    asked = asked_text.lower()
    scoped = SCOPED_NPM_RE.findall(asked)
    if scoped:  # a scoped name was asked: only that exact name counts ("wppconnect" != "@wppconnect-team/wppconnect")
        return package.lower() not in scoped
    return package.lower() not in asked


def security_rule(vuln_results: list, asked_text: str) -> dict | None:
    """Security verdict that code decides alone from all check_vulnerabilities results.
    Returns {"status", "note", "headline"?, "force"?, "results"} or None (nothing to decide)."""
    if not vuln_results:
        return None
    good, problems = [], []
    for r in vuln_results:
        if not r.get("ok"):
            problems.append(r.get("error", "check failed"))
        elif wrong_package(asked_text, r["package_checked"]):
            problems.append(f"checked '{r['package_checked']}', which is not the package asked about")
        elif not any(s == "ok" for s in r["sources"].values()):
            problems.append("no vulnerability source answered: " + "; ".join(f"{k} {v}" for k, v in r["sources"].items()))
        else:
            good.append(r)
    if not good:  # "nothing found" must never look like "clean"
        return {"status": "not_checked", "force": True, "headline": UNVERIFIED_HEADLINE,
                "note": "Security could not be verified: " + problems[0], "results": []}
    malware = {v: ids for r in good for v, ids in r["malware_versions"].items()}
    if malware:
        listed = "; ".join(f"{v}: {', '.join(ids)}" for v, ids in malware.items())
        return {"status": "red", "headline": MALWARE_HEADLINE, "results": good,
                "note": f"Do not use: malicious release ({listed}). Do not install it; versions without an advisory are not proven clean."}
    eol = [(v, d["eol"], r) for r in good for v, d in r["per_version"].items() if d.get("eol", {}).get("is_eol")]
    if eol:
        v, info, r = eol[0]
        newest = (r.get("endoflife", {}).get("supported_cycles") or ["a supported version"])[0]
        return {"status": "red", "results": good,
                "note": f"Version {v} reached end of life on {info['eol_date']}: no more security fixes. Upgrade to {newest}."}
    severe = severe_vulnerabilities(good)
    if severe:
        v, x = severe[0]
        fix = f" Upgrade to {', '.join(x['patched'])} or later." if x.get("patched") else " No fixed version is listed."
        return {"status": "red", "results": good,
                "note": f"Version {v} has a {x['severity'].lower()} known vulnerability ({vuln_label(x)}).{fix}"}
    hijacked = [x for r in good if not r["versions_checked"] for x in r["items"] if x["type"] == "malware"]
    if hijacked:  # no version given: some releases were hijacked, so versions must be pinned
        bad = ", ".join(str(a) for x in hijacked for a in x.get("affected", []) if a)
        return {"status": "yellow", "results": good,
                "note": f"Known malicious releases exist ({bad}): pin a safe version and never install those."}
    return {"status": None, "results": good, "note": None}  # nothing for code to decide; keep the LLM's view


SEVERE = {"critical", "high"}


def vuln_label(item: dict) -> str:
    """'GHSA-5c46-x3qw-q7j7 / CVE-2026-25244': every id a reader might search for."""
    ids = [item["id"]] + [a for a in [item.get("cve"), *item.get("aliases", [])] if a and a != item["id"]]
    return " / ".join(dict.fromkeys(ids))


def severe_vulnerabilities(results: list) -> list:
    """[(version, item)] for critical/high known vulnerabilities that affect an asked version."""
    found = []
    for r in results:
        items = {x["id"]: x for x in r["items"]}
        for v, d in r["per_version"].items():
            for vid in d["vulnerabilities"]:
                x = items.get(vid)
                if x and str(x.get("severity", "")).lower() in SEVERE and (v, vid) not in [(a, b["id"]) for a, b in found]:
                    found.append((v, x))
    return sorted(found, key=lambda f: str(f[1]["severity"]).lower() != "critical")  # critical first


def per_version_verdicts(results: list) -> list:
    """One line per asked version, decided by code from the tool data."""
    rows = []
    for r in results:
        any_malware = bool(r["malware_versions"])
        severe = {v: x for v, x in severe_vulnerabilities([r])[::-1]}  # reversed: critical wins per version
        for v, d in r["per_version"].items():
            if d["malware"]:
                rows.append({"version": v, "status": "red", "detail": "malicious release: " + ", ".join(d["malware"])})
            elif d.get("eol", {}).get("is_eol"):
                rows.append({"version": v, "status": "red", "detail": f"end of life since {d['eol']['eol_date']}"})
            elif v in severe:
                x = severe[v]
                fix = f"; fixed in {', '.join(x['patched'])}" if x.get("patched") else ""
                rows.append({"version": v, "status": "red", "detail": f"{x['severity'].lower()} vulnerability {vuln_label(x)}{fix}"})
            elif d["vulnerabilities"]:
                rows.append({"version": v, "status": "yellow", "detail": f"{len(d['vulnerabilities'])} known vulnerabilities: "
                             + ", ".join(d["vulnerabilities"][:4])})
            elif any_malware:  # same release window as a malicious version: absence of evidence is not proof
                rows.append({"version": v, "status": "yellow", "detail": "no advisory found, but not proven clean "
                             "(a nearby release was malicious); avoid until verified"})
            else:
                rows.append({"version": v, "status": "green", "detail": "no known advisory"})
        prev = r.get("previous_release")
        if prev and prev.get("checked"):
            clean = not prev["advisories"]
            rows.append({"version": prev["version"], "status": "green" if clean else "red", "candidate": clean,
                         "detail": ("previous release (not asked): no known advisory; candidate to pin, confirm it in "
                                    "your lockfile" if clean else "previous release (not asked): " + ", ".join(prev["advisories"]))})
    return rows


def malware_recommendation(rows: list) -> str:
    """Code writes the recommendation when malware is found, so no LLM text can suggest an affected version."""
    bad = [r["version"] for r in rows if r["status"] == "red"]
    unproven = [r["version"] for r in rows if r["status"] == "yellow"]
    pin = next((r["version"] for r in rows if r.get("candidate")), None)
    text = f"Do not install {', '.join(bad)}: published malicious release. If it was installed, treat that machine and its secrets as compromised."
    if unproven:
        text += f" {', '.join(unproven)}: no advisory, but not proven clean; avoid until verified."
    if pin:
        text += f" Pin {pin} (previous release, no known advisory) after confirming it in your lockfile."
    return text


def legal_refs(findings: list, areas: dict) -> list:
    """GDPR/CRA articles for VERIFIED findings only, plus CRA due diligence for any security issue."""
    refs = {}
    for f in findings:
        for tag in f.get("tags", []) if f.get("verified") else []:
            if tag in LEGAL_MAP:
                article, title, url = LEGAL_MAP[tag]
                refs.setdefault(article, {"article": article, "title": title, "url": url, "area": f["area"], "because": f["claim"]})
    if areas["security"]["status"] in ("yellow", "red") or any(f["area"] == "security" and f.get("verified") for f in findings):
        article, title, url = CRA_DUE_DILIGENCE
        refs[article] = {"article": article, "title": title, "url": url, "area": "security", "because": "security finding"}
    return list(refs.values())


def overall(areas: dict) -> str:
    """Overall verdict = worst area status. not_checked does not make it better or worse."""
    statuses = [a["status"] for a in areas.values()]
    worst = max(statuses, key=lambda s: RANK.get(s, 0), default="not_checked")
    if all(s == "not_checked" for s in statuses):
        return "not_checked"
    return worst if worst != "not_checked" else "green"
