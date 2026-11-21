"""Deterministic rules. Code, not the LLM, decides these, so they are
repeatable and explainable."""

PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "Zlib", "PSF-2.0"}
WEAK_COPYLEFT = {"LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only",
                 "LGPL-3.0-or-later", "MPL-2.0", "EPL-2.0"}
STRONG_COPYLEFT = {"GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"}
NETWORK_COPYLEFT = {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"}

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


def licence_rule(spdx: str | None, has_licence_file: bool) -> tuple[str, str] | None:
    """(status, note) from the SPDX id, or None if the LLM must judge from the licence text."""
    if not has_licence_file and spdx in (None, "NONE"):
        return "red", "No licence file: by default there is no permission to use the code."
    if spdx in PERMISSIVE:
        return "green", f"{spdx} is a permissive licence (keep the copyright notice)."
    if spdx in WEAK_COPYLEFT:
        return "green", f"{spdx} is weak copyleft: changes to the library itself must be shared."
    if spdx in STRONG_COPYLEFT:
        return "yellow", f"{spdx} is strong copyleft: distributing your product may require releasing its source."
    if spdx in NETWORK_COPYLEFT:
        return "yellow", f"{spdx} is network copyleft: offering it as a service may require releasing your source."
    return None  # NOASSERTION, custom or source-available: the LLM must read the licence file


def vulnerability_rule(result: dict) -> tuple[str, str] | None:
    """Red security facts that code can decide alone from a check_vulnerabilities result."""
    eol = result.get("endoflife")
    if isinstance(eol, dict) and eol.get("is_eol"):
        newest = (eol.get("supported_cycles") or ["a supported version"])[0]
        return "red", f"Version {result['version']} reached end of life on {eol['eol_date']}: no more security fixes. Upgrade to {newest}."
    malware = [a for a in result.get("github_items", []) if a["type"] == "malware"]
    if malware and result.get("version"):  # the advisory list was already filtered to this version
        return "red", f"Version {result['version']} is a known malicious release ({malware[0]['id']}). Do not install it."
    if malware:  # no version given: some releases were hijacked, so versions must be pinned
        bad = ", ".join(r for a in malware for r in a["affected"] if r)
        return "yellow", f"Known malicious releases exist ({bad}): pin a safe version and never install those."
    return None


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
