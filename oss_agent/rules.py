"""The few deterministic rules. The agent judges the evidence; code only enforces what must never go wrong:

  1. a published malicious release of an asked version  -> security red, never approved
  2. security not backed by a working vulnerability check -> security not_checked, never approved
  3. confirmed skill claims need an instruction quoted from lines read with read_file
  4. versions passed to the vulnerability check but not checked (over its limit) -> security never green
  5. a package its registry did not confirm exists (a misspelled name also finds "no advisories") -> never green
  6. privacy required (the agent decided it: privacy asked about, or personal/customer/user data involved) but
     no privacy result -> sent back once, then shown as "incomplete" with the reason, never left out
     (plus, in checks: an area status without a verified finding -> not_checked)
Everything else (licence, end of life, severity, applicability, privacy, skills) is the agent's judgement.
"""
import re

RANK = {"green": 0, "not_checked": 0, "yellow": 1, "red": 2}
EVIDENCE_LEVELS = ["suspicious", "confirmed_manipulation", "confirmed_dangerous"]
SKILL_CATEGORIES = ["instruction_override", "exfiltration", "secret_access", "destructive", "pipe_to_shell",
                    "obfuscation", "agent_directive", "off_purpose_instructions", "other"]
LICENCE_FILE_RE = re.compile(r"^(licen[cs]e|copying|unlicense)([.\-_].*)?$", re.IGNORECASE)

MALWARE_HEADLINE = "Do not use: malicious release"
UNVERIFIED_HEADLINE = "Security could not be verified"

GDPR = "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
CRA = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
# Fact tag (set by the agent on a finding) -> article (fixed here). The agent points to articles; it never says "compliant".
LEGAL_MAP = {
    "telemetry_on_by_default": ("GDPR Art. 25", "Data protection by design and by default", GDPR),
    "data_to_non_eu_service": ("GDPR Art. 44", "Transfers of personal data outside the EU", GDPR),
    "vendor_processes_data": ("GDPR Art. 28", "Processor: a contract is needed", GDPR),
    "large_scale_personal_data": ("GDPR Art. 35", "Data protection impact assessment", GDPR),
}
CRA_DUE_DILIGENCE = ("CRA Art. 13(5)", "Due diligence when integrating third-party (open-source) components", CRA)
LEGAL_TAGS = list(LEGAL_MAP)

VULN_SOURCES = ("osv", "github", "nvd")  # advisory databases; endoflife.date only knows lifecycle dates
# Explicit package identifiers in the user's words: "@scope/name" or "name@1.2.3".
EXPLICIT_PACKAGE_RE = re.compile(r"(@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*|(?<![\w@/])[a-z0-9][\w.-]*(?=@\d))", re.IGNORECASE)


def answered(sources: dict) -> list:
    """Advisory sources that answered. endoflife.date answering says nothing about vulnerabilities."""
    return [s for s in VULN_SOURCES if sources.get(s) == "ok"]


def wrong_package(asked_text: str, package: str) -> bool:
    """When the user named a package explicitly, only that exact name counts (no substitution, no look-alike).
    A loosely named product ("the X runtime") leaves the mapping to the agent; the checked name is shown."""
    explicit = {m.lower().rstrip(".") for m in EXPLICIT_PACKAGE_RE.findall(asked_text)}
    return bool(explicit) and package.lower() not in explicit


def unchecked_versions(tool_outputs: list) -> list:
    """Versions the vulnerability check returned as not checked (over its per-call limit) and no other call checked."""
    results = [o["result"] for o in tool_outputs if o["tool"] == "check_vulnerabilities" and o["result"].get("ok")]
    checked = {v for r in results for v in r.get("versions_checked", [])}
    return list(dict.fromkeys(v for r in results for v in r.get("not_checked_versions", []) if v not in checked))


def unconfirmed_packages(tool_outputs: list) -> list:
    """Packages checked for vulnerabilities whose registry did not confirm they exist (and no other check did)."""
    results = [o["result"] for o in tool_outputs if o["tool"] == "check_vulnerabilities" and o["result"].get("ok")
               and o["result"].get("ecosystem")]
    confirmed = {r["package_checked"] for r in results if r.get("package_confirmed")}
    return list(dict.fromkeys(f"{r['package_checked']} ({r['ecosystem']})" for r in results
                              if r["package_checked"] not in confirmed))


def safety(report: dict, tool_outputs: list, asked_text: str) -> None:
    """Rules 1 and 2. Can only make the security area stricter, never better."""
    results = [o["result"] for o in tool_outputs if o["tool"] == "check_vulnerabilities"]
    valid = [r for r in results if r.get("ok") and answered(r["sources"]) and not wrong_package(asked_text, r["package_checked"])]
    area = report["areas"]["security"]
    for r in valid:  # 1. malware: always a finding, always red
        for version, ids in r["malware_versions"].items():
            item = next((x for x in r["items"] if x["id"] in ids), {})
            report["findings"].insert(0, {"area": "security", "claim": f"Version {version} is a known malicious release "
                                          f"({', '.join(ids)}): do not install it.", "evidence_quote": item.get("summary", ids[0]),
                                          "url": item.get("url", ""), "verified": True, "source_tool": "check_vulnerabilities"})
            area.update(status="red", summary=f"Malicious release: {version} ({', '.join(ids)}).")
            report["headline"] = MALWARE_HEADLINE
    # 4. some versions involved were never checked: what was checked may be fine, the rest is unknown
    skipped = unchecked_versions(tool_outputs)
    if skipped and area["status"] == "green":
        area.update(status="yellow", summary=f"No known issues in the versions checked, but {len(skipped)} version"
                                             f"{'s were' if len(skipped) > 1 else ' was'} not checked: {', '.join(skipped)}.")
    # 5. "no advisories" for a name the registry did not confirm may only mean the name is wrong
    unconfirmed = unconfirmed_packages(tool_outputs)
    if unconfirmed and area["status"] == "green":
        area.update(status="yellow", summary=f"No known issues found, but the package name could not be confirmed in "
                                             f"its registry: {', '.join(unconfirmed)}.")
    # 2. a check was attempted but did not work, or "fine" has no working check behind it
    if not valid and area["status"] != "red" and (results or area["status"] in ("green", "yellow")):
        reason = next((_failure(r, asked_text) for r in results), "no vulnerability check was run")
        area.update(status="not_checked", summary=f"Security could not be verified: {reason}.")
        report["headline"] = UNVERIFIED_HEADLINE


def _failure(r: dict, asked_text: str) -> str:
    if not r.get("ok"):
        return r.get("error", "the check failed")
    if wrong_package(asked_text, r["package_checked"]):
        return f"'{r['package_checked']}' was checked, which is not the package asked about"
    return "no vulnerability database answered (" + "; ".join(f"{k} {v}" for k, v in r["sources"].items()
                                                              if k in VULN_SOURCES) + ")"


def confirmed_needs_inspection(findings: list, tool_outputs: list) -> None:
    """Rule 3: a confirmed skill claim must quote lines the agent actually read; otherwise it is suspicious."""
    read = " ".join(" ".join(o["result"].get("content", "").split()) for o in tool_outputs
                    if o["tool"] == "read_file" and o["result"].get("ok"))
    read = re.sub(r"\s*\d+\| ?", " ", read)
    for f in findings:
        quote = " ".join(str(f.get("evidence_quote", "")).split())
        if str(f.get("evidence_level", "")).startswith("confirmed") and (not quote or quote not in " ".join(read.split())):
            f["downgraded"] = f"{f['evidence_level']} needs the instruction quoted from lines read with read_file"
            f["evidence_level"] = "suspicious"


PRIVACY_GAP = ("privacy_check_required is true but the privacy area has no result: check what the component "
               "collects or sends, or, if that could not be completed, keep privacy not_checked and say why in its summary")


def privacy_missing(report: dict) -> bool:
    """Rule 6: the agent said privacy is required, but the privacy area has no result."""
    return report.get("privacy_check_required") is True and \
        report.get("areas", {}).get("privacy", {}).get("status", "not_checked") == "not_checked"


def privacy_gate(report: dict) -> None:
    """Rule 6, after the feedback round: a required privacy check without a result is marked incomplete, with the
    reason the agent gave (or that it was not done). The area is then always shown, never silently omitted."""
    if not privacy_missing(report):
        return
    area = report["areas"]["privacy"]
    reason = re.sub(r"^not checked[.:]?\s*", "", area.get("summary", "").strip(), flags=re.IGNORECASE)
    area.update(incomplete=True, summary="Incomplete: " + (reason or "the privacy check was not done."))


def legal_refs(findings: list, areas: dict) -> list:
    """GDPR/CRA articles for VERIFIED findings only, plus CRA due diligence for any security issue."""
    refs = {}
    for f in findings:
        for tag in f.get("tags", []) if f.get("verified") else []:
            if tag in LEGAL_MAP:
                article, title, url = LEGAL_MAP[tag]
                refs.setdefault(article, {"article": article, "title": title, "url": url, "area": f["area"], "because": f["claim"]})
    if areas["security"]["status"] in ("yellow", "red"):
        article, title, url = CRA_DUE_DILIGENCE
        refs[article] = {"article": article, "title": title, "url": url, "area": "security", "because": "security finding"}
    return list(refs.values())


def overall(areas: dict) -> str:
    """Worst checked area; not_checked only if nothing was checked."""
    checked = [a["status"] for a in areas.values() if a["status"] != "not_checked"]
    return max(checked, key=lambda s: RANK[s]) if checked else "not_checked"
