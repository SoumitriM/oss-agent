"""Report validation, deterministic post-processing, and terminal rendering."""
from datetime import date

from oss_agent import rules
from oss_agent.tools import AREAS, STATUSES

ICON = {"green": "🟢", "yellow": "🟡", "red": "🔴", "not_checked": "⚪"}
VERDICT = {"green": "OK to use", "yellow": "Usable with conditions", "red": "Do not adopt without review",
           "not_checked": "Not enough information"}


def validate(report) -> str | None:
    """Return an error message the LLM can act on, or None if the report is usable."""
    if not isinstance(report, dict):
        return "report must be an object"
    for key in ("repo", "question", "areas", "findings", "recommendation"):
        if key not in report:
            return f"missing field '{key}'"
    for name, area in report["areas"].items():
        if name not in AREAS:
            return f"unknown area '{name}' (use {AREAS})"
        if not isinstance(area, dict) or area.get("status") not in STATUSES:
            return f"area '{name}' needs status in {STATUSES}"
    return None


def minimal_report(question: str, repo_info: dict | None, reason: str) -> dict:
    """Fallback when the LLM never produced a valid report: every area not_checked."""
    return {
        "repo": (repo_info or {}).get("repo", "unknown"),
        "question": question,
        "assumptions": [],
        "areas": {},
        "findings": [],
        "open_questions": [reason],
        "recommendation": "No reliable assessment could be made; see open questions.",
    }


def _raise_status(area: dict, rule: tuple[str, str]) -> None:
    """Apply a code rule that can only make an area worse, never better."""
    status, note = rule
    area["rule"] = note
    if rules.RANK[status] > rules.RANK.get(area["status"], 0) or area["status"] == "not_checked":
        area["status"], area["summary"] = status, note  # code's words replace the LLM's


def _apply_security(report: dict, tool_outputs: list, asked_text: str) -> None:
    """Malware, end of life, failed or wrong-package checks: code decides, not the LLM."""
    rule = rules.security_rule([o["result"] for o in tool_outputs if o["tool"] == "check_vulnerabilities"], asked_text)
    if not rule:
        return
    area = report["areas"]["security"]
    if rule.get("force"):  # check failed / wrong package: an LLM "green" must not survive
        area.update(status="not_checked", summary=rule["note"], rule=rule["note"], forced=True)
    elif rule["status"]:
        _raise_status(area, (rule["status"], rule["note"]))
    if rule.get("headline"):
        report["headline"] = rule["headline"]
    report["per_version"] = rules.per_version_verdicts(rule["results"])
    if rule.get("headline") == rules.MALWARE_HEADLINE:  # code's words, not the LLM's, decide what to install
        report["llm_recommendation"] = report["recommendation"]
        report["recommendation"] = rules.malware_recommendation(report["per_version"])
    for v, x in reversed(rules.severe_vulnerabilities(rule["results"])):  # severe CVEs: always a finding too
        fix = f"; fixed in {', '.join(x['patched'])}" if x.get("patched") else ""
        report["findings"].insert(0, {"area": "security", "claim": f"Version {v} has a {x['severity'].lower()} "
                                      f"vulnerability ({rules.vuln_label(x)}){fix}.", "evidence_quote": x["summary"],
                                      "url": x["url"], "verified": True, "source_tool": "check_vulnerabilities (code rule)"})
    for r in rule["results"]:  # malware is always a finding, whatever the LLM wrote
        for v, ids in r["malware_versions"].items():
            item = next(x for x in r["items"] if x["id"] in ids)
            report["findings"].insert(0, {"area": "security", "claim": f"Version {v} is a known malicious release ({', '.join(ids)}).",
                                          "evidence_quote": item["summary"], "url": item["url"], "verified": True,
                                          "source_tool": "check_vulnerabilities (code rule)"})


def _apply_repo_lookup(report: dict, repo_info: dict | None, tool_outputs: list) -> None:
    """Monorepo location, or, if the package's repo could not be found, say so instead of guessing."""
    if repo_info and repo_info.get("package_directory"):
        report["package_location"] = f"{repo_info['repo']}/{repo_info['package_directory']}"
        report["package_url"] = repo_info["package_url"]
    if repo_info and repo_info.get("resolved_from", {}).get("note"):
        report["assumptions"].append(repo_info["resolved_from"]["note"])
    failed = [o["result"]["error"] for o in tool_outputs
              if o["tool"] == "get_repo_info" and o["args"].get("package") and not o["result"].get("ok")]
    if failed and not repo_info:  # no repo: licence/maintenance unknown, but the security result still stands
        for name in ("licence", "maintenance"):
            report["areas"][name] = {"status": "not_checked", "summary": f"Not checked: {failed[0]}", "forced": True}


def post_process(report: dict, repo_info: dict | None, tool_outputs: list = (), asked_text: str = "") -> dict:
    """Code overrides the LLM where facts are deterministic.
    asked_text = the user's question plus their answers, to catch a vulnerability check of the wrong package."""
    for a in AREAS:  # areas the LLM skipped are explicitly "not checked"
        report["areas"].setdefault(a, {"status": "not_checked", "summary": "not checked"})
    for key in ("assumptions", "conditions", "open_questions", "findings"):
        report.setdefault(key, [])
    if repo_info:
        report["repo"] = repo_info["repo"]
        report["commit"] = repo_info["head_commit"]  # taken from the API, not from the LLM
        text = (repo_info.get("licence_file") or {}).get("first_lines")
        rule = rules.licence_rule(repo_info["licence_spdx"], repo_info["licence_file"] is not None, text)
        if rule:
            report["areas"]["licence"].update(status=rule[0], rule=rule[1])
        if repo_info["archived"]:
            report["areas"]["maintenance"] = {"status": "red", "summary": "Repository is archived: no more fixes."}
    _apply_repo_lookup(report, repo_info, tool_outputs)
    _apply_security(report, tool_outputs, asked_text or report.get("question", ""))
    previous = next((o["result"]["previous"] for o in tool_outputs
                     if o["tool"] == "lookup_register" and o["result"].get("found")), None)
    if previous:  # re-check: compare with the last approved record
        report["previous"] = previous
        for name, area in report["areas"].items():
            old = previous["areas"].get(name)
            if area["status"] == "not_checked" and not area.get("forced") and old and old["status"] != "not_checked":
                area.update(status=old["status"], summary=old["summary"], carried_over=previous["checked_on"])
        report["changed_areas"] = [a for a in AREAS if previous["areas"].get(a, {}).get("status") != report["areas"][a]["status"]]
    report["legal"] = rules.legal_refs(report["findings"], report["areas"])
    report["overall"] = rules.overall(report["areas"])
    report["checked_on"] = date.today().isoformat()
    return report


def render(report: dict) -> str:
    commit = f"@ {report['commit'][:7]}" if report.get("commit") else "(no commit checked)"
    lines = [f"{report['repo']} {commit} · checked {report['checked_on']}",
             f"Overall: {ICON[report['overall']]} {report.get('headline') or VERDICT[report['overall']]}"]
    if report.get("package_location"):
        lines.append(f"Package lives in {report['package_location']}  → {report['package_url']}")
    if report["assumptions"]:
        lines.append("Assumed: " + " · ".join(report["assumptions"]))
    shown = AREAS
    prev = report.get("previous")
    if prev:  # re-check: show only what changed; everything else on one line
        same = "same commit" if prev.get("commit") == report.get("commit") else f"was @ {(prev.get('commit') or '?')[:7]}"
        lines.append(f"Re-check of {prev['checked_on']} ({same}, previous overall {ICON.get(prev['overall'], '?')})")
        shown = report["changed_areas"]
        unchanged = [f"{a.upper()} {ICON[report['areas'][a]['status']]}" for a in AREAS if a not in shown]
        lines.append(("Changed: " + ", ".join(a.upper() for a in shown)) if shown else "Changed: nothing")
        if unchanged:
            lines.append("Unchanged since last check: " + " · ".join(unchanged))
    lines.append("")
    for name in shown:
        area = report["areas"][name]
        articles = ", ".join(r["article"] for r in report.get("legal", []) if r["area"] == name)
        lines.append(f"{name.upper():<12} {ICON[area['status']]} {area['summary']}" + (f"  ({articles})" if articles else "")
                     + (f"  [from {area['carried_over']}]" if area.get("carried_over") else ""))
        findings = [f for f in report["findings"] if f.get("area") == name]
        # One evidence line per area: the LLM's most important VERIFIED finding (sort is stable).
        for f in sorted(findings, key=lambda f: not f.get("verified"))[:1]:
            quote = " ".join(f["evidence_quote"].split())  # one line, normalised whitespace
            mark = "✔" if f.get("verified") else "⚠ unverified"
            lines.append(f"{'':<14}\"{quote[:90]}{'…' if len(quote) > 90 else ''}\"")
            lines.append(f"{'':<14}→ {f['url']} {mark}")
        if name == "security":  # per-version verdicts, decided by code
            for row in report.get("per_version", []):
                lines.append(f"{'':<14}{ICON[row['status']]} {row['version']}: {row['detail']}")
    for label, items in (("Conditions", report["conditions"]), ("Open questions", report["open_questions"])):
        if items:  # keep the terminal view short; --json has everything
            more = f" (+{len(items) - 3} more in --json)" if len(items) > 3 else ""
            lines += ["", f"{label}: " + " · ".join(items[:3]) + more]
    lines += ["", f"Recommendation: {report['recommendation']}"]
    return "\n".join(lines)
