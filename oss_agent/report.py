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


def post_process(report: dict, repo_info: dict | None) -> dict:
    """Code overrides the LLM where facts are deterministic."""
    for a in AREAS:  # areas the LLM skipped are explicitly "not checked"
        report["areas"].setdefault(a, {"status": "not_checked", "summary": "not checked"})
    for key in ("assumptions", "conditions", "open_questions", "findings"):
        report.setdefault(key, [])
    if repo_info:
        report["repo"] = repo_info["repo"]
        report["commit"] = repo_info["head_commit"]  # taken from the API, not from the LLM
        rule = rules.licence_rule(repo_info["licence_spdx"], repo_info["licence_file"] is not None)
        if rule:
            report["areas"]["licence"]["status"] = rule[0]
            report["areas"]["licence"]["rule"] = rule[1]
        if repo_info["archived"]:
            report["areas"]["maintenance"] = {"status": "red", "summary": "Repository is archived: no more fixes."}
    report["overall"] = rules.overall(report["areas"])
    report["checked_on"] = date.today().isoformat()
    return report


def render(report: dict) -> str:
    commit = (report.get("commit") or "")[:7] or "?"
    lines = [f"{report['repo']} @ {commit} · checked {report['checked_on']}",
             f"Overall: {ICON[report['overall']]} {VERDICT[report['overall']]}"]
    if report["assumptions"]:
        lines.append("Assumed: " + " · ".join(report["assumptions"]))
    lines.append("")
    for name in AREAS:
        area = report["areas"][name]
        lines.append(f"{name.upper():<12} {ICON[area['status']]} {area['summary']}")
        findings = [f for f in report["findings"] if f.get("area") == name]
        # One evidence line per area: prefer verified quotes with a line-pinned link.
        for f in sorted(findings, key=lambda f: (not f.get("verified"), "#L" not in f["url"]))[:1]:
            quote = " ".join(f["evidence_quote"].split())  # one line, normalised whitespace
            mark = "✔" if f.get("verified") else "⚠ unverified"
            lines.append(f"{'':<14}\"{quote[:90]}{'…' if len(quote) > 90 else ''}\"")
            lines.append(f"{'':<14}→ {f['url']} {mark}")
    for label, items in (("Conditions", report["conditions"]), ("Open questions", report["open_questions"])):
        if items:  # keep the terminal view short; --json has everything
            more = f" (+{len(items) - 3} more in --json)" if len(items) > 3 else ""
            lines += ["", f"{label}: " + " · ".join(items[:3]) + more]
    lines += ["", f"Recommendation: {report['recommendation']}"]
    return "\n".join(lines)
