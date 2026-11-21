"""Coverage check: code judges the QUALITY of a report, not the order of the tool calls.

A gap is
  - an area with a status but no tool output that could support it,
  - an asked version that no check_vulnerabilities call covered (for the exact package),
  - a quote that is not found in any tool output (an unsupported claim).
First submit with gaps -> the report goes back to the agent once ("gather or mark not_checked").
Second submit -> code marks the affected areas not_checked itself (mark_gaps).
"""
from oss_agent import evidence

# Which tool outputs can support a status for each area.
SUPPORT = {"licence": {"get_repo_info", "read_file"}, "maintenance": {"get_repo_info"},
           "security": {"check_vulnerabilities"}, "privacy": {"search_code", "read_file"},
           "skills": {"get_repo_info", "read_file", "scan_skill"}}


def find_gaps(report: dict, tool_outputs: list, parsed: dict) -> list:
    """[{"area", "kind", "detail"}] for one draft report."""
    ok_tools = {o["tool"] for o in tool_outputs if o["result"].get("ok")}
    recheck = any(o["tool"] == "lookup_register" and o["result"].get("found") for o in tool_outputs)
    gaps = []
    for name, area in report.get("areas", {}).items():
        status = area.get("status")
        if status in (None, "not_checked") or name not in SUPPORT:
            continue
        if not SUPPORT[name] & ok_tools and not recheck:  # a re-check may carry an area over unchanged
            gaps.append({"area": name, "kind": "no_evidence",
                         "detail": f"{name} is '{status}' but no {' / '.join(sorted(SUPPORT[name]))} result supports it"})
    if report.get("areas", {}).get("security", {}).get("status") not in (None, "not_checked"):
        covered = {(o["result"]["package_checked"].lower(), v) for o in tool_outputs
                   if o["tool"] == "check_vulnerabilities" and o["result"].get("ok") for v in o["result"]["versions_checked"]}
        for p in parsed.get("packages", []):
            missing = [v for v in p["versions"] if (p["name"].lower(), v) not in covered]
            if missing:
                gaps.append({"area": "security", "kind": "versions",
                             "detail": f"asked versions {missing} of {p['name']} were not checked with check_vulnerabilities"})
    for f in evidence.verify(report.get("findings", []), tool_outputs):
        if not f["verified"]:
            gaps.append({"area": f.get("area"), "kind": "unverified",
                         "detail": f"quote not found in any tool output: \"{f.get('evidence_quote', '')[:60]}\""})
    return gaps


def feedback(gaps: list) -> dict:
    """The ToolMessage content for the one feedback round."""
    return {"ok": False, "coverage_gaps": [g["detail"] for g in gaps],
            "action": "For each gap: gather the missing evidence with a tool, OR set that area to not_checked "
                      "(and remove or fix the unverified quote). Then call submit_report again. This is the only round."}


def mark_gaps(report: dict, gaps: list) -> None:
    """Second submit: code marks areas whose gaps remain as not_checked (unverified quotes stay labelled)."""
    verified_areas = {f.get("area") for f in report.get("findings", []) if f.get("verified")}
    for g in gaps:
        area = report["areas"].get(g["area"]) if g["area"] else None
        if not area or (g["kind"] == "unverified" and g["area"] in verified_areas):
            continue  # an area that still has verified evidence keeps its status; the bad quote shows "⚠ unverified"
        area.update(status="not_checked", summary=f"Not verified: {g['detail']}", forced=True)
    report["coverage_gaps"] = [g["detail"] for g in gaps]
