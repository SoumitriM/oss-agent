"""Report validation, the few code-owned facts, and the answer the user reads.

The agent writes the verdicts, findings and recommendation. Code adds only facts it can read from tool
outputs (repo, commit, what was checked), applies the safety rules, and derives the decision line."""
import textwrap
from datetime import date
from urllib.parse import quote

from oss_agent import evidence, rules
from oss_agent.tools import AREAS, STATUSES

ICON = {"green": "🟢", "yellow": "🟡", "red": "🔴", "not_checked": "⚪"}
DECISION = {"green": "Recommended", "yellow": "Usable with conditions", "red": "Do not adopt"}
INSUFFICIENT = "Insufficient evidence to approve"
LABEL = {"licence": "Licence", "security": "Security", "maintenance": "Maintenance", "privacy": "Privacy", "skills": "Skill"}


def validate(report) -> str | None:
    """Return an error message the agent can act on, or None if the report is usable."""
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
    """Fallback when the agent never produced a valid report: nothing is assessed."""
    return {"repo": (repo_info or {}).get("repo", "unknown"), "question": question, "assumptions": [], "areas": {},
            "findings": [], "open_questions": [], "stopped": reason, "recommendation": "No reliable assessment could be made."}


def post_process(report: dict, repo_info: dict | None, tool_outputs: list = (), asked_text: str = "") -> dict:
    """Evidence first, then the safety rules, then the verdict. Never edits what the agent judged, except to
    make it stricter where evidence is missing."""
    for a in AREAS:
        report["areas"].setdefault(a, {"status": "not_checked", "summary": "Not checked."})
    for key in ("assumptions", "conditions", "open_questions", "findings"):
        report.setdefault(key, [])
    if repo_info:  # identity facts come from the API, not from the agent
        report["repo"], report["commit"] = repo_info["repo"], repo_info["head_commit"]
        if repo_info.get("package_directory"):
            report["package_location"] = f"{repo_info['repo']}/{repo_info['package_directory']}"
    report["findings"] = evidence.verify(report["findings"], tool_outputs)
    evidence.unbacked_to_not_checked(report)  # before stripping: an area backed only by an unverified claim is not checked
    report["left_out"] = evidence.strip_unsupported(report, tool_outputs, asked_text or report.get("question", ""))
    rules.confirmed_needs_inspection(report["findings"], tool_outputs)
    rules.safety(report, tool_outputs, asked_text or report.get("question", ""))
    for o in tool_outputs:  # instruction-like text in tool output: always shown, never followed
        for hit in o["result"].get("injections", [])[:2]:
            report["findings"].append({"area": "skills" if o["tool"] == "scan_skill" else "security",
                                       "claim": f"Content returned by {o['tool']} contains text aimed at AI agents. It was "
                                                "treated as data and not followed; its context decides whether it matters.",
                                       "evidence_quote": hit["snippet"], "url": hit["url"] or "", "verified": True,
                                       "source_tool": "guard"})
    report["legal"] = rules.legal_refs(report["findings"], report["areas"])
    report["overall"] = rules.overall(report["areas"])
    report["checked_on"] = date.today().isoformat()
    report["checks_run"] = _checks_run(tool_outputs)
    report["limitations"] = _limitations(report, tool_outputs)
    report["confidence"] = _confidence(report)
    return report


LEVELS = ["low", "medium", "high"]


def _confidence(report: dict) -> dict:
    """The agent's confidence, lowered (never raised) when the evidence says so."""
    c = report.get("confidence") if isinstance(report.get("confidence"), dict) else {}
    level = c.get("level") if c.get("level") in LEVELS else "low"
    reason = c.get("reason") or "No confidence was given."
    if decision(report)[1] == INSUFFICIENT and level != "low":
        level, reason = "low", "Not enough checked evidence to approve. " + reason
    elif (report.get("left_out") or any(f.get("downgraded") for f in report["findings"])) and level == "high":
        level, reason = "medium", "Some statements could not be confirmed and were left out. " + reason
    elif any("not checked for vulnerabilities" in x or "could not be confirmed in its registry" in x
             for x in report.get("limitations", [])) and level == "high":
        level, reason = "medium", "Some versions were not checked for vulnerabilities. " + reason
    return {"level": level, "reason": reason}


def _checks_run(tool_outputs: list) -> list:
    """Every check that ran, in plain words, with a link where the reader can see the same thing.
    Written by code from the tool outputs, so the list is exactly what happened."""
    rows = []
    for o in tool_outputs:
        r, a, tool = o["result"], o["args"], o["tool"]
        if not r.get("ok"):
            rows.append({"tool": tool, "text": f"could not run ({r.get('error', 'failed')})", "url": ""})
        elif tool == "get_repo_info":
            rows.append({"tool": tool, "text": f"{r['repo']} @ {r['head_commit'][:7]}",
                         "url": f"https://github.com/{r['repo']}/commit/{r['head_commit']}"})
        elif tool == "check_vulnerabilities":
            target = r["package_checked"] + (f"@{', '.join(r['versions_checked'])}" if r["versions_checked"] else " (any version)")
            ok = rules.answered(r["sources"])
            down = [s for s, v in r["sources"].items() if v.startswith("unavailable")]
            text = (f"{target} in {', '.join(ok)}" if ok else f"{target} could not be checked: no database answered")
            text += f"; unavailable: {', '.join(down)}" if down and ok else ""
            text += f"; NVD as {r['nvd_cpe']}" if "nvd" in ok and r.get("nvd_cpe") else ""
            text += f"; withdrawn, not counted: {', '.join(r['withdrawn_ignored'][:3])}" if r.get("withdrawn_ignored") else ""
            rows.append({"tool": tool, "text": text, "url": f"https://osv.dev/list?q={quote(r['package_checked'])}"})
        elif tool == "find_version":
            rows.append({"tool": tool, "text": f"'{r['when']}' = {r['version']} (released {r['released']}, {r['source']}; "
                                 f"latest {r['latest']['version']})", "url": r["url"]})
        elif tool == "search_code":
            rows.append({"tool": tool, "text": f"in {a.get('repo')}: '{a.get('query')}' ({r.get('total_count', len(r.get('hits', [])))} files)",
                         "url": f"https://github.com/search?q={quote('repo:' + str(a.get('repo')) + ' ' + str(a.get('query')))}&type=code"})
        elif tool == "read_file":
            rows.append({"tool": tool, "text": f"{r.get('path', a.get('path'))}, lines {r.get('start_line', '?')}-{r.get('end_line', '?')}", "url": r.get("url", "")})
        elif tool == "scan_skill":
            rows.append({"tool": tool, "text": f"{r.get('skill_path')} ({r.get('skill_lines', '?')} lines, "
                                 f"{sum(r.get('signal_counts', {}).values())} lines flagged for inspection)",
                         "url": f"https://github.com/{r.get('repo')}/blob/{r.get('commit')}/{r.get('skill_path')}"})
        elif tool == "lookup_register":
            rows.append({"tool": tool, "text": ("found" if r.get("found") else "none"), "url": ""})
    return rows


# Every tool, in plain words, in the order the footer lists them.
def _target(o: dict) -> str:
    a = o["args"]
    return str(a.get("repo") or a.get("package") or a.get("product") or "")


def _limitations(report: dict, tool_outputs: list) -> list:
    """Only what the answer needed and did not get: checks the agent tried (so the answer needed them) that failed
    and were not later redone successfully, databases that didn't answer, and claims that couldn't be backed.
    Areas the question didn't need are never listed."""
    out = [f"The assessment stopped before a report was written: {report['stopped']}"] if report.get("stopped") else []
    for i, o in enumerate(tool_outputs):
        r, label, target = o["result"], LABELS.get(o["tool"], o["tool"]), _target(o)
        redone = any(p["tool"] == o["tool"] and _target(p) == target and p["result"].get("ok") for p in tool_outputs[i + 1:])
        if not r.get("ok") and not redone:
            out.append(f"{label}{' for ' + target if target else ''} could not run: {r.get('error', 'it failed')}.")
        elif r.get("ok") and o["tool"] == "check_vulnerabilities":
            down = [f"{s} ({v.split(': ', 1)[-1]})" for s, v in r["sources"].items() if v.startswith("unavailable")]
            if down:
                out.append(f"{label} for {r['package_checked']}: no answer from {', '.join(down)}.")
            if not r.get("ecosystem") and r["sources"].get("endoflife", "").startswith("no match"):
                out.append(f"End-of-life status for {r['package_checked']} was not checked: "
                           f"{r['sources']['endoflife'].split(': ', 1)[-1]}.")
    for a in AREAS:  # the agent rated it, but no source backed the rating
        if "no verified evidence" in report["areas"][a].get("summary", ""):
            out.append(f"{LABEL[a]}: the assessment could not be backed by a source, so it is not shown.")
    unconfirmed = rules.unconfirmed_packages(tool_outputs)
    if unconfirmed:
        out.append(f"The package name could not be confirmed in its registry ({', '.join(unconfirmed)}), so "
                   "\"no known issues\" may also mean the name is not the one published.")
    skipped = rules.unchecked_versions(tool_outputs)
    if skipped:
        out.append(f"{len(skipped)} version{'s were' if len(skipped) > 1 else ' was'} not checked for vulnerabilities "
                   f"(the check covers at most 10 at a time): {', '.join(skipped)}.")
    if report.get("left_out"):
        n = len(report["left_out"])
        out.append(f"{n} statement{'s were' if n > 1 else ' was'} left out because no source confirmed "
                   f"{'them' if n > 1 else 'it'} (details under Show evidence).")
    return list(dict.fromkeys(out))


LABELS = {"get_repo_info": "Repository facts (licence, activity)", "check_vulnerabilities": "Vulnerability databases",
          "find_version": "Version lookup", "search_code": "Code search", "read_file": "File read",
          "scan_skill": "Skill scan", "lookup_register": "Earlier approval record"}


ANSWER = "Answer"


def is_answer(report: dict) -> bool:
    """A specific question (what does the licence allow?) gets an answer, not an approval verdict.
    A red finding always turns it back into a decision, so a serious problem is never just "an answer"."""
    return report.get("kind") == "answer" and report["overall"] != "red"


def decision(report: dict) -> tuple[str, str]:
    """(icon, text) from the statuses only. Approval needs a security (or skill) check backed by evidence."""
    areas = report["areas"]
    if report["overall"] == "red":
        return ICON["red"], DECISION["red"]
    if is_answer(report):
        return "ℹ️", ANSWER
    assessed = areas["security"]["status"] != "not_checked" or areas["skills"]["status"] != "not_checked"
    if report["overall"] == "not_checked" or not assessed:
        return ICON["not_checked"], INSUFFICIENT
    return ICON[report["overall"]], DECISION[report["overall"]]


def _insufficient_reason(report: dict) -> str | None:
    """Why an answer is not an approval, in one plain line (shown under the decision, never hidden)."""
    if is_answer(report):  # say what the answer rests on, and that it is not a security review
        checked = ", ".join(a for a in AREAS if report["areas"][a]["status"] != "not_checked") or "nothing"
        return f"Checked: {checked}." + ("" if report["areas"]["security"]["status"] != "not_checked"
                                          else " This answers your question; it is not a security review.")
    if decision(report)[1] != INSUFFICIENT:
        return None
    areas = report["areas"]
    if report["overall"] == "not_checked":
        return "Nothing could be checked with evidence, so this is not an approval."
    checked = ", ".join(a for a in AREAS if areas[a]["status"] != "not_checked")
    return (f"Only {checked} was checked. Security was not checked, so this answer cannot approve using it.")


def _short(text: str, n: int = 110) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + "…"


def present(report: dict) -> dict:
    """Sections of the answer: decision, the agent's answer, evidence per area, next steps, limits."""
    areas = report["areas"]
    shown = sorted((a for a in AREAS if areas[a]["status"] != "not_checked"), key=lambda a: -rules.RANK[areas[a]["status"]])
    why = []
    for a in shown:
        findings = sorted((f for f in report["findings"] if f.get("area") == a), key=lambda f: not f.get("verified"))[:3]
        articles = [r["article"] for r in report.get("legal", []) if r["area"] == a]
        why.append({"area": a, "status": areas[a]["status"],
                    "summary": areas[a]["summary"] + (f" ({', '.join(articles)})" if articles else ""),
                    "notes": [], "versions": [],
                    "evidence": [{"claim": f["claim"], "quote": _short(f.get("evidence_quote", "")), "url": f.get("url", ""),
                                  "verified": bool(f.get("verified")), "level": f.get("evidence_level"),
                                  "category": f.get("category"), "where": None, "downgraded": f.get("downgraded")}
                                 for f in findings]})
    follow_up = report.get("open_questions", [])[:2]  # facts only the user knows that could change the answer
    not_verified = []
    if report.get("left_out"):  # disclosed, never shown as claims
        n = len(report["left_out"])
        not_verified.append(f"{n} statement{'s' if n > 1 else ''} left out because no source confirmed "
                            f"{'them' if n > 1 else 'it'}: " + "; ".join(report["left_out"][:3]))
    icon, text = decision(report)
    target = [report["repo"] + (f" @ {report['commit'][:7]}" if report.get("commit") else "")]
    if report.get("package_location"):
        target.append(f"package in {report['package_location']}")
    return {"target": " · ".join(target), "checked_on": report["checked_on"],
            "decision": {"icon": icon, "text": text, "reason": report.get("headline") or _insufficient_reason(report)},
            "confidence": report["confidence"],
            "summary": report["recommendation"], "why": why,
            "next": [{"text": s["action"], "source": s.get("source")} for s in evidence.steps_shown(report)][:4],
            "follow_up": follow_up, "limitations": report.get("limitations", []), "not_verified": not_verified, "tools": [{"name": label, "used": any(c["tool"] == t for c in report.get("checks_run", [])),
                                         "calls": [c for c in report.get("checks_run", []) if c["tool"] == t]}
                                        for t, label in LABELS.items()],
            "also": [], "not_checked": [], "recheck": None}


def render(report: dict) -> str:
    p = present(report)
    wrap = lambda s, ind="": textwrap.fill(s, 100, initial_indent=ind, subsequent_indent=ind + "  ")
    d = p["decision"]
    out = [f"Target:   {p['target']} · checked {p['checked_on']}",
           f"Decision: {d['icon']} {d['text']}" + (f" — {d['reason']}" if d["reason"] else ""),
           f"Confidence: {p['confidence']['level']} — {p['confidence']['reason']}",
           "", textwrap.fill(" ".join(p["summary"].split()), 100)]
    if p["limitations"]:  # only what the answer needed and did not get
        out += ["", "Limitations"] + [wrap(f"• {x}", " ") for x in p["limitations"]]
    if p["follow_up"]:  # part of the answer, not a limitation: the user can answer and ask again
        out += ["", "Follow-up"] + [wrap(f"• {q}", " ") for q in p["follow_up"]]
    if p["why"]:
        out += ["", "Why"]
    for item in p["why"]:
        out.append(wrap(f"{ICON[item['status']]} {LABEL[item['area']]}: {item['summary']}", " "))
        for e in item["evidence"]:
            tag = f"[{e['level'].replace('_', ' ')}{' · ' + e['category'] if e.get('category') else ''}] " if e["level"] else ""
            out.append(wrap(f"• {tag}{e['claim']}", "   "))
            out.append(f"     \"{e['quote']}\" → {e['url']} {'✔' if e['verified'] else '⚠ unverified'}")
            if e.get("downgraded"):
                out.append(wrap(f"(downgraded by code: {e['downgraded']})", "     "))
        out += [wrap(n, "   ") for n in item["notes"]]
    if p["next"]:
        out += ["", "What to do next"]
        for i, s in enumerate(p["next"], 1):  # every step traceable: its source, or labelled as advice
            out.append(wrap(f"{i}. {s['text']}", " "))
            out.append(wrap(f"Source: \"{_short(s['source']['quote'], 90)}\"", "     "))
            if s["source"]["url"]:
                out.append(f"     → {s['source']['url']}")
    if p["not_verified"]:
        out += ["", "Not verified"] + [wrap(f"• {n}", " ") for n in p["not_verified"]]
    out += ["", "Tools"]  # every tool: ticked when this answer used it, with what it checked and a link
    for t in p["tools"]:
        if not t["used"]:
            out.append(f" ☐ {t['name']}")
        for c in t["calls"]:
            out.append(wrap(f"☑ {t['name']}: {c['text']}", " "))
            if c["url"]:  # a link is never wrapped: it must stay clickable
                out.append(f"     → {c['url']}")
    text = "\n".join(out)
    problems = check_consistency(report, text)
    if problems:  # the answer must never contradict the verdicts
        raise ValueError("rendered answer inconsistent with the report: " + "; ".join(problems))
    return text


def check_consistency(report: dict, text: str) -> list:
    problems = []
    icon, decided = decision(report)
    line = next((l for l in text.splitlines() if l.startswith("Decision:")), "")
    if not line.startswith(f"Decision: {icon} {decided}"):
        problems.append(f"decision line '{line}' does not match verdict {report['overall']} ({decided})")
    for a in AREAS:
        if report["areas"][a]["status"] == "red" and f"{LABEL[a]}:" not in text:
            problems.append(f"red area {a} is not shown")
    return problems
