"""Quote verification: never trust the LLM's evidence, check it against this run's tool output.

For each finding:
  1. Is evidence_quote really in a tool result from this run? (whitespace-normalised)
     No  -> "verified": False, shown as "⚠ unverified".
  2. If the quote is inside a file we read (read_file, licence or SECURITY.md excerpt),
     code computes the exact line range and pins the link: /blob/<sha>/<path>#L30-L33.
"""
import json
import re

NUMBERED_LINE = re.compile(r"^\s*(\d+)\| ?(.*)$")


def norm(text: str) -> str:
    """Collapse all whitespace; drop wrapping quotes and trailing ellipses the LLM may add."""
    text = " ".join(str(text).split())
    return text.strip("\"'“”").removesuffix("…").removesuffix("...").strip()


def _documents(tool_outputs: list):
    """Yield (lines, first_line_number, base_url) for every file excerpt whose lines we can pin."""
    for out in tool_outputs:
        r = out["result"]
        if not r.get("ok"):
            continue
        if out["tool"] == "read_file":
            parsed = [NUMBERED_LINE.match(row) for row in r["content"].splitlines()]
            lines = [m.group(2) for m in parsed if m]
            yield lines, r["start_line"], r["url"].split("#")[0]
        if out["tool"] == "get_repo_info":
            for key in ("licence_file", "security_policy"):
                if r.get(key):  # excerpts always start at line 1
                    yield r[key]["first_lines"].splitlines(), 1, r[key]["url"]


def _locate(quote: str, lines: list) -> tuple[int, int] | None:
    """0-based (first, last) line indexes that contain the normalised quote, or None."""
    joined, starts = "", []
    for line in lines:
        starts.append(len(joined))
        joined += norm(line) + " "
    pos = joined.find(quote)
    if pos < 0:
        return None
    first = max(i for i, s in enumerate(starts) if s <= pos)
    last = max(i for i, s in enumerate(starts) if s <= pos + len(quote) - 1)
    return first, last


def _strings(value) -> list:
    """All string values inside a nested dict/list."""
    if isinstance(value, str):
        return [value]
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
    return [s for child in children for s in _strings(child)]


def _items_with_url(value):
    """Dicts that carry their own "url", innermost first (a CVE before the list that holds it)."""
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
    for child in children:
        yield from _items_with_url(child)
    if isinstance(value, dict) and "url" in value and not str(value.get("url", "")).count("#L"):
        yield value  # line-pinned file excerpts are handled by _documents instead


NOT_EVIDENCE = ("query", "note", "error", "injection_warning", "licence_note")  # echoes of our input or our own notes


def _evidence(result: dict) -> dict:
    return {k: v for k, v in result.items() if k not in NOT_EVIDENCE}


def _haystack(tool_outputs: list) -> str:
    """Everything the tools returned as data (JSON text) plus all raw string values, normalised."""
    parts = []
    for out in tool_outputs:
        data = _evidence(out["result"])
        parts.append(json.dumps(data, ensure_ascii=False))
        parts += _strings(data)
    text = "\n".join(parts)
    text = "\n".join(NUMBERED_LINE.sub(r"\2", row) for row in text.splitlines())  # drop "  30| "
    return norm(text)


def _source_url(quote: str, tool_outputs: list, docs: list) -> str | None:
    """Code, not the LLM, picks the link: where was the quote actually found?"""
    for lines, first_line, base_url in docs:  # 1. a file excerpt -> pin the exact lines
        span = _locate(quote, lines)
        if span:
            a, b = first_line + span[0], first_line + span[1]
            return f"{base_url}#L{a}" + (f"-L{b}" if b > a else "")
    for out in tool_outputs:  # 2. an item with its own link (search hit, CVE, advisory, endoflife)
        for item in _items_with_url(out["result"]):
            if quote in norm(json.dumps(item, ensure_ascii=False)) or quote in norm(" ".join(_strings(item))):
                return item["url"]
    for out in tool_outputs:  # 3. repo metadata -> the repo page
        if out["tool"] == "get_repo_info" and out["result"].get("ok"):
            return f"https://github.com/{out['result']['repo']}"
    return None


def verify(findings: list, tool_outputs: list) -> list:
    """Return findings with "verified": bool and, if verified, the url of the real source."""
    haystack = _haystack(tool_outputs)
    docs = list(_documents(tool_outputs))
    checked = []
    for f in findings:
        f = dict(f)
        quote = norm(f.get("evidence_quote", ""))
        f["verified"] = bool(quote) and quote in haystack
        if f["verified"]:
            f["url"] = _source_url(quote, tool_outputs, docs) or f["url"]
        checked.append(f)
    return checked


# Hard facts a reader acts on: versions and advisory ids. Each must come from a tool result or the user's words.
FACT_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+|v?\d+\.\d+(?:\.\d+)*)\b", re.IGNORECASE)


def unsupported_facts(text: str, haystack: str, asked: str = "") -> list:
    """Versions / advisory ids in the text that appear neither in the tool output nor in what the user wrote."""
    out = []
    for fact in dict.fromkeys(m.group(0) for m in FACT_RE.finditer(text or "")):
        bare = fact.lstrip("vV")
        if bare.lower() not in haystack.lower() and bare.lower() not in (asked or "").lower():
            out.append(fact)
    return out


def _sentences(text: str) -> list:
    return [x for x in re.split(r"(?<=[.!?])\s+", text or "") if x.strip()]


def steps(report: dict) -> list:
    """Next steps as [{"action", "finding"}]: finding = the 1-based number of the finding the step rests on, or None
    (no evidence: the step is removed). Plain strings (older reports) have no finding."""
    out = []
    for c in report.get("conditions") or []:
        if isinstance(c, str) and c.strip():
            out.append({"action": c, "finding": None})
        elif isinstance(c, dict) and str(c.get("action", "")).strip():
            n = c.get("finding")
            out.append({"action": str(c["action"]), "finding": n if isinstance(n, int) and not isinstance(n, bool) else None})
    return out


def steps_shown(report: dict) -> list:
    """Processed next steps ({"action", "source"}): only steps that rest on a verified finding."""
    return [c for c in report.get("conditions") or [] if isinstance(c, dict) and c.get("source")]


def gaps(report: dict, tool_outputs: list, asked: str = "") -> list:
    """What is not backed by this run's tool output: unverified quotes, statuses without a verified finding,
    and versions or advisory ids in the summary or next steps that no source or user statement contains."""
    findings = verify(report.get("findings", []), tool_outputs)
    out = [f"quote not found in any tool result: \"{f.get('evidence_quote', '')[:80]}\"" for f in findings if not f["verified"]]
    backed = {f.get("area") for f in findings if f["verified"]}
    out += [f"area '{a}' is {v['status']} but no verified finding supports it" for a, v in report.get("areas", {}).items()
            if v.get("status") != "not_checked" and a not in backed]
    for i, step in enumerate(steps(report), 1):  # every step rests on a verified finding, or it is not shown
        n = step["finding"]
        if n is None:
            out.append(f"next step {i} rests on no finding: give the number of the finding it rests on, or drop it")
        elif not 1 <= n <= len(findings):
            out.append(f"next step {i} cites finding {n}, which does not exist (findings are numbered from 1)")
        elif not findings[n - 1]["verified"]:
            out.append(f"next step {i} rests on finding {n}, whose quote was not found in any tool result")
    hay = _haystack(tool_outputs)
    for where, text in [("recommendation", report.get("recommendation", ""))] + \
                       [("next step", s["action"]) for s in steps(report)]:
        out += [f"{where} names '{f}', which no tool result or user statement contains" for f in unsupported_facts(text, hay, asked)]
    return out


def feedback(found: list) -> dict:
    """The one feedback round: the agent fixes its own report."""
    return {"ok": False, "evidence_gaps": found,
            "error": "Some statements are not backed by evidence from this conversation. For each one: gather the "
                     "evidence with a tool, copy the exact quote from a tool result, or set the area to not_checked "
                     "with the reason. Then call submit_report again."}


def strip_unsupported(report: dict, tool_outputs: list, asked: str = "") -> list:
    """After the feedback round: nothing unverified is claimed. Unverified findings are left out, and a summary
    sentence or next step naming an unsupported version / advisory id is removed. Returns what was left out."""
    original = list(report["findings"])  # step citations refer to these numbers
    removed = [f"finding: {f.get('claim', '')[:90]}" for f in original if not f.get("verified")]
    report["findings"] = [f for f in original if f.get("verified")]
    hay = _haystack(tool_outputs)
    kept = []
    for sentence in _sentences(report.get("recommendation", "")):
        bad = unsupported_facts(sentence, hay, asked)
        if bad:
            removed.append(f"summary sentence naming {', '.join(bad)}")
        else:
            kept.append(sentence)
    report["recommendation"] = " ".join(kept) or "No statement could be confirmed by the sources checked."
    kept_steps = []
    for step in steps(report):
        n = step["finding"]
        if n is None or not 1 <= n <= len(original):  # no evidence behind it: not shown
            removed.append(f"next step with no source: {step['action'][:70]}")
            continue
        f = original[n - 1]
        if not f.get("verified"):  # resting on an unverified claim makes the step unverified too
            removed.append(f"next step resting on an unverified claim: {step['action'][:70]}")
            continue
        source = {"quote": f.get("evidence_quote", ""), "url": f.get("url", "")}
        bad = unsupported_facts(step["action"], hay, asked)
        if bad:
            removed.append(f"next step naming {', '.join(bad)}")
            continue
        kept_steps.append({"action": step["action"], "source": source})
    report["conditions"] = kept_steps
    return removed


def unbacked_to_not_checked(report: dict) -> None:
    """After the feedback round: a status no verified finding supports is not a result."""
    backed = {f.get("area") for f in report["findings"] if f.get("verified")}
    for name, area in report["areas"].items():
        if area["status"] != "not_checked" and name not in backed:
            area.update(status="not_checked", summary=f"Not checked: no verified evidence (was {area['status']}).")
