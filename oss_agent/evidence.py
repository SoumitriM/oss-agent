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


def _haystack(tool_outputs: list) -> str:
    """Everything the LLM saw (JSON text) plus all raw string values, normalised."""
    parts = []
    for out in tool_outputs:
        parts.append(json.dumps(out["result"], ensure_ascii=False))
        parts += _strings(out["result"])
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
