"""A local register of approved due-diligence records: one JSON object per line.

Append-only, plain text, easy to read with `cat`. A missing or corrupt file never
crashes the agent: it is treated as empty and a warning is returned instead.
"""
import json
import os
import re
from pathlib import Path

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")  # same rule as tools.py (no import: avoids a cycle)
REGISTER_PATH = Path(os.getenv("OSS_REGISTER", Path(__file__).parent.parent / "register.jsonl"))


def _read() -> tuple[list, str | None]:
    if not REGISTER_PATH.exists():
        return [], "register.jsonl does not exist yet (treated as empty)"
    records, bad = [], 0
    for line in REGISTER_PATH.read_text().splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            bad += 1
    return records, (f"{bad} corrupt line(s) in register.jsonl were skipped" if bad else None)


def lookup_register(repo: str) -> dict:
    """The most recent earlier record for this repo, or {"found": False}."""
    if not REPO_RE.match(repo or ""):
        return {"ok": False, "error": "repo must look like owner/name"}
    records, warning = _read()
    mine = [r for r in records if r.get("repo", "").lower() == repo.lower()]
    result = {"ok": True, "found": bool(mine)}
    if warning:
        result["warning"] = warning
    if mine:
        last = max(mine, key=lambda r: r.get("saved_at", ""))
        result["previous"] = {
            "checked_on": last.get("checked_on"), "commit": last.get("commit"), "overall": last.get("overall"),
            "areas": {name: {"status": a["status"], "summary": a["summary"]} for name, a in last.get("areas", {}).items()},
            "conditions": last.get("conditions", []), "decision": last.get("decision"),
        }
    return result


def append(record: dict) -> None:
    with REGISTER_PATH.open("a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
