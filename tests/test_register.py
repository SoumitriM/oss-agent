"""register.jsonl: missing/corrupt files never crash, latest record wins."""
import json

import pytest

from oss_agent import register


@pytest.fixture(autouse=True)
def tmp_register(monkeypatch, tmp_path):
    monkeypatch.setattr(register, "REGISTER_PATH", tmp_path / "register.jsonl")


def record(saved_at, overall):
    return {"repo": "o/r", "saved_at": saved_at, "checked_on": saved_at[:10], "commit": "abc", "overall": overall,
            "areas": {"licence": {"status": overall, "summary": "s"}}, "decision": {"approved": True}}


def test_missing_register_is_empty_with_warning():
    r = register.lookup_register("o/r")
    assert r["ok"] and not r["found"] and "does not exist" in r["warning"]


def test_corrupt_lines_are_skipped_with_warning():
    register.REGISTER_PATH.write_text("{not json\n" + json.dumps(record("2026-11-01T00:00:00", "green")) + "\n")
    r = register.lookup_register("o/r")
    assert r["found"] and "1 corrupt" in r["warning"]


def test_latest_record_for_repo_wins():
    register.append(record("2026-11-01T00:00:00", "green"))
    register.append(record("2026-11-20T00:00:00", "yellow"))
    assert register.lookup_register("O/R")["previous"]["overall"] == "yellow"


def test_other_repo_is_not_found():
    register.append(record("2026-11-01T00:00:00", "green"))
    assert not register.lookup_register("x/y")["found"]
