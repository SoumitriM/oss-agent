"""Regression cases from tests/test_cases.json, replayed offline (recorded HTTP fixtures, scripted LLM).
The live-LLM version of the same cases runs in tests/eval.py (M6)."""
import json
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from oss_agent import graph, http, register, rules

CASES = {c["id"]: c for c in json.loads((Path(__file__).parent / "test_cases.json").read_text())}
LLM_SAYS_YELLOW = {"repo": "wppconnect-team/wppconnect", "question": "q", "recommendation": "Usable with conditions.",
                   "findings": [], "areas": {"security": {"status": "yellow", "summary": "No known issues"}}}


class ScriptedModel:
    def __init__(self, replies):
        self.replies = list(replies)

    def invoke(self, messages):
        return self.replies.pop(0)


def call(name, args, i):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{i}", "type": "tool_call"}])


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(http, "OFFLINE", True)  # recorded fixtures only
    monkeypatch.setattr(register, "REGISTER_PATH", tmp_path / "register.jsonl")


def run_case(case, vuln_args):
    """The LLM's report says YELLOW in both runs: only code rules may turn it into the right verdict."""
    replies = [call("check_vulnerabilities", vuln_args, 1), call("submit_report", {"report": LLM_SAYS_YELLOW}, 2)]
    script = dict(case["interrupt_answers"])
    answer = lambda p: (script["ask"].pop(0) if script["ask"] else "") if p["type"] == "ask" else script["approve"]
    return graph.run(graph.build_graph(ScriptedModel(replies)), case["question"], answer)


def test_wppconnect_correct_check_is_red_with_mal_finding():
    case = CASES["wppconnect-malware-range"]
    state = run_case(case, case["expect"]["tool_args"]["check_vulnerabilities"])
    r = state["report"]
    assert r["overall"] == case["expect"]["verdict"] and r["headline"] == case["expect"]["headline"]
    assert any(case["expect"]["required_finding"] in f["claim"] + f["url"] for f in r["findings"])
    assert [(v["version"], v["status"]) for v in r["per_version"]] == [
        ("2.4.1", "red"), ("2.4.2", "yellow"), ("2.4.3", "yellow"), ("2.4.0", "green")]  # 2.4.0 = previous release
    # Code, not the LLM's "usable" text, writes the recommendation.
    assert r["recommendation"].startswith("Do not install 2.4.1") and "Pin 2.4.0" in r["recommendation"]
    assert not register.REGISTER_PATH.exists()  # scripted approve = "no"


def test_wppconnect_shortened_name_is_never_usable():
    """The original failure: checking 'wppconnect' instead of the scoped package."""
    state = run_case(CASES["wppconnect-malware-range"], {"package": "wppconnect", "ecosystem": "npm", "versions": ["2.4.1"]})
    r = state["report"]
    assert r["areas"]["security"]["status"] == "not_checked" and r["headline"] == rules.UNVERIFIED_HEADLINE
    assert "Usable" not in r["headline"]


def test_parsed_query_is_given_to_the_llm():
    msg = graph.initial_state(CASES["wppconnect-malware-range"]["question"])["messages"][0][1]
    assert "package: @wppconnect-team/wppconnect (ecosystem: npm); versions to check: ['2.4.1', '2.4.2', '2.4.3']" in msg
