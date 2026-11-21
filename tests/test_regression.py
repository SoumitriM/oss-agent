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


def run_case(case, vuln_args, resubmit=False):
    """The LLM's report says YELLOW in every run: only code rules may turn it into the right verdict.
    resubmit: the LLM ignores the coverage feedback and submits the same report again."""
    replies = [call("check_vulnerabilities", vuln_args, 1), call("submit_report", {"report": LLM_SAYS_YELLOW}, 2)]
    replies += [call("submit_report", {"report": LLM_SAYS_YELLOW}, 3)] if resubmit else []
    script = dict(case["interrupt_answers"])
    answer = lambda p: (script["ask"].pop(0) if script["ask"] else "") if p["type"] == "ask" else script["approve"]
    return graph.run(graph.build_graph(ScriptedModel(replies)), case["question"], answer)


def test_wppconnect_correct_check_is_red_with_mal_finding():
    case = CASES["wppconnect-malware-range"]
    state = run_case(case, case["expect"]["tool_args"]["check_vulnerabilities"])
    r = state["report"]
    assert r["overall"] in case["expect"]["verdict"] and r["headline"] == case["expect"]["headline"]
    assert any(case["expect"]["required_finding"] in f["claim"] + f["url"] for f in r["findings"])
    assert [(v["version"], v["status"]) for v in r["per_version"]] == [
        ("2.4.1", "red"), ("2.4.2", "yellow"), ("2.4.3", "yellow"), ("2.4.0", "green")]  # 2.4.0 = previous release
    # Code, not the LLM's "usable" text, writes the recommendation.
    assert r["recommendation"].startswith("Do not install 2.4.1") and "Pin 2.4.0" in r["recommendation"]
    assert not register.REGISTER_PATH.exists()  # scripted approve = "no"


def test_wppconnect_shortened_name_is_never_usable():
    """The original failure: checking 'wppconnect' instead of the scoped package."""
    state = run_case(CASES["wppconnect-malware-range"], {"package": "wppconnect", "ecosystem": "npm", "versions": ["2.4.1"]},
                     resubmit=True)
    r = state["report"]
    assert state["coverage_rounds"] == 1  # first submit was sent back: asked versions of the exact package not checked
    assert r["areas"]["security"]["status"] == "not_checked" and r["headline"] == rules.UNVERIFIED_HEADLINE
    assert "Usable" not in r["headline"]


def test_wdio_monorepo_is_found_via_registry_and_critical_cve_is_red():
    case = CASES["wdio-browserstack-cve"]
    guessed = {**LLM_SAYS_YELLOW, "repo": "wdio/browserstack-service",  # the old wrong guess, now overridden by code
               "areas": {"security": {"status": "yellow", "summary": "probably fine"}, "licence": {"status": "green", "summary": "MIT"}}}
    replies = [call("check_vulnerabilities", {"package": "@wdio/browserstack-service", "ecosystem": "npm", "versions": ["9.23.2"]}, 1),
               call("get_repo_info", {"package": "@wdio/browserstack-service", "ecosystem": "npm", "version": "9.23.2"}, 2),
               call("submit_report", {"report": guessed}, 3)]
    state = graph.run(graph.build_graph(ScriptedModel(replies)), case["question"], lambda p: "no")
    r, exp = state["report"], case["expect"]
    assert r["repo"] == exp["repo"] and r["package_location"] == exp["package_location"]
    assert r["areas"]["security"]["status"] == "red" and r["overall"] in exp["verdict"]
    assert any(exp["required_finding"] in f["claim"] for f in r["findings"])
    assert "9.24.0" in r["areas"]["security"]["summary"] and state["questions_asked"] == exp["max_questions"]


def test_unresolvable_package_marks_licence_and_maintenance_not_checked_but_keeps_security():
    replies = [call("check_vulnerabilities", {"package": "@wdio/browserstack-service", "ecosystem": "npm", "versions": ["9.23.2"]}, 1),
               call("get_repo_info", {"package": "@nope-xyz-4821/nothing", "ecosystem": "npm", "version": "1.0.0"}, 2),
               call("submit_report", {"report": {**LLM_SAYS_YELLOW, "areas": {"security": {"status": "yellow", "summary": "s"}}}}, 3)]
    state = graph.run(graph.build_graph(ScriptedModel(replies)), "@wdio/browserstack-service 9.23.2 ok?", lambda p: "no")
    r = state["report"]
    assert r["areas"]["licence"]["status"] == "not_checked" and "could not find the source repo" in r["areas"]["licence"]["summary"]
    assert r["areas"]["security"]["status"] == "red"  # the security result still stands


def test_parsed_query_is_given_to_the_llm():
    msg = graph.initial_state(CASES["wppconnect-malware-range"]["question"])["messages"][0][1]
    assert "package: @wppconnect-team/wppconnect (ecosystem: npm); versions to check: ['2.4.1', '2.4.2', '2.4.3']" in msg
