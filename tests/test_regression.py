"""Regression cases from tests/test_cases.json, replayed offline (recorded HTTP fixtures, scripted agent).
These check what CODE guarantees whatever the agent writes: malware is red, a substituted package name is never
an approval, a package's repository comes from the registry. The agent's own judgement (CVE severity, licence,
skills) is measured live in tests/eval.py."""
import json
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from oss_agent import graph, http, register, report, rules

CASES = {c["id"]: c for c in json.loads((Path(__file__).parent / "test_cases.json").read_text())}
AGENT_SAYS_FINE = {"repo": "r", "question": "q", "recommendation": "Usable with conditions.", "findings": [],
                   "areas": {"security": {"status": "yellow", "summary": "No known issues"}}}


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


def run(question, calls, agent_report=AGENT_SAYS_FINE):
    """The agent ignores the evidence feedback and submits the same report twice."""
    replies = [call(n, a, i) for i, (n, a) in enumerate(calls)]
    replies += [call("submit_report", {"report": agent_report}, 90), call("submit_report", {"report": agent_report}, 91)]
    return graph.run(graph.build_graph(ScriptedModel(replies)), question, lambda p: "no")


def test_malicious_release_is_red_even_when_the_agent_says_fine():
    case = CASES["wppconnect-malware-range"]
    state = run(case["question"], [("check_vulnerabilities", case["expect"]["tool_args"]["check_vulnerabilities"])])
    r = state["report"]
    assert r["overall"] == "red" and r["headline"] == rules.MALWARE_HEADLINE
    assert any(case["expect"]["required_finding"] in f["claim"] + f["url"] for f in r["findings"])
    assert report.decision(r)[1] == "Do not adopt" and "Decision: 🔴 Do not adopt" in report.render(r)


def test_substituted_package_name_is_never_an_approval():
    """The original failure: the scoped package asked about, the unscoped look-alike checked."""
    case = CASES["wppconnect-malware-range"]
    state = run(case["question"], [("check_vulnerabilities", {"package": "wppconnect", "ecosystem": "npm", "versions": ["2.4.1"]})])
    r = state["report"]
    assert r["areas"]["security"]["status"] == "not_checked" and r["headline"] == rules.UNVERIFIED_HEADLINE
    assert "not the package asked about" in r["areas"]["security"]["summary"]
    assert report.decision(r)[1] == report.INSUFFICIENT


def test_package_repository_comes_from_the_registry_not_a_guess():
    case = CASES["wdio-browserstack-cve"]
    guessed = {**AGENT_SAYS_FINE, "repo": "a-guessed/repo"}
    state = run(case["question"], [("get_repo_info", {"package": "@wdio/browserstack-service", "ecosystem": "npm",
                                                      "version": "9.23.2"})], guessed)
    r, exp = state["report"], case["expect"]
    assert r["repo"] == exp["repo"] and r["package_location"] == exp["package_location"]


def test_question_reaches_the_agent_as_written():
    question = CASES["wppconnect-malware-range"]["question"]
    assert graph.initial_state(question)["messages"][0][1] == question
