"""Graph routing tests with a scripted fake model: no LLM, no network (cached fixtures)."""
import json

import pytest
from langchain_core.messages import AIMessage

from oss_agent import graph, guard, http, register, rules
from oss_agent.report import render as rep_text


class ScriptedModel:
    """Returns pre-written AIMessages in order, like an LLM that always decides the same way."""

    def __init__(self, replies):
        self.replies = list(replies)

    def invoke(self, messages):
        return self.replies.pop(0)


def call(name, args, i=0):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{name}{i}", "type": "tool_call"}])


LICENCE_FINDING = {"area": "licence", "claim": "Permissive licence: keep the notice.", "evidence_quote": "Copyright 2010 Pallets",
                   "url": "x", "source_tool": "get_repo_info"}  # a real line of the recorded licence file
REPORT = {"repo": "x", "question": "q", "findings": [LICENCE_FINDING], "recommendation": "ok",
          "areas": {"licence": {"status": "green", "summary": "BSD-3-Clause"}}}
NOTHING_CLAIMED = {"repo": "x", "question": "q", "findings": [], "recommendation": "ok", "areas": {}}


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(http, "OFFLINE", True)
    monkeypatch.setattr(register, "REGISTER_PATH", tmp_path / "register.jsonl")


def run(replies, answers=()):
    """Like main.py: scripted interrupt answers; default "" for ask and "no" for approve."""
    answers, asked = list(answers), []

    def answer_fn(payload):
        asked.append(payload["type"])
        return answers.pop(0) if answers else ("" if payload["type"] == "ask" else "no")

    state = graph.run(graph.build_graph(ScriptedModel(replies)), "q", answer_fn)
    state["interrupts"] = asked
    return state


def nodes(state):
    return [t["node"] for t in state["trace"] if t["node"] != "guard"]


def test_direct_answer_ends_without_tools_or_approval_and_is_labelled():
    state = run_q("MIT vs GPL: which is safer for us?", [AIMessage(content="MIT is permissive.")])  # no evidence intent
    assert state["answer"] == guard.GENERAL_REPLY and "MIT is permissive" not in state["answer"]  # never from memory
    assert state["report"] is None and nodes(state) == ["agent"]


def run_q(question, replies, answers=()):
    answers = list(answers)
    fn = lambda p: (answers.pop(0) if answers else "") if p["type"] == "ask" else "no"
    return graph.run(graph.build_graph(ScriptedModel(replies)), question, fn)


def test_repo_info_then_report_goes_through_checks_and_approval():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": REPORT}, 1)])
    assert nodes(state) == ["agent", "tools", "agent", "tools", "checks", "approve"]
    r = state["report"]  # identity from the API; the agent's backed licence verdict stands; nothing else is claimed
    assert r["repo"] == "pallets/flask" and r["commit"]
    assert r["areas"]["licence"]["status"] == "green" and r["findings"][0]["url"].endswith("LICENSE.txt#L1")
    assert r["areas"]["privacy"]["status"] == "not_checked"


def test_unknown_tool_is_rejected_not_run():
    state = run([call("delete_repo", {}), call("submit_report", {"report": NOTHING_CLAIMED}, 1)])
    assert "unknown tool" in [t for t in state["trace"] if t["node"] == "tools"][0]["detail"]


def test_stopping_after_tools_gets_one_nudge_then_report():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), AIMessage(content="Looks fine."),
                 call("submit_report", {"report": REPORT}, 1)])
    assert nodes(state)[:7] == ["agent", "tools", "agent", "nudge", "agent", "tools", "checks"]


def test_stopping_twice_after_nudge_forces_a_partial_report():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), AIMessage(content="done"), AIMessage(content="done")])
    assert nodes(state)[-5:] == ["nudge", "agent", "force_report", "checks", "approve"]
    assert "even after a reminder" in state["report"]["limitations"][0] and not state["report"]["open_questions"]


def test_two_invalid_reports_force_a_partial_report():
    state = run([call("submit_report", {"report": {}}), call("submit_report", {"report": {}}, 1)])
    assert "force_report" in nodes(state) and state["report"]["overall"] == "not_checked"


def test_max_steps_forces_a_partial_report():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}, i) for i in range(graph.MAX_STEPS)])
    assert state["steps"] == graph.MAX_STEPS
    assert "Stopped after" in state["report"]["limitations"][0] and not state["report"]["open_questions"]


# ---------- evidence feedback loop ----------

UNBACKED = {**REPORT, "areas": {**REPORT["areas"], "security": {"status": "green", "summary": "no issues"}}}


def test_unbacked_status_gets_one_feedback_round_and_the_agent_can_fix_it():
    fixed = {**REPORT, "areas": {**REPORT["areas"], "security": {"status": "not_checked", "summary": "not checked"}}}
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": UNBACKED}, 1),
                 call("submit_report", {"report": fixed}, 2)])
    first_submit = [t for t in state["trace"] if t.get("tool") == "submit_report"][0]
    assert first_submit["detail"].startswith("sent back: 1 evidence gap") and "security" in first_submit["detail"]
    assert state["evidence_rounds"] == 1 and state["report"]["areas"]["security"]["status"] == "not_checked"


def test_same_unbacked_status_twice_is_set_not_checked_by_code():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": UNBACKED}, 1),
                 call("submit_report", {"report": UNBACKED}, 2)])
    sec = state["report"]["areas"]["security"]
    assert sec["status"] == "not_checked" and "no verified evidence" in sec["summary"]
    assert state["report"]["areas"]["licence"]["status"] == "green"  # the backed area is untouched


def test_invented_quote_is_sent_back_then_marked_unverified():
    invented = {**REPORT, "findings": [{**LICENCE_FINDING, "evidence_quote": "Licensed under the friendly terms"}]}
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": invented}, 1),
                 call("submit_report", {"report": invented}, 2)])
    r = state["report"]  # never claimed: left out of the answer, and the disclosure says so
    assert r["findings"] == [] and r["areas"]["licence"]["status"] == "not_checked"
    assert r["left_out"] and "friendly terms" not in rep_text(r)


def test_plan_text_is_captured_in_the_trace():
    planned = AIMessage(content="Plan: licence only, so get_repo_info is enough.",
                        tool_calls=[{"name": "get_repo_info", "args": {"repo": "pallets/flask"}, "id": "p1", "type": "tool_call"}])
    state = run([planned, call("submit_report", {"report": REPORT}, 1)])
    [entry] = [t for t in state["trace"] if t.get("plan")]
    assert entry["plan_kind"] == "plan" and "get_repo_info is enough" in entry["plan"]


# ---------- human in the loop (M4) ----------

def test_ask_limit_is_enforced_in_code_and_unclear_answer_is_unknown():
    state = run([call("ask_user", {"question": "Internal use?"}, 1), call("ask_user", {"question": "Version?"}, 2),
                 call("ask_user", {"question": "Hosting?"}, 3), call("submit_report", {"report": NOTHING_CLAIMED}, 4)],
                answers=["internal only", "?"])
    asks = [t["detail"] for t in state["trace"] if t["node"] == "ask"]
    assert asks[0] == "internal only" and asks[1].startswith("UNKNOWN") and asks[2] == graph.LIMIT_REACHED
    assert state["questions_asked"] == 2 and state["interrupts"] == ["ask", "ask", "approve"]


def test_approved_record_is_saved_with_decision():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": REPORT}, 1)],
                answers=["yes ok for internal use"])
    assert nodes(state)[-2:] == ["approve", "register"]
    [saved] = [json.loads(line) for line in register.REGISTER_PATH.read_text().splitlines()]
    assert saved["repo"] == "pallets/flask" and saved["decision"]["approved"] and saved["decision"]["comment"] == "ok for internal use"


def test_rejected_record_is_not_saved():
    state = run([call("submit_report", {"report": NOTHING_CLAIMED})], answers=["no"])
    assert nodes(state)[-1] == "approve" and not register.REGISTER_PATH.exists()


def test_a_crashing_tool_becomes_an_error_result_not_a_crash(monkeypatch):
    def boom(**kwargs):
        raise KeyError("data")
    monkeypatch.setitem(graph.DATA_TOOLS, "get_repo_info", boom)
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": NOTHING_CLAIMED}, 1)])
    assert "tool failed unexpectedly: KeyError" in [t for t in state["trace"] if t["node"] == "tools"][0]["detail"]


# ---------- several independent tools in one step ----------

def calls(*specs):
    return AIMessage(content="", tool_calls=[{"name": n, "args": a, "id": f"m{i}", "type": "tool_call"}
                                             for i, (n, a) in enumerate(specs)])


def test_independent_tools_run_in_one_step():
    state = run([calls(("get_repo_info", {"repo": "pallets/flask"}), ("lookup_register", {"repo": "pallets/flask"})),
                 call("submit_report", {"report": REPORT}, 1)])
    assert nodes(state)[:4] == ["agent", "tools", "tools", "agent"]  # two tool runs, one agent step
    assert state["steps"] == 2 and state["report"]["repo"] == "pallets/flask"


def test_question_in_the_same_step_is_asked_after_the_tools():
    state = run([calls(("get_repo_info", {"repo": "pallets/flask"}), ("ask_user", {"question": "Which version?"})),
                 call("submit_report", {"report": REPORT}, 1)], answers=["2.0"])
    assert nodes(state)[:4] == ["agent", "tools", "ask", "agent"]
    assert [t["answer"] for t in state["trace"] if t["node"] == "ask"] == ["2.0"]
    assert state["report"]["areas"]["licence"]["status"] == "green"  # the tool result in that step still counts
