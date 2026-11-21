"""Graph routing tests with a scripted fake model: no LLM, no network (cached fixtures)."""
import json

import pytest
from langchain_core.messages import AIMessage

from oss_agent import graph, http, register


class ScriptedModel:
    """Returns pre-written AIMessages in order, like an LLM that always decides the same way."""

    def __init__(self, replies):
        self.replies = list(replies)

    def invoke(self, messages):
        return self.replies.pop(0)


def call(name, args, i=0):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{name}{i}", "type": "tool_call"}])


REPORT = {"repo": "x", "question": "q", "findings": [], "recommendation": "ok",
          "areas": {"licence": {"status": "yellow", "summary": "llm guess"}}}


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
    return [t["node"] for t in state["trace"]]


def test_direct_answer_ends_without_tools_or_approval():
    state = run([AIMessage(content="MIT is permissive.")])
    assert state["answer"] == "MIT is permissive." and state["report"] is None
    assert nodes(state) == ["agent"] and state["interrupts"] == []


def test_repo_info_then_report_goes_through_checks_and_approval():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": REPORT}, 1)])
    assert nodes(state) == ["agent", "tools", "agent", "tools", "checks", "approve"]
    # checks overrides the LLM: repo/commit from the API, licence status from the SPDX table
    assert state["report"]["repo"] == "pallets/flask"
    assert state["report"]["areas"]["licence"]["status"] == "green"
    assert state["report"]["areas"]["privacy"]["status"] == "not_checked"


def test_unknown_tool_is_rejected_not_run():
    state = run([call("delete_repo", {}), call("submit_report", {"report": REPORT}, 1)])
    assert "unknown tool" in state["trace"][1]["detail"]


def test_stopping_after_tools_gets_one_nudge_then_report():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), AIMessage(content="Looks fine."),
                 call("submit_report", {"report": REPORT}, 1)])
    assert nodes(state)[:7] == ["agent", "tools", "agent", "nudge", "agent", "tools", "checks"]


def test_stopping_twice_after_nudge_forces_a_partial_report():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), AIMessage(content="done"), AIMessage(content="done")])
    assert nodes(state)[-5:] == ["nudge", "agent", "force_report", "checks", "approve"]
    assert "even after a reminder" in state["report"]["open_questions"][0]


def test_two_invalid_reports_force_a_partial_report():
    state = run([call("submit_report", {"report": {}}), call("submit_report", {"report": {}}, 1)])
    assert "force_report" in nodes(state) and state["report"]["overall"] == "not_checked"


def test_max_steps_forces_a_partial_report():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}, i) for i in range(graph.MAX_STEPS)])
    assert state["steps"] == graph.MAX_STEPS
    assert "Stopped after" in state["report"]["open_questions"][0]


# ---------- human in the loop (M4) ----------

def test_ask_limit_is_enforced_in_code_and_unclear_answer_is_unknown():
    state = run([call("ask_user", {"question": "Internal use?"}, 1), call("ask_user", {"question": "Version?"}, 2),
                 call("ask_user", {"question": "Hosting?"}, 3), call("submit_report", {"report": REPORT}, 4)],
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
    state = run([call("submit_report", {"report": REPORT})], answers=["no"])
    assert nodes(state)[-1] == "approve" and not register.REGISTER_PATH.exists()


def test_recheck_carries_over_unchecked_areas_and_lists_changes():
    first = {**REPORT, "areas": {"maintenance": {"status": "green", "summary": "active"}}}
    run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": first}, 1)], answers=["yes"])
    recheck = {**REPORT, "areas": {"security": {"status": "yellow", "summary": "new advisory"}}}  # maintenance skipped
    state = run([call("lookup_register", {"repo": "pallets/flask"}), call("get_repo_info", {"repo": "pallets/flask"}, 1),
                 call("submit_report", {"report": recheck}, 2)])
    r = state["report"]
    assert r["areas"]["maintenance"]["status"] == "green" and r["areas"]["maintenance"]["carried_over"]
    assert r["areas"]["licence"]["status"] == "green" and "carried_over" not in r["areas"]["licence"]  # re-checked by rule
    assert r["changed_areas"] == ["security"]
