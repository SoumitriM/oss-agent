"""Graph routing tests with a scripted fake model: no LLM, no network (cached fixtures)."""
import pytest
from langchain_core.messages import AIMessage

from oss_agent import graph, http


class ScriptedModel:
    """Returns pre-written AIMessages in order, like an LLM that always decides the same way."""

    def __init__(self, replies):
        self.replies = list(replies)

    def invoke(self, messages):
        return self.replies.pop(0)


def call(name, args, i=0):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{i}", "type": "tool_call"}])


REPORT = {"repo": "x", "question": "q", "findings": [], "recommendation": "ok",
          "areas": {"licence": {"status": "yellow", "summary": "llm guess"}}}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(http, "OFFLINE", True)


def run(replies):
    app = graph.build_graph(ScriptedModel(replies))
    return app.invoke(graph.initial_state("q"), {"recursion_limit": 50})


def test_direct_answer_ends_without_tools():
    state = run([AIMessage(content="MIT is permissive.")])
    assert state["answer"] == "MIT is permissive." and state["report"] is None
    assert [t["node"] for t in state["trace"]] == ["agent"]


def test_repo_info_then_report_goes_through_checks():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), call("submit_report", {"report": REPORT}, 1)])
    assert [t["node"] for t in state["trace"]] == ["agent", "tools", "agent", "tools", "checks"]
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
    assert [t["node"] for t in state["trace"]] == ["agent", "tools", "agent", "nudge", "agent", "tools", "checks"]
    assert state["report"]["repo"] == "pallets/flask"


def test_stopping_twice_after_nudge_forces_a_partial_report():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}), AIMessage(content="done"), AIMessage(content="done")])
    assert [t["node"] for t in state["trace"]][-4:] == ["nudge", "agent", "force_report", "checks"]
    assert "even after a reminder" in state["report"]["open_questions"][0]


def test_two_invalid_reports_force_a_partial_report():
    state = run([call("submit_report", {"report": {}}), call("submit_report", {"report": {}}, 1)])
    assert state["trace"][-2]["node"] == "force_report"
    assert state["report"]["overall"] == "not_checked"


def test_max_steps_forces_a_partial_report():
    state = run([call("get_repo_info", {"repo": "pallets/flask"}, i) for i in range(graph.MAX_STEPS)])
    assert state["steps"] == graph.MAX_STEPS
    assert "Stopped after" in state["report"]["open_questions"][0]
