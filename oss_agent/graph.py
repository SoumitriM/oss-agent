"""The agent as a LangGraph state machine. Every node is our own function.

START → agent ─route_after_agent─┬─ no tool calls, no tools used yet → END  (direct answer)
                                 ├─ no tool calls, tools used ──────→ nudge → agent (once)
                                 ├─ ... a second time, or steps ≥ MAX_STEPS → force_report → checks → END
                                 └─ otherwise ──────────────────────→ tools
       tools ─route_after_tools──┬─ report accepted ────→ checks → END
                                 ├─ report invalid twice → force_report
                                 └─ otherwise ──────────→ agent
"""
import json
import operator
import time
from typing import Annotated, TypedDict

from langchain_core.messages import SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from oss_agent import llm, report as rep
from oss_agent.prompts import SYSTEM_PROMPT
from oss_agent.tools import DATA_TOOLS, LC_TOOLS, TOOL_SCHEMAS

MAX_STEPS = 10
MAX_RESULT_CHARS = 4000
NUDGE = "You have used tools but not submitted a report. Finish by calling submit_report."


class State(TypedDict):
    question: str
    messages: Annotated[list, add_messages]     # conversation (system prompt added per call)
    steps: int                                  # LLM calls so far
    tool_outputs: Annotated[list, operator.add]  # full results, for quote verification (M2)
    repo_info: dict | None                      # last successful get_repo_info result
    report: dict | None                         # accepted submit_report payload
    report_retries: int                         # invalid submit_report attempts
    nudges: int                                 # "finish with submit_report" reminders sent
    answer: str | None                         # direct answer when no tools were needed
    trace: Annotated[list, operator.add]        # one entry per node run / tool call


def initial_state(question: str) -> dict:
    return {"question": question, "messages": [("user", question)], "steps": 0, "tool_outputs": [],
            "repo_info": None, "report": None, "report_retries": 0, "nudges": 0, "answer": None, "trace": []}


# ---------- helpers (unchanged guardrails from the M1 loop) ----------

def _validate_call(call: dict) -> str | None:
    """Check name and required args against the schema before running anything."""
    schema = next((t for t in TOOL_SCHEMAS if t["name"] == call["name"]), None)
    if schema is None:
        return f"unknown tool '{call['name']}'"
    missing = [k for k in schema["input_schema"]["required"] if k not in call["args"]]
    return f"missing arguments: {missing}" if missing else None


def _wrap(result: dict) -> str:
    """Truncate, then mark as untrusted so the prompt can tell data from instructions."""
    text = json.dumps(result, ensure_ascii=False)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + " ...[truncated]"
    return f"<untrusted_data>\n{text}\n</untrusted_data>"


def _summary(result: dict) -> str:
    if not result.get("ok"):
        return "error: " + result.get("error", "?")
    return ", ".join(f"{k}={str(v)[:30]}" for k, v in result.items()
                     if k != "ok" and not isinstance(v, (dict, list)))[:100]


# ---------- graph ----------

def build_graph(model=None):
    """model is injectable so tests can use a scripted fake instead of a real LLM."""
    model = model or llm.get_model(LC_TOOLS)

    def agent(state: State) -> dict:
        started = time.time()
        reply = llm.invoke(model, [SystemMessage(SYSTEM_PROMPT), *state["messages"]])
        u = reply.usage_metadata or {}
        names = [c["name"] for c in reply.tool_calls]
        update = {"messages": [reply], "steps": state["steps"] + 1, "trace": [{
            "node": "agent", "step": state["steps"] + 1, "detail": "→ " + ", ".join(names) if names else "no tool call",
            "tokens": u.get("input_tokens", 0) + u.get("output_tokens", 0), "seconds": round(time.time() - started, 2)}]}
        if not names:
            update["answer"] = reply.text
        return update

    def tools(state: State) -> dict:
        update = {"messages": [], "tool_outputs": [], "trace": [], "report_retries": state["report_retries"]}
        for call in state["messages"][-1].tool_calls:
            started = time.time()
            error = _validate_call(call)
            if error:
                result = {"ok": False, "error": error}
            elif call["name"] == "submit_report":
                error = rep.validate(call["args"]["report"])
                if error is None:
                    update["report"] = call["args"]["report"]
                    result = {"ok": True}
                else:  # the LLM gets the error and one more try
                    update["report_retries"] += 1
                    result = {"ok": False, "error": f"invalid report: {error}. Fix it and submit again."}
            else:
                result = DATA_TOOLS[call["name"]](**call["args"])  # plain function, never raises
                update["tool_outputs"].append({"tool": call["name"], "args": call["args"], "result": result})
                if call["name"] == "get_repo_info" and result.get("ok"):
                    update["repo_info"] = result
            update["messages"].append(ToolMessage(content=_wrap(result), tool_call_id=call["id"], name=call["name"]))
            update["trace"].append({"node": "tools", "step": state["steps"], "tool": call["name"], "args": call["args"],
                                    "detail": _summary(result), "seconds": round(time.time() - started, 2)})
        return update

    def nudge(state: State) -> dict:
        """The agent stopped talking after using tools: remind it once to submit the report."""
        return {"messages": [("user", NUDGE)], "nudges": state["nudges"] + 1,
                "trace": [{"node": "nudge", "step": state["steps"], "detail": "reminder: finish with submit_report"}]}

    def force_report(state: State) -> dict:
        if state["steps"] >= MAX_STEPS:
            reason = f"Stopped after {MAX_STEPS} steps."
        elif state["nudges"] >= 1 and not state["messages"][-1].tool_calls:
            reason = "The model stopped without submitting a report, even after a reminder."
        else:
            reason = "The model did not produce a valid report."
        return {"report": rep.minimal_report(state["question"], state["repo_info"], reason),
                "trace": [{"node": "force_report", "step": state["steps"], "detail": reason}]}

    def checks(state: State) -> dict:
        report = rep.post_process(dict(state["report"]), state["repo_info"])  # deterministic, no LLM
        return {"report": report, "trace": [{"node": "checks", "step": state["steps"], "detail": f"overall={report['overall']}"}]}

    def route_after_agent(state: State) -> str:
        calls = state["messages"][-1].tool_calls
        tools_used = any(isinstance(m, ToolMessage) for m in state["messages"])
        if not calls and not tools_used:
            return END  # direct answer, e.g. "MIT vs GPL?"
        if any(c["name"] == "submit_report" for c in calls):
            return "tools"  # always let a report through, even on the last step
        if state["steps"] >= MAX_STEPS or (not calls and state["nudges"] >= 1):
            return "force_report"
        return "tools" if calls else "nudge"

    def route_after_tools(state: State) -> str:
        if state["report"] is not None:
            return "checks"
        if state["report_retries"] > 1:
            return "force_report"
        return "agent"

    g = StateGraph(State)
    g.add_node("agent", agent)
    g.add_node("tools", tools)
    g.add_node("nudge", nudge)
    g.add_node("force_report", force_report)
    g.add_node("checks", checks)
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", route_after_agent, ["tools", "nudge", "force_report", END])
    g.add_edge("nudge", "agent")
    g.add_conditional_edges("tools", route_after_tools, ["checks", "force_report", "agent"])
    g.add_edge("force_report", "checks")
    g.add_edge("checks", END)
    return g.compile()
