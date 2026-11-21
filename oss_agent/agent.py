"""The agent loop: the LLM decides which tool to call next; code runs it."""
import json
import time

from oss_agent import llm, report as rep
from oss_agent.prompts import SYSTEM_PROMPT
from oss_agent.tools import DATA_TOOLS, TOOL_SCHEMAS

MAX_STEPS = 10
MAX_RESULT_CHARS = 4000


def _validate_call(call: dict) -> str | None:
    """Check name and required args against the schema before running anything."""
    schema = next((t for t in TOOL_SCHEMAS if t["name"] == call["name"]), None)
    if schema is None:
        return f"unknown tool '{call['name']}'"
    if not isinstance(call["input"], dict):
        return "arguments must be an object"
    missing = [k for k in schema["input_schema"]["required"] if k not in call["input"]]
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
    return ", ".join(f"{k}={str(v)[:30]}" for k, v in result.items() if k != "ok" and not isinstance(v, (dict, list)))[:100]


def run(question: str) -> dict:
    """Returns {"answer": str | None, "report": dict | None, "trace": [...], "tool_outputs": [...]}."""
    messages = [{"role": "user", "content": question}]
    trace, tool_outputs = [], []  # tool_outputs: full results, used later for quote verification
    repo_info, report, report_retries = None, None, 0

    for step in range(1, MAX_STEPS + 1):
        reply = llm.chat(SYSTEM_PROMPT, messages, TOOL_SCHEMAS)
        messages.append(reply["assistant_message"])
        tokens = reply["usage"]["input_tokens"] + reply["usage"]["output_tokens"]
        if not reply["tool_calls"]:  # no tools needed: a direct answer (e.g. "MIT vs GPL?")
            trace.append({"step": step, "tool": None, "args": None, "result": "direct answer",
                          "tokens": tokens, "seconds": reply["seconds"]})
            return {"answer": reply["text"], "report": None, "trace": trace, "tool_outputs": tool_outputs}

        results = []
        for call in reply["tool_calls"]:
            started = time.time()
            error = _validate_call(call)
            if error:
                result = {"ok": False, "error": error}
            elif call["name"] == "submit_report":
                error = rep.validate(call["input"]["report"])
                if error is None:
                    report = call["input"]["report"]
                    result = {"ok": True}
                else:  # one retry with the validation error, then fall back
                    report_retries += 1
                    result = {"ok": False, "error": f"invalid report: {error}. Fix it and submit again."}
            else:
                result = DATA_TOOLS[call["name"]](**call["input"])
                tool_outputs.append({"tool": call["name"], "args": call["input"], "result": result})
                if call["name"] == "get_repo_info" and result.get("ok"):
                    repo_info = result
            trace.append({"step": step, "tool": call["name"], "args": call["input"], "result": _summary(result),
                          "tokens": tokens, "seconds": round(reply["seconds"] + time.time() - started, 2)})
            tokens = 0  # count the LLM call's tokens once, on its first tool call
            results.append({"type": "tool_result", "tool_use_id": call["id"], "content": _wrap(result)})

        if report is not None:
            break
        if report_retries > 1:
            report = rep.minimal_report(question, repo_info, "The model did not produce a valid report.")
            break
        messages.append({"role": "user", "content": results})
    else:  # MAX_STEPS reached without a report: partial report, rest marked not checked
        report = rep.minimal_report(question, repo_info, f"Stopped after {MAX_STEPS} steps.")

    return {"answer": None, "report": rep.post_process(report, repo_info), "trace": trace, "tool_outputs": tool_outputs}
