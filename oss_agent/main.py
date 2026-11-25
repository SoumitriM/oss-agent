"""CLI: python -m oss_agent "question" [--trace] [--offline] [--json out.json] [--show-graph]
                                      [--answer TEXT ...]"""
import argparse
import json
import sys
import textwrap
import time

from dotenv import load_dotenv

from oss_agent import graph, http, llm, report


def print_trace(trace: list) -> None:
    print("\nTRACE")
    for t in trace:
        what = f"{t['tool']} {json.dumps(t['args'])[:50]}" if t.get("tool") else t["detail"]
        result = t["detail"] if t.get("tool") else ""
        tokens = f"{t['tokens']:>6} tok" if "tokens" in t else " " * 10
        if t.get("cache_read"):  # input tokens served from the prompt cache
            tokens += f" ({t['cache_read']} cached)"
        seconds = f"{t['seconds']:>5}s" if "seconds" in t else " " * 6
        print(f"  {t['step']:>2} {t['node']:<12} {what:<62} {tokens} {seconds}  {result[:70]}")
        if t.get("plan"):  # the model's own plan / plan update, written before its tool call
            for i, line in enumerate(textwrap.wrap(" ".join(t["plan"].split()), 100)):
                print(f"     {(t['plan_kind'] + ':') if i == 0 else '':<13}{line}")


def make_answer_fn(script: dict | None):
    """Answers to the agent's questions: from the human (input) or, offline/in eval, from a script
    {"ask": [answers in order]}. Default: "" (unknown)."""
    def answer(payload: dict) -> str:
        prompt = f"\n❓ {payload['question']}\n> "
        if script is None:
            return input(prompt)
        asks = script.setdefault("ask", [])
        reply = asks.pop(0) if asks else ""
        print(prompt + reply + "   (scripted)")
        return reply
    return answer


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="oss_agent", description="OSS due-diligence agent")
    parser.add_argument("question", nargs="?", help='e.g. "Can we use pallets/flask in a commercial product?"')
    parser.add_argument("--trace", action="store_true", help="print every node run and tool call")
    parser.add_argument("--offline", action="store_true", help="use cached HTTP responses only; scripted answers")
    parser.add_argument("--json", metavar="FILE", help="write the full record to a JSON file")
    parser.add_argument("--show-graph", action="store_true", help="print the agent graph as Mermaid and exit")
    parser.add_argument("--answer", action="append", metavar="TEXT", help="scripted answer to the agent's next question")
    parser.add_argument("--haiku", action="store_true", help="use Haiku and its prompt (default: Sonnet)")
    args = parser.parse_args()
    llm.choose_model(args.haiku)
    http.OFFLINE = args.offline
    # Scripted answers offline, when any are given, or when nobody is at the keyboard.
    use_script = args.answer or args.offline or not sys.stdin.isatty()
    script = {"ask": list(args.answer or [])} if use_script else None

    try:
        app = graph.build_graph()
        if args.show_graph:
            print(app.get_graph().draw_mermaid())
            return
        if not args.question:
            parser.error("a question is required")
        started = time.time()
        state = graph.run(app, args.question, make_answer_fn(script))
    except llm.LLMError as e:
        sys.exit(f"Error: {e}")
    except (KeyboardInterrupt, EOFError):  # Ctrl+C / Ctrl+D while waiting for an answer
        sys.exit("\nCancelled.")
    seconds = round(time.time() - started, 1)

    if state["report"] is None:
        print(state["answer"])  # direct answer: no report
    else:
        print(report.render(state["report"]))
    n_tools = sum(1 for t in state["trace"] if t.get("tool") not in (None, "submit_report", "ask_user"))
    n_q = state["questions_asked"]
    print(f"\n({n_tools} tool calls · {n_q} question{'s' * (n_q != 1)} · {seconds} s · --trace for details)")
    if args.trace:
        print_trace(state["trace"])
    if args.json:
        keys = ("question", "answer", "report", "trace", "tool_outputs")
        with open(args.json, "w") as f:
            json.dump({**{k: state[k] for k in keys}, "seconds": seconds}, f, indent=2, default=str)
