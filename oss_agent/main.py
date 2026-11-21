"""CLI: python -m oss_agent "question" [--trace] [--offline] [--json out.json] [--show-graph]"""
import argparse
import json
import sys
import time

from dotenv import load_dotenv

from oss_agent import graph, http, llm, report


def print_trace(trace: list) -> None:
    print("\nTRACE")
    for t in trace:
        what = f"{t['tool']} {json.dumps(t['args'])[:50]}" if t.get("tool") else t["detail"]
        result = t["detail"] if t.get("tool") else ""
        tokens = f"{t['tokens']:>6} tok" if "tokens" in t else " " * 10
        seconds = f"{t['seconds']:>5}s" if "seconds" in t else " " * 6
        print(f"  {t['step']:>2} {t['node']:<12} {what:<62} {tokens} {seconds}  {result[:70]}")


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="oss_agent", description="OSS due-diligence agent")
    parser.add_argument("question", nargs="?", help='e.g. "Can we use pallets/flask in a commercial product?"')
    parser.add_argument("--trace", action="store_true", help="print every node run and tool call")
    parser.add_argument("--offline", action="store_true", help="use cached HTTP responses only")
    parser.add_argument("--json", metavar="FILE", help="write the full record to a JSON file")
    parser.add_argument("--show-graph", action="store_true", help="print the agent graph as Mermaid and exit")
    args = parser.parse_args()
    http.OFFLINE = args.offline

    try:
        app = graph.build_graph()
        if args.show_graph:
            print(app.get_graph().draw_mermaid())
            return
        if not args.question:
            parser.error("a question is required")
        started = time.time()
        state = app.invoke(graph.initial_state(args.question), {"recursion_limit": 4 * graph.MAX_STEPS})
    except llm.LLMError as e:
        sys.exit(f"Error: {e}")
    seconds = round(time.time() - started, 1)

    print(state["answer"] if state["report"] is None else report.render(state["report"]))
    n_tools = sum(1 for t in state["trace"] if t.get("tool") and t["tool"] != "submit_report")
    print(f"\n({n_tools} tool calls · {seconds} s · --trace for details)")
    if args.trace:
        print_trace(state["trace"])
    if args.json:
        keys = ("question", "answer", "report", "trace", "tool_outputs")
        with open(args.json, "w") as f:
            json.dump({**{k: state[k] for k in keys}, "seconds": seconds}, f, indent=2, default=str)
