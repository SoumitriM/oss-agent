"""CLI: python -m oss_agent "question" [--trace] [--offline] [--json out.json]"""
import argparse
import json
import sys
import time

from dotenv import load_dotenv

from oss_agent import agent, http, llm, report


def print_trace(trace: list) -> None:
    print("\nTRACE")
    for t in trace:
        args = json.dumps(t["args"])[:60] if t["args"] else ""
        print(f"  {t['step']:>2}. {t['tool'] or '-':<15} {args:<60} {t['tokens']:>6} tok {t['seconds']:>5}s  {t['result']}")


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="oss_agent", description="OSS due-diligence agent")
    parser.add_argument("question", help='e.g. "Can we use pallets/flask in a commercial product?"')
    parser.add_argument("--trace", action="store_true", help="print every agent step")
    parser.add_argument("--offline", action="store_true", help="use cached HTTP responses only")
    parser.add_argument("--json", metavar="FILE", help="write the full record to a JSON file")
    args = parser.parse_args()
    http.OFFLINE = args.offline

    started = time.time()
    try:
        result = agent.run(args.question)
    except llm.LLMError as e:
        sys.exit(f"Error: {e}")
    seconds = round(time.time() - started, 1)

    print(result["answer"] if result["answer"] is not None else report.render(result["report"]))
    n_tools = sum(1 for t in result["trace"] if t["tool"] and t["tool"] != "submit_report")
    print(f"\n({n_tools} tool calls · {seconds} s · --trace for details)")
    if args.trace:
        print_trace(result["trace"])
    if args.json:
        with open(args.json, "w") as f:
            json.dump({**result, "seconds": seconds}, f, indent=2, default=str)
