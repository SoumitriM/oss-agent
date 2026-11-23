"""Evaluation: run every case in test_cases.json N times with the real LLM and check the behaviour.

  .venv/bin/python tests/eval.py --record          # once, online: fills the HTTP fixtures
  .venv/bin/python tests/eval.py                    # offline (cached HTTP), 3 runs per case
  .venv/bin/python tests/eval.py --case php-81-eol --runs 1

Per run, checks: required tools called, forbidden tools not called, steps <= max_steps,
questions asked <= 2, all quotes verified, expected verdict, plus optional area statuses,
headline, required finding text and legal article. Interrupts get the case's scripted answers.
The register is a fresh temp file per run, so earlier approvals never change a case.
"""
import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # run as a plain script from the repo root

from dotenv import load_dotenv  # noqa: E402

from oss_agent import graph, guard, http, llm, register  # noqa: E402

CASES = Path(__file__).parent / "test_cases.json"


def answer_fn(script: dict):
    asks = list(script.get("ask", []))
    return lambda p: (asks.pop(0) if asks else "") if p["type"] == "ask" else script.get("approve", "no")


def first_plan(state: dict) -> str:
    return next((t["plan"] for t in state["trace"] if t.get("plan")), "")


def similarity(a: str, b: str) -> float:
    """Jaccard overlap of the words of two plans (0 = nothing shared, 1 = same words)."""
    wa, wb = set(a.lower().split()), set(b.lower().split())
    return len(wa & wb) / len(wa | wb) if wa and wb else 0.0


def plan_diversity(plans: dict, limit: float = 0.7) -> tuple[bool, str]:
    """Plans for different question types should differ: the model plans, it does not follow a script."""
    pairs = [(similarity(plans[a], plans[b]), a, b) for i, a in enumerate(plans) for b in list(plans)[i + 1:]]
    if not pairs:
        return True, "not enough plans to compare"
    worst = max(pairs)
    return worst[0] <= limit, f"max similarity {worst[0]:.2f} ({worst[1]} vs {worst[2]}), limit {limit}"


def check(case: dict, state: dict) -> dict:
    """{check name: (passed, detail)} for one run."""
    exp, report = case["expect"], state["report"]
    tools = [t["tool"] for t in state["trace"] if t["node"] == "tools"]
    data_calls = [t for t in tools if t != "submit_report"]
    verdict = report["overall"] if report else "none"
    findings = report["findings"] if report else []
    checks = {
        "tools": (all(t in tools for t in exp["required_tools"]) and not any(t in tools for t in exp["forbidden_tools"]),
                  ",".join(dict.fromkeys(tools)) or "-"),
        "steps": (state["steps"] <= exp["max_steps"], f"{state['steps']}/{exp['max_steps']}"),
        "plan": (not data_calls or any(t.get("plan") for t in state["trace"]), "written" if first_plan(state) else "missing"),
        "questions": (state["questions_asked"] <= exp.get("max_questions", graph.MAX_QUESTIONS), str(state["questions_asked"])),
        "quotes": (all(f.get("verified") for f in findings), f"{sum(bool(f.get('verified')) for f in findings)}/{len(findings)}"),
        "verdict": (verdict in exp["verdict"], verdict),
    }
    if "max_tool_calls" in exp:  # simple questions must stay cheap
        checks["calls"] = (len(data_calls) <= exp["max_tool_calls"], f"{len(data_calls)}/{exp['max_tool_calls']}")
    if "refusal" in exp:  # out of scope or role-change: the agent's marker becomes code's fixed text
        checks["refusal"] = (state["answer"] in (guard.REFUSAL, guard.TOO_LONG, guard.GENERAL_REPLY), (state["answer"] or "-")[:40])
    if "min_tool_calls" in exp:  # questions about component facts must use evidence
        checks["min_calls"] = (len(data_calls) >= exp["min_tool_calls"], f"{len(data_calls)}>={exp['min_tool_calls']}")
    for key in ("repo", "package_location"):
        if key in exp:
            checks[key] = ((report or {}).get(key) == exp[key], (report or {}).get(key) or "-")
    for area, status in exp.get("areas", {}).items():
        got = report["areas"][area]["status"] if report else "none"
        checks[f"area:{area}"] = (got in (status if isinstance(status, list) else [status]), got)
    if "min_inspected" in exp:  # targeted follow-up: flagged lines were actually looked at (quality, not sequence)
        n = len([c for c in data_calls if c == "read_file"])
        checks["inspected"] = (n >= exp["min_inspected"], f"{n}>={exp['min_inspected']}")
    if "not_headline" in exp:
        checks["not_headline"] = ((report or {}).get("headline") != exp["not_headline"], (report or {}).get("headline") or "-")
    if "headline" in exp:
        checks["headline"] = ((report or {}).get("headline") == exp["headline"], (report or {}).get("headline") or "-")
    if "required_finding" in exp:
        text = json.dumps([[f["claim"], f["evidence_quote"], f["url"]] for f in findings]).lower()
        checks["finding"] = (exp["required_finding"].lower() in text, exp["required_finding"])
    if "required_legal" in exp:
        arts = [r["article"] for r in (report or {}).get("legal", [])]
        checks["legal"] = (exp["required_legal"] in arts, ",".join(arts) or "-")
    return checks


def fixture_misses(state: dict) -> list:
    """Tool calls that failed only because the offline cache had no recording for them (eval setup, not agent)."""
    misses = []
    for o in state["tool_outputs"]:
        text = json.dumps(o["result"])
        if "offline mode: no cached response" in text:
            misses.append(f"{o['tool']}({json.dumps(o['args'])[:50]})")
    return misses


def run_case(app, case: dict, run_no: int, offline: bool) -> dict:
    started = time.time()
    http.OFFLINE = offline and case.get("http") != "online"  # free-form search queries can't be pre-recorded
    try:
        state = graph.run(app, case["question"], answer_fn(case["interrupt_answers"]), thread_id=f"{case['id']}-{run_no}")
    except llm.LLMError as e:
        return {"ok": False, "checks": {"llm": (False, str(e)[:60])}, "tokens": 0, "seconds": round(time.time() - started, 1)}
    checks = check(case, state)
    misses = fixture_misses(state)
    if misses:  # not counted as pass or fail: re-record (--record) or mark the case "http": "online"
        checks = {"fixture": (False, "no recording for " + ", ".join(misses))}
    return {"ok": all(passed for passed, _ in checks.values()), "miss": bool(misses), "checks": checks, "plan": first_plan(state),
            "tokens": sum(t.get("tokens", 0) for t in state["trace"]), "seconds": round(time.time() - started, 1)}


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser()
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--case", help="run only this case id")
    p.add_argument("--record", action="store_true", help="online, 1 run: (re)fill the HTTP fixtures")
    args = p.parse_args()
    runs = 1 if args.record else args.runs
    cases = [c for c in json.loads(CASES.read_text()) if not args.case or c["id"] == args.case]
    register.REGISTER_PATH = Path(tempfile.mkdtemp()) / "register.jsonl"  # never the real register
    app = graph.build_graph()

    print(f"{'case':<28} {'run':>3}  {'result':<6} {'tokens':>7} {'sec':>6}  failed checks / details")
    results, pending = [], []
    for case in cases:
        if case.get("pending"):
            pending.append(case["id"])
            print(f"{case['id']:<28} {'-':>3}  {'skip':<6} {'':>7} {'':>6}  pending: {case['pending']}")
            continue
        register.REGISTER_PATH.unlink(missing_ok=True)
        for n in range(1, runs + 1):
            r = run_case(app, case, n, offline=not args.record)
            results.append((case["id"], r))
            failed = [f"{k}={d}" for k, (ok, d) in r["checks"].items() if not ok]
            detail = "; ".join(failed) if failed else f"verdict={r['checks'].get('verdict', (0, '?'))[1]}, tools={r['checks'].get('tools', (0, '?'))[1]}"
            label = "MISS" if r.get("miss") else "PASS" if r["ok"] else "FAIL"
            print(f"{case['id']:<28} {n:>3}  {label:<6} {r['tokens']:>7} {r['seconds']:>6}  {detail}", flush=True)

    scored = [(cid, r) for cid, r in results if not r.get("miss")]  # fixture misses are not agent results
    if scored:
        passed = sum(r["ok"] for _, r in scored)
        misses = len(results) - len(scored)
        print(f"\nPass rate: {passed}/{len(scored)} runs ({100 * passed // len(scored)}%) · "
              f"avg {sum(r['tokens'] for _, r in scored) // len(scored)} tokens · "
              f"avg {sum(r['seconds'] for _, r in scored) / len(scored):.1f} s per run"
              + (f" · fixture misses (not scored): {misses}" if misses else "")
              + (f" · pending: {', '.join(pending)}" if pending else ""))
        by_case = {}
        for cid, r in scored:
            by_case.setdefault(cid, []).append(r["ok"])
        print("Per case: " + " · ".join(f"{cid} {sum(v)}/{len(v)}" for cid, v in by_case.items()))
        plans = {cid: r["plan"] for cid, r in reversed(scored) if r.get("plan")}  # first run's plan per case
        diverse, detail = plan_diversity(plans)
        print(f"Plan diversity: {'PASS' if diverse else 'FAIL'} · {detail}")
    else:
        diverse = False
    sys.exit(0 if scored and diverse and all(r["ok"] for _, r in scored) else 1)


if __name__ == "__main__":
    main()
