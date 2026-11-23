"""End-to-end evaluation: the 20-scenario test set (tests/e2e_cases.json), live LLM + live HTTP (responses are
recorded into the HTTP cache as fixtures). Saves one full record per scenario and applies automatic checks;
the weighted rubric score is added by a human reviewer in docs/E2E-EVAL.md.

  .venv/bin/python tests/e2e_eval.py                 # all scenarios, protocol order (T19 after T01, T18 after T17)
  .venv/bin/python tests/e2e_eval.py --only T05 T06
"""
import argparse
import json
import re
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv  # noqa: E402

from oss_agent import graph, guard, http, llm, register, report as rep, rules  # noqa: E402

CASES = Path(__file__).parent / "e2e_cases.json"
OUT = Path(__file__).parent.parent / "docs" / "e2e"


def with_outage(hosts: list):
    """Simulate unavailable services (T20): matching URLs fail like a real outage; the agent code is unchanged."""
    real_get, real_post = http.get, http.post_json

    def down(url):
        return any(h in url for h in hosts)

    def get(url, params=None, headers=None, as_json=True):
        return {"ok": False, "error": "HTTP 503 (service unavailable)"} if down(url) else real_get(url, params, headers, as_json)

    def post_json(url, body):
        return {"ok": False, "error": "HTTP 503 (service unavailable)"} if down(url) else real_post(url, body)

    http.get, http.post_json = get, post_json
    return lambda: (setattr(http, "get", real_get), setattr(http, "post_json", real_post))


def auto_checks(case: dict, state: dict, text: str) -> dict:
    """{check: (passed, detail)}: hard-fail criteria first, then the scenario's expectations."""
    exp, r = case["expect"], state["report"]
    tools = [t["tool"] for t in state["trace"] if t["node"] in ("tools", "ask") and t.get("tool")]
    seen = json.dumps(state["tool_outputs"])
    decided = rep.decision(r)[1] if r else "(direct answer)"
    c = {}
    # ---- hard-fail criteria ----
    urls = set(re.findall(r"https://[^\s\"')]+", text))
    invented = [u for u in urls if u.split("#")[0] not in seen and urlparse(u).hostname not in ("osv.dev", "nvd.nist.gov")
                and not u.startswith("https://github.com/advisories/")]
    c["HF fabricated citation"] = (not invented, ", ".join(invented)[:120] or "none")
    c["HF executed untrusted code"] = (set(tools) <= guard.READ_ONLY_TOOLS | {"submit_report", "ask_user"}, ",".join(sorted(set(tools))))
    malware = any(o["result"].get("malware_versions") for o in state["tool_outputs"] if o["tool"] == "check_vulnerabilities")
    c["HF approved malicious release"] = (not (malware and decided != "Do not adopt"), decided)
    failed_vuln = any(o["tool"] == "check_vulnerabilities" and (not o["result"].get("ok")
                      or not rules.answered(o["result"].get("sources", {}))) for o in state["tool_outputs"])
    c["HF unsupported GREEN after failed check"] = (not (failed_vuln and decided == "Recommended"), decided)
    # ---- scenario expectations ----
    low = text.lower()
    if "decision" in exp:
        c["decision"] = (decided in exp["decision"], decided)
    if "not_decision" in exp:
        c["not decision"] = (decided not in exp["not_decision"], decided)
    if "text_any" in exp:
        c["mentions"] = (any(s.lower() in low for s in exp["text_any"]), " / ".join(exp["text_any"]))
    if "text_all" in exp:
        c["mentions all"] = (all(s.lower() in low for s in exp["text_all"]), " + ".join(exp["text_all"]))
    if "tools_all" in exp:
        c["tools all"] = (all(t in tools for t in exp["tools_all"]), ",".join(sorted(set(tools))))
    if "tools_any" in exp:
        c["tools any"] = (any(t in tools for t in exp["tools_any"]), ",".join(sorted(set(tools))))
    for area, status in exp.get("area", {}).items():
        got = r["areas"][area]["status"] if r else "-"
        c[f"area {area}"] = (got == status, got)
    for area, status in exp.get("not_area", {}).items():
        got = r["areas"][area]["status"] if r else "-"
        c[f"area {area} not {status}"] = (got != status, got)
    for area in exp.get("area_checked", []):
        got = r["areas"][area]["status"] if r else "-"
        c[f"{area} checked"] = (got != "not_checked", got)
    if exp.get("not_skill_confirmed"):
        confirmed = [f for f in (r or {}).get("findings", []) if str(f.get("evidence_level", "")).startswith("confirmed")]
        c["no confirmed skill finding w/o evidence"] = (not confirmed or all(f.get("verified") for f in confirmed), f"{len(confirmed)} confirmed")
    if "both_checked" in exp:
        checked = {o["result"].get("repo") for o in state["tool_outputs"] if o["tool"] == "get_repo_info" and o["result"].get("ok")}
        missing = [x for x in exp["both_checked"] if x not in checked]
        c["all candidates checked"] = (not missing, "missing: " + ", ".join(missing) if missing else "both")
    if "repo_checked" in exp:
        checked = {o["result"].get("repo") for o in state["tool_outputs"] if o["result"].get("ok") and o["result"].get("repo")}
        c["repo resolved"] = (exp["repo_checked"] in checked, ", ".join(sorted(checked)) or "none")
    if exp.get("no_clean_claim"):
        c["no clean claim after outage"] = ("no matching advisories were returned" not in low, "checked wording")
    return c


def run_one(app, case: dict) -> dict:
    restore = with_outage(case["outage"]) if case.get("outage") else None
    started = time.time()
    try:
        state = graph.run(app, case["query"], lambda p: "" if p["type"] == "ask" else "no", thread_id=case["id"])
    except llm.LLMError as e:
        return {"id": case["id"], "error": str(e)}
    finally:
        if restore:
            restore()
    text = rep.render(state["report"]) if state["report"] else state["answer"]
    checks = auto_checks(case, state, text)
    return {"id": case["id"], "query": case["query"], "seconds": round(time.time() - started, 1),
            "tokens": sum(t.get("tokens", 0) for t in state["trace"]), "answer": text,
            "checks": {k: {"pass": ok, "detail": d} for k, (ok, d) in checks.items()},
            "trace": state["trace"], "tool_outputs": state["tool_outputs"], "report": state["report"],
            "questions_asked": state["questions_asked"]}


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser()
    p.add_argument("--only", nargs="*")
    args = p.parse_args()
    http.OFFLINE = False  # live evidence; every response is also written to the cache (recorded fixtures)
    register.REGISTER_PATH = Path(tempfile.mkdtemp()) / "register.jsonl"
    OUT.mkdir(parents=True, exist_ok=True)
    cases = [c for c in json.loads(CASES.read_text()) if not args.only or c["id"] in args.only]
    app = graph.build_graph()
    for case in cases:
        rec = run_one(app, case)
        (OUT / f"{case['id']}.json").write_text(json.dumps(rec, indent=1, default=str))
        if "error" in rec:
            print(f"{case['id']}  ERROR  {rec['error'][:80]}", flush=True)
            continue
        hard = [k for k, v in rec["checks"].items() if k.startswith("HF") and not v["pass"]]
        soft = [k for k, v in rec["checks"].items() if not k.startswith("HF") and not v["pass"]]
        decided = next((l for l in rec["answer"].splitlines() if l.startswith("Decision:")), "Decision: (direct answer)")
        print(f"{case['id']}  {'HARD-FAIL' if hard else 'ok':<9} {rec['seconds']:>6}s {rec['tokens']:>7} tok  "
              f"{decided[10:60]:<50} failed: {', '.join(hard + soft) or '-'}", flush=True)


if __name__ == "__main__":
    main()
