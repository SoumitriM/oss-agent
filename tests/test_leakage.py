"""Leak check: no test-case specifics in anything the LLM sees.

The test sets (eval cases, e2e scenarios, regression tests, skill fixtures) are the answers we grade against.
If their names, ids, versions or phrases appear in the system prompt, the tool descriptions or the fixed
notes that tools return, a pass can mean "the prompt told it", not "it works". Comments are exempt
(the LLM never sees them); only string literals and the assembled prompt/schemas are checked.
"""
import ast
import json
import re
from pathlib import Path

from oss_agent import prompts, tools

ROOT = Path(__file__).parent.parent
TESTS = Path(__file__).parent
# Modules whose string literals can reach the LLM (tool results, notes, feedback, nudges).
LLM_VISIBLE_MODULES = ["tools.py", "vulns.py", "skills.py", "graph.py", "evidence.py", "guard.py"]
# Words the product must be able to say whatever the test set is (domain vocabulary, licence names, English).
# Only these are exempt; every name, id, version, path and fixture phrase from the tests stays banned.
VOCABULARY = {"skills", "skill", "node", "rules", "rule", "agent", "charts", "fixtures", "service", "security",
              "review", "threat", "malware", "malicious", "end-of-life", "secret", "line", "date", "team", "apache",
              "dataset", "detect", "prototype", "end of life", "scanner", "days"}


def _test_texts() -> str:
    files = [*TESTS.glob("test_*.py"), *TESTS.glob("*.json"), TESTS / "skill_fixtures.py"]
    return "\n".join(f.read_text() for f in files if f.name != "test_leakage.py")


def banned_terms() -> set:
    raw = _test_texts()
    cases = json.loads((TESTS / "test_cases.json").read_text()) + json.loads((TESTS / "e2e_cases.json").read_text())
    for c in json.loads((TESTS / "robustness" / "cases.json").read_text())["cases"]:  # every wording is test data
        cases += [{"question": q} for q in [c["question"], *c["variants"].values()]]
    questions = " ".join(" ".join(str(c.get(k) or "") for k in ("question", "query", "repo")) for c in cases)
    terms = set()
    terms |= set(re.findall(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+)\b", raw))  # advisory ids
    terms |= set(re.findall(r"\b\d+\.\d+\.\d+\b", questions))  # versions asked about
    for slug in re.findall(r"\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\b", questions):  # owner/repo and their parts
        slug = slug.strip(".")
        if slug.count("/") == 1 and not slug.startswith("http"):
            terms.add(slug.lower())
            terms |= {p.lower() for p in re.split(r"[/_.-]", slug) if len(p) >= 4 and p.lower() not in VOCABULARY}
    terms |= {m.lower() for m in re.findall(r"@?[a-z0-9-]+(?=@\d)", questions)}  # name@version
    terms |= {p.lower() for p in re.findall(r"\b[\w.-]+(?:/[\w.-]+){2,}", questions)}  # file paths in questions
    terms |= {m.lower() for m in re.findall(r"\blines? \d{3,}", raw)}  # exact line numbers of fixture signals
    for c in cases:  # what a passing answer must contain
        e = c.get("expect", {})
        for key in ("required_finding", "text_any", "text_all"):
            v = e.get(key, [])
            terms |= {s.lower() for s in ([v] if isinstance(v, str) else v) if len(s) >= 4}
    # Distinctive phrases from skill fixtures: three consecutive long words ("xxxx yyyy zzzz").
    for s in ast.walk(ast.parse((TESTS / "skill_fixtures.py").read_text())):
        if isinstance(s, ast.Constant) and isinstance(s.value, str):
            words = re.findall(r"[a-z]+", s.value.lower())
            terms |= {" ".join(words[i:i + 3]) for i in range(len(words) - 2) if all(len(w) >= 5 for w in words[i:i + 3])}
    return {t for t in terms if t and len(t) >= 4 and t not in VOCABULARY}


def llm_visible() -> dict:
    """{where: text} for everything the model can read."""
    out = {"prompts.SYSTEM_PROMPT": prompts.SYSTEM_PROMPT, "tools.TOOL_SCHEMAS": json.dumps(tools.TOOL_SCHEMAS)}
    for name in LLM_VISIBLE_MODULES:
        tree = ast.parse((ROOT / "oss_agent" / name).read_text())
        # Regex patterns are matched by code, never shown to the model: re.*(pattern, ...) and *_RE / *PATTERNS tables.
        patterns = {id(a) for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "re" for a in n.args[:1]}
        patterns |= {id(c) for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(
                     isinstance(t, ast.Name) and t.id.endswith(("_RE", "PATTERNS")) for t in n.targets)
                     for c in ast.walk(n.value) if isinstance(c, ast.Constant)}
        docstrings = {id(n.body[0].value) for n in ast.walk(tree) if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef))
                      and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings | patterns:
                out.setdefault(name, "")
                out[name] += "\n" + n.value
    return out


def find_leaks() -> list:
    terms = banned_terms()
    leaks = []
    for where, text in llm_visible().items():
        low = text.lower()
        for t in terms:
            if re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", low):
                leaks.append((where, t))
    return sorted(set(leaks))


def test_banned_terms_are_collected():  # guards the check itself: an empty list would pass everything
    terms = banned_terms()
    assert len(terms) > 50 and "minimistjs/minimist" in terms and any(t.startswith("CVE-") for t in terms)


def test_no_test_case_specifics_in_llm_visible_text():
    leaks = find_leaks()
    assert not leaks, "test-case specifics the LLM can see:\n" + "\n".join(f"  {w}: {t!r}" for w, t in leaks)
