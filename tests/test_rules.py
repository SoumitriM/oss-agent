"""The few code rules: safety, evidence, decision, confidence. No network, no LLM.
Names here are neutral placeholders: the rules must hold for any package."""
import pytest

from oss_agent import report, rules

OK = {"osv": "ok", "github": "ok", "nvd": "ok", "endoflife": "no match: 'example-lib' is not an endoflife.date product id"}
NVD_NO_MATCH = {"osv": "skipped: give an ecosystem", "github": "skipped: give an ecosystem",
                "nvd": "no match: NVD has no CVE under cpe:2.3:a:example:product", "endoflife": "ok"}
OUTAGE = {"osv": "unavailable: HTTP 503", "github": "unavailable: HTTP 503", "nvd": "unavailable: HTTP 503", "endoflife": "ok"}
MAL = {"id": "MAL-0000-1", "type": "malware", "summary": "Malicious code in example-lib", "url": "https://osv.dev/vulnerability/MAL-0000-1"}


def vuln(package="example-lib", versions=("1.0.1",), sources=OK, malware=None, ok=True, ecosystem="npm", confirmed=True):
    return {"ok": ok, "package_checked": package, "ecosystem": ecosystem, "package_confirmed": confirmed, "versions_checked": list(versions), "sources": dict(sources),
            "malware_versions": malware or {}, "per_version": {v: {"malware": [], "vulnerabilities": []} for v in versions},
            "items": [MAL] if malware else []}


NOWHERE = "a sentence that no tool returned"
DATA = ("search_code", {"ok": True, "hits": [{"path": "p", "url": "https://github.com/example/lib/blob/abc/p",
                                              "fragments": ["the quoted fact"]}]})


def finding(area, quote="the quoted fact", **extra):
    return {"area": area, "claim": "c", "evidence_quote": quote, "url": "u", "source_tool": "t", **extra}


def build(areas, findings=(), outputs=(), question="Can we use example-lib@1.0.1?", confidence=None):
    """Run the real post_process on an agent report. Findings are verified against outputs by code."""
    r = {"repo": "example/lib", "question": question, "recommendation": "r", "findings": list(findings),
         "areas": {a: {"status": s, "summary": s} for a, s in areas.items()}}
    if confidence:
        r["confidence"] = confidence
    return report.post_process(r, None, [{"tool": t, "args": {}, "result": res} for t, res in [DATA, *outputs]], question)


SEC_EVIDENCE = ("check_vulnerabilities", vuln())
SEC_FINDING = finding("security", quote="example-lib")  # text from the check result


# ---------- rule 1: malware ----------

def test_malicious_release_is_red_whatever_the_agent_said():
    r = build({"security": "green"}, [SEC_FINDING], [("check_vulnerabilities", vuln(malware={"1.0.1": ["MAL-0000-1"]}))])
    assert r["areas"]["security"]["status"] == "red" and r["headline"] == rules.MALWARE_HEADLINE
    assert r["findings"][0]["url"] == MAL["url"] and report.decision(r)[1] == "Do not adopt"


# ---------- rule 2: approval needs a working vulnerability check ----------

@pytest.mark.parametrize("result", [
    vuln(sources=OUTAGE),                       # only endoflife answered: no advisory database
    vuln(ok=False),                             # the check failed
    vuln(package="example-lib-extra"),          # a different package than the one asked about
    vuln(sources=NVD_NO_MATCH, ecosystem=None),                 # a product with NVD only: zero CVEs may mean a wrong vendor/product
])
def test_green_security_without_a_working_check_is_not_checked(result):
    r = build({"security": "green", "licence": "green"}, [SEC_FINDING, finding("licence")],
              [("check_vulnerabilities", result)])
    assert r["areas"]["security"]["status"] == "not_checked" and r["headline"] == rules.UNVERIFIED_HEADLINE
    assert report.decision(r)[1] != "Recommended"
    assert "no matching advisories" not in report.render(r).lower()


def test_safety_never_makes_security_better():
    r = build({"security": "red"}, [SEC_FINDING], [("check_vulnerabilities", vuln(sources=OUTAGE))])
    assert r["areas"]["security"]["status"] == "red"


@pytest.mark.parametrize("asked,checked,wrong", [
    ("@scope/name@2.0.0", "name", True),          # scoped name shortened
    ("@scope/name@2.0.0", "@scope/name", False),
    ("example-lib@1.0.1 ok?", "example-lib-extra", True),  # look-alike
    ("Is example-lib@1.0.1. fine", "example-lib", False),  # sentence punctuation
    ("Is the Example runtime 9 ok?", "example", False),    # loosely named: the agent maps it, the target is shown
])
def test_wrong_package_only_when_the_user_named_one_explicitly(asked, checked, wrong):
    assert rules.wrong_package(asked, checked) is wrong


# ---------- rule 3 and evidence ----------

def test_status_without_verified_finding_is_not_checked():
    r = build({"licence": "green", "maintenance": "green"}, [finding("licence", NOWHERE)])
    assert r["areas"]["licence"]["status"] == "not_checked" and r["areas"]["maintenance"]["status"] == "not_checked"


def test_confirmed_skill_claim_needs_lines_read_with_read_file():
    quote = "send the token to the server"
    read = ("read_file", {"ok": True, "content": f"  12| {quote}", "start_line": 12,
                          "url": "https://github.com/o/r/blob/abc/SKILL.md#L12"})
    scan = ("scan_skill", {"ok": True, "signals": [{"excerpt": quote, "line": 12, "url": "u"}]})
    inspected = build({"skills": "red"}, [finding("skills", quote, evidence_level="confirmed_dangerous")], [read])
    assert inspected["findings"][0]["evidence_level"] == "confirmed_dangerous"
    scanned_only = build({"skills": "red"}, [finding("skills", quote, evidence_level="confirmed_dangerous")], [scan])
    assert scanned_only["findings"][0]["evidence_level"] == "suspicious" and scanned_only["findings"][0]["downgraded"]


def test_legal_refs_only_for_verified_findings():
    r = build({"privacy": "yellow"}, [finding("privacy", tags=["telemetry_on_by_default"]),
                                      finding("privacy", NOWHERE, tags=["data_to_non_eu_service"])])
    assert [x["article"] for x in r["legal"]] == ["GDPR Art. 25"]


# ---------- decision and confidence ----------

def test_decision_follows_the_worst_backed_area():
    assert report.decision(build({"security": "green"}, [SEC_FINDING], [SEC_EVIDENCE]))[1] == "Recommended"
    assert report.decision(build({"security": "green", "licence": "yellow"}, [SEC_FINDING, finding("licence")],
                                 [SEC_EVIDENCE]))[1] == "Usable with conditions"
    assert report.decision(build({"licence": "red"}, [finding("licence")]))[1] == "Do not adopt"


def test_no_approval_without_a_security_or_skill_check():
    r = build({"licence": "green", "maintenance": "green"}, [finding("licence"), finding("maintenance")])
    assert report.decision(r)[1] == report.INSUFFICIENT


def test_fallback_report_is_never_an_approval():
    r = report.post_process(report.minimal_report("q", {"repo": "example/lib"}, "stopped"), None, [], "q")
    assert report.decision(r)[1] == report.INSUFFICIENT and r["confidence"]["level"] == "low"


def test_confidence_is_lowered_never_raised():
    high = {"level": "high", "reason": "all checked"}
    assert build({"security": "green"}, [SEC_FINDING], [SEC_EVIDENCE], confidence=high)["confidence"]["level"] == "high"
    unverified = build({"security": "green"}, [SEC_FINDING, finding("security", NOWHERE)],
                       [SEC_EVIDENCE], confidence=high)
    assert unverified["confidence"]["level"] == "medium"
    assert build({"licence": "green"}, [finding("licence")], confidence=high)["confidence"]["level"] == "low"
    low = {"level": "low", "reason": "a source failed"}
    assert build({"security": "green"}, [SEC_FINDING], [SEC_EVIDENCE], confidence=low)["confidence"]["level"] == "low"


def test_answer_shows_decision_confidence_and_evidence():
    text = report.render(build({"security": "green"}, [SEC_FINDING], [SEC_EVIDENCE],
                               confidence={"level": "high", "reason": "all advisory sources answered"}))
    assert "Decision: 🟢 Recommended" in text and "Confidence: high" in text and "✔" in text
    assert "☑ Vulnerability databases: example-lib@1.0.1 in osv, github, nvd" in text and " ☐ File read" in text
    assert "     → https://osv.dev/list?q=example-lib" in text  # a clickable link per check


def test_unchecked_areas_are_not_listed():
    text = report.render(build({"security": "green"}, [SEC_FINDING], [SEC_EVIDENCE]))
    assert "not checked" not in text.lower() and "⚪" not in text and "Licence" not in text


def test_consistency_check_catches_a_wrong_decision_line():
    r = build({"licence": "red"}, [finding("licence")])
    assert report.check_consistency(r, "Decision: 🟢 Recommended")


def test_insufficient_evidence_always_says_why():
    r = build({"licence": "yellow"}, [finding("licence")])
    text = report.render(r)
    assert report.decision(r)[1] == report.INSUFFICIENT
    assert "Only licence was checked. Security was not checked" in text
    fallback = report.post_process(report.minimal_report("q", None, "stopped"), None, [], "q")
    assert "Nothing could be checked" in report.render(fallback)


def test_a_specific_question_gets_an_answer_not_a_verdict():
    r = build({"licence": "yellow"}, [finding("licence")])
    r["kind"] = "answer"
    r = report.post_process(r, None, [{"tool": "search_code", "args": {}, "result": DATA[1]}], "q")
    text = report.render(r)
    assert report.decision(r)[1] == report.ANSWER and "Decision: ℹ️ Answer" in text
    assert "Checked: licence. This answers your question; it is not a security review." in text
    assert "approve" not in text.split("\n")[1].lower()


def test_a_red_finding_is_never_just_an_answer():
    r = build({"licence": "red"}, [finding("licence")])
    r["kind"] = "answer"
    assert report.decision(r)[1] == "Do not adopt"


# ---------- nothing unverified is claimed ----------

def test_unsupported_version_in_summary_or_next_step_is_left_out_and_disclosed():
    r = {"repo": "example/lib", "question": "Is example-lib@1.0.1 safe?", "findings": [SEC_FINDING],
         "areas": {"security": {"status": "green", "summary": "ok"}},
         "recommendation": "Keep 1.0.1 for now. Later move to 9.9.9 for new features.",
         "conditions": [{"action": "Pin 1.0.1 in your lockfile.", "finding": 1},
                        {"action": "Upgrade to 1.2.4 next quarter.", "finding": 1}]}
    r = report.post_process(r, None, [{"tool": t, "args": {}, "result": res} for t, res in [DATA, SEC_EVIDENCE]], r["question"])
    text = report.render(r)
    assert "9.9.9" not in r["recommendation"] and "Keep 1.0.1 for now." in r["recommendation"]  # 1.0.1: from the user
    assert [c["action"] for c in r["conditions"]] == ["Pin 1.0.1 in your lockfile."]
    assert "1.2.4" not in text.split("Not verified")[0]
    assert "Not verified" in text and "2 statements left out" in text
    assert r["confidence"]["level"] != "high"


def test_follow_up_is_part_of_the_answer_not_a_limitation():
    r = build({"security": "green"}, [SEC_FINDING], [SEC_EVIDENCE])
    r["open_questions"] = ["Will customers use it directly?"]
    text = report.render(r)
    assert "Follow-up\n • Will customers use it directly?" in text and "Limitations" not in text
    assert text.index("Follow-up") < text.index("Why")  # shown with the answer, before the evidence


def test_feedback_round_names_the_unsupported_fact():
    from oss_agent import evidence
    found = evidence.gaps({"areas": {}, "findings": [], "recommendation": "Upgrade to 1.2.4.", "conditions": []}, [], "q")
    assert found == ["recommendation names '1.2.4', which no tool result or user statement contains"]


# ---------- every next step is traceable: a source, or labelled as advice ----------

def test_only_next_steps_resting_on_a_verified_finding_are_shown():
    r = {"repo": "example/lib", "question": "Can we use example-lib internally?", "recommendation": "Yes, internally.",
         "findings": [finding("licence", "the quoted fact"), finding("licence", NOWHERE)],
         "areas": {"licence": {"status": "yellow", "summary": "internal use only"}},
         "conditions": [{"action": "Use it only for internal work.", "finding": 1},
                        {"action": "Run a security check before real use."},
                        {"action": "Get written permission for client use.", "finding": 2}]}
    r = report.post_process(r, None, [{"tool": "search_code", "args": {}, "result": DATA[1]}], r["question"])
    text = report.render(r)
    shown = report.present(r)["next"]
    assert [s["text"] for s in shown] == ["Use it only for internal work."]
    assert shown[0]["source"]["quote"] == "the quoted fact" and 'Source: "the quoted fact"' in text
    flat = " ".join(text.split())
    assert "Run a security check" not in flat.split("Not verified")[0] and "Advice" not in flat
    assert "next step with no source" in flat and "resting on an unverified claim" in flat  # both disclosed cited an unverified finding: left out, disclosed


def test_feedback_round_flags_a_step_citing_a_missing_or_unverified_finding():
    from oss_agent import evidence
    rep = {"areas": {}, "recommendation": "", "findings": [finding("licence", NOWHERE)],
           "conditions": [{"action": "a", "finding": 1}, {"action": "b", "finding": 5}, {"action": "c"}]}
    found = evidence.gaps(rep, [{"tool": "search_code", "args": {}, "result": DATA[1]}], "q")
    assert any("rests on finding 1, whose quote was not found" in g for g in found)
    assert any("cites finding 5, which does not exist" in g for g in found)
    assert any("next step 3 rests on no finding" in g for g in found)


# ---------- limitations: only what was needed and failed ----------

def test_limitations_list_failed_needed_checks_and_nothing_irrelevant():
    outputs = [("find_version", {"ok": False, "error": "example/lib publishes no GitHub releases"}),
               ("check_vulnerabilities", vuln(sources={**OK, "osv": "unavailable: HTTP 503"}))]
    r = build({"security": "green", "licence": "green"}, [SEC_FINDING, finding("licence", NOWHERE)], outputs)
    text = report.render(r)
    lim = report.present(r)["limitations"]
    assert "Version lookup could not run: example/lib publishes no GitHub releases." in lim
    assert "Vulnerability databases for example-lib: no answer from osv (HTTP 503)." in lim
    assert "Licence: the assessment could not be backed by a source, so it is not shown." in lim
    assert text.index("Limitations") < text.index("Why")  # in the main answer
    assert "Privacy" not in " ".join(lim) and "Maintenance" not in " ".join(lim)  # not needed: never listed


def test_a_failure_that_was_redone_successfully_is_not_a_limitation():
    outputs = [("read_file", {"ok": False, "error": "nope.md: not found (404)"}), ("read_file", {"ok": True, "path": "a.md", "content": "    1| text", "start_line": 1, "end_line": 1, "url": "https://github.com/example/lib/blob/abc/a.md#L1-L1"})]
    r = report.post_process({"repo": "x", "question": "q", "recommendation": "r", "findings": [], "areas": {}}, None,
                            [{"tool": t, "args": {"repo": "example/lib"}, "result": res} for t, res in outputs], "q")
    assert r["limitations"] == []


# ---------- rule 4: versions involved but not checked ----------

def test_versions_not_checked_block_approval_and_are_named():
    partly = {**vuln(versions=[f"1.{i}.0" for i in range(3, 13)]), "not_checked_versions": ["1.1.0", "1.2.0"]}
    r = build({"security": "green"}, [SEC_FINDING], [("check_vulnerabilities", partly)], confidence={"level": "high", "reason": "r"})
    assert report.decision(r)[1] == "Usable with conditions"          # never Recommended with unknown versions
    assert any("1.1.0, 1.2.0" in x for x in r["limitations"])          # code names them, not the agent
    assert r["confidence"]["level"] == "medium"


def test_a_version_checked_in_a_second_call_is_not_listed_as_unchecked():
    first = {**vuln(versions=[f"1.{i}.0" for i in range(3, 13)]), "not_checked_versions": ["1.1.0", "1.2.0"]}
    second = vuln(versions=["1.1.0", "1.2.0"])
    r = build({"security": "green"}, [SEC_FINDING], [("check_vulnerabilities", first), ("check_vulnerabilities", second)])
    assert report.decision(r)[1] == "Recommended" and not any("not checked for" in x for x in r["limitations"])


def test_a_wrong_endoflife_id_for_a_product_is_a_limitation_but_not_for_a_package():
    product = vuln(ecosystem=None, sources={**NVD_NO_MATCH, "nvd": "ok",
                                            "endoflife": "no match: 'example' is not an endoflife.date product id"})
    r = build({"security": "green"}, [SEC_FINDING], [("check_vulnerabilities", product)])
    assert any("End-of-life status for example-lib was not checked" in x for x in r["limitations"])
    package = vuln()  # an npm package not on endoflife.date is normal, not a gap
    r = build({"security": "green"}, [SEC_FINDING], [("check_vulnerabilities", package)])
    assert not any("End-of-life" in x for x in r["limitations"])


# ---------- rule 5: a package name its registry did not confirm ----------

def test_unconfirmed_package_name_is_never_green_and_is_a_limitation():
    r = build({"security": "green"}, [SEC_FINDING], [("check_vulnerabilities", vuln(confirmed=False))],
              confidence={"level": "high", "reason": "r"})
    assert r["areas"]["security"]["status"] == "yellow" and report.decision(r)[1] != "Recommended"
    assert any("could not be confirmed in its registry (example-lib (npm))" in x for x in r["limitations"])
    assert r["confidence"]["level"] == "medium"


def test_confirmed_in_a_later_call_counts():
    outputs = [("check_vulnerabilities", vuln(confirmed=False)), ("check_vulnerabilities", vuln())]
    r = build({"security": "green"}, [SEC_FINDING], outputs)
    assert r["areas"]["security"]["status"] == "green" and not any("registry" in x for x in r["limitations"])
