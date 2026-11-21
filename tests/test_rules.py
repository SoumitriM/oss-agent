"""Deterministic rules: no network, no LLM."""
from oss_agent import report, rules

EOL = {"ok": True, "version": "8.1", "endoflife": {
    "supported_cycles": ["8.6", "8.5"], "cycle": "8.1", "eol_date": "2025-12-31", "is_eol": True}}
MALWARE = {"type": "malware", "id": "GHSA-x", "affected": ["= 1.14.1"]}


def test_end_of_life_version_is_red_with_upgrade_advice():
    status, note = rules.vulnerability_rule(EOL)
    assert status == "red" and "8.6" in note


def test_malware_for_given_version_is_red():
    assert rules.vulnerability_rule({"version": "1.14.1", "github_items": [MALWARE]})[0] == "red"


def test_malware_without_version_is_yellow_and_names_bad_releases():
    status, note = rules.vulnerability_rule({"version": None, "github_items": [MALWARE]})
    assert status == "yellow" and "= 1.14.1" in note


def test_rule_never_makes_an_area_better():
    area = {"status": "red", "summary": "llm"}
    report._raise_status(area, ("yellow", "note"))
    assert area["status"] == "red" and area["summary"] == "llm"


def test_legal_refs_only_for_verified_findings_and_cra_for_security():
    findings = [
        {"area": "privacy", "claim": "telemetry on", "verified": True, "tags": ["telemetry_on_by_default"]},
        {"area": "privacy", "claim": "invented", "verified": False, "tags": ["data_to_non_eu_service"]},
    ]
    areas = {"security": {"status": "yellow"}}
    articles = [r["article"] for r in rules.legal_refs(findings, areas)]
    assert articles == ["GDPR Art. 25", "CRA Art. 13(5)"]
