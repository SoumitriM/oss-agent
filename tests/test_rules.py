"""Deterministic rules: no network, no LLM."""
import pytest

from oss_agent import report, rules


def vuln(package="@wppconnect-team/wppconnect", malware=None, per_version=None, sources=None, versions=None, items=None, ok=True):
    return {"ok": ok, "package_checked": package, "versions_checked": versions or [],
            "sources": sources or {"osv": "ok", "github": "ok"}, "malware_versions": malware or {},
            "per_version": per_version or {}, "items": items or []}


# ---------- licence ----------

@pytest.mark.parametrize("spdx", ["LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "lgpl-3.0+", " LGPL-2.1-or-later "])
def test_lgpl_variants_are_weak_copyleft_green_with_note(spdx):
    status, note = rules.licence_rule(spdx, True)
    assert status == "green" and "weak copyleft" in note


@pytest.mark.parametrize("spdx,base", [("GPL-3.0-or-later", "GPL-3.0"), ("AGPL-3.0-only", "AGPL-3.0"), ("mit", "MIT"), (None, None)])
def test_normalise_spdx(spdx, base):
    assert rules.normalise_spdx(spdx) == base


def test_noassertion_with_lgpl_header_is_recognised_from_text():
    text = "GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n Copyright (C) 2007"
    status, note = rules.licence_rule("NOASSERTION", True, text)
    assert status == "green" and "LGPL-3.0 (recognised from the licence file header)" in note


def test_custom_licence_is_left_to_the_llm():
    assert rules.licence_rule("NOASSERTION", True, "Sustainable Use License Version 1.0") is None


# ---------- package identity ----------

def test_shortened_package_name_counts_as_wrong_package():
    asked = "@wppconnect-team/wppconnect@2.4.1–2.4.3 this version?"
    assert rules.wrong_package(asked, "wppconnect")
    assert not rules.wrong_package(asked, "@wppconnect-team/wppconnect")


def test_plain_names_must_appear_in_question_or_answers():
    assert not rules.wrong_package("Can we add axios/axios?", "axios")
    assert rules.wrong_package("Can we add axios/axios?", "got")


# ---------- security ----------

MAL = {"2.4.1": ["MAL-2026-20044"]}
PV = {"2.4.1": {"malware": ["MAL-2026-20044"], "vulnerabilities": []}, "2.4.2": {"malware": [], "vulnerabilities": []}}


def test_malware_for_any_asked_version_is_red_with_headline():
    rule = rules.security_rule([vuln(malware=MAL, per_version=PV, versions=["2.4.1", "2.4.2"])], "@wppconnect-team/wppconnect")
    assert rule["status"] == "red" and rule["headline"] == rules.MALWARE_HEADLINE and "MAL-2026-20044" in rule["note"]


def test_other_versions_next_to_malware_are_not_proven_clean():
    rows = rules.per_version_verdicts([vuln(malware=MAL, per_version=PV)])
    assert [(r["version"], r["status"]) for r in rows] == [("2.4.1", "red"), ("2.4.2", "yellow")]
    assert "not proven clean" in rows[1]["detail"]


def test_wrong_package_or_failed_check_means_not_verified():
    for results in ([vuln(package="wppconnect")], [{"ok": False, "error": "bad name"}],
                    [vuln(sources={"osv": "unavailable: timeout", "github": "unavailable: 403"})]):
        rule = rules.security_rule(results, "@wppconnect-team/wppconnect@2.4.1")
        assert rule["status"] == "not_checked" and rule["headline"] == rules.UNVERIFIED_HEADLINE


def test_end_of_life_version_is_red_with_upgrade_advice():
    r = vuln(package="php", per_version={"8.1": {"malware": [], "vulnerabilities": [], "eol": {"is_eol": True, "eol_date": "2025-12-31"}}},
             versions=["8.1"])
    r["endoflife"] = {"supported_cycles": ["8.6", "8.5"]}
    rule = rules.security_rule([r], "PHP 8.1 php/php-src")
    assert rule["status"] == "red" and "8.6" in rule["note"]


def test_malware_without_version_is_yellow_and_names_bad_releases():
    r = vuln(package="axios", items=[{"id": "MAL-1", "type": "malware", "affected": ["1.14.1"]}])
    rule = rules.security_rule([r], "Can we add axios/axios?")
    assert rule["status"] == "yellow" and "1.14.1" in rule["note"]


def test_forced_not_checked_overrides_an_llm_green():
    rep = {"repo": "x", "question": "q", "findings": [], "recommendation": "ok",
           "areas": {"security": {"status": "green", "summary": "llm says fine"}}}
    out = {"tool": "check_vulnerabilities", "result": vuln(package="wppconnect")}
    r = report.post_process(rep, None, [out], "@wppconnect-team/wppconnect@2.4.1")
    assert r["areas"]["security"]["status"] == "not_checked" and r["headline"] == rules.UNVERIFIED_HEADLINE


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
    assert [r["article"] for r in rules.legal_refs(findings, areas)] == ["GDPR Art. 25", "CRA Art. 13(5)"]
