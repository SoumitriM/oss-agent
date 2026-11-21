"""Query normalising: exact names, repos and versions from the question."""
import pytest

from oss_agent.query import as_prompt, parse_query


def test_scoped_npm_package_with_en_dash_range():
    p = parse_query("@wppconnect-team/wppconnect@2.4.1–2.4.3 this version?")
    assert p["packages"] == [{"name": "@wppconnect-team/wppconnect", "ecosystem": "npm", "versions": ["2.4.1", "2.4.2", "2.4.3"]}]
    assert p["repos"] == []  # never guessed from the scope: the npm registry is asked instead
    assert "never guess it from the name" in as_prompt(p)


def test_version_after_a_space_belongs_to_the_only_package():
    p = parse_query("We use @wdio/browserstack-service 9.23.2 with BrowserStack smart selection in our CI pipeline. Is it safe?")
    assert p["packages"] == [{"name": "@wdio/browserstack-service", "ecosystem": "npm", "versions": ["9.23.2"]}]
    assert p["repos"] == []


@pytest.mark.parametrize("q", ["@wppconnect-team/wppconnect@2.4.1 - 2.4.3", "@wppconnect-team/wppconnect@2.4.1..2.4.3"])
def test_range_spellings(q):
    assert parse_query(q)["packages"][0]["versions"] == ["2.4.1", "2.4.2", "2.4.3"]


def test_repo_and_loose_version():
    p = parse_query("Our portal runs PHP 8.1 (php/php-src). Do we need to act?")
    assert p["repos"] == [{"repo": "php/php-src", "how": "as written"}] and p["versions"] == ["8.1"]


def test_plain_package_at_version_is_not_a_repo():
    p = parse_query("is axios@1.14.1 safe?")
    assert p["packages"][0]["name"] == "axios" and p["packages"][0]["versions"] == ["1.14.1"] and p["repos"] == []


def test_github_url_gives_repo():
    assert parse_query("https://github.com/axios/axios/blob/main/README.md ok?")["repos"][0]["repo"] == "axios/axios"


def test_wide_range_is_not_expanded():
    p = parse_query("flask versions 2.0 to 3.1?")
    assert p["versions"] == ["2.0", "3.1"] and "too wide" in p["notes"][0]


def test_nothing_recognised_gives_no_prompt_block():
    assert as_prompt(parse_query("MIT vs GPL: which is safer for us?")) is None
