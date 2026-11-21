"""Quote verification: pure functions, no network."""
from oss_agent import evidence

READ = {"tool": "read_file", "args": {}, "result": {
    "ok": True, "start_line": 28, "url": "https://github.com/o/r/blob/abc/LICENSE.md#L28-L31",
    "content": "   28| ### Limitations\n   29| You may use or modify the software only for your own internal\n"
               "   30| business purposes or for non-commercial or personal use.\n   31| "}}
INFO = {"tool": "get_repo_info", "args": {}, "result": {"ok": True, "repo": "o/r", "archived": False, "licence_spdx": "MIT"}}
SEARCH = {"tool": "search_code", "args": {}, "result": {"ok": True, "hits": [
    {"path": "cfg.ts", "url": "https://github.com/o/r/blob/abc/cfg.ts", "fragments": ["telemetry: boolean = true;"]}]}}


def finding(quote, url="https://github.com/o/r"):
    return {"area": "licence", "claim": "c", "evidence_quote": quote, "url": url, "source_tool": "read_file"}


def test_quote_across_lines_is_verified_and_pinned_to_those_lines():
    [f] = evidence.verify([finding("only for your own internal business purposes")], [READ])
    assert f["verified"] and f["url"] == "https://github.com/o/r/blob/abc/LICENSE.md#L29-L30"


def test_invented_quote_is_unverified():
    [f] = evidence.verify([finding("You may resell the software freely")], [READ, INFO])
    assert not f["verified"] and f["url"] == "https://github.com/o/r"


def test_whitespace_wrapping_quotes_and_ellipsis_are_ignored():
    [f] = evidence.verify([finding('"You may use or   modify the software…"')], [READ])
    assert f["verified"]


def test_metadata_fact_gets_repo_page_even_if_llm_gave_a_file_link():
    [f] = evidence.verify([finding('"archived": false', url="https://github.com/o/r/blob/abc/LICENSE.md")], [READ, INFO])
    assert f["verified"] and f["url"] == "https://github.com/o/r"


def test_search_fragment_quote_links_to_that_file():
    [f] = evidence.verify([finding("telemetry: boolean = true;")], [INFO, SEARCH])
    assert f["verified"] and f["url"] == "https://github.com/o/r/blob/abc/cfg.ts"


def test_empty_quote_is_unverified():
    assert not evidence.verify([finding("")], [READ])[0]["verified"]
