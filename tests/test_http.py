"""Offline tests for http.py: no network needed."""
import json
import time

import pytest

from oss_agent import http


@pytest.fixture(autouse=True)
def tmp_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(http, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(http, "OFFLINE", False)


def test_rejects_host_not_on_allowlist():
    r = http.get("https://evil.example.com/x")
    assert r == {"ok": False, "error": "host not allowed: evil.example.com"}


def test_rejects_plain_http():
    assert http.get("http://api.github.com/repos/a/b")["ok"] is False


def test_offline_without_cache_returns_error():
    http.OFFLINE = True
    r = http.get("https://api.github.com/repos/a/b")
    assert r["ok"] is False and "offline" in r["error"]


def test_offline_serves_old_cache_entry():
    url = "https://api.github.com/repos/a/b"
    http._cache_path(url).write_text(json.dumps({"url": url, "fetched_at": 0, "data": {"x": 1}}))
    http.OFFLINE = True
    assert http.get(url) == {"ok": True, "data": {"x": 1}, "cached": True}


def test_head_commit_cache_expires_quickly_online(monkeypatch):
    url = "https://api.github.com/repos/a/b/commits/HEAD"
    http._cache_path(url).write_text(json.dumps({"url": url, "fetched_at": time.time() - 600, "data": "old"}))
    monkeypatch.setattr(http, "_fetch", lambda *a: (_ for _ in ()).throw(http.requests.Timeout()))
    assert http.get(url)["ok"] is False  # 10 min old -> not reused, a fresh fetch was attempted


def test_post_only_allowed_to_osv():
    assert http.post_json("https://api.github.com/graphql", {})["error"].startswith("POST not allowed")


def test_post_body_is_part_of_cache_key():
    url, body = "https://api.osv.dev/v1/query", {"version": "2.4.1"}
    key = url + "#" + json.dumps(body, sort_keys=True)
    http._cache_path(key).write_text(json.dumps({"url": url, "fetched_at": time.time(), "data": {"vulns": [1]}}))
    http.OFFLINE = True
    assert http.post_json(url, body)["data"] == {"vulns": [1]}
    assert http.post_json(url, {"version": "2.4.0"})["ok"] is False  # different body, not cached


def test_params_are_part_of_cache_key():
    url = "https://endoflife.date/api/php.json"
    http._cache_path(url + "?v=1").write_text(json.dumps({"url": url, "fetched_at": time.time(), "data": "one"}))
    assert http.get(url, params={"v": "1"})["data"] == "one"
