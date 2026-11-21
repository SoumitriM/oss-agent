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


def test_params_are_part_of_cache_key():
    url = "https://endoflife.date/api/php.json"
    http._cache_path(url + "?v=1").write_text(json.dumps({"url": url, "fetched_at": time.time(), "data": "one"}))
    assert http.get(url, params={"v": "1"})["data"] == "one"
