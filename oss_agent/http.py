"""The ONLY way the agent talks to the internet.

One function, get(). It enforces: host allowlist, timeout, one retry,
size cap, and a disk cache that doubles as the offline fixture store.
It never raises; callers get {"ok": False, "error": ...} instead.
"""
import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse

import requests

ALLOWED_HOSTS = {
    "api.github.com",
    "raw.githubusercontent.com",
    "services.nvd.nist.gov",
    "endoflife.date",
    "api.osv.dev",
    "registry.npmjs.org",  # package registries: package -> source repo, versions, existence (GET only)
    "repo.packagist.org",
    "pypi.org",
    "crates.io",
    "rubygems.org",
}
POST_ENDPOINTS = {"https://api.osv.dev/v1/query"}  # read-only query API that needs POST; everything else is GET-only
TIMEOUT_S = 15
MAX_BYTES = 2 * 1024 * 1024
CACHE_TTL_S = 24 * 3600  # online: reuse answers from the last day
FRESH_TTL_S = 300  # "what is HEAD now?" must stay fresh, or a re-check would miss new commits
CACHE_DIR = Path(os.getenv("OSS_CACHE_DIR", Path(__file__).parent.parent / "tests" / "fixtures" / "http_cache"))

# Set by main.py --offline: serve only from cache, never touch the network.
OFFLINE = False


def _cache_path(url: str) -> Path:
    # Auth headers are deliberately NOT part of the key, so fixtures contain no secrets.
    return CACHE_DIR / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".json")


def _auth_headers(host: str) -> dict:
    # Secrets are added here, at the last moment, and never logged or cached.
    if host == "api.github.com" and os.getenv("GITHUB_TOKEN"):
        return {"Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}"}
    if host == "services.nvd.nist.gov" and os.getenv("NVD_API_KEY"):
        return {"apiKey": os.getenv("NVD_API_KEY")}
    return {}


def _fetch(url: str, headers: dict, body: dict | None = None) -> requests.Response:
    """One GET (or JSON POST) with a hard size cap (streamed so a huge file can't fill memory)."""
    if body is None:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT_S, stream=True)
    else:
        resp = requests.post(url, json=body, headers=headers, timeout=TIMEOUT_S, stream=True)
    body = b""
    for chunk in resp.iter_content(64 * 1024):
        body += chunk
        if len(body) > MAX_BYTES:
            resp.close()
            raise ValueError("response larger than 2 MB")
    resp._content = body
    return resp


def _error_for(status: int) -> str:
    if status == 404:
        return "not found (404)"
    if status in (403, 429):
        return f"rate limited or forbidden ({status}); try again later or set a token"
    return f"HTTP {status}"


def get(url: str, params: dict | None = None, headers: dict | None = None, as_json: bool = True) -> dict:
    """GET a URL. Returns {"ok": True, "data": <json or text>} or {"ok": False, "error": str}."""
    if params:
        url = f"{url}?{urlencode(params)}"
    return _request(url, headers, as_json, None)


def post_json(url: str, body: dict) -> dict:
    """JSON POST, only to exact read-only query endpoints (POST_ENDPOINTS). Same result shape as get()."""
    if url not in POST_ENDPOINTS:
        return {"ok": False, "error": f"POST not allowed to: {url}"}
    return _request(url, None, True, body)


def _request(url: str, headers: dict | None, as_json: bool, body: dict | None) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        return {"ok": False, "error": f"host not allowed: {parsed.hostname}"}

    # A POST body is part of the cache key: two OSV queries for different versions differ only there.
    path = _cache_path(url if body is None else url + "#" + json.dumps(body, sort_keys=True))
    cached = None
    if path.exists():
        try:  # an unreadable or foreign cache entry is a cache miss, never a crash
            cached = json.loads(path.read_text())
            cached = cached if ("data" in cached or "error" in cached) and "fetched_at" in cached else None
        except (ValueError, OSError):
            cached = None
    if cached:
        ttl = FRESH_TTL_S if "/commits/" in url else CACHE_TTL_S
        if OFFLINE or time.time() - cached["fetched_at"] < ttl:
            if "error" in cached:  # a recorded "not found" replays as "not found", not as "unavailable"
                return {"ok": False, "error": cached["error"], "cached": True}
            return {"ok": True, "data": cached["data"], "cached": True}
    if OFFLINE:
        return {"ok": False, "error": "offline mode: no cached response for this request"}

    all_headers = {"User-Agent": "oss-due-diligence-agent", **(headers or {}), **_auth_headers(parsed.hostname)}
    for attempt in (1, 2):  # one retry, only for transient failures
        try:
            resp = _fetch(url, all_headers, body)
        except requests.Timeout:
            if attempt == 2:
                return {"ok": False, "error": f"timeout after {TIMEOUT_S}s"}
            continue
        except (requests.RequestException, ValueError) as e:
            return {"ok": False, "error": str(e)[:200]}
        if resp.status_code >= 500 and attempt == 1:
            time.sleep(1)
            continue
        if resp.status_code == 404:  # a real answer ("not listed"), so it is cached like one
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"url": url, "fetched_at": time.time(), "error": _error_for(404)}))
        if resp.status_code != 200:
            return {"ok": False, "error": _error_for(resp.status_code)}
        try:
            data = resp.json() if as_json else resp.text
        except ValueError:
            return {"ok": False, "error": "response was not valid JSON"}
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"url": url, "fetched_at": time.time(), "data": data}))
        return {"ok": True, "data": data}
