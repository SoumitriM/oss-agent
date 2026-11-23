"""Tools gather facts; the agent judges them. Recorded fixtures (offline) or fake HTTP; no LLM."""
import pytest

from oss_agent import http, tools, vulns


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(http, "OFFLINE", True)


# ---------- licence facts: what get_repo_info shows the agent ----------

@pytest.mark.parametrize("repo,root,sub_files,note", [
    ("pallets/flask", ["LICENSE.txt"], None, None),                         # one licence file, detected
    ("facebook/rocksdb", ["COPYING", "LICENSE.Apache", "LICENSE.leveldb"], None, "Several licence files"),
    ("date-fns/date-fns", [], ["pkgs/core/LICENSE.md"], "sub-folders"),     # monorepo: licence per package
    ("jackfrued/Python-100-Days", [], [], None),                            # nothing anywhere
])
def test_licence_facts_on_recorded_repos(repo, root, sub_files, note):
    r = tools._repo_info(repo)
    assert r["root_licence_files"] == root
    if sub_files is not None:
        assert all(f in r["sub_licence_files"] for f in sub_files)
    assert (note in r.get("licence_note", "")) if note else not r.get("licence_note")


def test_licence_folder_is_not_a_licence_file():
    assert "licenses" not in tools._repo_info("apache/echarts")["root_licence_files"]


# ---------- withdrawn advisories are not vulnerabilities ----------

def test_withdrawn_advisory_is_ignored_on_a_recorded_package():
    r = vulns.check_vulnerabilities("jsonwebtoken", "npm", ["8.5.1"])
    withdrawn = r["withdrawn_ignored"][0]
    assert withdrawn not in r["per_version"]["8.5.1"]["vulnerabilities"]
    assert withdrawn not in [x["id"] for x in r["items"]]
    assert r["per_version"]["8.5.1"]["vulnerabilities"]  # the live advisories remain


def test_withdrawn_entries_are_dropped_from_every_source(monkeypatch):
    gh = [{"ghsa_id": "GHSA-gone", "withdrawn_at": "2023-01-27T00:00:00Z", "type": "reviewed", "severity": "critical",
           "summary": "x", "html_url": "u", "vulnerabilities": []},
          {"ghsa_id": "GHSA-live", "withdrawn_at": None, "type": "reviewed", "severity": "low", "cve_id": None,
           "summary": "y", "html_url": "u", "vulnerabilities": []}]
    osv = {"vulns": [{"id": "OSV-gone", "withdrawn": "2024-01-01T00:00:00Z"}, {"id": "OSV-live", "summary": "z"}]}
    monkeypatch.setattr(http, "get", lambda url, params=None, headers=None, as_json=True: {"ok": True, "data": gh})
    monkeypatch.setattr(http, "post_json", lambda url, body: {"ok": True, "data": osv})
    assert vulns._github("p", "npm", ["1.0.0"])[2] == {"withdrawn": ["GHSA-gone"]}
    pv, _, extra = vulns._osv("p", "npm", ["1.0.0"])
    assert pv == {"1.0.0": ["OSV-live"]} and extra == {"withdrawn": ["OSV-gone"]}


def test_rejected_nvd_cve_is_not_matched(monkeypatch):
    match = {"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "vulnerable": True, "versionEndExcluding": "2.0"}
    cve = lambda i, status: {"id": i, "vulnStatus": status, "published": "2022-01-01", "descriptions": [{"value": "d"}],
                             "metrics": {}, "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}
    data = {"totalResults": 2, "vulnerabilities": [{"cve": cve("CVE-1", "Rejected")}, {"cve": cve("CVE-2", "Analyzed")}]}
    monkeypatch.setattr(http, "get", lambda url, params=None, headers=None, as_json=True: {"ok": True, "data": data})
    pv, _, extra = vulns._nvd("v", "p", ["1.0"])
    assert pv == {"1.0": ["CVE-2"]} and extra["withdrawn"] == ["CVE-1"]


# ---------- find_version: a described version becomes an exact, sourced one ----------

from datetime import date  # noqa: E402

from oss_agent import versions  # noqa: E402


class FixedDate(date):
    @classmethod
    def today(cls):
        return cls(2026, 6, 1)


NPM = {"time": {"created": "2024-01-01T00:00:00Z", "modified": "2026-05-20T00:00:00Z", "1.0.0": "2025-01-10T00:00:00Z",
                "1.1.0": "2025-10-01T00:00:00Z", "1.2.0-beta.1": "2025-11-15T00:00:00Z", "1.2.0": "2026-02-01T00:00:00Z",
                "1.2.1": "2026-05-20T00:00:00Z"}}
RELEASES = [{"tag_name": "v3.1.0", "published_at": "2026-04-02T10:00:00Z", "draft": False, "prerelease": False},
            {"tag_name": "v3.1.0-rc1", "published_at": "2026-03-20T10:00:00Z", "draft": False, "prerelease": True},
            {"tag_name": "v3.0.2", "published_at": "2025-11-02T10:00:00Z", "draft": False, "prerelease": False},
            {"tag_name": "v2.9.9", "published_at": "2026-04-10T10:00:00Z", "draft": False, "prerelease": False}]  # backport


@pytest.fixture
def fake_http(monkeypatch):
    monkeypatch.setattr(versions, "date", FixedDate)
    data = {"registry.npmjs.org": NPM, "/releases": RELEASES,
            "endoflife.date": [{"cycle": "9", "latest": "9.4.1", "latestReleaseDate": "2026-05-01"},
                               {"cycle": "8", "latest": "8.12.3", "latestReleaseDate": "2026-04-01"}]}
    monkeypatch.setattr(http, "get", lambda url, params=None, headers=None, as_json=True:
                        next(({"ok": True, "data": d} for k, d in data.items() if k in url), {"ok": False, "error": "404"}))


def test_latest_is_the_newest_stable_release(fake_http):
    r = versions.find_version("latest", package="example-lib", ecosystem="npm")
    assert r["version"] == "1.2.1" and r["source"] == "npm registry" and r["newer_releases"] == 0


def test_months_ago_gives_the_version_of_that_date_and_what_came_since(fake_http):
    r = versions.find_version("6 months ago", package="example-lib")  # 2026-06-01 minus 180 days = 2025-12-03
    assert r["as_of"] == "2025-12-03" and r["version"] == "1.1.0"  # the beta is skipped
    assert r["newer"] == ["1.2.0", "1.2.1"] and r["latest"]["version"] == "1.2.1"


def test_repository_releases_skip_prereleases_and_order_by_version(fake_http):
    r = versions.find_version("2026-04-05", repo="example/app")
    assert r["version"] == "3.1.0"  # the later 2.9.9 backport is not "newer"
    assert versions.find_version("2026-01-01", repo="example/app")["version"] == "3.0.2"


def test_product_latest_from_endoflife_but_no_history(fake_http):
    assert versions.find_version("latest", product="Example")["version"] == "9.4.1"
    assert not versions.find_version("6 months ago", product="example")["ok"]


def test_unreadable_when_and_missing_target_are_errors(fake_http):
    assert "not 'latest'" in versions.find_version("last spring", package="example-lib")["error"]
    assert not versions.find_version("latest")["ok"]


# ---------- read_file at a version's tag ----------

def fake_repo(monkeypatch, tags):
    """A repo whose tags map to commits; raw files return text that names the commit."""
    def get(url, params=None, headers=None, as_json=True):
        if "/commits/" in url:
            ref = url.rsplit("/commits/", 1)[1]
            sha = {"HEAD": "f" * 40, **tags}.get(ref)
            return {"ok": True, "data": {"sha": sha}} if sha else {"ok": False, "error": "not found (404)"}
        return {"ok": True, "data": f"code at {url.split('/')[5][:7]}\nline 2"}
    monkeypatch.setattr(http, "get", get)


def test_read_file_at_a_version_tag_pins_that_commit(monkeypatch):
    fake_repo(monkeypatch, {"v1.2.3": "a" * 40})
    r = tools.read_file("example/lib", "src/verify.js", ref="1.2.3")  # written without the "v"
    assert r["ref"] == "v1.2.3" and r["commit"] == "a" * 40 and "code at aaaaaaa" in r["content"]
    assert r["url"].startswith("https://github.com/example/lib/blob/" + "a" * 40 + "/src/verify.js#L")


def test_read_file_without_ref_is_the_latest_code(monkeypatch):
    fake_repo(monkeypatch, {})
    r = tools.read_file("example/lib", "src/verify.js")
    assert r["commit"] == "f" * 40 and r["ref"].startswith("HEAD")


def test_unknown_version_never_falls_back_to_the_latest_code(monkeypatch):
    fake_repo(monkeypatch, {})
    r = tools.read_file("example/lib", "src/verify.js", ref="9.9.9")
    assert not r["ok"] and "not read" in r["error"] and "content" not in r


def test_unsafe_ref_is_rejected(monkeypatch):
    fake_repo(monkeypatch, {})
    assert not tools.read_file("example/lib", "a.js", ref="../../etc")["ok"]



# ---------- several packages in one repository ("name==1.2.3" release tags) ----------

def multi_repo(monkeypatch, tags):
    monkeypatch.setattr(versions, "date", FixedDate)
    rel = [{"tag_name": t, "published_at": d + "T00:00:00Z", "draft": False, "prerelease": False} for t, d in tags]
    monkeypatch.setattr(http, "get", lambda url, params=None, headers=None, as_json=True: {"ok": True, "data": rel})


def test_package_tags_are_read_for_the_package_named_like_the_repo(monkeypatch):
    multi_repo(monkeypatch, [("example-core==2.0.0", "2026-05-20"), ("example==1.5.2", "2026-05-18"),
                             ("example-plugin==0.3.0", "2026-05-10"), ("example==1.5.0", "2026-05-01")])
    r = versions.find_version("latest", repo="org/example")
    assert r["version"] == "1.5.2" and r["package"] == "example" and r["released"] == "2026-05-18"


def test_a_named_package_wins_and_plain_tags_still_work(monkeypatch):
    multi_repo(monkeypatch, [("example-core==2.0.0", "2026-05-20"), ("1.4.0", "2026-05-19"), ("cli==0.9.0", "2026-05-21")])
    assert versions.find_version("latest", repo="org/example", package="example-core")["version"] == "2.0.0"
    assert versions.find_version("latest", repo="org/example")["version"] == "1.4.0"  # plain tags = main package


def test_several_packages_and_no_match_names_them_instead_of_guessing(monkeypatch):
    multi_repo(monkeypatch, [("alpha==1.0.0", "2026-05-20"), ("beta==2.0.0", "2026-05-19")])
    r = versions.find_version("latest", repo="org/example")
    assert not r["ok"] and "several packages (alpha, beta)" in r["error"]


# ---------- vulnerability check: per-call version limit ----------

def test_over_the_limit_the_newest_versions_are_checked_and_the_rest_returned(monkeypatch):
    seen = []
    monkeypatch.setattr(vulns, "_osv", lambda p, e, v: (seen.append(list(v)), ({}, [], {}))[1])
    monkeypatch.setattr(vulns, "_github", lambda p, e, v: ({}, [], {}))
    monkeypatch.setattr(vulns, "_nvd", lambda *a: ({}, [], {}))
    monkeypatch.setattr(vulns, "_endoflife", lambda p, v: {"listed": False})
    asked = [f"1.{i}.0" for i in range(12, 0, -1)]  # 12 versions, in any order
    r = vulns.check_vulnerabilities("example-lib", "npm", asked)
    assert r["versions_checked"] == [f"1.{i}.0" for i in range(3, 13)]   # the newest 10
    assert r["not_checked_versions"] == ["1.1.0", "1.2.0"]               # never dropped silently
    assert seen == [r["versions_checked"]]


# ---------- find_version: a range between two versions ----------

def test_range_lists_every_released_version_including_patches_a_guess_would_miss(fake_http, monkeypatch):
    npm = {"time": {**NPM["time"], "1.1.1": "2025-10-20T00:00:00Z", "1.1.2": "2025-12-01T00:00:00Z"}}
    monkeypatch.setattr(http, "get", lambda url, params=None, headers=None, as_json=True: {"ok": True, "data": npm})
    r = versions.find_version("1.1.0", package="example-lib", ecosystem="npm", until="1.2.0")
    assert r["range"] == ["1.1.0", "1.1.1", "1.1.2", "1.2.0"]  # from the registry; the beta is not a release


@pytest.mark.parametrize("when,until,error", [
    ("1.0.5", "1.2.0", "1.0.5 was not found"),      # a version that does not exist: an error, never a clean result
    ("1.0.0", "1.9.9", "1.9.9 was not found"),
    ("1.2.0", "1.0.0", "older than"),               # reversed range
])
def test_range_with_a_version_that_does_not_exist_is_an_error(fake_http, when, until, error):
    r = versions.find_version(when, package="example-lib", ecosystem="npm", until=until)
    assert not r["ok"] and error in r["error"]


def test_a_version_alone_is_looked_up_not_guessed(fake_http):
    r = versions.find_version("1.1.0", package="example-lib", ecosystem="npm")
    assert r["version"] == "1.1.0" and r["released"] == "2025-10-01" and r["newer"] == ["1.2.0", "1.2.1"]


# ---------- ids the agent chose (NVD CPE, endoflife.date id): a wrong one must not look clean ----------

def test_zero_nvd_cves_is_no_match_not_a_clean_answer(monkeypatch):
    calls = []
    def fake_get(url, params=None, headers=None, as_json=True):
        calls.append(url)
        if "endoflife" in url:
            return {"ok": False, "error": "HTTP 404"}
        return {"ok": True, "data": {"totalResults": 0, "vulnerabilities": []}}
    monkeypatch.setattr(http, "get", fake_get)
    r = vulns.check_vulnerabilities("example-product", versions=["1.0.0"])
    assert r["sources"]["nvd"].startswith("no match") and "cpe:2.3:a:example-product:example-product" in r["sources"]["nvd"]
    assert r["sources"]["endoflife"].startswith("no match") and "'example-product'" in r["sources"]["endoflife"]
    from oss_agent import rules
    assert rules.answered(r["sources"]) == []          # so rule 2 makes security not checked, never green
    assert sum("nvd" in u for u in calls) == 1           # no second page fetched for an empty product


def test_nvd_with_cves_answers_and_shows_the_cpe_used(monkeypatch):
    data = {"totalResults": 0, "vulnerabilities": []}
    def fake_get(url, params=None, headers=None, as_json=True):
        if "endoflife" in url:
            return {"ok": False, "error": "HTTP 404"}
        return {"ok": True, "data": {**data, "totalResults": 1}}
    monkeypatch.setattr(http, "get", fake_get)
    r = vulns.check_vulnerabilities("example-product", versions=["1.0.0"], cpe_vendor="example")
    assert r["sources"]["nvd"] == "ok" and r["nvd_cpe"] == "cpe:2.3:a:example:example-product"


# ---------- registries: the registry, not the model, names the repo and the versions ----------

from oss_agent import registries  # noqa: E402

REGISTRY = {
    "https://repo.packagist.org/p2/acme/lib.json": {"packages": {"acme/lib": [
        {"version": "v2.1.0", "time": "2026-03-01T00:00:00+00:00", "source": {"url": "https://github.com/acme-org/Lib.git"}},
        {"version": "v2.0.0", "time": "2025-01-01T00:00:00+00:00", "source": {"url": "https://github.com/acme-org/Lib.git"}}]}},
    "https://pypi.org/pypi/acme-lib/json": {"info": {"project_urls": {"Docs": "https://docs.example", "Source": "https://github.com/acme-org/lib-py"}},
        "releases": {"1.0.0": [{"upload_time": "2025-05-01T10:00:00", "yanked": False}], "1.1.0": [{"upload_time": "2026-01-02T10:00:00", "yanked": True}]}},
    "https://crates.io/api/v1/crates/acme": {"crate": {"repository": "https://github.com/acme-org/acme-rs"},
        "versions": [{"num": "0.2.0", "created_at": "2026-02-01T00:00:00Z", "yanked": False}]},
    "https://rubygems.org/api/v1/gems/acme.json": {"source_code_uri": "https://github.com/acme-org/acme-rb/tree/v3.0.0"},
    "https://rubygems.org/api/v1/versions/acme.json": [{"number": "3.0.0", "created_at": "2026-04-01T00:00:00Z", "prerelease": False},
                                                     {"number": "3.0.0", "created_at": "2026-04-01T00:00:00Z", "prerelease": False}],
}


@pytest.fixture
def fake_registry(monkeypatch):
    def get(url, params=None, headers=None, as_json=True):
        return {"ok": True, "data": REGISTRY[url]} if url in REGISTRY else {"ok": False, "error": "not found (404)"}
    monkeypatch.setattr(http, "get", get)


@pytest.mark.parametrize("package, eco, repo", [("acme/lib", "composer", "acme-org/Lib"), ("acme-lib", "pypi", "acme-org/lib-py"),
                                                ("acme", "rust", "acme-org/acme-rs"), ("acme", "rubygems", "acme-org/acme-rb")])
def test_registry_names_the_repository(fake_registry, package, eco, repo):
    assert registries.lookup(package, eco)["repo"] == repo


def test_registry_versions_skip_yanked_and_keep_dates(fake_registry):
    assert registries.lookup("acme-lib", "pypi")["releases"] == [("1.0.0", "2025-05-01")]
    assert registries.lookup("acme", "rubygems")["releases"] == [("3.0.0", "2026-04-01")]
    r = versions.find_version("latest", package="acme/lib", ecosystem="composer")
    assert r["ok"] and r["version"] == "2.1.0" and r["source"] == "Packagist" and r["released"] == "2026-03-01"


def test_a_package_that_does_not_exist_is_an_error_not_a_clean_result(fake_registry):
    r = vulns.check_vulnerabilities("acme/missing", "composer", ["1.0.0"])
    assert not r["ok"] and "does not exist in the composer registry" in r["error"]
    assert not tools.get_repo_info(package="acme/missing", ecosystem="composer")["ok"]


def test_no_registry_answer_means_unconfirmed_not_missing(monkeypatch):
    monkeypatch.setattr(http, "get", lambda *a, **k: {"ok": False, "error": "HTTP 503"})
    assert registries.exists("acme/lib", "composer") is None and registries.exists("acme.lib", "maven") is None
    assert registries.exists("github.com/acme-org/mod", "go") is None


def test_go_module_path_names_its_repository():
    assert registries.GO_GITHUB.match("github.com/acme-org/mod/v2").group(2) == "mod"
