"""Web chat: one request gives the finished answer; never an approve/save step. Scripted agent, offline."""
import json
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

import pytest
from langchain_core.messages import AIMessage

from oss_agent import graph, http, register, server

REPORT = {"repo": "x", "question": "q", "recommendation": "Fine to use.",
          "findings": [{"area": "licence", "claim": "Permissive licence.", "evidence_quote": "Copyright 2010 Pallets",
                        "url": "x", "source_tool": "get_repo_info"}],
          "areas": {"licence": {"status": "green", "summary": "BSD-3-Clause"}}}


class ScriptedModel:
    def __init__(self, replies):
        self.replies = list(replies)

    def invoke(self, messages):
        return self.replies.pop(0)


def call(name, args, i):
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{i}", "type": "tool_call"}])


@pytest.fixture
def web(monkeypatch, tmp_path):
    monkeypatch.setattr(http, "OFFLINE", True)
    monkeypatch.setattr(register, "REGISTER_PATH", tmp_path / "register.jsonl")

    def start(replies):
        server.APP = graph.build_graph(ScriptedModel(replies))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
    servers = []
    yield lambda replies: servers.append(start(replies)) or servers[-1]
    for srv in servers:
        srv.shutdown()


def post(srv, path, body):
    req = Request(f"http://127.0.0.1:{srv.server_port}{path}", json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urlopen(req) as res:
        return json.loads(res.read())


def test_answer_arrives_finished_with_no_approval_and_nothing_saved(web):
    srv = web([call("get_repo_info", {"repo": "pallets/flask"}, 1), call("submit_report", {"report": REPORT}, 2)])
    data = post(srv, "/api/start", {"question": "What licence does pallets/flask use?"})
    assert data["status"] == "done" and data["decision"]["approved"] is False
    p = data["presentation"]
    assert p["decision"]["text"] and p["summary"] == "Fine to use." and p["why"][0]["evidence"][0]["verified"]
    assert any(t["used"] for t in p["tools"])
    assert not register.REGISTER_PATH.exists()


def test_agent_question_still_comes_back_to_the_user(web):
    srv = web([call("ask_user", {"question": "Which version do you run?"}, 1),
               call("get_repo_info", {"repo": "pallets/flask"}, 2), call("submit_report", {"report": REPORT}, 3)])
    first = post(srv, "/api/start", {"question": "Is flask ok?"})
    assert first["status"] == "interrupt" and first["interrupt"]["type"] == "ask"
    done = post(srv, "/api/resume", {"thread_id": first["thread_id"], "answer": "3.0"})
    assert done["status"] == "done" and done["presentation"]


def test_resuming_a_conversation_the_server_no_longer_has_is_a_clear_message(web):
    from urllib.error import HTTPError
    srv = web([])
    try:
        post(srv, "/api/resume", {"thread_id": "unknown-after-restart", "answer": "3.0"})
        raise AssertionError("expected an error")
    except HTTPError as e:
        assert e.code == 410 and "ask your question again" in json.loads(e.read())["error"]
