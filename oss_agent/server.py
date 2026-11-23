"""Tiny local web UI for the agent: python -m oss_agent.server  ->  http://127.0.0.1:8000

Standard library only (no web framework). Two JSON endpoints map onto the graph:
  POST /api/start  {"question"}           -> runs until the graph needs a human, or is done
  POST /api/resume {"thread_id", "answer"} -> resumes after the agent's question (ask interrupt)
The web chat never saves to the register: its approve step is answered "no" by the server, so the page
shows the answer without any approve/save controls. (The command line keeps the approval step.)
The MemorySaver checkpointer in the graph keeps each conversation's state between requests.
"""
import json
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dotenv import load_dotenv
from langgraph.types import Command

from oss_agent import graph, llm, report

HOST, PORT = "127.0.0.1", 8000  # localhost only: this UI has no login
PAGE = Path(__file__).parent / "web" / "index.html"
APP = None
STARTED = {}  # thread_id -> start time, for the "seconds" figure


def _step(result: dict, thread_id: str) -> dict:
    """Turn a graph result into what the page needs next."""
    if result.get("__interrupt__"):
        payload = dict(result["__interrupt__"][0].value)
        if payload.get("report"):  # same sections as the terminal answer (one renderer, one source of truth)
            payload["presentation"] = report.present(payload["report"])
        return {"status": "interrupt", "thread_id": thread_id, "interrupt": payload}
    trace = result["trace"]
    rep = result["report"]
    return {
        "status": "done", "thread_id": thread_id, "question": result["question"], "answer": result["answer"],
        "report": result["report"],
        "decision": result["decision"], "trace": trace, "presentation": report.present(rep) if rep else None,
        "tool_calls": sum(1 for t in trace if t.get("tool") not in (None, "submit_report", "ask_user")),
        "questions": result["questions_asked"], "seconds": round(time.time() - STARTED.pop(thread_id, time.time()), 1),
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data, default=str).encode(), "application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "invalid JSON"})
        try:
            if self.path == "/api/start":
                question = str(body.get("question", "")).strip()
                if not question:
                    return self._json(400, {"error": "question is empty"})
                thread_id = uuid.uuid4().hex
                STARTED[thread_id] = time.time()
                result = APP.invoke(graph.initial_state(question), _config(thread_id))
            elif self.path == "/api/resume":
                thread_id = str(body.get("thread_id", ""))
                if not APP.get_state(_config(thread_id)).next:  # unknown (server restarted) or already finished
                    return self._json(410, {"error": EXPIRED})
                result = APP.invoke(Command(resume=str(body.get("answer", ""))), _config(thread_id))
            else:
                return self._json(404, {"error": "not found"})
            while _is_approval(result):  # web chat: never save, never ask for approval
                result = APP.invoke(Command(resume="no"), _config(thread_id))
            step = _step(result, thread_id)
        except llm.LLMError as e:
            return self._json(502, {"error": str(e)})
        except Exception as e:  # never drop the connection: the browser would only say "Failed to fetch"
            traceback.print_exc()
            return self._json(500, {"error": f"server error: {type(e).__name__}: {str(e)[:200]}"})
        self._json(200, step)

    def log_message(self, fmt, *args):  # one short line per request, no bodies (they may hold data)
        print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")


EXPIRED = "This conversation is no longer open (the server was restarted, or it already finished). Please ask your question again."


def _is_approval(result: dict) -> bool:
    return bool(result.get("__interrupt__")) and result["__interrupt__"][0].value.get("type") == "approve"


def _config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}, "recursion_limit": 6 * graph.MAX_STEPS}


def main() -> None:
    global APP
    load_dotenv()
    APP = graph.build_graph()
    print(f"OSS due-diligence chat on http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
