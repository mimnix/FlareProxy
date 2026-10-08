#!/usr/bin/env python3
"""Black-box mock of FlareSolverr v3.5.2 for FlareProxy behaviour tests.

Usage::

    python tests/mock_flaresolverr.py <port>

The mock speaks the JSON-in / JSON-out ``POST /v1`` protocol used by
FlareSolverr and additionally exposes two control endpoints that only the test
harness is expected to call::

    GET /__state  -> JSON snapshot of counters + recorded events
    GET /__reset  -> zero all counters and forget sessions

Environment:
    MOCK_DELAY  float seconds to sleep before answering any ``request.*``
                command (used to exercise single-flight coalescing).

Only the standard library is used.
"""

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MOCK_DELAY = float(os.getenv("MOCK_DELAY", "0") or 0)
VERSION = "3.5.2"


class _State:
    """Mutable, thread-safe mock state."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.session_creates = 0
        self.requests = 0
        self.requests_with_session = 0
        self.requests_without_session = 0
        self.urls = {}
        self.sessions = []          # insertion-ordered session ids
        self.session_set = set()
        self.events = []
        self.session_visits = {}    # session id -> monotonic visit counter
        self.fresh_visits = 0       # cold "fresh browser" visit counter

    def snapshot(self):
        with self.lock:
            return {
                "version": VERSION,
                "session_creates": self.session_creates,
                "requests": self.requests,
                "requests_with_session": self.requests_with_session,
                "requests_without_session": self.requests_without_session,
                "urls": dict(self.urls),
                "sessions": list(self.sessions),
                "session_visits": dict(self.session_visits),
                "fresh_visits": self.fresh_visits,
                "events": list(self.events),
            }


STATE = _State()


def _record(event):
    STATE.events.append(event)


def _handle_command(payload):
    cmd = payload.get("cmd", "")
    if cmd == "sessions.create":
        sid = payload.get("session")
        if not sid:
            return {"status": "error", "message": "session name is required"}
        with STATE.lock:
            if sid in STATE.session_set:
                _record({"type": "session_exists", "session": sid})
                return {
                    "status": "ok",
                    "message": "Session already exists.",
                    "session": sid,
                    "version": VERSION,
                }
            STATE.session_set.add(sid)
            STATE.sessions.append(sid)
            STATE.session_visits.setdefault(sid, 0)
            STATE.session_creates += 1
            _record({"type": "session_create", "session": sid})
        return {
            "status": "ok",
            "message": "Session created successfully.",
            "session": sid,
            "version": VERSION,
        }

    if cmd == "sessions.list":
        with STATE.lock:
            sessions = list(STATE.sessions)
        return {"status": "ok", "message": "", "sessions": sessions}

    if cmd == "sessions.destroy":
        sid = payload.get("session")
        with STATE.lock:
            if sid in STATE.session_set:
                STATE.session_set.discard(sid)
                STATE.sessions = [s for s in STATE.sessions if s != sid]
                _record({"type": "session_destroy", "session": sid})
                return {"status": "ok", "message": "The session has been removed."}
        return {"status": "error", "message": "Session not found."}

    if cmd in ("request.get", "request.post"):
        if MOCK_DELAY > 0:
            time.sleep(MOCK_DELAY)
        url = payload.get("url", "")
        sid = payload.get("session") or None
        with STATE.lock:
            STATE.requests += 1
            STATE.urls[url] = STATE.urls.get(url, 0) + 1
            if sid:
                STATE.requests_with_session += 1
                if sid not in STATE.session_set:
                    # Be forgiving: auto-register an unknown session so the
                    # mock never crashes on ordering races. This does NOT count
                    # as a sessions.create call.
                    STATE.session_set.add(sid)
                    STATE.sessions.append(sid)
                    STATE.session_visits.setdefault(sid, 0)
                    _record({"type": "session_implicit", "session": sid})
                STATE.session_visits[sid] = STATE.session_visits.get(sid, 0) + 1
                visit = STATE.session_visits[sid]
                label = sid
            else:
                STATE.requests_without_session += 1
                STATE.fresh_visits += 1
                visit = STATE.fresh_visits
                label = "none"
                _record(
                    {
                        "type": "fresh_browser",
                        "url": url,
                        "method": cmd,
                        "visit": visit,
                    }
                )
            _record(
                {
                    "type": "request",
                    "method": cmd,
                    "url": url,
                    "session": sid,
                    "visit": visit,
                }
            )
        body = "visits=%d,session=%s" % (visit, label)
        return {
            "status": "ok",
            "message": "Challenge not detected!",
            "solution": {
                "status": 200,
                "headers": {"Content-Type": "text/html"},
                "response": body,
                "userAgent": "Mozilla/5.0 (MockFlareSolverr)",
            },
        }

    return {"status": "error", "message": "Unknown command: %s" % cmd}


class MockHandler(BaseHTTPRequestHandler):
    server_version = "MockFlareSolverr/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence access logging
        pass

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionError, OSError):
            pass

    def do_GET(self):
        if self.path.startswith("/__state"):
            self._send_json(STATE.snapshot())
            return
        if self.path.startswith("/__reset"):
            with STATE.lock:
                STATE.reset()
            self._send_json({"status": "ok"})
            return
        self._send_json({"status": "error", "message": "not found"}, status=404)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            self._send_json({"status": "error", "message": "invalid json"}, status=400)
            return
        if not isinstance(payload, dict):
            self._send_json({"status": "error", "message": "invalid payload"}, status=400)
            return
        self._send_json(_handle_command(payload))


def main(argv):
    if len(argv) != 2:
        print("usage: mock_flaresolverr.py <port>", file=sys.stderr)
        return 2
    port = int(argv[1])
    server = ThreadingHTTPServer(("127.0.0.1", port), MockHandler)
    server.daemon_threads = True
    print("Mock FlareSolverr v%s listening on 127.0.0.1:%d" % (VERSION, port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
