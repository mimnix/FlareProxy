#!/usr/bin/env python3
"""Black-box behaviour tests for the FlareProxy FlareSolverr adapter.

Starts the mock FlareSolverr (``mock_flaresolverr.py``) and ``flareproxy.py`` as
subprocesses, drives real HTTP proxy requests through the proxy listener and
asserts observable behaviour via the mock's control channel.

Only the Python standard library is used. Exits non-zero if any case fails.

Run::

    python tests/run_behavior_tests.py
"""

import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parent.parent
MOCK_SCRIPT = TESTS_DIR / "mock_flaresolverr.py"
PROXY_SCRIPT = ROOT / "flareproxy.py"
LOG_DIR = Path("/tmp/opencode")
LOG_DIR.mkdir(parents=True, exist_ok=True)

READY_TIMEOUT = 45.0
REQUEST_TIMEOUT = 60.0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def free_port():
    """Return a currently-free localhost TCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _read_state(port):
    url = "http://127.0.0.1:%d/__state" % port
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def proxy_get(proxy_port, target_url, timeout=REQUEST_TIMEOUT):
    """Issue an absolute-URI GET through the proxy's HTTP listener."""
    split = urllib.parse.urlsplit(target_url)
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=timeout)
    try:
        conn.request("GET", target_url, headers={"Host": split.netloc})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body
    finally:
        conn.close()


def proxy_post(proxy_port, target_url, body, timeout=REQUEST_TIMEOUT):
    """Issue an absolute-URI POST through the proxy's HTTP listener."""
    split = urllib.parse.urlsplit(target_url)
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=timeout)
    try:
        conn.request(
            "POST",
            target_url,
            body=body.encode("utf-8"),
            headers={"Host": split.netloc, "Content-Type": "application/x-www-form-urlencoded"},
        )
        resp = conn.getresponse()
        payload = resp.read().decode("utf-8", errors="replace")
        return resp.status, payload
    finally:
        conn.close()


def _tail(path, n=15):
    try:
        lines = Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return "<no log>"
    return "\n".join(lines[-n:])


# --------------------------------------------------------------------------- #
# Process supervisors
# --------------------------------------------------------------------------- #
class Mock:
    def __init__(self, delay=0.0):
        self.port = free_port()
        self.log_path = LOG_DIR / ("mock-%d.log" % self.port)
        env = os.environ.copy()
        env["MOCK_DELAY"] = str(delay)
        self.log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, str(MOCK_SCRIPT), str(self.port)],
            env=env,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        self._wait_ready()

    def _wait_ready(self):
        deadline = time.time() + READY_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "mock exited early (code %s):\n%s"
                    % (self.proc.returncode, _tail(self.log_path))
                )
            try:
                _read_state(self.port)
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("mock did not become ready:\n%s" % _tail(self.log_path))

    def state(self):
        return _read_state(self.port)

    def reset(self):
        urllib.request.urlopen(
            "http://127.0.0.1:%d/__reset" % self.port, timeout=5
        ).read()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            self.log.close()
        except OSError:
            pass


class Proxy:
    def __init__(self, mock_port, env_overrides=None):
        self.http_port = free_port()
        self.https_port = free_port()
        self.log_path = LOG_DIR / ("flareproxy-%d.log" % self.http_port)
        env = os.environ.copy()
        env["FLARESOLVERR_URL"] = "http://127.0.0.1:%d/v1" % mock_port
        env["FLAREPROXY_PORT"] = str(self.http_port)
        env["FLAREPROXY_HTTPS_PORT"] = str(self.https_port)
        env.pop("MOCK_DELAY", None)
        if env_overrides:
            env.update(env_overrides)
        self.log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [sys.executable, str(PROXY_SCRIPT)],
            env=env,
            cwd=str(ROOT),
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        self._wait_ready()

    def _wait_ready(self):
        deadline = time.time() + READY_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "flareproxy exited early (code %s):\n%s"
                    % (self.proc.returncode, _tail(self.log_path))
                )
            try:
                conn = http.client.HTTPConnection(
                    "127.0.0.1", self.http_port, timeout=2
                )
                conn.request("GET", "/__flareproxy/ca.crt")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                if resp.status == 200:
                    return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError(
            "flareproxy did not become ready:\n%s" % _tail(self.log_path)
        )

    def get(self, target_url, timeout=REQUEST_TIMEOUT):
        return proxy_get(self.http_port, target_url, timeout=timeout)

    def post(self, target_url, body, timeout=REQUEST_TIMEOUT):
        return proxy_post(self.http_port, target_url, body, timeout=timeout)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            self.log.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Test framework
# --------------------------------------------------------------------------- #
def case(name):
    def decorator(fn):
        fn._case_name = name
        return fn

    return decorator


@case("A. Session reuse (one session per host, attached to requests)")
def test_session_reuse():
    mock = Mock(delay=0.0)
    proxy = Proxy(mock.port, {"FLAREPROXY_CACHE_TTL": "0"})
    try:
        url = "http://target.test/alpha?q=1"
        s1, b1 = proxy.get(url)
        s2, b2 = proxy.get(url)
        assert s1 == 200, "first response status %s" % s1
        assert s2 == 200, "second response status %s" % s2

        st = mock.state()
        assert st["session_creates"] == 1, (
            "expected exactly 1 session_create, got %r" % st["session_creates"]
        )
        reqs = [e for e in st["events"] if e["type"] == "request"]
        assert len(reqs) >= 2, "expected >=2 upstream requests, got %d" % len(reqs)
        assert all(e.get("session") for e in reqs), (
            "every request must carry a non-empty session field: %r" % reqs
        )
        ids = {e["session"] for e in reqs}
        assert len(ids) == 1, "requests must reuse the SAME session id, saw %r" % ids
    finally:
        proxy.stop()
        mock.stop()


@case("B. Cache (TTL=300: second GET served locally, new URL goes upstream)")
def test_cache():
    mock = Mock(delay=0.0)
    proxy = Proxy(mock.port, {"FLAREPROXY_CACHE_TTL": "300"})
    try:
        url = "http://target.test/cache-me?x=1"
        other = "http://target.test/other?y=2"
        s1, b1 = proxy.get(url)
        s2, b2 = proxy.get(url)
        assert s1 == 200 and s2 == 200, "statuses %s/%s" % (s1, s2)
        assert b1 == b2, "cached body differs: %r != %r" % (b1, b2)

        st = mock.state()
        assert st["urls"].get(url, 0) == 1, (
            "expected 1 upstream hit for cached url, got %r" % st["urls"].get(url, 0)
        )
        # A different URL must still go upstream.
        s3, b3 = proxy.get(other)
        assert s3 == 200, "third response status %s" % s3
        st = mock.state()
        assert st["urls"].get(other, 0) == 1, (
            "different url must hit upstream once, got %r"
            % st["urls"].get(other, 0)
        )
    finally:
        proxy.stop()
        mock.stop()


@case("C. Single-flight (5 concurrent identical GETs -> 1 upstream request)")
def test_single_flight():
    mock = Mock(delay=1.0)
    proxy = Proxy(mock.port, {"FLAREPROXY_CACHE_TTL": "0"})
    try:
        url = "http://target.test/inflight?z=9"
        n = 5
        barrier = threading.Barrier(n)
        results = [None] * n
        errors = [None] * n

        def worker(i):
            try:
                barrier.wait(timeout=15)
                results[i] = proxy.get(url)
            except Exception as exc:  # noqa: BLE001
                errors[i] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=REQUEST_TIMEOUT + 15)

        assert not any(errors), "worker errors: %r" % [e for e in errors if e]
        assert all(r is not None for r in results), "some workers returned nothing"
        statuses = {r[0] for r in results}
        assert statuses == {200}, "expected all 200, got %r" % statuses
        bodies = {r[1] for r in results}
        assert len(bodies) == 1, "expected identical bodies, got %d variants" % len(bodies)

        st = mock.state()
        assert st["urls"].get(url, 0) == 1, (
            "single-flight must produce exactly 1 upstream request, got %r"
            % st["urls"].get(url, 0)
        )
    finally:
        proxy.stop()
        mock.stop()


@case("D. Sessionless fallback (FLAREPROXY_SESSION=false)")
def test_sessionless():
    mock = Mock(delay=0.0)
    proxy = Proxy(
        mock.port,
        {"FLAREPROXY_CACHE_TTL": "0", "FLAREPROXY_SESSION": "false"},
    )
    try:
        url = "http://target.test/stateless?q=1"
        status, _body = proxy.get(url)
        assert status == 200, "response status %s" % status

        st = mock.state()
        assert st["session_creates"] == 0, (
            "no session must be created, got %r" % st["session_creates"]
        )
        assert st["requests_with_session"] == 0, (
            "requests must not carry a session, got %r"
            % st["requests_with_session"]
        )
        assert st["requests_without_session"] >= 1, (
            "expected a sessionless request, got %r"
            % st["requests_without_session"]
        )
        reqs = [e for e in st["events"] if e["type"] == "request"]
        assert all(not e.get("session") for e in reqs), (
            "every request must have no session field: %r" % reqs
        )
    finally:
        proxy.stop()
        mock.stop()


@case("E. Cache disabled (TTL=0: every GET goes upstream)")
def test_cache_disabled():
    mock = Mock(delay=0.0)
    proxy = Proxy(mock.port, {"FLAREPROXY_CACHE_TTL": "0"})
    try:
        url = "http://target.test/no-cache?q=1"
        s1, _ = proxy.get(url)
        s2, _ = proxy.get(url)
        assert s1 == 200 and s2 == 200, "statuses %s/%s" % (s1, s2)
        st = mock.state()
        assert st["urls"].get(url, 0) == 2, (
            "cache disabled must hit upstream twice, got %r"
            % st["urls"].get(url, 0)
        )
    finally:
        proxy.stop()
        mock.stop()


@case("F. POST never coalesced (5 concurrent identical POSTs -> 5 upstream)")
def test_post_not_coalesced():
    mock = Mock(delay=1.0)
    proxy = Proxy(mock.port, {"FLAREPROXY_CACHE_TTL": "0"})
    try:
        url = "http://target.test/write?op=1"
        body = "action=update&value=1"
        n = 5
        barrier = threading.Barrier(n)
        results = [None] * n
        errors = [None] * n

        def worker(i):
            try:
                barrier.wait(timeout=15)
                results[i] = proxy.post(url, body)
            except Exception as exc:  # noqa: BLE001
                errors[i] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=REQUEST_TIMEOUT + 15)

        assert not any(errors), "worker errors: %r" % [e for e in errors if e]
        assert all(r is not None and r[0] == 200 for r in results), (
            "expected all 200, got %r" % [r[0] if r else None for r in results]
        )
        st = mock.state()
        posts = [
            e
            for e in st["events"]
            if e.get("method") == "request.post" and e.get("url") == url
        ]
        assert len(posts) == n, (
            "identical concurrent POSTs must NOT coalesce: expected %d "
            "upstream calls, got %d" % (n, len(posts))
        )
    finally:
        proxy.stop()
        mock.stop()


CASES = [
    test_session_reuse,
    test_cache,
    test_single_flight,
    test_sessionless,
    test_cache_disabled,
    test_post_not_coalesced,
]


def main():
    if not PROXY_SCRIPT.exists():
        print("FAIL: %s not found" % PROXY_SCRIPT)
        return 1
    if not MOCK_SCRIPT.exists():
        print("FAIL: %s not found" % MOCK_SCRIPT)
        return 1

    print("=" * 68)
    print("FlareProxy black-box behaviour tests")
    print("  proxy : %s" % PROXY_SCRIPT)
    print("  mock  : %s" % MOCK_SCRIPT)
    print("=" * 68)

    passed = 0
    failed = 0
    for fn in CASES:
        name = fn._case_name
        try:
            fn()
            print("PASS  %s" % name)
            passed += 1
        except AssertionError as exc:
            print("FAIL  %s" % name)
            print("      -> %s" % exc)
            failed += 1
        except Exception as exc:  # noqa: BLE001 - report and continue
            print("FAIL  %s" % name)
            print("      -> %s: %s" % (type(exc).__name__, exc))
            failed += 1

    print("-" * 68)
    print("Summary: %d passed, %d failed, %d total" % (passed, failed, passed + failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
