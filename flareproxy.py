"""FlareProxy - a transparent HTTP/HTTPS proxy adapter for FlareSolverr.

It accepts plain HTTP, HTTPS (TLS) and CONNECT (MITM) requests from clients and
relays them to a FlareSolverr instance so that Cloudflare / DDoS-GUARD protected
sites can be fetched.

All TLS material (a local CA and the leaf certificates) is generated fresh at
startup inside a temporary directory and is discarded when the process exits.
"""

import collections
import hashlib
import ipaddress
import json
import os
import ssl
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
FLARESOLVERR_URL = os.getenv("FLARESOLVERR_URL", "http://flaresolverr:8191/v1")
FLAREPROXY_PORT = int(os.getenv("FLAREPROXY_PORT", "8080"))
FLAREPROXY_HTTPS_PORT = int(os.getenv("FLAREPROXY_HTTPS_PORT", "8443"))
FLAREPROXY_CERT_NAMES = os.getenv(
    "FLAREPROXY_CERT_NAMES", "localhost,127.0.0.1,flareproxy"
)

# Response cache: identical GET requests within this window are served from
# memory instead of re-solving the challenge. Set to 0 to disable caching.
CACHE_TTL = float(os.getenv("FLAREPROXY_CACHE_TTL", "300"))
CACHE_MAX_ENTRIES = int(os.getenv("FLAREPROXY_CACHE_MAX_ENTRIES", "512"))

# Reuse one persistent FlareSolverr browser session per target host so the
# Cloudflare clearance cookie (cf_clearance) survives between requests. This is
# the single biggest latency win (cold solve ~12s -> warm request ~1-3s).
SESSION_ENABLED = os.getenv("FLAREPROXY_SESSION", "true").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)
# Destroy a host's session once it has been idle for this many seconds so
# browsers are not leaked for hosts that are only queried occasionally
# (0 = never reap). FlareSolverr itself has no idle reaper.
SESSION_IDLE_TTL = float(os.getenv("FLAREPROXY_SESSION_IDLE_TTL", "900"))
# Per-request timeout when talking to FlareSolverr (a cold solve can take a while).
FLARESOLVERR_TIMEOUT = float(os.getenv("FLAREPROXY_FLARESOLVERR_TIMEOUT", "90"))
# Prefix for the deterministic per-host session id.
SESSION_ID_PREFIX = os.getenv("FLAREPROXY_SESSION_PREFIX", "flareproxy")

# Maximum number of per-host leaf certificates kept in memory/on disk at once.
MAX_CACHED_CERTS = 256
# Maximum accepted request body size (client -> proxy).
MAX_BODY_BYTES = 10 * 1024 * 1024

# --------------------------------------------------------------------------- #
# Ephemeral certificate material (generated at startup, removed on exit)
# --------------------------------------------------------------------------- #
CERT_DIR = tempfile.TemporaryDirectory(prefix="flareproxy-")
CERT_DIR_PATH = CERT_DIR.name
CA_CERT_PATH = os.path.join(CERT_DIR_PATH, "ca.crt")
CA_KEY_PATH = os.path.join(CERT_DIR_PATH, "ca.key")

_ca_cert = None  # x509.Certificate
_ca_key = None  # rsa.RSAPrivateKey
_ca_cert_pem = b""
_proxy_ssl_context = None
_server_ssl_contexts = collections.OrderedDict()  # hostname -> (ctx, cert, key)
_ssl_contexts_lock = threading.Lock()


def _write_pem(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _private_key_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _san_entry(hostname):
    """Build a SAN entry: IPAddress for literals, DNSName otherwise."""
    try:
        return x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        return x509.DNSName(hostname)


def _leaf_paths(hostname):
    safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in hostname)
    return (
        os.path.join(CERT_DIR_PATH, "leaf-%s.crt" % safe),
        os.path.join(CERT_DIR_PATH, "leaf-%s.key" % safe),
    )


def _build_ca():
    """Generate a self-signed RSA-2048 CA key + certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "FlareProxy Local CA")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _generate_leaf(hostnames):
    """Generate a leaf key + cert signed by the ephemeral CA.

    ``hostnames`` may be a single string or an iterable of names. The first
    name is used as CN; every name becomes a SAN entry. Returns (cert, key)
    file paths.
    """
    if isinstance(hostnames, str):
        hostnames = [hostnames]
    hostnames = [h for h in hostnames if h]
    if not hostnames:
        hostnames = ["localhost"]

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([_san_entry(h) for h in hostnames]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(_ca_key, hashes.SHA256())
    )

    cert_path, key_path = _leaf_paths(hostnames[0])
    _write_pem(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(key_path, _private_key_pem(key))
    return cert_path, key_path


def get_server_ssl_context(hostname):
    """Return a cached server SSLContext whose leaf cert is valid for hostname."""
    with _ssl_contexts_lock:
        cached = _server_ssl_contexts.get(hostname)
        if cached is not None:
            _server_ssl_contexts.move_to_end(hostname)
            return cached[0]
        cert_path, key_path = _generate_leaf([hostname])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        _server_ssl_contexts[hostname] = (ctx, cert_path, key_path)
        while len(_server_ssl_contexts) > MAX_CACHED_CERTS:
            _, (_old_ctx, old_cert, old_key) = _server_ssl_contexts.popitem(
                last=False
            )
            for stale_path in (old_cert, old_key):
                try:
                    os.remove(stale_path)
                except OSError:
                    pass
        return ctx


def _init_certs():
    """Generate the CA and the proxy's own listener certificate."""
    global _ca_cert, _ca_key, _ca_cert_pem, _proxy_ssl_context

    _ca_key, _ca_cert = _build_ca()
    _ca_cert_pem = _ca_cert.public_bytes(serialization.Encoding.PEM)
    _write_pem(CA_CERT_PATH, _ca_cert_pem)
    _write_pem(CA_KEY_PATH, _private_key_pem(_ca_key))

    names = [n.strip() for n in FLAREPROXY_CERT_NAMES.split(",") if n.strip()]
    if not names:
        names = ["localhost"]
    cert_path, key_path = _generate_leaf(names)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    _proxy_ssl_context = ctx


# --------------------------------------------------------------------------- #
# FlareSolverr helper
# --------------------------------------------------------------------------- #
def _error_response(message):
    return 502, {"Content-Type": "application/json"}, json.dumps({"error": message})


class _FlareSolverrError(Exception):
    """Raised when FlareSolverr answers with ``status = "error"``."""


# Errors after which a session's browser may be in an indeterminate state (a
# failed or timed-out solve), so the session must be dropped and recreated.
_SESSION_ERRORS = (_FlareSolverrError, requests.exceptions.Timeout)


class _Inflight:
    """A pending request other callers can wait on (single-flight)."""

    __slots__ = ("event", "result")

    def __init__(self):
        self.event = threading.Event()
        self.result = None


def _host_of(url):
    """Return the ``host:port`` authority for a URL, or None if unparseable."""
    try:
        return urlsplit(url).netloc or None
    except ValueError:
        return None


def _session_id_for(host):
    """Deterministic, idempotent session id for a host (stable across restarts)."""
    digest = hashlib.sha256(host.encode("utf-8")).hexdigest()[:16]
    return "%s-%s" % (SESSION_ID_PREFIX, digest)


class FlareSolverrClient:
    """Stateful FlareSolverr client with session reuse, caching and single-flight.

    * One persistent browser session per target host keeps the ``cf_clearance``
      cookie warm, turning ~12s cold solves into ~1-3s warm requests.
    * GET responses are memoised by URL for ``CACHE_TTL`` seconds.
    * Identical concurrent GET requests collapse into a single upstream call
      (writes are never coalesced, since they may have side effects).
    * Requests to the same host are serialised, because a FlareSolverr session
      holds a single (non-thread-safe) browser: one in-flight request per
      session.
    """

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self._cache = collections.OrderedDict()  # url -> (expiry, result)
        self._cache_lock = threading.Lock()
        self._sessions = {}  # host -> session id
        self._last_used = {}  # host -> monotonic timestamp
        self._host_locks = {}  # host -> Lock (serialises + guards creation)
        self._state_lock = threading.Lock()
        self._inflight = {}  # key -> _Inflight
        self._inflight_lock = threading.Lock()
        self._stats = {
            "requests": 0,
            "cache_hits": 0,
            "coalesced": 0,
            "session_creates": 0,
            "session_errors": 0,
        }
        self._stats_lock = threading.Lock()
        if SESSION_ENABLED and SESSION_IDLE_TTL > 0:
            threading.Thread(
                target=self._reap_idle_sessions,
                name="session-reaper",
                daemon=True,
            ).start()

    # ----- stats ---------------------------------------------------------- #
    def _bump(self, name, amount=1):
        with self._stats_lock:
            self._stats[name] = self._stats.get(name, 0) + amount

    def stats(self):
        with self._stats_lock:
            return dict(self._stats)

    # ----- low level FlareSolverr calls ----------------------------------- #
    def _call(self, payload):
        """POST a single command to FlareSolverr and return the parsed JSON."""
        response = requests.post(
            self.endpoint, json=payload, timeout=FLARESOLVERR_TIMEOUT
        )
        data = response.json()
        if data.get("status") != "ok":
            raise _FlareSolverrError(data.get("message", "unknown error"))
        return data

    def _request(self, url, method, post_data, session_id):
        """Issue one request.get/request.post. Returns (status, headers, body)."""
        cmd = "request.post" if method == "POST" else "request.get"
        payload = {"cmd": cmd, "url": url, "maxTimeout": 60000}
        if session_id:
            payload["session"] = session_id
        if cmd == "request.post":
            payload["postData"] = post_data or ""

        data = self._call(payload)
        solution = data.get("solution") or {}
        try:
            status = int(solution.get("status", 200))
        except (TypeError, ValueError):
            status = 502
        if not (100 <= status <= 599):
            status = 502
        headers = solution.get("headers") or {}
        body = solution.get("response") or ""
        return status, headers, body

    # ----- session management --------------------------------------------- #
    def _host_lock(self, host):
        with self._state_lock:
            lock = self._host_locks.get(host)
            if lock is None:
                lock = threading.Lock()
                self._host_locks[host] = lock
            return lock

    def _ensure_session(self, host):
        """Return a live session id for host, creating one if needed.

        Always called with the per-host lock held, so creation is single-flight.
        """
        with self._state_lock:
            session_id = self._sessions.get(host)
        if session_id is not None:
            return session_id

        desired = _session_id_for(host)
        try:
            data = self._call({"cmd": "sessions.create", "session": desired})
        except Exception:  # noqa: BLE001 - fall back to sessionless for now
            self._bump("session_errors")
            return None

        session_id = data.get("session") or desired
        with self._state_lock:
            self._sessions[host] = session_id
            self._last_used[host] = time.monotonic()
        self._bump("session_creates")
        return session_id

    def _touch(self, host):
        with self._state_lock:
            if host in self._sessions:
                self._last_used[host] = time.monotonic()

    def _destroy_session(self, host):
        with self._state_lock:
            session_id = self._sessions.pop(host, None)
            self._last_used.pop(host, None)
        if not session_id:
            return
        try:
            self._call({"cmd": "sessions.destroy", "session": session_id})
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass

    def _reap_idle_sessions(self):
        """Drop browser sessions that have been idle for too long."""
        interval = max(10.0, min(60.0, SESSION_IDLE_TTL / 4.0))
        while True:
            time.sleep(interval)
            now = time.monotonic()
            with self._state_lock:
                stale = [
                    host
                    for host, last in self._last_used.items()
                    if now - last > SESSION_IDLE_TTL
                ]
            for host in stale:
                with self._host_lock(host):
                    with self._state_lock:
                        last = self._last_used.get(host)
                        if last is None or now - last <= SESSION_IDLE_TTL:
                            continue
                    self._destroy_session(host)

    # ----- cache ---------------------------------------------------------- #
    def _cache_get(self, url):
        with self._cache_lock:
            item = self._cache.get(url)
            if item is None:
                return None
            expiry, result = item
            if expiry <= time.monotonic():
                del self._cache[url]
                return None
            self._cache.move_to_end(url)
            return result

    def _cache_put(self, url, result):
        with self._cache_lock:
            self._cache[url] = (time.monotonic() + CACHE_TTL, result)
            self._cache.move_to_end(url)
            while len(self._cache) > CACHE_MAX_ENTRIES:
                self._cache.popitem(last=False)

    # ----- single-flight -------------------------------------------------- #
    def _join_inflight(self, key):
        with self._inflight_lock:
            entry = self._inflight.get(key)
            if entry is not None:
                return entry, False
            entry = _Inflight()
            self._inflight[key] = entry
            return entry, True

    def _leave_inflight(self, key, entry):
        entry.event.set()
        with self._inflight_lock:
            self._inflight.pop(key, None)

    # ----- public API ----------------------------------------------------- #
    def fetch(self, url, method="GET", post_data=None):
        method = (method or "GET").upper()
        cacheable = method == "GET" and CACHE_TTL > 0

        if cacheable:
            cached = self._cache_get(url)
            if cached is not None:
                self._bump("cache_hits")
                return cached

        if method != "GET":
            # Never coalesce writes: identical concurrent POSTs may have side
            # effects, so each must reach FlareSolverr. They are still
            # serialised per host by the session lock.
            return self._guarded_fetch(url, method, post_data)

        key = url
        entry, is_leader = self._join_inflight(key)
        if not is_leader:
            self._bump("coalesced")
            entry.event.wait()
            return entry.result

        result = None
        try:
            # A leader that raced a just-finished leader can still hit cache.
            if cacheable:
                result = self._cache_get(url)
                if result is not None:
                    self._bump("cache_hits")
            if result is None:
                result = self._fetch_uncached(url, method, post_data)
                if cacheable and 200 <= result[0] < 300:
                    self._cache_put(url, result)
        except _FlareSolverrError as exc:
            result = _error_response("FlareSolverr error: %s" % exc)
        except Exception as exc:  # noqa: BLE001 - never let a request crash
            result = _error_response("FlareSolverr request failed: %s" % exc)
        finally:
            # Publish the outcome *before* waking followers, so coalesced
            # callers always observe a concrete result (never None).
            entry.result = result
            self._leave_inflight(key, entry)
        return result

    def _guarded_fetch(self, url, method, post_data):
        """Run a non-coalesced request, turning errors into a 502 tuple."""
        try:
            return self._fetch_uncached(url, method, post_data)
        except _FlareSolverrError as exc:
            return _error_response("FlareSolverr error: %s" % exc)
        except Exception as exc:  # noqa: BLE001 - never let a request crash
            return _error_response("FlareSolverr request failed: %s" % exc)

    def _fetch_uncached(self, url, method, post_data):
        self._bump("requests")
        host = _host_of(url)
        if SESSION_ENABLED and host:
            with self._host_lock(host):
                session_id = self._ensure_session(host)
                if session_id is not None:
                    try:
                        result = self._request(url, method, post_data, session_id)
                    except _SESSION_ERRORS:
                        # The solve failed or timed out; the driver may be in an
                        # indeterminate state, so drop the session and retry once
                        # with a fresh browser.
                        self._bump("session_errors")
                        self._destroy_session(host)
                        session_id = self._ensure_session(host)
                        if session_id is None:
                            return self._request_sessionless(
                                url, method, post_data
                            )
                        try:
                            result = self._request(
                                url, method, post_data, session_id
                            )
                        except _SESSION_ERRORS:
                            self._destroy_session(host)
                            raise
                    self._touch(host)
                    return result
        return self._request_sessionless(url, method, post_data)

    def _request_sessionless(self, url, method, post_data):
        return self._request(url, method, post_data, None)


_CLIENT = FlareSolverrClient(FLARESOLVERR_URL)


def fetch_via_flaresolverr(url, method="GET", post_data=None):
    """Relay a request through FlareSolverr.

    Returns a tuple ``(status, headers_dict, body_str)``. On failure it returns
    a 502 JSON error rather than raising.
    """
    try:
        return _CLIENT.fetch(url, method, post_data)
    except _FlareSolverrError as exc:
        return _error_response("FlareSolverr error: %s" % exc)
    except Exception as exc:  # noqa: BLE001 - never let a request crash the server
        return _error_response("FlareSolverr request failed: %s" % exc)


def _sanitize_header_value(value):
    """Strip CR/LF and surrounding whitespace from an upstream header value."""
    if not value:
        return ""
    return str(value).replace("\r", "").replace("\n", "").strip()


def _get_header(headers, name):
    """Case-insensitive lookup in a headers dict."""
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return value
    return None


def _reason_phrase(status):
    try:
        return HTTPStatus(int(status)).phrase
    except (ValueError, TypeError):
        return "OK"


# --------------------------------------------------------------------------- #
# Nested TLS stream (TLS-in-TLS over an already encrypted outer socket)
# --------------------------------------------------------------------------- #
class _NestedTLSStream:
    """Adapt a server-side ``ssl.SSLObject`` to a stream-like transport.

    Used when the client reaches us through the HTTPS listener and then issues
    CONNECT: the outer socket is already an ``ssl.SSLSocket``, so we cannot
    ``wrap_socket`` it again (that would operate on the raw fd and double
    encrypt). Instead we drive a nested TLS session over the *decrypted* outer
    channel using the ``MemoryBIO`` API.

    The object provides ``readline(limit)``, ``read(n)`` and ``sendall(data)``
    so it can be used as both the reader and the writer of ``_handle_tunnel``.
    """

    def __init__(self, ctx, outer_sock):
        self._outer = outer_sock
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._sslobj = ctx.wrap_bio(
            self._incoming, self._outgoing, server_side=True
        )
        self._buffer = bytearray()
        self._eof = False
        self._handshake()

    # -- low level plumbing ------------------------------------------------ #
    def _feed(self):
        """Move encrypted bytes from the outer socket into the incoming BIO."""
        data = self._outer.recv(65536)
        if not data:
            self._eof = True
            raise ConnectionError("outer connection closed")
        self._incoming.write(data)

    def _drain(self):
        """Flush pending outgoing TLS records to the outer socket."""
        while self._outgoing.pending:
            data = self._outgoing.read()
            if data:
                self._outer.sendall(data)

    def _handshake(self):
        while True:
            try:
                self._sslobj.do_handshake()
                break
            except ssl.SSLWantReadError:
                self._drain()
                self._feed()
            except ssl.SSLWantWriteError:
                self._drain()
        self._drain()

    def _read_some(self):
        """Return decrypted bytes from the nested session, or b'' on EOF."""
        while True:
            try:
                return self._sslobj.read(65536)
            except ssl.SSLWantReadError:
                self._drain()
                try:
                    self._feed()
                except ConnectionError:
                    return b""
            except ssl.SSLWantWriteError:
                self._drain()
            except ssl.SSLError:
                # Unexpected EOF / unclean shutdown: surface as EOF.
                return b""

    # -- stream API used by _handle_tunnel --------------------------------- #
    def read(self, n):
        if n <= 0:
            return b""
        while len(self._buffer) < n:
            chunk = self._read_some()
            if not chunk:
                break
            self._buffer.extend(chunk)
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data

    def readline(self, limit=-1):
        while True:
            idx = self._buffer.find(b"\n")
            if idx != -1:
                end = idx + 1
                if limit and limit > 0:
                    end = min(end, limit)
                line = bytes(self._buffer[:end])
                del self._buffer[:end]
                return line
            if limit and limit > 0 and len(self._buffer) >= limit:
                line = bytes(self._buffer[:limit])
                del self._buffer[:limit]
                return line
            chunk = self._read_some()
            if not chunk:
                if self._buffer:
                    line = bytes(self._buffer)
                    self._buffer.clear()
                    return line
                return b""
            self._buffer.extend(chunk)

    def sendall(self, data):
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            try:
                offset += self._sslobj.write(view[offset:])
            except ssl.SSLWantReadError:
                try:
                    self._feed()
                except ConnectionError:
                    raise OSError("outer connection closed")
            except ssl.SSLWantWriteError:
                pass
            self._drain()
        self._drain()

    def close(self):
        try:
            self._drain()
        except (ssl.SSLError, OSError):
            pass


# --------------------------------------------------------------------------- #
# Request handler
# --------------------------------------------------------------------------- #
class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "FlareProxy/2.0"
    protocol_version = "HTTP/1.1"

    # ----- helpers -------------------------------------------------------- #
    def _resolve_target_url(self):
        if self.path.startswith("http://") or self.path.startswith("https://"):
            return self.path
        host = self.headers.get("Host")
        if not host:
            return None
        return "https://%s%s" % (host, self.path)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        if length <= 0:
            return ""
        if length > MAX_BODY_BYTES:
            raise ValueError("request body too large")
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def _send_json_error(self, status, message):
        body = json.dumps({"error": message}).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionError, OSError):
            pass

    def _serve_ca_cert(self):
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Length", str(len(_ca_cert_pem)))
            self.end_headers()
            self.wfile.write(_ca_cert_pem)
        except (BrokenPipeError, ConnectionError, OSError):
            pass

    def _handle_http(self, method):
        try:
            url = self._resolve_target_url()
            if not url:
                self._send_json_error(400, "Missing Host header")
                return
            try:
                post_data = self._read_body() if method == "POST" else None
            except ValueError as exc:
                # The client-declared body is too large: we did not consume it,
                # so the connection can no longer be safely reused.
                self.close_connection = True
                self._send_json_error(413, str(exc))
                return
            status, headers, body = fetch_via_flaresolverr(url, method, post_data)
            body_bytes = body.encode("utf-8")
            content_type = (
                _sanitize_header_value(_get_header(headers, "content-type"))
                or "text/html; charset=utf-8"
            )
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)
        except (BrokenPipeError, ConnectionError, OSError):
            pass
        except Exception as exc:  # noqa: BLE001 - one bad request must not crash
            self._send_json_error(502, str(exc))

    # ----- HTTP verbs ----------------------------------------------------- #
    def do_GET(self):
        if self.path == "/__flareproxy/ca.crt":
            self._serve_ca_cert()
            return
        self._handle_http("GET")

    def do_POST(self):
        self._handle_http("POST")

    # ----- CONNECT / MITM ------------------------------------------------- #
    def _parse_connect_target(self):
        target = self.path or ""
        host, _, port = target.rpartition(":")
        if not host:
            host = target
            port = "443"
        try:
            port = int(port)
        except ValueError:
            port = 443
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return host or None, port

    def _write_tunnel_response(self, writer, status, headers, body):
        body_bytes = body.encode("utf-8")
        content_type = (
            _sanitize_header_value(_get_header(headers, "content-type"))
            or "text/html; charset=utf-8"
        )
        head = (
            "HTTP/1.1 %s %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %d\r\n"
            "\r\n"
        ) % (status, _reason_phrase(status), content_type, len(body_bytes))
        writer.sendall(head.encode("iso-8859-1") + body_bytes)

    def _handle_tunnel(self, reader, writer, host, port):
        try:
            while True:
                request_line = reader.readline(65536)
                if not request_line:
                    break  # client disconnected
                try:
                    line = request_line.decode("iso-8859-1").strip()
                except Exception:  # noqa: BLE001
                    break
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 3:
                    break  # malformed request

                method, path = parts[0], parts[1]
                headers = {}
                while True:
                    header_line = reader.readline(65536)
                    if not header_line:
                        break
                    if header_line in (b"\r\n", b"\n"):
                        break
                    try:
                        text = header_line.decode("iso-8859-1").strip()
                    except Exception:  # noqa: BLE001
                        continue
                    if ":" in text:
                        key, value = text.split(":", 1)
                        headers[key.strip().lower()] = value.strip()

                try:
                    content_length = int(headers.get("content-length", 0) or 0)
                except (TypeError, ValueError):
                    content_length = 0
                if content_length > MAX_BODY_BYTES:
                    self._write_tunnel_response(
                        writer,
                        413,
                        {"Content-Type": "application/json"},
                        json.dumps({"error": "request body too large"}),
                    )
                    break
                body = reader.read(content_length) if content_length > 0 else b""

                if path.startswith("http://") or path.startswith("https://"):
                    url = path
                else:
                    url = "https://%s%s" % (host, path)

                post_data = None
                if method.upper() == "POST" and body:
                    post_data = body.decode("utf-8", errors="replace")

                status, resp_headers, resp_body = fetch_via_flaresolverr(
                    url, method, post_data
                )
                self._write_tunnel_response(writer, status, resp_headers, resp_body)
        except (ssl.SSLError, OSError, ValueError):
            return

    def do_CONNECT(self):
        host, port = self._parse_connect_target()
        if not host:
            self._send_json_error(400, "Malformed CONNECT target")
            return

        try:
            ctx = get_server_ssl_context(host)
        except Exception as exc:  # noqa: BLE001
            self._send_json_error(502, "TLS context error: %s" % exc)
            return

        try:
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionError, OSError):
            return

        # We manage the tunnel socket manually from here on.
        self.close_connection = True

        if isinstance(self.connection, ssl.SSLSocket):
            # The client reached us through the HTTPS listener: the outer
            # socket is already a TLS session. Nesting another wrap_socket()
            # would operate on the raw fd and double-encrypt, so drive a
            # nested server session over the decrypted outer channel instead.
            try:
                stream = _NestedTLSStream(ctx, self.connection)
            except (ssl.SSLError, OSError, ConnectionError):
                return
            try:
                self._handle_tunnel(stream, stream, host, port)
            finally:
                stream.close()
            return

        # Plain listener: wrap the raw client socket directly.
        try:
            tls = ctx.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError):
            return

        reader = None
        try:
            reader = tls.makefile("rb")
            self._handle_tunnel(reader, tls, host, port)
        finally:
            if reader is not None:
                try:
                    reader.close()
                except (OSError, ValueError):
                    pass
            try:
                tls.close()
            except (ssl.SSLError, OSError):
                pass


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main():
    _init_certs()

    http_server = ThreadingHTTPServer(("", FLAREPROXY_PORT), ProxyHTTPRequestHandler)
    https_server = ThreadingHTTPServer(("", FLAREPROXY_HTTPS_PORT), ProxyHTTPRequestHandler)
    https_server.daemon_threads = True
    http_server.daemon_threads = True
    https_server.socket = _proxy_ssl_context.wrap_socket(
        https_server.socket, server_side=True
    )

    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    threading.Thread(target=https_server.serve_forever, daemon=True).start()

    print("FlareProxy adapter running", flush=True)
    print("  HTTP  proxy:   http://0.0.0.0:%d" % FLAREPROXY_PORT, flush=True)
    print("  HTTPS proxy:   https://0.0.0.0:%d" % FLAREPROXY_HTTPS_PORT, flush=True)
    print("  CA cert:       %s" % CA_CERT_PATH, flush=True)
    print(
        "  CA download:   http://<host>:%d/__flareproxy/ca.crt" % FLAREPROXY_PORT,
        flush=True,
    )
    print("  FlareSolverr:  %s" % FLARESOLVERR_URL, flush=True)
    print(
        "  Sessions:      %s (idle TTL %gs)"
        % ("enabled" if SESSION_ENABLED else "disabled", SESSION_IDLE_TTL),
        flush=True,
    )
    print(
        "  Response cache: %s"
        % ("%gs TTL" % CACHE_TTL if CACHE_TTL > 0 else "disabled"),
        flush=True,
    )
    print(
        "Note: TLS certificates are ephemeral and regenerated on every start.",
        flush=True,
    )

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
