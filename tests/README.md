# FlareProxy tests

Black-box tests for the FlareProxy → FlareSolverr adapter. Everything here is
**stdlib-only** and never imports `flareproxy.py`; the proxy is always exercised
as a real subprocess over its HTTP proxy listener.

## Files

| File | Purpose |
| --- | --- |
| `mock_flaresolverr.py` | Mock of the FlareSolverr v3.5.2 `POST /v1` protocol plus the `GET /__state` and `GET /__reset` control channels. Runnable as `python tests/mock_flaresolverr.py <port>`. |
| `run_behavior_tests.py` | Orchestrator: starts the mock + `flareproxy.py`, drives requests through the proxy, asserts behaviour and prints `PASS`/`FAIL` per case. |
| `smoke_real_flaresolverr.sh` | End-to-end smoke test against the real FlareSolverr Docker image. |

## Behaviour tests (no Docker, no network)

Starts a mock FlareSolverr and a fresh `flareproxy.py` for each case. All client
traffic goes to `127.0.0.1` only; target URLs are fake-but-well-formed
(e.g. `http://target.test/path?q=1`) and the mock ignores the host.

```bash
python tests/run_behavior_tests.py
```

Cases:

- **A. Session reuse** — `FLAREPROXY_CACHE_TTL=0`; two sequential GETs to the
  same URL produce exactly one `sessions.create` and both upstream requests
  carry the *same* `session` id.
- **B. Cache** — `FLAREPROXY_CACHE_TTL=300`; the second GET of the same URL is
  served from cache (one upstream hit, identical body); a different URL still
  goes upstream.
- **C. Single-flight** — `FLAREPROXY_CACHE_TTL=0` with `MOCK_DELAY=1.0`; five
  concurrent identical GETs result in exactly one upstream request and five
  identical client responses.
- **D. Sessionless fallback** — `FLAREPROXY_SESSION=false`; no session is
  created and requests carry no `session` field.
- **E. Cache disabled** — `FLAREPROXY_CACHE_TTL=0`; repeated GETs hit upstream
  every time.
- **F. POST never coalesced** — `MOCK_DELAY=1.0`; five concurrent identical
  POSTs each reach upstream (writes must not be collapsed), all returning 200.

Per-case logs are written to `/tmp/opencode/` (`mock-<port>.log`,
`flareproxy-<port>.log`). The process exits `0` only if every case passes.

> Note: against the pre-session/cache version of `flareproxy.py` (before this
> change), cases A–C are expected to fail. That is the point — the harness
> reports the missing behaviour without crashing.

## Real FlareSolverr smoke test (requires Docker)

Pulls/runs `ghcr.io/flaresolverr/flaresolverr:latest`, waits for it to become
ready, starts `flareproxy.py` against it, downloads the proxy's ephemeral CA,
fetches `https://example.com` through the HTTP proxy with `curl` (trusting that
CA, since the proxy MITMs HTTPS) asserting HTTP 200, and checks that a session
prefixed `flareproxy-` is present. Cleans up the container and the proxy on
exit.

```bash
tests/smoke_real_flaresolverr.sh
```

Environment overrides: `FLAREPROXY_PORT` (default 8080),
`FLAREPROXY_HTTPS_PORT` (default 8443), `FLARESOLVERR_PORT` (default 8191).

Requires `docker`, `curl` and `python3` with the `flareproxy.py` dependencies
(`requests`, `cryptography`) installed.
