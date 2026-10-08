#!/usr/bin/env bash
#
# Integration smoke test against the REAL FlareSolverr docker image.
#
#   1. docker run ghcr.io/flaresolverr/flaresolverr:latest (name flareproxy-it)
#   2. wait for POST /v1 {"cmd":"sessions.list"} to answer status ok (~90s)
#   3. start flareproxy.py locally against it
#   4. curl https://example.com through the HTTP proxy, assert HTTP 200
#   5. assert sessions.list contains a session prefixed "flareproxy-"
#   6. clean up both processes (docker rm -f, kill proxy)
#
# Requires: docker, curl, python3 (with the flareproxy dependencies installed).
# Exits non-zero on any failure.

set -euo pipefail

FS_IMAGE="ghcr.io/flaresolverr/flaresolverr:latest"
FS_NAME="flareproxy-it"
FS_PORT="${FLARESOLVERR_PORT:-8191}"
PROXY_PORT="${FLAREPROXY_PORT:-8080}"
PROXY_HTTPS_PORT="${FLAREPROXY_HTTPS_PORT:-8443}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGDIR="/tmp/opencode"
mkdir -p "$LOGDIR"
PROXY_LOG="$LOGDIR/flareproxy-smoke.log"

PROXY_PID=""
READY_TIMEOUT=90
PROXY_READY_TIMEOUT=45

log()  { printf '[smoke] %s\n' "$*"; }
fail() { printf '[smoke] FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$FS_NAME"; then
    log "removing container $FS_NAME"
    docker rm -f "$FS_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker not found on PATH"
command -v curl   >/dev/null 2>&1 || fail "curl not found on PATH"

# --- 1. start FlareSolverr ------------------------------------------------- #
if docker ps -a --format '{{.Names}}' | grep -qx "$FS_NAME"; then
  log "removing stale container $FS_NAME"
  docker rm -f "$FS_NAME" >/dev/null 2>&1 || true
fi

log "starting FlareSolverr container ($FS_IMAGE)"
docker run -d --rm --name "$FS_NAME" \
  -p "127.0.0.1:${FS_PORT}:8191" \
  -e LOG_LEVEL=info \
  "$FS_IMAGE" >/dev/null

fs_api() {
  curl -sS --max-time 10 -X POST "http://127.0.0.1:${FS_PORT}/v1" \
    -H 'Content-Type: application/json' -d "$1" || true
}

# --- 2. wait for readiness ------------------------------------------------- #
log "waiting for FlareSolverr readiness (up to ${READY_TIMEOUT}s)"
fs_ready=0
for _ in $(seq 1 "$READY_TIMEOUT"); do
  if ! docker ps --format '{{.Names}}' | grep -qx "$FS_NAME"; then
    docker logs "$FS_NAME" 2>&1 | tail -n 30 || true
    fail "container exited early (see logs above)"
  fi
  out="$(fs_api '{"cmd":"sessions.list"}')"
  if printf '%s' "$out" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    fs_ready=1
    break
  fi
  sleep 1
done
[[ "$fs_ready" -eq 1 ]] || fail "FlareSolverr not ready after ${READY_TIMEOUT}s"

# --- 3. start flareproxy.py ------------------------------------------------ #
log "starting flareproxy.py on HTTP ${PROXY_PORT} / HTTPS ${PROXY_HTTPS_PORT}"
FLARESOLVERR_URL="http://127.0.0.1:${FS_PORT}/v1" \
FLAREPROXY_PORT="$PROXY_PORT" \
FLAREPROXY_HTTPS_PORT="$PROXY_HTTPS_PORT" \
python3 "$ROOT/flareproxy.py" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

proxy_ready=0
for _ in $(seq 1 "$PROXY_READY_TIMEOUT"); do
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    tail -n 30 "$PROXY_LOG" || true
    fail "flareproxy exited early (see log above)"
  fi
  if curl -s -o /dev/null --max-time 2 \
       "http://127.0.0.1:${PROXY_PORT}/__flareproxy/ca.crt"; then
    proxy_ready=1
    break
  fi
  sleep 1
done
[[ "$proxy_ready" -eq 1 ]] || { tail -n 30 "$PROXY_LOG" || true; fail "flareproxy not ready"; }

# --- 4. fetch a benign URL through the proxy ------------------------------- #
# The proxy intercepts (MITMs) HTTPS targets, so the client must trust its
# ephemeral CA. Download it from the convenience endpoint first.
CA_FILE="$LOGDIR/flareproxy-smoke-ca.crt"
log "downloading the ephemeral CA to ${CA_FILE}"
curl -sS --max-time 10 -o "$CA_FILE" \
  "http://127.0.0.1:${PROXY_PORT}/__flareproxy/ca.crt" \
  || fail "could not download the proxy CA"

log "fetching https://example.com through the HTTP proxy (MITM + CA trust)"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
  --proxy "http://127.0.0.1:${PROXY_PORT}" --cacert "$CA_FILE" \
  https://example.com/ || true)"
[[ "$code" == "200" ]] || fail "expected HTTP 200 through proxy, got '${code}'"
log "proxy returned HTTP 200"

# --- 5. assert a flareproxy- session exists -------------------------------- #
list_out="$(fs_api '{"cmd":"sessions.list"}')"
printf '%s' "$list_out" | grep -Eq '"flareproxy-[^"]*"' \
  || fail "no session prefixed 'flareproxy-' in sessions.list: ${list_out}"
log "found a flareproxy- prefixed session"

log "ALL CHECKS PASSED"
exit 0
