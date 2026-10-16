#!/usr/bin/env bash
set -euo pipefail

# Stop the re-hosted web service that start_rehost.sh launched inside a
# container. Only touches the traced httpd chain in the named container -
# other containers' httpd (e.g. a 24/7 lab instance) is never matched, because
# the scan runs INSIDE the target container's own guest /proc.
#
# Why in-container kill: the emulated httpd ignores SIGTERM, and killing the
# host-side qemu PID from outside the container usually fails (operation not
# permitted - those PIDs are root-owned). Killing the emulated PID via
# `docker exec ... kill -9` works (verified: it stopped the 878 GB writer).
#
# Best practice: run the traced httpd only for the duration of a fuzz session.
# Wrap start/stop with FuzzingRecord/rehost_session.sh.
#
# Usage:
#   FuzzingRecord/stop_rehost.sh --container NAME [--port 80] [--timeout 20]
#   FuzzingRecord/stop_rehost.sh --container NAME --reset-log

CONTAINER=""
PORT="80"
TIMEOUT="20"
RESET_LOG="0"
LOG_NAME="qemu_trace.log"
SCRATCH="/scratch"

usage() {
  cat <<'EOF'
Usage:
  FuzzingRecord/stop_rehost.sh --container NAME [options]

Terminates the traced httpd (instrumented QEMU) that start_rehost.sh launched
in the given container, then waits for the HTTP port to go back down.

Options:
  --container NAME   Container whose traced httpd to stop (required)
  --port PORT        HTTP port to verify dropped (default: 80)
  --timeout SEC      How long to wait for the port to drop (default: 20)
  --reset-log        Also zero the trace log in the container (default: no)
  --log-name NAME    Trace log file name inside scratch (default: qemu_trace.log)
  --scratch DIR      Scratch path in the container (default: /scratch)
EOF
}

log() { echo "[stop_rehost] $*"; }
die() { echo "[-] $*" >&2; exit 1; }
curl_device() { curl --noproxy '*' "$@"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --container)  CONTAINER="$2"; shift 2 ;;
    --port)       PORT="$2"; shift 2 ;;
    --timeout)    TIMEOUT="$2"; shift 2 ;;
    --reset-log)  RESET_LOG="1"; shift ;;
    --log-name)   LOG_NAME="$2"; shift 2 ;;
    --scratch)    SCRATCH="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            usage >&2; die "unknown option: $1" ;;
  esac
done

[[ -n "$CONTAINER" ]] || { usage >&2; die "--container is required"; }
docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" \
  || die "container '$CONTAINER' is not running"

CONTAINER_IP="$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$CONTAINER")"
HTTP_URL="http://${CONTAINER_IP}:${PORT}/"

# Kill traced httpd INSIDE the container: scan the guest /proc for the
# qemu -execve ... /sbin/httpd chain and SIGKILL it (SIGTERM is ignored).
# The scanner's own sh -c is excluded by the "/bin/sh -c" guard.
log "scanning '$CONTAINER' guest /proc for the traced httpd chain"
KILLED=$(docker exec "$CONTAINER" sh -c '
  for p in /proc/[0-9]*; do
    [ -r "$p/cmdline" ] || continue
    c=$(cat "$p/cmdline" 2>/dev/null) || continue
    case "$c" in
      *" /bin/sh -c"*)  continue ;;              # our own scanner shell
      *-execve*httpd*)  pid=${p#/proc/}; echo "$pid"
                        kill -9 "$pid" 2>/dev/null || true ;;
    esac
  done' 2>/dev/null || true)

if [[ -z "$KILLED" ]]; then
  log "no traced httpd found in '$CONTAINER'"
else
  log "killed traced httpd emulated PIDs: $(echo "$KILLED" | tr '\n' ' ')"
fi

if [[ "$RESET_LOG" == "1" ]]; then
  TRACE_LOG="${SCRATCH%/}/$LOG_NAME"
  docker exec "$CONTAINER" sh -c "> '$TRACE_LOG' 2>/dev/null || :" \
    && log "reset trace log: $TRACE_LOG" \
    || log "WARNING: could not reset $TRACE_LOG"
fi

# Verify the port actually went down.
log "waiting for $HTTP_URL to stop answering (timeout ${TIMEOUT}s)"
ELAPSED=0
CODE="000"
while [[ "$ELAPSED" -lt "$TIMEOUT" ]]; do
  CODE="$(curl_device -s -o /dev/null -w '%{http_code}' --max-time 3 "$HTTP_URL" || true)"
  [[ "$CODE" == "000" ]] && break
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done
if [[ "$CODE" != "000" ]]; then
  die "port $PORT still answering (HTTP $CODE) after ${TIMEOUT}s; inspect '$CONTAINER' manually"
fi
echo
log "traced service stopped; $HTTP_URL is down (HTTP 000)."
log "fuzz session over - the trace log is bounded to the session."