#!/usr/bin/env bash
set -euo pipefail

# Start the re-hosted web service inside a Greenhouse container, under
# instrumented QEMU with taint logging. No in-container fuzzing: fuzzing is
# done from the host by FuzzingRecord/Fuzzer.py against the service IP.
#
# Equivalent manual commands are documented in README.md (Runtime Monitoring).

CONTAINER=""
HTTPD_PATH="/sbin/httpd"
QEMU_BIN="/qemu-mips-static"
QEMU_ARGS="-hackbind -hackproc -hacksysinfo"
SCRATCH="/scratch"
DFILTER="${QEMU_DFILTER:-}"
DFILTER_FILE=""
LOG_NAME="qemu_trace.log"
QEMU_LOG_FLAGS="cpu,exec,nochain"
TRACE_MAX_MIB="${TRACE_MAX_MIB:-0}"
BACKGROUND_CMD="/bin/sh /run_background.sh"
SETUP_CMD="/run_setup.sh"
PRELOAD="libnvram-faker.so"
HEALTH_PORT="80"
HEALTH_TIMEOUT="60"
FORCE="0"
LEAVE_RUNNING="0"

usage() {
  cat <<'EOF'
Usage:
  FuzzingRecord/start_rehost.sh --container NAME [options]

Starts the re-hosted web service inside a running Greenhouse container under
instrumented QEMU, with taint tracing written to the shared volume. Then print
the next-step commands for host-side guided fuzzing.

Required:
  --container NAME        Running container (name or id)

Options:
  --httpd PATH            Service binary inside the container (default: /sbin/httpd)
  --qemu PATH             Instrumented qemu inside the container (default: /qemu-mips-static)
  --scratch DIR           Shared-volume mount point for the trace log (default: /scratch)
  --dfilter "RANGES"      QEMU_DFILTER sink scope, e.g. "0x405538..0x4059D8,..."
  --dfilter-file FILE     Read QEMU_DFILTER from a file (e.g. a trimmed sink_scope_addr.txt)
  --log-name NAME         Trace log file name inside scratch (default: qemu_trace.log)
  --qemu-log-flags F      QEMU_LOG value (default: cpu,exec,nochain)
  --trace-max-mib N      Optional trace size limit (default: 0 = unlimited)
  --background-cmd CMD    Background service command (default: "/bin/sh /run_background.sh"; "none" skips)
  --setup-cmd CMD         Device setup command (default: "/run_setup.sh"; "none" skips)
  --preload LIB           Guest LD_PRELOAD library (default: libnvram-faker.so; "none" skips)
  --port PORT             HTTP port for the health check (default: 80)
  --timeout SEC           Health check timeout in seconds (default: 60)
  --force                 Start even if the device already answers on --port
  --leave-running         Keep container unpaused after startup (default: pause while idle)

Note: keep the QEMU_DFILTER string short (a few ranges). Very long scope
strings (multi-KB) may prevent the guest from starting.
EOF
}

log()  { echo "[start_rehost] $*"; }
die()  { echo "[-] $*" >&2; exit 1; }

# Health checks must reach the container directly - never through an HTTP proxy
curl_device() { curl --noproxy '*' "$@"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --container)        CONTAINER="$2"; shift 2 ;;
    --httpd)            HTTPD_PATH="$2"; shift 2 ;;
    --qemu)             QEMU_BIN="$2"; shift 2 ;;
    --scratch)          SCRATCH="$2"; shift 2 ;;
    --dfilter)          DFILTER="$2"; shift 2 ;;
    --dfilter-file)     DFILTER_FILE="$2"; shift 2 ;;
    --log-name)         LOG_NAME="$2"; shift 2 ;;
    --qemu-log-flags)   QEMU_LOG_FLAGS="$2"; shift 2 ;;
    --trace-max-mib)    TRACE_MAX_MIB="$2"; shift 2 ;;
    --background-cmd)   BACKGROUND_CMD="$2"; shift 2 ;;
    --setup-cmd)        SETUP_CMD="$2"; shift 2 ;;
    --preload)          PRELOAD="$2"; shift 2 ;;
    --port)             HEALTH_PORT="$2"; shift 2 ;;
    --timeout)          HEALTH_TIMEOUT="$2"; shift 2 ;;
    --force)            FORCE="1"; shift ;;
    --leave-running)    LEAVE_RUNNING="1"; shift ;;
    -h|--help)          usage; exit 0 ;;
    *)                  usage >&2; die "unknown option: $1" ;;
  esac
done

[[ -n "$CONTAINER" ]] || { usage >&2; die "--container is required"; }
[[ "$TRACE_MAX_MIB" =~ ^(0|[1-9][0-9]*)$ ]] || die "--trace-max-mib must be a nonnegative integer"

docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" \
  || die "container '$CONTAINER' is not running"

if [[ -n "$DFILTER_FILE" ]]; then
  [[ -f "$DFILTER_FILE" ]] || die "dfilter file not found: $DFILTER_FILE"
  DFILTER="$(tr -d '\n' < "$DFILTER_FILE")"
fi

if [[ -z "$DFILTER" ]]; then
  log "WARNING: no QEMU_DFILTER set - the trace log will grow unboundedly."
  log "         Pass --dfilter with a few sink ranges (from sink_scope_addr.txt)."
fi

CONTAINER_IP="$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$CONTAINER")"
[[ -n "$CONTAINER_IP" ]] || die "cannot resolve container IP"

HTTP_URL="http://${CONTAINER_IP}:${HEALTH_PORT}/"
if [ "$FORCE" != "1" ]; then
  CODE="$(curl_device -s -o /dev/null -w '%{http_code}' --max-time 3 "$HTTP_URL" || true)"
  if [[ "$CODE" != "000" ]]; then
    die "device already answers at $HTTP_URL (HTTP $CODE). Use --force to continue."
  fi
fi

# Container-side existence checks for optional steps
container_has() {
  docker exec "$CONTAINER" sh -c "test -e \"$1\"" >/dev/null 2>&1
}

# 1) Background service chain (nvram-faker etc.)
if [[ "$BACKGROUND_CMD" != "none" ]]; then
  if container_has "${BACKGROUND_CMD##* }"; then
    log "starting background chain: $BACKGROUND_CMD"
    docker exec "$CONTAINER" sh -c "
      export QEMU_SET_ENV=\"PATH=\$PATH,LD_PRELOAD=\$LD_PRELOAD\"
      unset LD_PRELOAD
      exec $QEMU_BIN $QEMU_ARGS \
        -execve \"$QEMU_BIN $QEMU_ARGS \" \
        -E LD_PRELOAD=\"$PRELOAD\" $BACKGROUND_CMD
    " || log "WARNING: background chain exited non-zero (may be non-fatal)"
  else
    log "WARNING: $BACKGROUND_CMD not found in container - skipping background chain"
  fi
fi

# 2) Device setup
if [[ "$SETUP_CMD" != "none" ]]; then
  if container_has "${SETUP_CMD##* }"; then
    log "running setup: $SETUP_CMD"
    docker exec "$CONTAINER" sh -c "$SETUP_CMD" \
      || log "WARNING: setup exited non-zero (may be non-fatal, e.g. dummy0 netlink)"
  else
    log "WARNING: $SETUP_CMD not found in container - skipping setup"
  fi
fi

# 3) Start the web service under instrumented QEMU with taint tracing
TRACE_LOG="${SCRATCH%/}/$LOG_NAME"
log "starting $HTTPD_PATH under $QEMU_BIN (log: $TRACE_LOG)"
docker exec -d "$CONTAINER" sh -c "
  export QEMU_SET_ENV=\"PATH=\$PATH,LD_PRELOAD=\$LD_PRELOAD\"
  unset LD_PRELOAD
  ulimit -c 0
  if [ $TRACE_MAX_MIB -gt 0 ]; then
    ulimit -f $((TRACE_MAX_MIB * 2048)) || exit 1
  fi
  export QEMU_LOG=\"$QEMU_LOG_FLAGS\"
  export QEMU_LOG_FILENAME=\"$TRACE_LOG\"
  export QEMU_DFILTER=\"$DFILTER\"
  exec $QEMU_BIN $QEMU_ARGS \
    -execve \"$QEMU_BIN $QEMU_ARGS\" \
    -E LD_PRELOAD=\"$PRELOAD\" $HTTPD_PATH
"

# 4) Health check
log "waiting for $HTTP_URL (timeout ${HEALTH_TIMEOUT}s)"
ELAPSED=0
CODE="000"
while [[ "$ELAPSED" -lt "$HEALTH_TIMEOUT" ]]; do
  CODE="$(curl_device -s -o /dev/null -w '%{http_code}' --max-time 3 "$HTTP_URL" || true)"
  [[ "$CODE" != "000" ]] && break
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

if [[ "$CODE" == "000" ]]; then
  die "service did not come up within ${HEALTH_TIMEOUT}s (no HTTP response)"
fi
if [[ "$LEAVE_RUNNING" != "1" ]]; then
  docker pause "$CONTAINER" >/dev/null || die "could not pause idle container '$CONTAINER'"
fi

echo
if [[ "$LEAVE_RUNNING" = 1 ]]; then
  log "service started: $HTTP_URL (HTTP $CODE)"
else
  log "service started: $HTTP_URL (HTTP $CODE); paused while idle"
fi
log "trace log (container): $TRACE_LOG"
log "trace log (host):      the host path backing '$SCRATCH' volume"
cat <<EOF

Next steps (host side):

  # 1. fuzzer: resume only while each PoC request is being evaluated
  python3 FuzzingRecord/Fuzzer.py \\
    --json-file <workdir>/Pre_fuzzing.json \\
    --distance-file <workdir>/sink_distance_scores.json \\
    --qemu-log <host-path-to>/$LOG_NAME \\
    --idle-pause-container $CONTAINER \\
    --trace-windows-out <workdir>/trace_windows.jsonl \\
    --delay 0.5 --host $CONTAINER_IP --method POST \\
    --taint-tag TAINTTAG --tag-mode unique

  # 2. build Source.json (exact join):
  python3 FuzzingRecord/build_source_json.py \\
    --qemu-log <host-path-to>/$LOG_NAME \\
    --windows <workdir>/trace_windows.jsonl \\
    --result-stream <workdir>/result_stream.ndjson \\
    --output <workdir>/Source.json
EOF
