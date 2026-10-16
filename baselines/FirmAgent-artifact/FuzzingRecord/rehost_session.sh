#!/usr/bin/env bash
set -euo pipefail

# Session-scope the traced re-host service, so the QEMU trace log only grows
# during active fuzzing instead of 24/7 (observed: one 878 GB trace).
#
# Best practice this wrapper enforces (see README "Keep the trace log small"):
#   1. the traced httpd runs ONLY for the duration of a session (start..stop),
#   2. the trace log is zeroed at the START of every session,
#   3. stopping also resets the log, so an idle service never grows one.
#
# Subcommands:
#   start [start_rehost.sh options...]   reset log, then launch the service
#   stop  [stop_rehost.sh options...]    terminate the traced httpd, reset log
#   status                                print whether a traced httpd is running
#
# Examples:
#   FuzzingRecord/rehost_session.sh start --container tew632 \
#       --dfilter "$(python3 FuzzingRecord/make_dfilter.py e2e/tew632/sink_scope_addr.txt)"
#   ... fuzz with Fuzzer.py / taint_monitor.py / build_source_json.py ...
#   FuzzingRecord/rehost_session.sh stop --container tew632
#
# start_rehost.sh can apply a per-process file-size limit. Do not truncate the
# log during a fuzz session: doing so invalidates feedback and Source offsets.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
START_REHOST="$SCRIPT_DIR/start_rehost.sh"
STOP_REHOST="$SCRIPT_DIR/stop_rehost.sh"

log() { echo "[rehost_session] $*"; }
die() { echo "[-] $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  FuzzingRecord/rehost_session.sh {start|stop|status} [options]

Starts/stops the traced re-host service as a bounded session: the trace log is
reset at session start (and stop), and the traced httpd only runs between
`start` and `stop`.

Subcommands:
  start   Reset the trace log, then delegate to FuzzingRecord/start_rehost.sh
          with the same options (--container, --dfilter, --dfilter-file, ...).
  stop    Delegate to FuzzingRecord/stop_rehost.sh: kill the traced httpd in
          the container and reset the trace log (pass --reset-log to keep it).
  status  Show whether the container currently runs a traced httpd and whether
          its HTTP port answers.

Options are forwarded to the underlying script; see their --help. Common:
    --container NAME        container to start/stop the traced service in
EOF
}

[[ $# -ge 1 ]] || { usage >&2; die "subcommand required: start|stop|status"; }
SUB="$1"; shift

case "$SUB" in
  start)
    # Extract --container (needed for the pre-start log reset) and forward the rest.
    CONTAINER=""
    FORWARD=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --container) CONTAINER="$2"; FORWARD+=("$1" "$2"); shift 2 ;;
        -h|--help)   exec "$START_REHOST" -h ;;
        *)           FORWARD+=("$1"); shift ;;
      esac
    done
    [[ -n "$CONTAINER" ]] || die "start requires --container NAME"
    docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" \
      || die "container '$CONTAINER' is not running"
    # Reset the trace log BEFORE the session starts (best practice #2).
    docker exec "$CONTAINER" sh -c '> /scratch/qemu_trace.log 2>/dev/null || :' \
      && log "trace log reset: /scratch/qemu_trace.log" \
      || log "WARNING: could not reset /scratch/qemu_trace.log"
    log "starting traced session on '$CONTAINER' ..."
    exec "$START_REHOST" "${FORWARD[@]}"
    ;;
  stop)
    # stop_rehost.sh scans /proc with docker exec, which requires an unpaused container.
    CONTAINER=""
    ARGS=("$@")
    for ((i = 0; i < ${#ARGS[@]}; i++)); do
      if [[ "${ARGS[i]}" == --container ]] && ((i + 1 < ${#ARGS[@]})); then
        CONTAINER="${ARGS[i + 1]}"
        break
      fi
    done
    if [[ -n "$CONTAINER" ]] && \
        [[ "$(docker inspect "$CONTAINER" --format '{{.State.Paused}}' 2>/dev/null || true)" == true ]]; then
      docker unpause "$CONTAINER" >/dev/null || die "could not unpause '$CONTAINER' before stopping"
    fi
    # Forward everything to stop_rehost.sh; add --reset-log by default unless
    # the caller explicitly passes --reset-log/--keep-log themselves.
    HAS_RESET=0
    for a in "$@"; do
      case "$a" in --reset-log|--keep-log) HAS_RESET=1 ;; esac
    done
    if [[ "$HAS_RESET" == "0" ]]; then
      exec "$STOP_REHOST" --reset-log "$@"
    fi
    exec "$STOP_REHOST" "$@"
    ;;
  status)
    CONTAINER=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --container) CONTAINER="$2"; shift 2 ;;
        *)           CONTAINER="$1"; shift ;;   # tolerate positional form
      esac
    done
    [[ -n "$CONTAINER" ]] || die "status requires --container NAME"
    docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" \
      || die "container '$CONTAINER' is not running"
    PIDS="$(docker top "$CONTAINER" 2>/dev/null \
      | awk 'NR>1 && $0 ~ /httpd/ {print $2":"$NF}' | tr '\n' ' ' || true)"
    IP="$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$CONTAINER")"
    CODE="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
      --max-time 3 "http://${IP}/" || true)"
    if [[ -n "${PIDS// /}" ]]; then
      log "traced httpd RUNNING ($PIDS); HTTP $CODE"
    else
      log "no traced httpd; HTTP $CODE"
    fi
    ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; die "unknown subcommand: $SUB (expected start|stop|status)" ;;
esac
