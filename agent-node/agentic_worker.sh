#!/usr/bin/env bash
set -Eeuo pipefail
STATE_ROOT="${AB_AGENT_STATE_ROOT:-/tmp/amazingbecca-agent-${UID}}"
QUEUE_ROOT="${AB_AGENT_QUEUE_ROOT:-/tmp/amazingbecca-agentic-queue-${UID}}"
RUN="$STATE_ROOT/run"
LOG="$STATE_ROOT/log"
PID="$RUN/worker.pid"
mkdir -p "$QUEUE_ROOT" "$RUN" "$LOG"

alive() {
  [[ -f "$PID" ]] || return 1
  local p; p="$(cat "$PID")"
  kill -0 "$p" 2>/dev/null
}

start() {
  if alive; then echo "agentic worker already running pid=$(cat "$PID")"; return 0; fi
  rm -f "$PID"
  AB_AGENT_QUEUE_ROOT="$QUEUE_ROOT" nohup python3 -B "$(dirname "$0")/agentic_executor.py" worker --interval 0.25 >"$LOG/worker.log" 2>&1 &
  echo $! > "$PID"
  sleep .2
  alive || { echo "agentic worker failed to start" >&2; tail -50 "$LOG/worker.log" >&2 || true; exit 1; }
  echo "agentic worker started pid=$(cat "$PID") queue=$QUEUE_ROOT"
}

stop() {
  if alive; then
    local p; p="$(cat "$PID")"
    kill "$p" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep .1; done
    kill -9 "$p" 2>/dev/null || true
  fi
  rm -f "$PID"
  echo "agentic worker stopped"
}

status() {
  if alive; then echo "RUNNING pid=$(cat "$PID") queue=$QUEUE_ROOT"; else echo "STOPPED queue=$QUEUE_ROOT"; fi
  find "$QUEUE_ROOT" -maxdepth 1 -type f -name '*.json' -printf '%f\n' 2>/dev/null | sort || true
}

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  *) echo "usage: $0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
