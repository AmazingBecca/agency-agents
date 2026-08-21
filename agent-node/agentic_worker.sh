#!/usr/bin/env bash
set -Eeuo pipefail
STATE_ROOT="${AB_AGENT_STATE_ROOT:-/tmp/amazingbecca-agent-${UID}}"
QUEUE_ROOT="${AB_AGENT_QUEUE_ROOT:-/tmp/amazingbecca-agentic-queue-${UID}}"
RUN="$STATE_ROOT/run"
LOG="$STATE_ROOT/log"
META="$RUN/worker.meta"
EXECUTOR="${AB_AGENT_EXECUTOR:-$(dirname "$0")/agentic_executor.py}"
mkdir -p "$QUEUE_ROOT" "$RUN" "$LOG"

proc_start() {
  local p="$1"
  [[ -r "/proc/$p/stat" ]] || return 1
  awk '{print $22}' "/proc/$p/stat"
}

alive() {
  [[ -f "$META" ]] || return 1
  local p expected_start current_start cmdline
  read -r p expected_start < "$META" || return 1
  [[ "$p" =~ ^[0-9]+$ && "$expected_start" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$p" 2>/dev/null || return 1
  current_start="$(proc_start "$p")" || return 1
  [[ "$current_start" == "$expected_start" ]] || return 1
  cmdline="$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)"
  [[ "$cmdline" == *"agentic_executor.py"*" worker"* ]] || return 1
}

start() {
  if alive; then echo "agentic worker already running pid=$(awk '{print $1}' "$META")"; return 0; fi
  rm -f "$META"
  AB_AGENT_QUEUE_ROOT="$QUEUE_ROOT" AB_AGENT_EXECUTOR="$EXECUTOR" nohup bash -c '
    set -Eeuo pipefail
    exec 9>"$AB_AGENT_QUEUE_ROOT/.worker.lock"
    flock -n 9 || exit 73
    exec python3 -B "$AB_AGENT_EXECUTOR" worker --interval 0.25
  ' >"$LOG/worker.log" 2>&1 &
  local p=$!
  sleep .2
  kill -0 "$p" 2>/dev/null || { echo "agentic worker failed to start" >&2; cat "$LOG/worker.log" >&2 || true; exit 1; }
  local started; started="$(proc_start "$p")"
  printf '%s %s\n' "$p" "$started" > "$META"
  chmod 600 "$META"
  alive || { echo "agentic worker identity validation failed" >&2; exit 1; }
  echo "agentic worker started pid=$p queue=$QUEUE_ROOT"
}

stop() {
  if alive; then
    local p; p="$(awk '{print $1}' "$META")"
    kill "$p" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep .1; done
    kill -9 "$p" 2>/dev/null || true
  fi
  rm -f "$META"
  echo "agentic worker stopped"
}

status() {
  if alive; then echo "RUNNING pid=$(awk '{print $1}' "$META") queue=$QUEUE_ROOT"; else echo "STOPPED queue=$QUEUE_ROOT"; fi
  find "$QUEUE_ROOT" -maxdepth 1 -type f -name '*.json' -printf '%f\n' 2>/dev/null | sort || true
}

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  *) echo "usage: $0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
