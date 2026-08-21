#!/usr/bin/env bash
set -Eeuo pipefail

STATE_ROOT="${AB_CAPLAB_STATE_ROOT:-/tmp/amazingbecca-caplab-${UID}}"
STATE="$STATE_ROOT/state"
RUN="$STATE_ROOT/run"
LOG="$STATE_ROOT/log"
PROFILE="$STATE_ROOT/profile"
mkdir -p "$STATE" "$RUN" "$LOG" "$PROFILE"

find_free_port() {
  python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
}

find_display() {
  local n
  for n in $(seq 91 139); do
    if [[ ! -S "/tmp/.X11-unix/X$n" && ! -e "/tmp/.X$n-lock" ]]; then
      printf '%s\n' "$n"
      return 0
    fi
  done
  return 1
}

write_kv() { printf 'export %s=%q\n' "$1" "$2" >> "$STATE/env.sh"; }

start_lab() {
  if [[ -f "$STATE/pids" ]] && awk '{print $2}' "$STATE/pids" | xargs -r -n1 kill -0 2>/dev/null; then
    echo "capability lab already running"
    status_lab
    return 0
  fi
  rm -f "$STATE/pids" "$STATE/env.sh" "$STATE/manifest.json"
  : > "$STATE/pids"
  : > "$STATE/env.sh"

  local display_num cdp_port vnc_port jupyter_port lo_port dbus_out dbus_addr dbus_pid vnc_pass jupyter_token
  display_num="$(find_display)"
  cdp_port="${AB_CAPLAB_CDP_PORT:-$(find_free_port)}"
  vnc_port="${AB_CAPLAB_VNC_PORT:-$(find_free_port)}"
  jupyter_port="${AB_CAPLAB_JUPYTER_PORT:-$(find_free_port)}"
  lo_port="${AB_CAPLAB_LIBREOFFICE_PORT:-$(find_free_port)}"
  vnc_pass="$(python3 - <<'PY'
import secrets; print(secrets.token_urlsafe(20))
PY
)"
  jupyter_token="$(python3 - <<'PY'
import secrets; print(secrets.token_urlsafe(32))
PY
)"
  export DISPLAY=":$display_num"
  export HOME="$PROFILE/home"
  export XDG_RUNTIME_DIR="$RUN/runtime"
  mkdir -p "$HOME" "$PROFILE/chrome" "$PROFILE/jupyter" "$PROFILE/lo" "$XDG_RUNTIME_DIR"
  chmod 700 "$XDG_RUNTIME_DIR"

  Xvfb "$DISPLAY" -screen 0 1280x800x24 -nolisten tcp >"$LOG/xvfb.log" 2>&1 &
  echo "xvfb $!" >> "$STATE/pids"
  for _ in $(seq 1 50); do [[ -S "/tmp/.X11-unix/X$display_num" ]] && break; sleep .1; done
  [[ -S "/tmp/.X11-unix/X$display_num" ]] || { echo "Xvfb failed" >&2; return 1; }

  dbus_out="$(dbus-daemon --session --fork --print-address=1 --print-pid=1)"
  dbus_addr="$(printf '%s\n' "$dbus_out" | sed -n '1p')"
  dbus_pid="$(printf '%s\n' "$dbus_out" | sed -n '2p')"
  export DBUS_SESSION_BUS_ADDRESS="$dbus_addr"
  echo "dbus $dbus_pid" >> "$STATE/pids"

  openbox >"$LOG/openbox.log" 2>&1 & echo "openbox $!" >> "$STATE/pids"
  picom --backend xrender --no-vsync --config /dev/null >"$LOG/picom.log" 2>&1 & echo "picom $!" >> "$STATE/pids"

  chromium \
    --user-data-dir="$PROFILE/chrome" \
    --remote-debugging-address=127.0.0.1 \
    --remote-debugging-port="$cdp_port" \
    --no-first-run --no-default-browser-check \
    --disable-background-networking --disable-sync --disable-extensions \
    --disable-features=Translate,MediaRouter \
    --disable-dev-shm-usage --no-sandbox \
    about:blank >"$LOG/chromium.log" 2>&1 &
  echo "chromium $!" >> "$STATE/pids"

  x11vnc -storepasswd "$vnc_pass" "$STATE/vnc.pass" >/dev/null
  x11vnc -display "$DISPLAY" -rfbauth "$STATE/vnc.pass" -localhost -rfbport "$vnc_port" -forever -shared >"$LOG/x11vnc.log" 2>&1 &
  echo "x11vnc $!" >> "$STATE/pids"

  jupyter server --no-browser --ServerApp.ip=127.0.0.1 --ServerApp.port="$jupyter_port" \
    --ServerApp.port_retries=0 --ServerApp.token="$jupyter_token" --ServerApp.password='' --allow-root \
    --ServerApp.root_dir="$PROFILE/jupyter" >"$LOG/jupyter.log" 2>&1 &
  echo "jupyter $!" >> "$STATE/pids"

  libreoffice --headless --nologo --nodefault --nofirststartwizard \
    "--accept=socket,host=127.0.0.1,port=$lo_port;urp;StarOffice.ComponentContext" \
    -env:UserInstallation="file://$PROFILE/lo" >"$LOG/libreoffice.log" 2>&1 &
  echo "libreoffice $!" >> "$STATE/pids"

  write_kv DISPLAY "$DISPLAY"
  write_kv DBUS_SESSION_BUS_ADDRESS "$DBUS_SESSION_BUS_ADDRESS"
  write_kv XDG_RUNTIME_DIR "$XDG_RUNTIME_DIR"
  write_kv AB_CAPLAB_CDP_PORT "$cdp_port"
  write_kv AB_CAPLAB_VNC_PORT "$vnc_port"
  write_kv AB_CAPLAB_JUPYTER_PORT "$jupyter_port"
  write_kv AB_CAPLAB_LIBREOFFICE_PORT "$lo_port"
  write_kv AB_CAPLAB_JUPYTER_TOKEN "$jupyter_token"
  chmod 600 "$STATE/env.sh" "$STATE/vnc.pass"

  for _ in $(seq 1 80); do
    if python3 - "$cdp_port" "$vnc_port" "$jupyter_port" "$lo_port" <<'PY'
import socket,sys
for p in map(int,sys.argv[1:]):
 s=socket.socket(); s.settimeout(.15)
 try: s.connect(('127.0.0.1',p))
 except OSError: raise SystemExit(1)
 finally: s.close()
PY
    then break; fi
    sleep .15
  done

  manifest_lab > "$STATE/manifest.json"
  echo "capability lab started"
  status_lab
}

manifest_lab() {
  [[ -f "$STATE/env.sh" ]] && source "$STATE/env.sh"
  python3 - "$STATE/pids" <<'PY'
import hashlib,json,os,pathlib,shutil,sys
pids=pathlib.Path(sys.argv[1])
commands=['python3','git','node','chromium','Xvfb','x11vnc','dbus-daemon','openbox','picom','jupyter','libreoffice']
def ident(cmd):
 p=shutil.which(cmd)
 if not p:return None
 real=os.path.realpath(p)
 h=hashlib.sha256()
 try:
  with open(real,'rb') as f:
   for c in iter(lambda:f.read(1024*1024),b''):h.update(c)
 except Exception:return {'path':real,'sha256':None}
 return {'path':real,'sha256':h.hexdigest()}
services=[]
if pids.exists():
 for line in pids.read_text().splitlines():
  if not line.strip():continue
  name,pid=line.split(maxsplit=1)
  services.append({'name':name,'pid':int(pid),'alive':os.path.exists('/proc/'+pid)})
value={
 'schema':'amazingbecca-capability-lab/v1',
 'vm_build':os.getenv('CUA_DD_VM_BUILD',''),
 'vm_commit_sha':os.getenv('CUA_DD_VM_COMMIT_SHA',''),
 'feature_set':os.getenv('ACE_TOOLS_FEATURE_SET',''),
 'cluster':os.getenv('OPENAI_CLUSTER',''),
 'display':os.getenv('DISPLAY',''),
 'loopback_ports':{
  'chromium_cdp':os.getenv('AB_CAPLAB_CDP_PORT',''),
  'vnc':os.getenv('AB_CAPLAB_VNC_PORT',''),
  'jupyter':os.getenv('AB_CAPLAB_JUPYTER_PORT',''),
  'libreoffice':os.getenv('AB_CAPLAB_LIBREOFFICE_PORT',''),
 },
 'services':services,
 'executables':{c:ident(c) for c in commands},
 'product_gates':{k:v for k,v in sorted(os.environ.items()) if k.startswith('CUA_DD_')},
}
raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
value['manifest_sha256']=hashlib.sha256(raw).hexdigest()
print(json.dumps(value,sort_keys=True,separators=(',',':')))
PY
}

status_lab() {
  [[ -f "$STATE/env.sh" ]] && source "$STATE/env.sh"
  printf 'state_root=%s\n' "$STATE_ROOT"
  if [[ -f "$STATE/pids" ]]; then
    while read -r name pid; do
      [[ -n "${pid:-}" ]] || continue
      if kill -0 "$pid" 2>/dev/null; then printf '%-12s pid=%s RUNNING\n' "$name" "$pid"; else printf '%-12s pid=%s STOPPED\n' "$name" "$pid"; fi
    done < "$STATE/pids"
  fi
  printf 'cdp=http://127.0.0.1:%s\n' "${AB_CAPLAB_CDP_PORT:-}"
  printf 'vnc=127.0.0.1:%s (password file: %s)\n' "${AB_CAPLAB_VNC_PORT:-}" "$STATE/vnc.pass"
  printf 'jupyter=http://127.0.0.1:%s\n' "${AB_CAPLAB_JUPYTER_PORT:-}"
  printf 'libreoffice=127.0.0.1:%s\n' "${AB_CAPLAB_LIBREOFFICE_PORT:-}"
  if [[ -f "$STATE/manifest.json" ]]; then printf 'manifest=%s\n' "$STATE/manifest.json"; fi
  return 0
}

stop_lab() {
  if [[ -f "$STATE/pids" ]]; then
    tac "$STATE/pids" | while read -r name pid; do
      [[ -n "${pid:-}" ]] || continue
      kill "$pid" 2>/dev/null || true
    done
    sleep .3
    tac "$STATE/pids" | while read -r name pid; do kill -9 "$pid" 2>/dev/null || true; done
  fi
  rm -f "$STATE/pids"
  echo "capability lab stopped"
}

case "${1:-status}" in
  start) start_lab ;;
  status) status_lab ;;
  manifest) manifest_lab ;;
  stop) stop_lab ;;
  restart) stop_lab; start_lab ;;
  *) echo "usage: $0 {start|status|manifest|stop|restart}" >&2; exit 2 ;;
esac
