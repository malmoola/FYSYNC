#!/bin/zsh
# fwsync launcher for macOS. Double-click it in Finder (first time: right-click > Open).
# First run: finds Python (3.12 preferred, any 3.10 to 3.13), creates a venv in ~/Library/Application Support/fwsync and installs fwsync
# offline from the bundled vendor/wheels. Every run: starts the web UI on 127.0.0.1 on the first free port from 8765, opens the
# browser, and stops the server when this Terminal window is closed.
set -u

HERE="${0:A:h}"
ROOT="${HERE:h:h}"
WHEELS="$ROOT/vendor/wheels"
APP="$HOME/Library/Application Support/fwsync"
VENV="$APP/venv"
LOG="$APP/fwsync-web.log"

find_python() {
  local c p
  for c in python3.12 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12 \
           /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
           python3.13 python3.11 python3.10 \
           /opt/homebrew/bin/python3 /usr/local/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/3.11/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/3.10/bin/python3 \
           python3; do
    p=$(command -v "$c" 2>/dev/null) || continue
    [[ -x "$p" ]] || continue
    "$p" -c 'import sys; sys.exit(0 if (3, 10) <= sys.version_info[:2] <= (3, 13) else 1)' 2>/dev/null && { print -r -- "$p"; return 0; }
  done
  return 1
}

no_python() {
  local a
  a=$(osascript -e 'display dialog "fwsync needs Python 3.10 to 3.13 (3.12 preferred).\n\nInstall it from python.org (macOS 64-bit universal installer), then open fwsync again." with title "fwsync" buttons {"Cancel", "Open python.org"} default button 2 with icon caution' 2>/dev/null)
  [[ "$a" == *"python.org"* ]] && open "https://www.python.org/downloads/macos/"
  exit 1
}

bundled_version() {
  local w
  w=( "$WHEELS"/fwsync-*-py3-none-any.whl(N) )
  (( ${#w} )) || return 1
  print -r -- "${${w[1]:t}#fwsync-}" | cut -d- -f1
}

install_venv() {
  local py=$1
  mkdir -p "$APP"
  print "fwsync: setting up $VENV (one time, offline) ..."
  rm -rf "$VENV"
  if ! "$py" -m venv "$VENV" 2>/dev/null; then
    "$py" -m venv --without-pip "$VENV" || return 1
    local pipw=( "$WHEELS"/pip-*.whl(N) )
    "$VENV/bin/python" "${pipw[1]}/pip" install -q --no-index --find-links "$WHEELS" pip || return 1
  fi
  "$VENV/bin/pip" install -q --no-index --find-links "$WHEELS" "fwsync[web,yaml,fmc]" || return 1
}

[[ -d "$WHEELS" ]] || { osascript -e 'display alert "fwsync" message "vendor/wheels not found next to this launcher. Keep the unzipped fwsync folder together."' >/dev/null 2>&1; exit 1; }

want=$(bundled_version) || want=""
have=""
[[ -x "$VENV/bin/python" ]] && have=$("$VENV/bin/python" -c 'import fwsync; print(fwsync.__version__)' 2>/dev/null)
if [[ -z "$have" || ( -n "$want" && "$have" != "$want" ) ]]; then
  PY=$(find_python) || no_python
  install_venv "$PY" || { osascript -e 'display alert "fwsync" message "Installing fwsync failed. See the Terminal window."' >/dev/null 2>&1; exit 1; }
fi

PORT=$("$VENV/bin/python" - <<'PY'
import socket
for p in range(8765, 8865):
    s = socket.socket()
    try:
        s.bind(('127.0.0.1', p))
    except OSError:
        continue
    finally:
        s.close()
    print(p)
    break
PY
)
[[ -n "$PORT" ]] || { print "no free port in 8765-8864"; exit 1; }
"$VENV/bin/fwsync" web --port "$PORT" >"$LOG" 2>&1 &
PID=$!
cleanup() { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }
trap cleanup EXIT HUP INT TERM

for i in {1..60}; do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break
  kill -0 "$PID" 2>/dev/null || { print "fwsync did not start, see $LOG"; exit 1; }
  sleep 0.5
done
open "http://127.0.0.1:$PORT/"
print "fwsync $("$VENV/bin/python" -c 'import fwsync; print(fwsync.__version__)') is running at http://127.0.0.1:$PORT/"
print "Close this window (or press Ctrl-C) to stop it."
wait "$PID"
