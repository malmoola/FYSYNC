#!/bin/zsh
# fwsync selftest for macOS. Double-click it in Finder (first time: right-click > Open).
# Finds Python 3.10+ (3.12 preferred), installs fwsync offline from vendor/wheels into a fresh venv, runs the test suite,
# a synthetic compare 1:1 and 2:1, the web UI for 10 s on 127.0.0.1 and the report protection check.
# Writes selftest-result.txt in the fwsync folder.
set -u

HERE="${0:A:h}"
ROOT="${HERE:h:h}"
WHEELS="$ROOT/vendor/wheels"
VENV="$HOME/Library/Application Support/fwsync/selftest-venv"

find_python() {
  local c p
  for c in python3.12 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12 \
           /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
           python3.13 python3.11 python3.10 /opt/homebrew/bin/python3 /usr/local/bin/python3 python3; do
    p=$(command -v "$c" 2>/dev/null) || continue
    [[ -x "$p" ]] || continue
    "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null && { print -r -- "$p"; return 0; }
  done
  return 1
}

[[ -d "$WHEELS" ]] || { print "vendor/wheels not found next to this launcher. Keep the unzipped fwsync folder together."; exit 2; }
PY=$(find_python) || { print "fwsync needs Python 3.10 or newer (python.org, macOS 64-bit universal installer)."; exit 2; }
mkdir -p "${VENV:h}"
"$PY" "$ROOT/scripts/selftest.py" --root "$ROOT" --venv "$VENV" --wheels "$WHEELS" --out "$ROOT/selftest-result.txt"
RC=$?
print "Result: $ROOT/selftest-result.txt"
exit $RC
