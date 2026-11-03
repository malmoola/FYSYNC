"""fwsync selftest (standard library only). Run by selftest.cmd (Windows), selftest.command (macOS) and CI.

  python scripts/selftest.py --root DIR [--venv DIR --wheels DIR] [--install-status ok|failed] [--out FILE]

--venv: create a fresh venv with this Python and install fwsync[web,yaml,fmc,test] offline from --wheels into it
        (no network), then run every check with the venv's Python.
otherwise: this Python already has fwsync installed (the bundled Windows python\\ after selftest.cmd installed it);
        --install-status reports how that went.
Checks: offline install, the test suite, a synthetic compare 1:1 and 2:1, the web UI for 10 s on 127.0.0.1, owner-only
protection of a report. Writes selftest-result.txt (default: in --root). Exit code 0 only if every check passed."""
import argparse
import datetime
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

WIN = os.name == 'nt'
EXTRAS = 'fwsync[web,yaml,fmc,test]'


def venv_python(venv):
    return Path(venv) / ('Scripts/python.exe' if WIN else 'bin/python')


def install(venv, wheels, log):
    """fresh venv + offline install; returns (ok, detail, python)"""
    import shutil
    import venv as venv_mod
    venv = Path(venv)
    if venv.exists():
        shutil.rmtree(venv)
    py = venv_python(venv)
    try:
        venv_mod.EnvBuilder(with_pip=True, clear=True).create(venv)
    except (subprocess.CalledProcessError, OSError, SystemExit):
        venv_mod.EnvBuilder(with_pip=False, clear=True).create(venv)
    if subprocess.run([str(py), '-m', 'pip', '--version'], capture_output=True).returncode:
        pipw = sorted(Path(wheels).glob('pip-*-py3-none-any.whl'))
        if not pipw:
            return False, 'no pip in the venv and no pip wheel in %s' % wheels, py
        r = subprocess.run([str(py), str(pipw[-1] / 'pip'), 'install', '-q', '--no-index', '--find-links', str(wheels),
                            'pip'], capture_output=True, text=True)
        log.append('bootstrap pip from %s: rc %d %s' % (pipw[-1].name, r.returncode, (r.stdout + r.stderr).strip()))
    cmd = [str(py), '-m', 'pip', 'install', '-q', '--no-index', '--find-links', str(wheels),
           '--no-warn-script-location', EXTRAS]
    r = subprocess.run(cmd, capture_output=True, text=True)
    log.append('$ ' + ' '.join(cmd) + '\n' + (r.stdout + r.stderr).strip())
    return r.returncode == 0, 'venv %s, wheels %s' % (venv, wheels), py


def run(cmd, timeout=900, cwd=None):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=timeout, cwd=cwd,
                       encoding='utf-8', errors='replace')
    return r.returncode, (r.stdout + r.stderr)


def check_suite(py, root):
    rc, out = run([py, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', root / 'tests'], cwd=root)
    m = re.findall(r'(\d+ (?:passed|failed|skipped|error)s?)', out.strip().splitlines()[-1] if out.strip() else '')
    return rc == 0, ', '.join(m) or out.strip()[-300:], out


def check_compare(py, root, tmp):
    s = root / 'samples'
    res = []
    for mode, files in (('1:1', [s / 'edge-a.txt', s / 'edge-b.txt']),
                        ('2:1', [s / 'chain' / 'edge.txt', s / 'chain' / 'inner.txt', s / 'chain' / 'target.txt'])):
        out = tmp / ('compare-' + mode.replace(':', 'to'))
        rc, text = run([py, '-m', 'fwsync', 'compare'] + files + ['--out', out, '--prefix', 'selftest'])
        made = sorted(p.name for p in out.glob('selftest*')) if out.exists() else []
        ok = rc == 0 and 'selftest.html' in made and 'selftest.json' in made
        res.append((mode, ok, '%d files' % len(made) if ok else text.strip()[-400:], out))
    return res


def check_web(py, seconds=10):
    """start fwsync web (no browser), poll 127.0.0.1 for up to `seconds`, then stop it the way a user would
    (Ctrl-Break on Windows, Ctrl-C elsewhere)"""
    kw = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if WIN else {}
    p = subprocess.Popen([str(py), '-m', 'fwsync', 'web', '--no-browser'], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', **kw)
    url, lines, ok, detail = None, [], False, ''
    t0 = time.time()
    try:
        while time.time() - t0 < seconds and url is None:
            line = p.stdout.readline()
            if not line:
                break
            lines.append(line)
            m = re.search(r'(http://127\.0\.0\.1:\d+/)', line)
            if m:
                url = m.group(1)
        if url:
            while time.time() - t0 < seconds:
                try:
                    with urllib.request.urlopen(url, timeout=2) as r:
                        body = r.read().decode('utf-8', 'replace')
                    ok = r.status == 200 and '<title>fwsync</title>' in body
                    detail = '%s answered %d' % (url, r.status)
                    if ok:
                        break
                except OSError as e:
                    detail = '%s: %s' % (url, e)
                    time.sleep(0.5)
            while time.time() - t0 < seconds:
                time.sleep(0.25)
        else:
            detail = 'no URL printed: ' + ''.join(lines)[-300:]
    finally:
        p.send_signal(signal.CTRL_BREAK_EVENT if WIN else signal.SIGINT)
        try:
            rest, _ = p.communicate(timeout=15)
            lines.append(rest or '')
            stopped = 'stopped' in ''.join(lines)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            stopped = False
    if url and not url.startswith('http://127.0.0.1:'):
        ok, detail = False, 'not bound to 127.0.0.1: ' + url
    return ok, detail, stopped


def check_protect(py, report):
    code = ('import sys; from fwsync.osutil import is_protected, is_windows; import subprocess, os;'
            'p = sys.argv[1]; ok = is_protected(p);'
            'ev = subprocess.run(["icacls", p], capture_output=True, text=True).stdout.strip() if is_windows() '
            'else oct(os.stat(p).st_mode & 0o777);'
            'print(ev.replace(chr(10), " | ")); sys.exit(0 if ok else 1)')
    rc, out = run([py, '-c', code, report])
    return rc == 0, out.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument('--venv')
    ap.add_argument('--wheels')
    ap.add_argument('--install-status', default='')
    ap.add_argument('--kind', default='')
    ap.add_argument('--out')
    a = ap.parse_args()
    root = Path(a.root).resolve()
    out = Path(a.out) if a.out else root / 'selftest-result.txt'
    log, results = [], []

    def rec(name, ok, detail):
        results.append((name, ok, detail))
        print('%-28s %s  %s' % (name, 'PASS' if ok else 'FAIL', detail), flush=True)

    py = Path(sys.executable)
    kind = a.kind or ('bundled' if (root / 'python') in py.parents else 'installed')
    if a.venv:
        ok, detail, py = install(a.venv, a.wheels or root / 'vendor' / 'wheels', log)
        rec('offline install', ok, detail)
        kind += ' + venv'
    else:
        st = a.install_status or 'not run (fwsync already installed)'
        rec('offline install', st.startswith(('ok', 'not run')), st)
    rc, ver = run([py, '-c', 'import fwsync, sys; print(fwsync.__version__, sys.version.split()[0])'])
    rec('fwsync importable', rc == 0, ver.strip()[-200:])
    if rc == 0:
        ok, detail, text = check_suite(py, root)
        rec('test suite', ok, detail)
        if not ok:
            log.append(text[-6000:])
        with tempfile.TemporaryDirectory() as td:
            cmp = check_compare(py, root, Path(td))
            for mode, ok, detail, _ in cmp:
                rec('compare %s' % mode, ok, detail)
            ok, detail, stopped = check_web(py)
            rec('web UI 10 s on 127.0.0.1', ok, detail)
            rec('web UI clean stop', stopped, 'Ctrl-Break' if WIN else 'Ctrl-C (SIGINT)')
            rep = cmp[0][3] / 'selftest.html'
            if rep.exists():
                ok, detail = check_protect(py, rep)
                rec('report owner-only', ok, detail)
            else:
                rec('report owner-only', False, 'no report from compare 1:1')
    passed = all(r[1] for r in results)
    head = ['fwsync selftest %s' % ('PASSED' if passed else 'FAILED'),
            'date      %s' % datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
            'system    %s %s (%s)' % (platform.system(), platform.release(), platform.machine()),
            'python    %s %s (%s)' % (py, platform.python_version(), kind),
            'root      %s' % root, '']
    body = ['%-28s %s  %s' % (n, 'PASS' if ok else 'FAIL', d) for n, ok, d in results]
    out.write_text('\n'.join(head + body + ([''] + ['--- log'] + log if log else [])) + '\n', encoding='utf-8')
    print('\n%s -> %s' % (head[0], out))
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
