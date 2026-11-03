"""Download every wheel fwsync[web,yaml,fmc,test] needs, for offline installs, into one folder.

  python scripts/fetch_wheels.py [--out vendor/wheels] [--targets win,mac,linux] [--pythons 3.10,3.11,3.12,3.13]

Targets: win = win_amd64; mac = macOS arm64 and x86_64; linux = manylinux x86_64 and aarch64. Python 3.10 - 3.13.
pip download evaluates platform markers (sys_platform, platform_system) for the machine it runs on, so the packages
that only other platforms pull in are added explicitly (EXTRA). At the end every compiled package is checked for a
wheel per target and Python version; missing ones are listed and the exit code is 1."""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQS = ['fastapi>=0.110', 'uvicorn>=0.27', 'python-multipart>=0.0.9', 'requests>=2.25', 'PyYAML>=6.0',
        'pytest>=7', 'httpx>=0.24', 'pip']
EXTRA = ['colorama', 'exceptiongroup', 'tomli', 'typing_extensions']
TARGETS = {
    'win': {'win_amd64': ['win_amd64']},
    'mac': {'macos_arm64': ['macosx_11_0_arm64', 'macosx_10_9_universal2'],
            'macos_x86_64': ['macosx_10_15_x86_64', 'macosx_10_13_x86_64', 'macosx_10_12_x86_64', 'macosx_10_9_x86_64',
                             'macosx_10_9_universal2']},
    'linux': {'linux_x86_64': ['manylinux_2_17_x86_64', 'manylinux2014_x86_64', 'manylinux_2_28_x86_64'],
              'linux_aarch64': ['manylinux_2_17_aarch64', 'manylinux2014_aarch64', 'manylinux_2_28_aarch64']},
}
WHEEL = re.compile(r'^(?P<name>[^-]+)-(?P<ver>[^-]+)(-\d[^-]*)?-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>.+)\.whl$')


def download(out, plats, pyver, pkgs, deps=True):
    cmd = [sys.executable, '-m', 'pip', 'download', '-q', '--disable-pip-version-check', '-d', str(out),
           '--only-binary=:all:', '--python-version', pyver, '--implementation', 'cp']
    for p in plats:
        cmd += ['--platform', p]
    if not deps:
        cmd.append('--no-deps')
    r = subprocess.run(cmd + pkgs, capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def norm(n):
    return re.sub(r'[-_.]+', '_', n).lower()


def plat_ok(plat, want):
    tags = plat.split('.')
    for t in tags:
        if t == 'any':
            return True
        for w in want:
            if t == w:
                return True
            if w.startswith('macosx') and t.startswith('macosx'):
                arch = w.rsplit('_', 1)[-1]
                if t.endswith('_' + arch) or t.endswith('_universal2'):
                    return True
            if w.startswith('manylinux') and t.startswith('manylinux') and t.endswith(w.rsplit('_', 1)[-1]):
                return True
    return False


def py_ok(py, abi, ver):
    cp = 'cp' + ver.replace('.', '')
    for p in py.split('.'):
        if p in ('py3', 'py2.py3') or p == cp:
            return True
        if abi == 'abi3' and p.startswith('cp3') and int(p[3:]) <= int(cp[3:]):
            return True
    return False


def check(out, combos):
    wheels = [m.groupdict() for m in (WHEEL.match(p.name) for p in Path(out).glob('*.whl')) if m]
    compiled = sorted({norm(w['name']) for w in wheels if w['plat'] != 'any'})
    missing = []
    for name in compiled:
        cand = [w for w in wheels if norm(w['name']) == name]
        if any(w['plat'] == 'any' for w in cand):
            continue
        for label, plats, ver in combos:
            if not any(plat_ok(w['plat'], plats) and py_ok(w['py'], w['abi'], ver) for w in cand):
                missing.append((name, label, ver))
    return compiled, missing


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT / 'vendor' / 'wheels'))
    ap.add_argument('--targets', default='win,mac,linux')
    ap.add_argument('--pythons', default='3.10,3.11,3.12,3.13')
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    combos, errors = [], []
    for t in a.targets.split(','):
        for label, plats in TARGETS[t].items():
            for ver in a.pythons.split(','):
                combos.append((label, plats, ver))
                ok, err = download(out, plats, ver, REQS)
                ok2, err2 = download(out, plats, ver, EXTRA, deps=False)
                print('%-14s cp%s  %s' % (label, ver.replace('.', ''), 'ok' if ok and ok2 else 'ERROR'), flush=True)
                if not (ok and ok2):
                    errors.append('%s %s: %s %s' % (label, ver, err[-500:], err2[-300:]))
    compiled, missing = check(out, combos)
    print('compiled packages: %s' % ', '.join(compiled))
    print('%d wheels in %s' % (len(list(out.glob('*.whl'))), out))
    for e in errors:
        print('download error:', e)
    if missing:
        print('MISSING wheels (package, target, python):')
        for m in missing:
            print('  %s %s cp%s' % (m[0], m[1], m[2].replace('.', '')))
    else:
        print('every compiled package has a wheel for every target and Python version')
    sys.exit(1 if missing or errors else 0)


if __name__ == '__main__':
    main()
