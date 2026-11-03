"""Build the release zips from a clean tree (git archive of HEAD, never the working folder).

  python scripts/build_release.py [--out dist] [--wheels DIR] [--ref HEAD] [--allow-dirty]

  dist/fwsync-<ver>.zip           macOS / Linux: source, launchers, vendor/wheels (macOS + Linux + pure)
  dist/fwsync-<ver>-windows.zip   Windows: the same plus python\\ (official Python 3.12 embeddable, win_amd64),
                                  fwsync.cmd / selftest.cmd at the top, vendor\\wheels (win_amd64 + pure)
  each with <zip>.sha256

--wheels: an existing wheel folder (from scripts/fetch_wheels.py); default: fetch now. Wheels and the bundled Python
are downloaded at build time and never committed. The zips are checked for files that must never ship."""
import argparse
import hashlib
import io
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY_EMBED = {
    'version': '3.12.10',
    'url': 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip',
    'sha256': '4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3',
    'pth': 'python312._pth',
}
PTH = 'python312.zip\n.\nLib\\site-packages\n\nimport site\n'
NEVER = re.compile(r'(^|/)(prod|reports?|\.venv|build|dist|\.fwsync|__pycache__|\.pytest_cache)/|\.pyc$|'
                   r'(^|/)selftest-result\.txt$')
SAMPLE_REPORTS = re.compile(r'samples/(chain/)?report/[^/]+$|python/')
EXEC = ('.command', '.sh')


def sh(*cmd, cwd=None):
    r = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        sys.exit('%s failed:\n%s' % (' '.join(map(str, cmd)), r.stdout + r.stderr))
    return r.stdout


def export(ref, dst, allow_dirty):
    if not allow_dirty and sh('git', 'status', '--porcelain', '--untracked-files=no', cwd=ROOT).strip():
        sys.exit('working tree has uncommitted changes: commit first (or --allow-dirty)')
    data = subprocess.run(['git', 'archive', '--format=tar', ref], cwd=ROOT, capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        if hasattr(tarfile, 'data_filter'):
            t.extractall(dst, filter='data')
        else:
            t.extractall(dst)
    return sh('git', 'rev-parse', '--short', ref, cwd=ROOT).strip()


def version(tree):
    return re.search(r"__version__ = '([^']+)'", (tree / 'fwsync' / '__init__.py').read_text()).group(1)


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def is_win_wheel(n):
    return n.endswith('-any.whl') or 'win_amd64' in n


def is_posix_wheel(n):
    return n.endswith('-any.whl') or 'macosx' in n or 'manylinux' in n or 'musllinux' in n


def python_embed(dst, cache):
    z = cache / Path(PY_EMBED['url']).name
    if not z.exists():
        print('downloading', PY_EMBED['url'], flush=True)
        urllib.request.urlretrieve(PY_EMBED['url'], z)
    got = sha256(z)
    if got != PY_EMBED['sha256']:
        sys.exit('python embeddable sha256 mismatch: %s (expected %s)' % (got, PY_EMBED['sha256']))
    with zipfile.ZipFile(z) as f:
        f.extractall(dst)
    (dst / PY_EMBED['pth']).write_text(PTH, newline='\r\n')
    return dst


def add_pip(pydir, wheels):
    """the embeddable Python has no pip: unpack the pip wheel into python\\Lib\\site-packages"""
    pip = sorted(wheels.glob('pip-*-py3-none-any.whl'))[-1]
    sp = pydir / 'Lib' / 'site-packages'
    sp.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(pip) as f:
        f.extractall(sp)
    return pip.name


def make_zip(src, zpath, top):
    with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(src.rglob('*')):
            if p.is_dir():
                continue
            rel = p.relative_to(src).as_posix()
            zi = zipfile.ZipInfo('%s/%s' % (top, rel), date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if rel.endswith(EXEC) else 0o644
            zi.external_attr = (0o100000 | mode) << 16
            z.writestr(zi, p.read_bytes())
    bad = [n for n in zipfile.ZipFile(zpath).namelist()
           if NEVER.search(n.split('/', 1)[1]) and not SAMPLE_REPORTS.match(n.split('/', 1)[1])]
    if bad:
        zpath.unlink()
        sys.exit('refused, %s would contain: %s' % (zpath.name, ', '.join(bad[:10])))
    h = sha256(zpath)
    Path(str(zpath) + '.sha256').write_text('%s  %s\n' % (h, zpath.name), newline='\n')
    return h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT / 'dist'))
    ap.add_argument('--wheels')
    ap.add_argument('--ref', default='HEAD')
    ap.add_argument('--allow-dirty', action='store_true')
    a = ap.parse_args()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        tree = td / 'tree'
        tree.mkdir()
        rev = export(a.ref, tree, a.allow_dirty)
        ver = version(tree)
        wheels = td / 'wheels'
        if a.wheels:
            shutil.copytree(a.wheels, wheels)
        else:
            sh(sys.executable, ROOT / 'scripts' / 'fetch_wheels.py', '--out', wheels)
        for old in wheels.glob('fwsync-*.whl'):
            old.unlink()
        src = td / 'wheel-src'
        shutil.copytree(tree, src)
        sh(sys.executable, '-m', 'pip', 'wheel', '-q', '--no-deps', '-w', wheels, src)
        fw = sorted(wheels.glob('fwsync-%s-*.whl' % ver))
        if not fw:
            sys.exit('fwsync %s wheel not built' % ver)

        posix = td / 'posix'
        shutil.copytree(tree, posix)
        (posix / 'vendor' / 'wheels').mkdir(parents=True, exist_ok=True)
        for w in wheels.glob('*.whl'):
            if is_posix_wheel(w.name):
                shutil.copy2(w, posix / 'vendor' / 'wheels')
        zp = out / ('fwsync-%s.zip' % ver)
        hp = make_zip(posix, zp, 'fwsync-%s' % ver)

        win = td / 'win'
        shutil.copytree(tree, win)
        (win / 'vendor' / 'wheels').mkdir(parents=True, exist_ok=True)
        for w in wheels.glob('*.whl'):
            if is_win_wheel(w.name):
                shutil.copy2(w, win / 'vendor' / 'wheels')
        for f in ('fwsync.cmd', 'selftest.cmd', 'README-FIRST.txt'):
            shutil.copy2(tree / 'packaging' / 'windows' / f, win / f)
        cache = out / '.cache'
        cache.mkdir(exist_ok=True)
        pydir = python_embed(win / 'python', cache)
        pipw = add_pip(pydir, wheels)
        zw = out / ('fwsync-%s-windows.zip' % ver)
        hw = make_zip(win, zw, 'fwsync-%s-windows' % ver)

    for z, h in ((zp, hp), (zw, hw)):
        print('%s  %.1f MB  sha256 %s' % (z, z.stat().st_size / 1e6, h))
    print('from %s (%s), Python %s embeddable (%s), %s' % (a.ref, rev, PY_EMBED['version'], PY_EMBED['sha256'][:12], pipw))


if __name__ == '__main__':
    main()
