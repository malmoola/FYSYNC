"""Scan what would be published (every blob reachable from the given refs, or a folder/zip) before a push.

  python scripts/scan_public.py [--refs main,v0.5.1] [--path DIR_OR_ZIP ...] [--patterns FILE]

Always checks for secrets (private keys, GitHub/AWS tokens, password assignments) and files that must not be published
(reports, prod/, venvs, wheels, the bundled python). --patterns (or env FWSYNC_SCAN_PATTERNS) adds your own
regular expressions, one per line, for names and address ranges of the networks you work on. Keep that file outside
the repository. Exit code 1 on any hit."""
import argparse
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

SECRETS = [r'-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----', r'github_pat_[A-Za-z0-9_]{20,}', r'\bghp_[A-Za-z0-9]{30,}',
           r'\bAKIA[0-9A-Z]{16}\b', r'(?i)"password"\s*:\s*"[^".]{4,}"']
BAD_PATH = re.compile(r'(^|/)(prod|reports?|\.venv|venv|python|vendor/wheels|dist|build|\.fwsync)/|\.whl$|\.p12$|\.pem$|'
                      r'(^|/)selftest-result\.txt$')
ALLOWED_PATH = re.compile(r'^(samples/(chain/)?report/)')


def blobs_from_refs(refs):
    seen = set()
    for ref in refs:
        revs = subprocess.run(['git', 'rev-list', ref], capture_output=True, text=True, check=True).stdout.split()
        for rev in revs:
            out = subprocess.run(['git', 'ls-tree', '-r', '--full-tree', rev], capture_output=True, text=True,
                                 check=True).stdout
            for line in out.splitlines():
                meta, path = line.split('\t', 1)
                sha = meta.split()[2]
                if (sha, path) in seen:
                    continue
                seen.add((sha, path))
                data = subprocess.run(['git', 'cat-file', 'blob', sha], capture_output=True, check=True).stdout
                yield '%s:%s' % (rev[:8], path), path, data


def blobs_from_path(p):
    p = Path(p)
    if p.is_file() and p.suffix == '.zip':
        with zipfile.ZipFile(p) as z:
            for n in z.namelist():
                if not n.endswith('/'):
                    rel = n.split('/', 1)[1] if '/' in n else n
                    yield '%s!%s' % (p.name, n), rel, z.read(n)
    else:
        for f in sorted(p.rglob('*')):
            if f.is_file() and '.git' not in f.parts:
                yield str(f), f.relative_to(p).as_posix(), f.read_bytes()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--refs', default='')
    ap.add_argument('--path', action='append', default=[])
    ap.add_argument('--patterns', default=os.environ.get('FWSYNC_SCAN_PATTERNS', ''))
    ap.add_argument('--allow-path', action='append', default=[], help='regex of paths allowed despite the path rules')
    a = ap.parse_args()
    pats = [re.compile(x.encode()) for x in SECRETS]
    own = []
    if a.patterns:
        own = [l.strip() for l in Path(a.patterns).read_text(encoding='utf-8').splitlines()
               if l.strip() and not l.startswith('#')]
        pats += [re.compile(x.encode(), re.I) for x in own]
    allow = [re.compile(x) for x in a.allow_path]
    hits, n = [], 0
    srcs = [blobs_from_refs([r for r in a.refs.split(',') if r])] if a.refs else []
    srcs += [blobs_from_path(p) for p in a.path]
    for src in srcs:
        for where, rel, data in src:
            n += 1
            if BAD_PATH.search(rel) and not ALLOWED_PATH.search(rel) and not any(x.search(rel) for x in allow):
                hits.append((where, 'path not allowed in a public repo'))
            for p in pats:
                m = p.search(data)
                if m:
                    hits.append((where, 'matches pattern #%d' % pats.index(p)))
    print('scanned %d files, %d own patterns, %d secret patterns' % (n, len(own), len(SECRETS)))
    for w, why in hits[:200]:
        print('HIT', w, '-', why)
    print('CLEAN' if not hits else '%d hits' % len(hits))
    sys.exit(1 if hits else 0)


if __name__ == '__main__':
    main()
