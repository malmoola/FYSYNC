"""Push a generated plan to FMC. Off unless --allow-push and the FMC URL is on the allowlist.
Always runs a dry run first; idempotent: objects/rules that already exist by name are skipped."""
import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

from .osutil import config_dir, read_text

ALLOWLIST_FILE = os.environ.get('FWSYNC_ALLOWLIST') or str(config_dir() / 'fmc_allowlist.txt')


def allowed(url, allowlist_file=ALLOWLIST_FILE):
    host = urlparse(url).hostname
    if not host or not Path(allowlist_file).is_file():
        return False
    for l in read_text(allowlist_file).split('\n'):
        l = l.split('#')[0].strip()
        if l and l == host:
            return True
    return False


class FMCClient:
    def __init__(self, url, user, password, verify=True):
        from .fmc import new_session
        self.url = url.rstrip('/')
        self.s = new_session(verify)
        r = self.s.post(self.url + '/api/fmc_platform/v1/auth/generatetoken', auth=(user, password), timeout=60)
        r.raise_for_status()
        self.s.headers.update({'X-auth-access-token': r.headers['X-auth-access-token'], 'Content-Type': 'application/json'})
        self.dom = r.headers['DOMAIN_UUID']

    def api(self, method, path, data=None, params=None):
        u = self.url + '/api/fmc_config/v1/domain/%s%s' % (self.dom, path)
        for _ in range(5):
            r = self.s.request(method, u, json=data, params=params, timeout=120)
            if r.status_code == 429:
                time.sleep(5)
                continue
            break
        if r.status_code >= 400:
            raise RuntimeError('%s %s: %s %s' % (method, path, r.status_code, r.text[:300]))
        return r.json() if r.text.strip() else {}

    def all(self, path):
        out, off = [], 0
        while True:
            j = self.api('GET', path, params={'limit': 1000, 'offset': off})
            out += j.get('items', [])
            if not j.get('items') or len(out) >= j.get('paging', {}).get('count', 0):
                return out
            off = len(out)

    def policy_id(self, kind, name):
        for p in self.all('/policy/%s' % kind):
            if p['name'] == name:
                return p['id']
        raise RuntimeError('%s %s not found on FMC' % (kind, name))


def resolve_paths(plan, fmc):
    """fill {policy name} placeholders with ids"""
    cache = {}
    for op in plan:
        p = op['path']
        for kind in ('accesspolicies', 'ftdnatpolicies'):
            if '/%s/{' % kind in p:
                name = p.split('/%s/{' % kind)[1].split('}')[0]
                if (kind, name) not in cache:
                    cache[(kind, name)] = fmc.policy_id(kind, name)
                op['path'] = p.replace('{%s}' % name, cache[(kind, name)])
    return plan


def run(plan, url, user, password, allow_push=False, dry_run=True, log=print, verify=True):
    if not allow_push:
        raise PermissionError('push disabled: start with --allow-push')
    if not allowed(url):
        raise PermissionError('%s is not in %s' % (url, ALLOWLIST_FILE))
    fmc = FMCClient(url, user, password, verify=verify)
    plan = resolve_paths([dict(o) for o in plan], fmc)
    existing = {}
    results = []
    refs = {}
    for op in plan:
        base = op['path'].split('/{lookup}')[0]
        if base not in existing and op['method'] in ('POST', 'PUT'):
            existing[base] = {i['name']: i for i in fmc.all(base) if 'name' in i} if op['method'] == 'POST' else {}
        if op['method'] == 'POST' and op['payload'].get('name') in existing.get(base, {}):
            results.append((op['n'], 'skip (exists)', op['name']))
            refs[op['payload']['name']] = existing[base][op['payload']['name']]
            continue
        if dry_run:
            results.append((op['n'], 'would %s %s' % (op['method'], base), op['name']))
            continue
        payload = json.loads(json.dumps(op['payload']))
        for k in ('originalSource', 'translatedSource'):
            if k in payload and payload[k].get('name') in refs:
                payload[k] = {'type': refs[payload[k]['name']]['type'], 'id': refs[payload[k]['name']]['id']}
        if op['method'] == 'POST':
            j = fmc.api('POST', base, payload)
            refs[payload.get('name', op['name'])] = j
            results.append((op['n'], 'created', op['name']))
        else:
            results.append((op['n'], 'manual (PUT needs the rule id; see change list)', op['name']))
    for r in results:
        log('%3d %-40s %s' % (r[0], r[1], r[2]))
    return results
