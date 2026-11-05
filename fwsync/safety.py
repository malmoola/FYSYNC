"""Last check on everything the tool outputs (0.5.4): no fix, takeover step, runbook or failback item may give a
permit whose source and destination are both any, whatever code path made it (an L7 rule, a rule narrowed by an
ignored interface, a rule with a destination interface). Such a line is stripped, the item says "Compare in FMC"
instead, and the count is kept in res['safety'] so a test or a report can fail on it."""
import re

ANY_ANY = re.compile(r'\bpermit\s+(?:object-group\s+\S+|object\s+\S+|\S+)\s+(?:ifc\s+\S+\s+)?any[46]?\s+'
                     r'(?:(?:eq|lt|gt|neq)\s+\S+\s+|range\s+\S+\s+\S+\s+)?(?:ifc\s+\S+\s+)?any[46]?(?:\s|$)')
FMC_ANY = re.compile(r'Action Allow\b.*Networks: Source any[46]?, Destination any[46]?\b')
NOTE = ('Compare in FMC: this would allow any source to any destination, so the tool gives no command for it. '
        'Compare the rule in FMC with its owner.')


LIVE_NOTE = ('Edit this NAT rule in FMC instead: it carries traffic today, so the tool gives no command that removes '
             'it.')


def bad(line, live=()):
    if not isinstance(line, str):
        return False
    if line.startswith('no nat ') and line[3:] in live:
        return True
    return ANY_ANY.search(line) is not None or FMC_ANY.search(line) is not None


def live_nats(B):
    """the NAT lines of B that carry traffic today: active, and their real addresses reach their real interface
    (any interface counts)"""
    from .detect import route_split_up
    out = set()
    for m in getattr(B, 'nats', []) if B is not None else []:
        if m.inactive or m.real is None or m.obj:
            continue
        if m.real_ifc in (None, '', 'any') or any(i == m.real_ifc for i, x in route_split_up(B, m.real)):
            out.add(m.line)
    return out


def _walk(x, path, hits, live=()):
    if isinstance(x, dict):
        cut = nat = False
        for k in ('cli', 'fmc', 'config'):
            v = x.get(k)
            if isinstance(v, list) and any(bad(y, live) for y in v):
                nat = nat or any(isinstance(y, str) and y.startswith('no nat ') and y[3:] in live for y in v)
                cut = cut or any(bad(y) for y in v)
                x[k] = [y for y in v if not bad(y, live)]
                hits.append(path)
        if cut:
            if isinstance(x.get('fmc'), list) and NOTE not in x['fmc']:
                x['fmc'].insert(0, NOTE)
            x['safety'] = 'any-to-any permit stripped'
            if 'when' in x:
                x['when'] = 'Compare in FMC'
                x['config'] = [NOTE] + [y for y in x['config'] if y != NOTE]
        for k in ('fmc', 'config'):
            if nat and isinstance(x.get(k), list) and LIVE_NOTE not in x[k]:
                x[k].append(LIVE_NOTE)
        for k, v in x.items():
            if k not in ('cli', 'fmc', 'config') and not k.startswith('_'):
                _walk(v, '%s.%s' % (path, k), hits, live)
    elif isinstance(x, list):
        for i, v in enumerate(x):
            _walk(v, '%s[%d]' % (path, i), hits, live)


def enforce(res, keys=('findings', 'takeover', 'runbook', 'failback', 'plan'), B=None):
    """strip any-to-any permits, and 'no nat' for a B rule that carries traffic today, from res in place:
    {'stripped': n, 'where': [paths]}. A finding that loses an any-to-any permit becomes something to check, never a
    fix to apply"""
    hits = []
    live = live_nats(B)
    for k in keys:
        if k in res:
            _walk(res[k], k, hits, live)
    for f in res.get('findings', []) if isinstance(res.get('findings'), list) else []:
        if f.get('safety') == 'any-to-any permit stripped' or (f.get('fix') or {}).get('safety'):
            f['level'], f['group'] = 'check', 'check'
            f['fix'].pop('safety', None)
            f['safety'] = 'any-to-any permit stripped'
            f['fix']['cli'] = [c for c in f['fix']['cli'] if c.startswith('show ')]
            f['fix']['objects'] = []
            f.pop('acp_rules', None)
            if NOTE not in f['fix']['fmc']:
                f['fix']['fmc'].insert(0, NOTE)
    prev = res.get('safety') or {'stripped': 0, 'where': []}
    out = {'stripped': prev['stripped'] + len(hits), 'where': prev['where'] + hits}
    res['safety'] = out
    return out
