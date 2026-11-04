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


def bad(line):
    return isinstance(line, str) and (ANY_ANY.search(line) is not None or FMC_ANY.search(line) is not None)


def _walk(x, path, hits):
    if isinstance(x, dict):
        cut = False
        for k in ('cli', 'fmc'):
            v = x.get(k)
            if isinstance(v, list) and any(bad(y) for y in v):
                x[k] = [y for y in v if not bad(y)]
                hits.append(path)
                cut = True
        if cut:
            if isinstance(x.get('fmc'), list) and NOTE not in x['fmc']:
                x['fmc'].insert(0, NOTE)
            x['safety'] = 'any-to-any permit stripped'
        for k, v in x.items():
            if k not in ('cli', 'fmc') and not k.startswith('_'):
                _walk(v, '%s.%s' % (path, k), hits)
    elif isinstance(x, list):
        for i, v in enumerate(x):
            _walk(v, '%s[%d]' % (path, i), hits)


def enforce(res, keys=('findings', 'takeover', 'runbook', 'failback', 'plan')):
    """strip any-to-any permits from res in place: {'stripped': n, 'where': [paths]}. A finding that loses one
    becomes something to check, never a fix to apply"""
    hits = []
    for k in keys:
        if k in res:
            _walk(res[k], k, hits)
    for f in res.get('findings', []) if isinstance(res.get('findings'), list) else []:
        if f.get('safety') or (f.get('fix') or {}).get('safety'):
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
