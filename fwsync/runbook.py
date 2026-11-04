"""Takeover runbook (0.5.3): every finding, choice, takeover check and whole-firewall check in one ordered list,
grouped by when to act. Each item: subject (subnet or interface), reason, what's wrong, why it matters, what to do
(FMC path + CLI), how to verify."""
from .findings import many

GROUPS = [('before', 'Fix before failover'), ('during', 'Do during failover'), ('check', 'Check on the firewall'),
          ('later', 'Review later'), ('unprovable', "Can't be proven from this config")]
LEVEL_GROUP = {'fix': 'before', 'choice': 'before', 'check': 'check', 'review': 'later'}


def _item(group, kind, subject, reason, what, why, fmc, cli, verify, ref):
    return {'group': group, 'kind': kind, 'subject': subject, 'reason': reason, 'what': what, 'why': why,
            'fmc': list(fmc), 'cli': list(cli), 'verify': list(verify), 'ref': ref}


def _from_finding(f):
    g = 'later' if f['state'] == 'later' else LEVEL_GROUP.get(f.get('level', 'fix'), 'before')
    kind = {'fix': 'thing to fix', 'choice': 'your choice needed', 'check': 'thing to verify'}.get(f.get('level'), 'note')
    fmc = list(f['fix']['fmc'])
    if f['fix']['objects']:
        fmc = ['Objects > Object Management > Network > Add: %s.' % '; '.join(
            '%s = %s' % (o['name'], o['value']) for o in f['fix']['objects'][:6])] + fmc
    cli = [c for o in f['fix']['objects'] for c in o['cli']] + f['fix']['cli']
    return _item(g, kind, f.get('subject') or f['scope'], f.get('short') or f['what'], f['what'], f['why'], fmc, cli,
                 f['verify'], f['id'])


def _from_decision(d, names):
    return _item('before', 'your choice needed', ', '.join(d.get('scopes', [])[:3]) or d['title'],
                 '%s: %s' % (d['kind'], d['title']), d['text'], 'The tool cannot decide this for you.',
                 ['fwsync > Your choices: choose %s. Then make the matching change in FMC.' % ' or '.join(
                     '"%s"' % o for o in d['options'])],
                 ['show running-config | include %s' % (d.get('rule') or d['title']).split()[0]], [
                     'Compare again: this item leaves the list once a choice is saved.'], d['id'])


def _from_firewide(r, names):
    b = names.get('B_short', names['B'])
    if r['check'].startswith('published'):
        real = r['detail'].split(' -> ')[0]
        return _item('before', 'thing to fix', r['item'], 'Published on %s with no NAT on %s' % (names['A_short'], b),
                     '%s is published at %s as %s; %s has no NAT for it.' % (real, names['A_short'], r['item'], b),
                     'During a %s internet outage it is unreachable from the internet.' % names['A_short'],
                     ['Devices > NAT > <%s NAT policy> > Add Rule: NAT Rule Manual, Type Static, Original Source the '
                      'server, Translated Source a %s public IP.' % (b, b)],
                     ['nat (<inside>,<outside>) source static <server object> <%s public object>' % b],
                     ['show nat detail', 'show xlate global <%s public IP>' % b], r['id'])
    if r['check'].startswith('A block'):
        return _item('later', 'note', r['item'], '%s blocks this; %s has no equal block' % (names['A_short'], b),
                     '%s block "%s" has no equal block on %s (%s).' % (names['A_short'], r['item'], b, r['detail']),
                     'If nothing else on %s blocks it, %s allows traffic %s blocks today.' % (b, b, names['A_short']),
                     ['Policies > Access Control > <%s access policy> > Add Rule: Action Block, the same sources, '
                      'destinations and ports as "%s" on %s.' % (b, r['item'], names['A_short'])],
                     ['access-list CSM_FW_ACL_ advanced deny <same as %s line %s>' % (names['A_short'], r['line'])],
                     ['packet-tracer input <interface> tcp <source> 40000 <destination> <port>'], r['id'])
    return _item('later', 'note', r['item'], 'Rule "%s" on %s can never match' % (r['item'], b),
                 '%s rule "%s" can never match: %s.' % (b, r['item'], r['detail']),
                 'It is dead config on %s, or it was written for an interface that does not exist yet.' % b,
                 ['Policies > Access Control > <%s access policy> > rule "%s": fix the source zone or remove the rule.'
                  % (b, r['item'])],
                 ['show access-list CSM_FW_ACL_ | include %s' % r['item']], ['show route <rule source>'], r['id'])


def build(res):
    """res['runbook'] = [{key, title, count, items}] in runbook order; res['verdict'] text and counts follow it"""
    names = res.get('names') or {'A': 'A', 'B': 'B'}
    names.setdefault('A_short', names['A'])
    names.setdefault('B_short', names['B'])
    items = [_from_finding(f) for f in res.get('findings', []) if f['state'] != 'not needed']
    items += [_from_decision(d, names) for d in res.get('decisions', []) if d.get('open')]
    for t in res.get('takeover', []):
        items.append(_item(t.get('group', 'later'), 'thing to fix' if t.get('group') == 'before' else
                           'thing to do' if t.get('group') == 'during' else 'note', t.get('subject', t['area']),
                           t['title'], '%s. %s' % (t['title'], t['detail']) if t['detail'] else t['title'],
                           t['action'], t.get('fmc', []), t.get('cli', []), t.get('verify', []), t['id']))
    items += [_from_firewide(r, names) for r in res.get('firewide', []) if not r.get('row_state')]
    groups = [{'key': k, 'title': t, 'items': [i for i in items if i['group'] == k]} for k, t in GROUPS]
    for g in groups:
        g['count'] = len(g['items'])
    res['runbook'] = groups
    c = {g['key']: g['count'] for g in groups}
    choices = sum(i['kind'] == 'your choice needed' for i in items)
    fix = c['before']
    parts = ['%s before failover%s' % (many(fix, 'thing to fix', 'things to fix'),
                                       ' (%s)' % many(choices, 'choice needed', 'choices needed') if choices else ''),
             '%d to do during failover' % c['during'], '%d to check on the firewall' % c['check'],
             '%d to review later' % c['later'], "%d can't be proven from this config" % c['unprovable']]
    text = '%s %s %s%s: %s.' % (names['B'], 'can take over from' if not fix else "can't take over from", names['A'],
                                '' if not fix else ' yet', '; '.join(parts))
    v = res.setdefault('verdict', {'areas': []})
    v.update({'ready': fix == 0, 'text': text, 'counts': c, 'choices': choices})
    return res
