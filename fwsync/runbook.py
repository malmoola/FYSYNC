"""Takeover runbook (0.5.3, 0.5.4): every finding, choice, takeover check and whole-firewall check in one ordered
list, grouped by when to act. Each item: subject (subnet or interface), reason, what's wrong, why it matters, what to
do (FMC path + CLI), how to verify. The group follows from whether the change could alter traffic that works today:
safe now (before), only in the takeover window (during), check first (on the firewall), or review. Every during step
has a failback step that reverses it (res['failback'])."""
from .findings import many
from .netset import IPSet

GROUPS = [('before', 'Fix before failover'), ('during', 'Do during failover'), ('check', 'Check on the firewall'),
          ('later', 'Review later'), ('unprovable', "Can't be proven from this config")]
LEVEL_GROUP = {'fix': 'before', 'choice': 'before', 'check': 'check', 'review': 'later'}


def _item(group, kind, subject, reason, what, why, fmc, cli, verify, ref, undo=None):
    return {'group': group, 'kind': kind, 'subject': subject, 'reason': reason, 'what': what, 'why': why,
            'fmc': list(fmc), 'cli': list(cli), 'verify': list(verify), 'ref': ref, 'undo': undo}


def _from_finding(f):
    g = 'later' if f['state'] == 'later' else LEVEL_GROUP.get(f.get('level', 'fix'), 'before')
    if f['state'] != 'later' and f.get('group') and f.get('level') != 'review':
        g = f['group']
    kind = {'fix': 'thing to fix', 'choice': 'your choice needed', 'check': 'thing to verify'}.get(f.get('level'), 'note')
    fmc = list(f['fix']['fmc'])
    if f['fix']['objects']:
        fmc = ['Objects > Object Management > Network > Add: %s.' % '; '.join(
            '%s = %s' % (o['name'], o['value']) for o in f['fix']['objects'][:6])] + fmc
    cli = [c for o in f['fix']['objects'] for c in o['cli']] + f['fix']['cli']
    kind = 'thing to do' if g == 'during' else kind
    return _item(g, kind, f.get('subject') or f['scope'], f.get('short') or f['what'], f['what'], f['why'], fmc, cli,
                 f['verify'], f['id'], f.get('undo'))


def _enable(f):
    """the during-failover step that enables a rule a finding creates disabled"""
    e = f['enable']
    return _item('during', 'thing to do', e['subject'], e['reason'], e['what'], e['why'], e['fmc'], e['cli'],
                 e['verify'], f['id'] + '-enable', e.get('undo'))


def _from_decision(d, names):
    return _item('before', 'your choice needed', ', '.join(d.get('scopes', [])[:3]) or d['title'],
                 '%s: %s' % (d['kind'], d['title']), d['text'], 'The tool cannot decide this for you.',
                 ['fwsync > Your choices: choose %s. Then make the matching change in FMC.' % ' or '.join(
                     '"%s"' % o for o in d['options'])],
                 ['show running-config | include %s' % (d.get('rule') or d['title']).split()[0]], [
                     'Compare again: this item leaves the list once a choice is saved.'], d['id'])


def _from_firewide(r, names):
    b, a = names.get('B_short', names['B']), names['A_short']
    if r['check'].startswith('published'):
        real = r['detail'].split(' -> ')[0].replace('/32)', ')')
        ip = r.get('real_ip') or real.split('(')[-1].rstrip(')')
        pub = r['item'].replace('/32', '')
        return _item('later', 'note', r['item'], 'Confirm whether %s must be reachable at %s after failover' % (
                         real, pub),
                     '%s is published at %s as %s; %s has no NAT for it.' % (real, a, pub, b),
                     'Only the servers that must work after failover need a static NAT on %s; during a %s internet '
                     'outage the others stay unreachable from the internet.' % (b, a),
                     ['Confirm: must %s be reachable from the internet at %s after failover? Decide which of these '
                      'must work after failover with the server owner. If no, nothing to do. If yes, add a static NAT on %s for it: Devices > NAT > <%s NAT policy> > Add '
                      'Rule: NAT Rule Manual, Type Static, Original Source %s, Translated Source a %s public IP, on the '
                      'interface %s is behind, and update DNS for %s.' % (real, pub, b, b, real.split(' (')[0],
                                                                         b, ip, pub)],
                     ['show route %s' % ip, 'show nat detail | include %s' % real.split(' (')[0]],
                     ['show nat detail | include %s' % real.split(' (')[0], 'show route %s' % ip], r['id'])
    if r['check'].startswith('A block'):
        deps = r.get('deps') or []
        fmc = []
        if deps:
            fmc.append('First add the %s allows that sit above this block on %s, or the block alone cuts those hosts '
                       'off: %s.' % (b, a, '; '.join('"%s" (%s -> %s, %s, line %s)' % (
                           d['rule'], d['src'], d['dst'], d['service'], d['line']) for d in deps[:6])))
        fmc.append('Policies > Access Control > <%s access policy> > Add Rule: Action Block, the same sources, '
                   'destinations and ports as "%s" on %s, below those allows; untick Enabled (create it disabled: it '
                   'would change traffic %s passes today). Enable it during failover after checking it.' % (
                       b, r['item'], a, b))
        what = '%s block "%s" has no equal block on %s (%s).' % (a, r['item'], b, r['detail'])
        if deps:
            what += ' Warning: copying the block alone would cut off hosts %s allows above it.' % a
        return _item('later', 'note', r['item'], '%s blocks this; %s has no equal block' % (a, b), what,
                     'If nothing else on %s blocks it, %s allows traffic %s blocks today.' % (b, b, a), fmc,
                     ['access-list CSM_FW_ACL_ advanced deny <same as %s line %s> inactive' % (a, r['line'])],
                     ['packet-tracer input <interface> tcp <source> 40000 <destination> <port>'], r['id'])
    if r['check'].startswith('Rule position'):
        return _item('later', 'note', r['item'], 'Block "%s" sits in another place among the allow rules on %s' % (
            r['item'], b), '%s.' % r['detail'], 'Traffic %s blocks today passes %s, because an allow rule comes '
            'first there.' % (a, b),
            ['Compare the order in FMC: Policies > Access Control > <%s access policy>: rule "%s" and allow rule(s) %s. '
             'Moving a rule changes traffic that works today: decide it with the rule owner.' % (
                 b, r.get('b_rule', r['item']), ', '.join('"%s"' % x for x in r.get('b_allows', [])[:4]))],
            ['show access-list CSM_FW_ACL_ | include %s' % r.get('b_rule', r['item'])],
            ['packet-tracer input <interface> tcp <source> 40000 <destination> <port>'], r['id'])
    if r['check'].startswith('B rule source moves'):
        z = ', '.join(r.get('add_zone', []))
        return _item('before', 'thing to fix', r['item'], 'Rule "%s": add zone %s, keep %s' % (r['item'], z, r['src_ifc']),
                     'Rule "%s" on %s: %s.' % (r['item'], b, r['detail']),
                     'After takeover this traffic arrives on %s, and the rule would no longer match it.' % z,
                     ['Policies > Access Control > <%s access policy> > edit rule "%s": Source Zones: add %s and keep %s '
                      '(it carries traffic from the other site today).' % (b, r['item'], z, r['src_ifc'])],
                     ['show access-list CSM_FW_ACL_ | include %s' % r['item']],
                     ['packet-tracer input %s tcp <rule source> 40000 <destination> <port>' % (r.get('add_zone') or [''])[0],
                      'Not testable yet if %s is shut down: run it after it is brought up.' % z], r['id'])
    if r['status'] == 'optional cleanup':
        why = ('Rule "%s" carries this traffic, so nothing is lost.' % r['carried_by'] if r.get('carried_by') else
               'The source only exists at %s, so this rule has nothing to match at %s.' % (a, b))
        return _item('later', 'note', r['item'], 'Optional cleanup: rule "%s" on %s can never match' % (r['item'], b),
                     '%s rule "%s" can never match: %s.' % (b, r['item'], r['detail']), why,
                     ['Optional cleanup: Policies > Access Control > <%s access policy> > rule "%s": remove it or fix '
                      'its source zone when convenient. Nothing is needed for takeover.' % (b, r['item'])],
                     ['show access-list CSM_FW_ACL_ | include %s' % r['item']], ['show route <rule source>'], r['id'])
    return _item('later', 'note', r['item'], 'Rule "%s" on %s can never match' % (r['item'], b),
                 '%s rule "%s" can never match: %s.' % (b, r['item'], r['detail']),
                 'It is dead config on %s, or it was written for an interface that does not exist yet.' % b,
                 ['Policies > Access Control > <%s access policy> > rule "%s": fix the source zone or remove the rule.'
                  % (b, r['item'])],
                 ['show access-list CSM_FW_ACL_ | include %s' % r['item']], ['show route <rule source>'], r['id'])


def _published(f):
    try:
        return IPSet.parse(f.get('a_public') or '')
    except Exception:
        return None


def _shut_item(c, names):
    """one 'Do during failover' item for a shut B interface a readiness card points to"""
    b, ifc = names['B_short'], c['shut_ifc']
    return _item('during', 'thing to do', ifc, '%s is shut down on %s' % (ifc, b), '%s is shut down on %s; %s is '
                 'behind it.' % (ifc, b, c['subnet']), 'Traffic on it cannot pass until it is brought up. Bring it up '
                 'only after %s is really gone.' % names['A_short'],
                 ['Devices > Device Management > %s > Interfaces > edit %s: tick Enabled > OK > Save, then Deploy.' % (
                     b, ifc)], ['interface %s' % (c.get('shut_phys') or '<%s physical interface>' % ifc), ' no shutdown'],
                 ['show interface %s' % ifc, 'show interface ip brief'], 'SHUT-%s' % ifc,
                 {'fmc': ['Devices > Device Management > %s > Interfaces > edit %s: untick Enabled > OK > Save, then '
                          'Deploy.' % (b, ifc)],
                  'cli': ['interface %s' % (c.get('shut_phys') or '<%s physical interface>' % ifc), ' shutdown']})


def failback(items, names):
    """one step per during-failover change, in reverse order, that puts it back"""
    out = []
    for i in reversed([x for x in items if x['group'] == 'during']):
        u = i.get('undo') or {}
        out.append(_item('failback', 'thing to undo', i['subject'], 'Undo: %s' % i['reason'],
                         'During failover: %s' % i['what'], 'Failback returns %s to the state it had before takeover, '
                         'once %s carries the traffic again.' % (names['B_short'], names['A_short']),
                         u.get('fmc') or ['Reverse this during-failover step: %s.' % i['reason']],
                         u.get('cli') or ['show running-config | include %s' % i['subject'].split()[0]], i['verify'],
                         i['ref'] + '-back'))
    return out


def build(res):
    """res['runbook'] = [{key, title, count, items}] in runbook order; res['verdict'] text and counts follow it"""
    names = res.get('names') or {'A': 'A', 'B': 'B'}
    names.setdefault('A_short', names['A'])
    names.setdefault('B_short', names['B'])
    items = [_from_finding(f) for f in res.get('findings', []) if f['state'] != 'not needed']
    items += [_enable(f) for f in res.get('findings', []) if f['state'] != 'not needed' and f.get('enable')]
    items += [_from_decision(d, names) for d in res.get('decisions', []) if d.get('open')]
    for t in res.get('takeover', []):
        items.append(_item(t.get('group', 'later'), 'thing to fix' if t.get('group') == 'before' else
                           'thing to do' if t.get('group') == 'during' else 'note', t.get('subject', t['area']),
                           t['title'], '%s. %s' % (t['title'], t['detail']) if t['detail'] else t['title'],
                           t['action'], t.get('fmc', []), t.get('cli', []), t.get('verify', []), t['id'], t.get('undo')))
    shown = [s for s in (_published(f) for f in res.get('findings', []) if f['category'] == 'inbound') if s]
    for r in res.get('firewide', []):
        if r.get('row_state'):
            continue
        if r['check'].startswith('published') and any(IPSet.parse(r['item']).issubset(s) for s in shown):
            continue
        items.append(_from_firewide(r, names))
    for c in res.get('readiness', []):
        if c.get('shut_ifc') and not any(i['group'] == 'during' and i['subject'] == c['shut_ifc'] for i in items):
            items.append(_shut_item(c, names))
    kept, seen = [], set()
    for i in items:
        k = (i['group'], i['subject'], i['reason'], i['what'])
        if k in seen or not (i['fmc'] or i['cli']):
            continue                                    # a duplicate, or nothing to do: not an item
        seen.add(k)
        kept.append(i)
    items = kept
    res['failback'] = failback(items, names)
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
    if res.get('go_nogo'):
        text += ' Go/no-go: %s.' % '; '.join(x.split(': ', 1)[1] for x in res['go_nogo'])
    v = res.setdefault('verdict', {'areas': []})
    v.update({'ready': fix == 0, 'text': text, 'counts': c, 'choices': choices})
    return res
