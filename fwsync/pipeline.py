"""Configs in, compare result out. Modes: 1:1 (A -> B) and 2:1 (A1 + A2 -> B). The profile is optional:
whatever it leaves empty is auto-detected. User controls (fwsync.controls) are applied around the compare."""
import re
from pathlib import Path

from . import controls, ignore, sitemap
from .adapters import load
from .chain import build, order_edge
from .compare import compare, counts, summary
from .detect import detect, route_table
from .netset import IPSet
from .osutil import read_text
from .profile import Profile


def read(path):
    """config file -> (text, name): utf-8 / utf-8 BOM / cp1252, any line ending"""
    p = Path(path).expanduser()
    return read_text(p), p.name


def _strip(names, tag):
    """profile names for one firewall: '<tag>:x' and bare 'x' (2:1) or all (1:1)"""
    if not tag:
        return set(names)
    return {n[len(tag) + 1:] if n.startswith(tag + ':') else n for n in names if n.startswith(tag + ':') or ':' not in n}


def prefixes(cfgs):
    """every connected / static prefix of the given configs: [{prefix, where, ifc}] for scope expand and checks"""
    out = []
    for cfg, tag in cfgs:
        for r in route_table(cfg):
            if r['plen'] == 0:
                continue
            where = '%s%s %s' % (tag + ' ' if tag else '', r['kind'], r['ifc'])
            out.append({'prefix': r['net'], 'where': where, 'ifc': ('%s:%s' % (tag, r['ifc'])) if tag and tag != 'B' else r['ifc']})
    return out


def run(a_list, b, prof=None, parts=None):
    """a_list: [(text, name)] with 1 or 2 entries, b: (text, name). Returns (result, A, B, profile)."""
    if isinstance(prof, dict):
        prof = Profile(**{k: v for k, v in prof.items() if k in Profile.__dataclass_fields__})
    prof = prof or Profile()
    As = [load(t, n) for t, n in a_list]
    B = load(*b)
    B.pools = [IPSet.parse('%s-%s' % m) for m in re.findall(r'^ip local pool \S+ (\S+)-(\S+) mask', b[0], re.M)]
    for cfg, (text, n) in zip(As, a_list):
        cfg.pools = [IPSet.parse('%s-%s' % m) for m in re.findall(r'^ip local pool \S+ (\S+)-(\S+) mask', text, re.M)]
    apply_decisions(prof)
    roles_a = prof.roles_a or {}
    ign = ignore.ignored_names(prof) | {k for k, v in roles_a.items() if v == 'ignore'}
    links = {k for k, v in roles_a.items() if v == 'chain link'}
    for k, v in list(prof.interface_map.items()):
        if v and v != ignore.IGNORE and v not in B.interfaces:
            ifs = prof.whatif.setdefault('interfaces', [])
            if v not in [i['name'] if isinstance(i, dict) else i for i in ifs]:
                ifs.append({'name': v, 'role': roles_a.get(k, 'inside') if roles_a.get(k) in ('inside', 'outside') else 'inside'})
    planned = controls.apply_whatif(B, prof)
    chain_info = None
    if len(As) == 2:
        edge, inner, note = order_edge(As[0], As[1])
        tagged = ((edge, 'A1'), (inner, 'A2'))
        for cfg, tag in tagged:
            controls.apply_rule_actions(cfg, prof, tag)
            ignore.apply(cfg, _strip(ign, tag))
        src_prefixes = prefixes([(edge, 'A1'), (inner, 'A2'), (B, 'B')])
        link = next(iter(_strip({l for l in links if l.startswith('A1:')}, 'A1')), None)
        uplink = next(iter(_strip({l for l in links if l.startswith('A2:')}, 'A2')), None)
        A, chain_info = build(edge, inner, link=link, uplink=uplink)
        chain_info['note'] = note
    elif len(As) == 1:
        A = As[0]
        tagged = ((A, ''),)
        controls.apply_rule_actions(A, prof, '')
        controls.apply_rule_actions(B, prof, 'B')
        ignore.apply(A, ign)
        src_prefixes = prefixes([(A, 'A'), (B, 'B')])
    else:
        raise ValueError('give one A config (1:1) or two (2:1)')
    user_scope = bool(prof.scope)
    prof, info = detect(A, B, prof)
    pairs = sitemap.net_pairs(A, B, prof.interface_map)
    for n in sorted(prof.scope):
        prof.scope_names.setdefault(n, n)
    if pairs:
        sitemap.translate(A, pairs)
        names = {}
        for pa, pb in pairs:
            names[pb] = '%s (A %s)' % (prof.scope_names.get(pa, pa), pa)
        prof.scope = list(dict.fromkeys(sitemap.map_prefix(p, pairs) for p in prof.scope))
        prof.scope_names.update(names)
        for c in info['scope_candidates']:
            c['subnet'] = sitemap.map_prefix(c['subnet'], pairs)
    info['net_pairs'] = pairs
    if len(a_list) == 1:
        pp = sitemap.pool_pairs(sitemap.pools(a_list[0][0]), sitemap.pools(b[0]))
        sitemap.translate_pools(A, pp)
        info['pool_pairs'] = [(x['name'], y['name']) for x, y in pp]
    B.ra_ifcs = re.findall(r'^ enable (\S+)', '\n'.join(re.findall(r'^webvpn\n((?: .*\n)+)', b[0], re.M))) + \
        re.findall(r'^crypto ikev2 enable (\S+) client-services', b[0], re.M)
    for p, n in (prof.scope_add or {}).items():
        if p not in prof.scope:
            prof.scope.append(p)
        if n:
            prof.scope_names[p] = n
    for p in (prof.whatif or {}).get('public', []):
        if p not in prof.public_b:
            prof.public_b.append(p)
    if chain_info:
        for tag, n in (('A1', chain_info['a1_toward_a2']), ('A2', chain_info['a2_uplink'])):
            if n:
                info['interface_map'].append({'a': '%s:%s' % (tag, n), 'a_role': 'chain link', 'b': '',
                                              'a_reason': 'link between A1 and A2', 'how': 'chain', 'flag': '', 'note':
                                              'internal to the chain, not mapped to B'})
    info['mode'] = '2:1' if chain_info else '1:1'
    info['chain'] = chain_info
    info['prefixes'] = src_prefixes
    info['scope_warnings'] = controls.scope_checks(prof, [(x['prefix'], x['where']) for x in src_prefixes])
    res = compare(A, B, prof, **({'parts': parts} if parts else {}))
    res['held_rules'] = controls.held_rows([(c, t) for c, t in tagged], prof, prof.scope_set())
    controls.row_keys(res)
    controls.apply_row_state(res, prof)
    res['counts'] = counts(res)
    from .compare import l7_counts
    res['counts']['l7_actions'] = l7_counts(res)
    res['summary'] = summary(res, prof)
    res['planned'] = planned
    res['mode'] = info['mode']
    res['detected'] = info
    res['profile_used'] = prof.to_dict()
    res['warnings'] = (A.warnings[:50], B.warnings[:50])
    from . import findings, gaps
    findings.build(res, prof, A, B, info)
    if len(a_list) == 1 and A.vendor != 'fmc' and B.vendor != 'fmc':
        from . import settings
        prof.ignored_ifcs = set(A.ignored)
        res.update(settings.build(a_list[0][0], b[0], A, B, prof, pairs, sitemap.edge_pairs(A, B, prof.interface_map, prof.outside_a),
                                  res.get('names', {'A': 'A', 'B': 'B'})))
        res['verdict'] = settings.verdict(res, res.get('names', {'A': 'A', 'B': 'B'}))
    from . import gapcheck, runbook
    gapcheck.build(res, prof, A, B, info)
    runbook.build(res)
    if len(a_list) == 1:
        from . import gaplist
        gaplist.build(res, prof, A, B, info, a_list[0][0], b[0])
        gaplist.align_verdict(res)
    from . import safety
    safety.enforce(res, ('takeover', 'runbook', 'failback', 'plan', 'gaplist'), B=B)
    if res['safety']['stripped']:
        res['warnings'][0].append('safety: %d any-to-any permit line(s) stripped from the output' % res['safety']['stripped'])
    res['gaps_area'] = 'fmc' if 'fmc' in (A.vendor, B.vendor) or any(a.vendor == 'fmc' for a in As) else 'lina'
    res['known_gaps'] = gaps.ranked(res['gaps_area'])
    return res, A, B, prof


def apply_decisions(prof):
    """decision choices -> the profile fields they control (rule actions, finding states, extra public pool)"""
    for did, d in (prof.decision_state or {}).items():
        c = (d.get('choice') or '').lower()
        if did.startswith('D-held-') and d.get('rule') and c in ('block', 'permit'):
            prof.rule_actions.setdefault(d['rule'], c)
        elif (did.startswith('D-test-') or did.startswith('D-verify-')) and d.get('finding'):
            if c.startswith('not needed'):
                prof.finding_state.setdefault(d['finding'], {'state': 'not needed', 'reason': d.get('reason') or c})
            elif c.startswith('replicate'):
                prof.finding_state.setdefault(d['finding'], {'state': 'fix', 'reason': ''})
        elif did == 'D-pool' and d.get('pool'):
            for p in str(d['pool']).split(','):
                if p.strip() and p.strip() not in prof.whatif.setdefault('public', []):
                    prof.whatif['public'].append(p.strip())
