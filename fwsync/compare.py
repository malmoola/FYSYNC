"""Compare engine: A vs B by value (address/port sets), first-match rule semantics on B.
Both directions in one run: A -> B (what B is missing) and B -> A (what B has or allows beyond A)."""
import ipaddress
import re

from . import natorder
from .netset import IPSet, Service

PERMIT = ('permit', 'trust', 'allow', 'fastpath')
L7 = 'L7 rule: LINA shows permit, Snort applies the real action (check FMC)'
ORDER = ['covered', 'not compared (FQDN)', 'compare in FMC', 'partial', 'shadowed', 'denied', 'missing']
TUNNEL_PROTOS = ('ipinip', '41', 'gre', '4', '47')
MAX_CUBES = 32
MAX_FRAG = 64            # past this many (src, dst) parts a walk only drops parts a rule holds whole, never splits
SUSPECT = r'(?i)\b(block|blocklist|blocked|deny|denied|drop|reject|unwanted)\b|trojan|stratum miner'
CONFIRM = 'confirm in FMC'


def block_name(name, pat=None):
    """the rule name suggests a block. '_' and '-' separate words, so Block_X_to_Y and Deny-Social count"""
    return bool(name) and re.search(pat or SUSPECT, re.sub(r'[_\-]+', ' ', name)) is not None


def base_rule_name(name):
    """A rule name without the -NNN that FMC adds when a rule is copied, or stray spaces"""
    return re.sub(r'-\d{1,4}$', '', (name or '').strip()).strip()


def same_rule_name(a, b):
    return base_rule_name(a) == base_rule_name(b)


def _any_side(s, ref):
    """any, also when an ignored interface narrowed A's copy of any (the rule still says any)"""
    return s.is_any() or (ref or '').split(' ')[0] in ('any', 'any4')


def tunnel_default(r):
    """FTD prefilter tunnel defaults (ipinip, 41, gre, teredo from any to any): they match the encapsulation, not the
    traffic inside it, so they are never compared"""
    if 'DEFAULT TUNNEL' in (r.rule_name or '').upper():
        return True
    if not (r.src.is_any() and r.dst.is_any()) or not r.svc.items:
        return False
    return all(p in TUNNEL_PROTOS or (p == 'udp' and repr(s) == '3544') for p, d, s in r.svc.items)


def l7_any(r):
    """an L7 rule that shows as any to any in LINA: its URL, application or geo conditions are only in FMC, so it is
    never copied and never a match (only l7_cover rules count as coverage)"""
    return getattr(r, 'l7', False) and _any_side(r.src, r.src_ref) and _any_side(r.dst, r.dst_ref)


def any_any(r):
    """source and destination are both any: never copied, whatever the rule type"""
    return _any_side(r.src, r.src_ref) and _any_side(r.dst, r.dst_ref)


def l7_cover(r):
    """an L7 any-to-any permit that still counts as coverage: permit ip from a specific source zone, with a name that
    does not suggest a block (a final 'allow all from inside'). What it covers is marked 'confirm in FMC'"""
    return l7_any(r) and r.action in PERMIT and r.svc.is_any() and bool(r.src_ifc) and \
        not block_name(r.rule_name) and getattr(r, 'override', '') != 'suspect block name'


def effective_rules(cfg):
    """Rules that are applied: ACLs bound by access-group (interface ACLs get their ingress nameif),
    or CSM_FW_ACL_ when there is no access-group line. Tunnel default rules are left out."""
    out = []
    groups = cfg.access_groups or {'CSM_FW_ACL_': 'global'}
    for r in cfg.rules:
        if r.inactive or r.acl not in groups or r.action in ('unknown', 'l7block', 'ignore') or tunnel_default(r):
            continue
        g = groups[r.acl].split()
        if g and g[0] == 'in' and len(g) >= 3 and r.src_ifc is None:
            r.src_ifc = g[2]
        out.append(r)
    return out


def fqdn_names(cfg, r):
    """{'src': [...], 'dst': [...]}: FQDN objects (or groups holding one) the rule names on each side"""
    out = {}
    for side in ('src', 'dst'):
        names = getattr(r, side + '_names', None) or []
        hit = [n for n in names if _has_fqdn(cfg, n)]
        if hit:
            out[side] = hit
    return out


def _has_fqdn(cfg, name, seen=()):
    o = cfg.objects.get(name)
    if o is None or name in seen:
        return False
    if o.kind == 'fqdn':
        return True
    return o.kind == 'group' and any(m.startswith('obj:') and _has_fqdn(cfg, m[4:], seen + (name,)) for m in o.members)


def fqdn_value(cfg, name):
    o = cfg.objects.get(name)
    return o.value if o is not None and o.kind == 'fqdn' else ''


def _ifc_ok(b_ifc, want):
    """B rule interface field vs wanted (mapped) interface: (matches, fully_covers)"""
    if b_ifc is None or want is False:
        return True, True
    if want is None:
        return True, False
    return b_ifc == want, b_ifc == want


def _is_default(r):
    return r.action not in PERMIT and r.src.is_any() and r.dst.is_any() and r.svc.is_any() and \
        r.src_ifc is None and r.dst_ifc is None


def _sub(cubes, S, D, split=True):
    out = []
    for s, d in cubes:
        if not (s.overlaps(S) and d.overlaps(D)):
            out.append((s, d))
            continue
        if not split:
            if not (s.issubset(S) and d.issubset(D)):
                out.append((s, d))
            continue
        a = s - S
        if a:
            out.append((a, d))
        b = d - D
        if b:
            out.append((s & S, b))
    return out


def _hull(cubes):
    """all sources and all destinations of the parts still to check: a cheap test before the part-by-part one"""
    su, du = IPSet(), IPSet()
    for s, d in cubes:
        su, du = su | s, du | d
    return su, du


def eval_slice(b_rules, src_ifc, dst_ifc, src, dst, svc, skip=(), cubes=None):
    """First-match walk of B for traffic (src_ifc,dst_ifc,src,dst,svc). src_ifc/dst_ifc False = ignore interfaces.
    skip: ids of B rules to leave out (blocks that equal a block the A side has above the rule). cubes: the
    (src, dst) parts still to check, when an earlier A block already took some. Returns (status, matched B rules,
    detail)."""
    cubes = list(cubes) if cubes is not None else [(src, dst)]
    permits, denies = [], []
    su, du = _hull(cubes)
    for r in b_rules:
        if id(r) in skip or (l7_any(r) and r.action in PERMIT and not l7_cover(r)):
            continue
        m1, f1 = _ifc_ok(r.src_ifc, src_ifc)
        m2, f2 = _ifc_ok(r.dst_ifc, dst_ifc)
        if not (m1 and m2):
            continue
        if not svc.overlaps(r.svc) or not (su.overlaps(r.src) and du.overlaps(r.dst)):
            continue
        if len(cubes) > 1 and not any(s.overlaps(r.src) and d.overlaps(r.dst) for s, d in cubes):
            continue
        full_svc = svc.covered_by(r.svc)
        if _is_default(r):
            break                                   # default action: what is left is simply not permitted
        if r.action in PERMIT:
            permits.append(r)
            if full_svc and f1 and f2:
                cubes = _sub(cubes, r.src, r.dst, len(cubes) <= MAX_FRAG)
        else:
            denies.append(r)
            if full_svc:
                cubes = _sub(cubes, r.src, r.dst, len(cubes) <= MAX_FRAG)
        if not cubes:
            break
        su, du = _hull(cubes)
    remaining = sum(s.size() * d.size() for s, d in cubes)
    if not permits:
        return ('denied' if denies else 'missing'), denies, 'no B permit'
    first_deny_before = denies and permits and denies[0].seq < permits[0].seq
    if remaining == 0 and not denies:
        return 'covered', permits, ''
    if first_deny_before:
        return 'shadowed', denies[:1] + permits, 'earlier B deny %s' % (denies[0].rule_name or denies[0].seq)
    return 'partial', permits + denies, 'not all traffic or services permitted'


def a_blocks_above(a_rules, r, index=None):
    """A blocks above permit r that overlap it: on A they take that traffic first. A block on one interface still
    takes part of a rule on any interface (only blocks that cover r's interfaces remove traffic from it). index:
    [(position, block)] of a_rules, to skip the permits"""
    out = []
    pos = index.get(id(r)) if index else None
    blocks = index['blocks'] if index else list(enumerate(a_rules))
    for i, d in blocks:
        if (pos is not None and i >= pos) or d is r:
            break
        if d.action in PERMIT or _is_default(d) or (r.src_ifc is not None and d.src_ifc not in (None, r.src_ifc)) or \
                (r.dst_ifc is not None and d.dst_ifc not in (None, r.dst_ifc)):
            continue
        if d.src.overlaps(r.src) and d.dst.overlaps(r.dst) and d.svc.overlaps(r.svc):
            out.append(d)
    return out


def block_index(a_rules):
    idx = {id(r): i for i, r in enumerate(a_rules)}
    idx['blocks'] = [(i, r) for i, r in enumerate(a_rules) if r.action not in PERMIT and not _is_default(r)]
    return idx


def same_blocks(b_rules, a_blocks, prof):
    """ids of B blocks that block nothing more than an A block above the rule: both sides drop that traffic first. A's
    any narrowed by an ignored interface is still any"""
    out = set()
    for x in b_rules:
        if x.action in PERMIT or _is_default(x):
            continue
        for d in a_blocks:
            si, di = prof.map_ifc(d.src_ifc), prof.map_ifc(d.dst_ifc)
            if (d.src_ifc is None or x.src_ifc == si) and (d.dst_ifc is None or x.dst_ifc == di) and \
                    (x.src.issubset(d.src) or _any_side(d.src, d.src_ref)) and \
                    (x.dst.issubset(d.dst) or _any_side(d.dst, d.dst_ref)) and x.svc.covered_by(d.svc):
                out.add(id(x))
                break
    return out


BROAD = 2 ** 24          # a side covering a /8 or more ("any") does not reference a subnet specifically


def scope_split(prof, src, dst):
    """(specific, via_any): scope prefixes the rule names specifically vs only through any / a very broad range"""
    spec, broad = [], []
    for p, x in prof._parsed():
        hit_s, hit_d = src.overlaps(x), dst.overlaps(x)
        if not (hit_s or hit_d):
            continue
        if (hit_s and src.size() < BROAD) or (hit_d and dst.size() < BROAD):
            spec.append(p)
        else:
            broad.append(p)
    return spec, broad


def _slices(r, scope):
    out = []
    if r.src.overlaps(scope):
        out.append(('from scope', r.src & scope, r.dst))
    if r.dst.overlaps(scope):
        out.append(('to scope', r.src, r.dst & scope))
    return out


def _b_path(r, B, prof, A=None):
    """interfaces this traffic uses on B: the mapped ones, unless B routes the addresses elsewhere (Azure sits behind
    a tunnel on B and behind inside on A). When A itself routes them away from the rule's interface, the rule is
    kept as A has it"""
    from .detect import specific_ifc
    si, di = prof.map_ifc(r.src_ifc), prof.map_ifc(r.dst_ifc)

    def real(ifc, addrs, a_ifc):
        i = B.interfaces.get(ifc)
        if not ifc or i is None or i.planned:
            return ifc
        if A is not None and a_ifc and specific_ifc(A, addrs) not in (None, a_ifc):
            return ifc
        return specific_ifc(B, addrs) or ifc
    return real(si, r.src, r.src_ifc), real(di, r.dst, r.dst_ifc)


def compare_rules(A, B, prof):
    """each A permit in scope, judged by first match on both sides: A blocks above it take their traffic first, and a
    B block equal to one of them is not a difference. L7 any-to-any rules are not compared; FQDN rules are matched by
    object name and port"""
    scope = prof.scope_set()
    b_rules = effective_rules(B)
    a_rules = effective_rules(A)
    a_held = held_blocks(A)
    bidx = block_index(a_rules)
    out = []
    for r in a_rules:
        if r.action not in PERMIT:
            continue
        slices = _slices(r, scope)
        fq = fqdn_names(A, r)
        if not slices and fq and (r.src.overlaps(scope) or r.dst.overlaps(scope)):
            slices = [('fqdn', r.src, r.dst)]
        if not slices:
            continue
        si, di = _b_path(r, B, prof, A)
        results, other = [], None
        if l7_any(r):
            same = [x for x in b_rules if l7_any(x) and x.action in PERMIT and x.src_ifc == si and x.dst_ifc == di
                    and repr(x.svc.items) == repr(r.svc.items) and same_rule_name(x.rule_name, r.rule_name)]
            results = [(label, 'covered', same[:1], 'same L7 rule on B (any to any): %s that its conditions match' %
                        CONFIRM) if same else (label, 'compare in FMC', [], 'L7 rule shows as any to any in this config')
                       for label, s, d in slices]
        elif fq:
            results = [(slices[0][0],) + _fqdn_status(A, B, a_rules, b_rules, r, fq, a_held)]
        else:
            parts = []
            pre, skip = None, None
            for label, s, d in slices:
                st = eval_slice(b_rules, si, di, s, d, r.svc)
                if st[0] != 'covered':
                    pre = a_blocks_above(a_rules, r, bidx) if pre is None else pre
                cubes = [(s, d)]
                if st[0] != 'covered' and pre:
                    for x in pre if len(s.iv) + len(d.iv) <= MAX_CUBES else ():
                        if not cubes:
                            break
                        if r.svc.covered_by(x.svc) and len(x.src.iv) + len(x.dst.iv) <= MAX_CUBES and \
                                x.src_ifc in (None, r.src_ifc) and x.dst_ifc in (None, r.dst_ifc):
                            nxt = _sub(cubes, x.src, x.dst)
                            if len(nxt) > MAX_CUBES:
                                break               # too fragmented to follow: equal B blocks are still skipped
                            cubes = nxt
                    if not cubes:
                        results.append((label, 'covered', [], 'never reached on A: an earlier A block takes it'))
                        continue
                    if st[0] in ('shadowed', 'partial', 'denied'):
                        skip = same_blocks(b_rules, pre, prof) if skip is None else skip
                        st = eval_slice(b_rules, si, di, s, d, r.svc, skip, cubes)
                parts.append((label, s, d, cubes))
                results.append((label,) + st)
            if parts and any(x[1] in ('missing', 'partial') for x in results):
                twins = [x for x in b_rules if x.action not in PERMIT or specific_twin(r.src, r.dst, x)]
                alt = [eval_slice(twins, False, False, s, d, r.svc, skip or (), cubes) for label, s, d, cubes in parts]
                if all(a[0] == 'covered' for a in alt):
                    other = [m for a in alt for m in a[1] if m.src_ifc != si or m.dst_ifc != di]
        worst = max(results, key=lambda x: ORDER.index(x[1]))
        position = ''
        if worst[1] == 'shadowed' and worst[2]:
            den = worst[2][0]
            below = next((x for x in a_rules[a_rules.index(r) + 1:] if x.action not in PERMIT and not _is_default(x)
                          and den.src.issubset(x.src) and den.dst.issubset(x.dst) and den.svc.covered_by(x.svc)), None)
            if below is not None:
                position = 'On A, the same block "%s" sits below this rule; on B, "%s" sits above it.' % (
                    below.rule_name or below.seq, den.rule_name or den.seq)
        twin = _same_on_b(r, b_rules, si, di)
        if twin is not None and worst[1] == 'partial':
            results = [(label, 'covered', [twin], 'same rule on B') for label, s, d in slices]
            worst = results[0]
        l7c = [m for x in results for m in x[2] if l7_cover(m)]
        if worst[1] == 'covered' and l7c and CONFIRM not in worst[3]:
            worst = (worst[0], worst[1], worst[2], 'covered by L7 rule "%s" (any to any from %s): %s that its '
                     'conditions allow this traffic' % (l7c[0].rule_name or l7c[0].seq, l7c[0].src_ifc, CONFIRM))
        out.append({
            'id': 'R%d' % r.seq, 'path': getattr(r, 'path', ''), 'policy': r.policy, 'rule': r.rule_name, 'rule_id': r.rule_id,
            'action': r.action, 'src_ifc': r.src_ifc or 'any', 'dst_ifc': r.dst_ifc or 'any',
            'b_src_ifc': si or 'any', 'b_dst_ifc': di or 'any',
            'src': r.src_ref, 'dst': r.dst_ref, 'service': r.svc_ref, 'svc': repr(r.svc),
            'scope': prof.scope_label(r.src | r.dst), 'scopes': scope_split(prof, r.src, r.dst)[0],
            'scopes_any': scope_split(prof, r.src, r.dst)[1],
            'direction': ' + '.join(x[0] for x in results), 'status': worst[1],
            'detail': worst[3], 'l7': getattr(r, 'l7', False), 'action_check': _action_check(r),
            'confirm_fmc': worst[1] == 'covered' and CONFIRM in worst[3], 'block_name': block_name(r.rule_name),
            'b_rules': sorted({'%s %s' % (m.rule_name or m.rule_id or '', '#%d' % m.seq) for x in results for m in x[2]})[:8],
            'line': r.line, '_rule': r, '_b': [m for x in results for m in x[2]][:8], 'fqdn': fq,
            '_b_other': other if other and worst[1] in ('missing', 'partial') else [], 'position': position,
        })
    return _merge_origin(out, prof.scope_names)


def specific_twin(src, dst, x):
    """B rule x names this traffic as specifically as A does (it is the same rule, perhaps on other zones), not a
    broad any or /8 rule that happens to cover it"""
    for a, b in ((src, x.src), (dst, x.dst)):
        if not a.is_any() and (b.is_any() or b.size() >= BROAD or not a.issubset(b)):
            return False
    return True


def held_blocks(cfg):
    """rules left out of the compare because their name suggests a block (L7 rules show permit in LINA): they are
    still blocks for the FQDN position check"""
    groups = cfg.access_groups or {'CSM_FW_ACL_': 'global'}
    return [r for r in cfg.rules if not r.inactive and r.acl in groups and r.action in ('unknown', 'l7block')
            and (r.action == 'l7block' or block_name(r.rule_name))]


def _fqdn_status(A, B, a_rules, b_rules, r, fq, held=()):
    """FQDN objects have no addresses in a config: a B permit naming the same FQDN object (by name or by FQDN) with
    the ports covered is the same rule. Without one, it is a gap only when an A block below the rule (also an L7
    rule held as a block by its name) would take that traffic: (status, matched B rules, detail)"""
    want = {side: set(names) | {fqdn_value(A, n) for n in names if fqdn_value(A, n)} for side, names in fq.items()}
    for x in b_rules:
        if x.action not in PERMIT:
            continue
        xf = fqdn_names(B, x)
        if not all(want[side] & (set(xf.get(side, [])) | {fqdn_value(B, n) for n in xf.get(side, [])}) for side in fq):
            continue
        rest = [side for side in ('src', 'dst') if side not in fq]
        if any(not getattr(r, side).issubset(getattr(x, side)) for side in rest) or not r.svc.covered_by(x.svc):
            continue
        return 'covered', [x], 'same FQDN rule on B'
    blocks = [d for d in a_rules if d.action not in PERMIT and not _is_default(d)] + list(held)
    below = sorted([d for d in blocks if d.seq > r.seq and d.svc.overlaps(r.svc) and d.src_ifc in (None, r.src_ifc)
                    and d.dst_ifc in (None, r.dst_ifc) and ('src' in fq or r.src.overlaps(d.src))
                    and ('dst' in fq or r.dst.overlaps(d.dst))], key=lambda d: d.seq)
    names = ', '.join(n for v in fq.values() for n in v)
    if below:
        return 'missing', [], 'FQDN rule above A block "%s"; B has no rule for %s' % (
            below[0].rule_name or below[0].seq, names)
    return 'not compared (FQDN)', [], 'FQDN rule %s: no A block below it, B may allow it with a broader rule' % names


def _action_check(r):
    """L7 rules show permit in LINA even when the FMC action is block: flagged until the profile sets the action"""
    ov = getattr(r, 'override', '')
    if ov == 'permit':
        return 'permit (confirmed)'
    if getattr(r, 'l7', False):
        return 'action unknown (L7)'
    return ''


def _merge_origin(rows, names=None):
    """2:1: one A rule becomes several combined rules (one per region pair / intersection); report one row per
    original rule and path, with the worst status"""
    out, idx = [], {}
    for x in rows:
        o = getattr(x['_rule'], 'origin', None)
        if o is None:
            out.append(x)
            continue
        k = (o, x['path'])
        via = getattr(x['_rule'], 'via', [])
        if k not in idx:
            x['rule'] = x['rule'].split(' ∩ ')[0]
            x['intersected_with'] = list(via)
            x['_parts'] = [x['_rule']]
            idx[k] = x
            out.append(x)
            continue
        y = idx[k]
        y['_parts'].append(x['_rule'])
        y['intersected_with'] = sorted(set(y['intersected_with']) | set(via))
        if x.get('action_check') == 'action unknown (L7)':
            y['action_check'] = x['action_check']
        if ORDER.index(x['status']) > ORDER.index(y['status']):
            y['status'], y['detail'] = x['status'], x['detail']
        y['b_rules'] = sorted(set(y['b_rules']) | set(x['b_rules']))[:8]
        y['_b'] = (y.get('_b', []) + [m for m in x.get('_b', []) if m not in y.get('_b', [])])[:8]
        y['scopes'] = sorted(set(y['scopes']) | set(x['scopes']))
        y['scopes_any'] = sorted((set(y['scopes_any']) | set(x['scopes_any'])) - set(y['scopes']))
        for f in ('src_ifc', 'dst_ifc', 'b_src_ifc', 'b_dst_ifc'):
            if x[f] not in y[f].split(', '):
                y[f] += ', ' + x[f]
        if x['direction'] not in y['direction']:
            y['direction'] += ' + ' + x['direction']
    for y in idx.values():
        if len(y['_parts']) > 1:
            y['src'] = ' | '.join(dict.fromkeys(r.src_ref for r in y['_parts']))
            y['dst'] = ' | '.join(dict.fromkeys(r.dst_ref for r in y['_parts']))
        if names:
            y['scope'] = ', '.join(names.get(p, p) for p in y['scopes'])
        y['intersected_with'] = ', '.join(y['intersected_with'][:12]) + (' ...' if len(y['intersected_with']) > 12 else '')
        y['id'] = 'R%d' % y['_parts'][0].seq
        y['_rules'] = y.pop('_parts')
    return out


def compare_rules_reverse(A, B, prof):
    """B -> A: every B permit in scope, checked against A by address and service (interfaces ignored). Addresses
    behind an ignored A interface are left out: A's rules were narrowed there on purpose"""
    scope = prof.scope_set()
    a_rules = effective_rules(A)
    ign = getattr(A, '_ignored_set', None) or IPSet()
    names = {'covered': 'also on A', 'partial': 'over-permitted (partial)', 'shadowed': 'over-permitted (partial)',
             'denied': 'over-permitted', 'missing': 'over-permitted'}
    out = []
    for r in effective_rules(B):
        if r.action not in PERMIT:
            continue
        slices = _slices(r, scope)
        if not slices:
            continue
        cubes = []
        for label, s, d in slices:
            cubes += [(x - ign, y - ign) for x, y in _crossing(A, s, d)]
        cubes = [(x, y) for x, y in cubes if x and y]
        if not cubes:
            continue
        results = [eval_slice(a_rules, False, False, s, d, r.svc) for s, d in cubes]
        worst = max(results, key=lambda x: ORDER.index(x[0]))
        twin = _same_on_a(r, a_rules, prof, ign)
        if twin is not None:
            worst = ('covered', [twin])
            results = [worst]
        out.append({'id': 'BR%d' % r.seq, 'policy': r.policy, 'rule': r.rule_name, 'rule_id': r.rule_id,
                    'src_ifc': r.src_ifc or 'any', 'dst_ifc': r.dst_ifc or 'any', 'src': r.src_ref, 'dst': r.dst_ref,
                    'service': r.svc_ref, 'scope': prof.scope_label(r.src | r.dst), 'scopes': scope_split(prof, r.src, r.dst)[0],
                    'scopes_any': scope_split(prof, r.src, r.dst)[1], 'status': names[worst[0]],
                    'a_rules': sorted({'%s #%d' % (m.rule_name or m.rule_id or '', m.seq) for x in results for m in x[1]})[:8],
                    'line': r.line, '_rule': r})
    return out


def _same_on_b(r, b_rules, si, di):
    """the identical permit on B: extra narrow B blocks are reported by the block checks, not on every broad rule"""
    for x in b_rules:
        if x.action in PERMIT and x.src_ifc == si and x.dst_ifc == di and _same_addr(r.src, x.src, r.src_ref, x.src_ref) \
                and _same_addr(r.dst, x.dst, r.dst_ref, x.dst_ref) and repr(r.svc.items) == repr(x.svc.items):
            return x
    return None


def _same_addr(a, b, a_ref, b_ref):
    """equal addresses; 'any' on both sides also counts (an ignored interface narrows A's copy of any)"""
    return a == b or a_ref == b_ref == 'any'


def _same_on_a(r, a_rules, prof, ign=None):
    """the A permit with the same mapped interfaces, addresses and service: B allows nothing more with this rule.
    ign: addresses behind ignored A interfaces, left out of A's rules on purpose"""
    ign = ign or IPSet()
    rs, rd = r.src - ign, r.dst - ign
    for a in a_rules:
        if a.action in PERMIT and prof.map_ifc(a.src_ifc) == r.src_ifc and prof.map_ifc(a.dst_ifc) == r.dst_ifc \
                and _same_addr(a.src, rs, a.src_ref, r.src_ref) and _same_addr(a.dst, rd, a.dst_ref, r.dst_ref) \
                and repr(a.svc.items) == repr(r.svc.items):
            return a
    return None


def compare_firewide(A, B, prof):
    """checks that do not depend on the scope: A blocks with no equal on B (with the A allows above them that B lacks),
    blocks whose place among the allows differs, published A addresses with no B NAT, and B rules whose source is not
    behind their source interface"""
    from .netset import is_public
    out = []
    b_rules, a_rules = effective_rules(B), effective_rules(A)
    b_denies = [r for r in b_rules if r.action == 'deny' and not (r.src.is_any() and r.dst.is_any() and r.src_ifc is None)]
    seen, equal = {}, []
    for r in a_rules:
        if r.action != 'deny' or (r.src.is_any() and r.dst.is_any() and r.src_ifc is None and r.dst_ifc is None):
            continue
        si, di = prof.map_ifc(r.src_ifc), prof.map_ifc(r.dst_ifc)
        same = next((x for x in b_denies if x.src_ifc in (None, si) and x.dst_ifc in (None, di) and r.src.issubset(x.src)
                     and r.dst.issubset(x.dst) and repr(x.svc.items) == repr(r.svc.items)), None)
        if same is None:
            seen.setdefault(r.rule_name or r.rule_id or r.line, []).append(r)
        else:
            equal.append((r, same))
    for name, rs in seen.items():
        deps = dependent_allows(a_rules, b_rules, rs, prof)
        out.append({'id': 'FW-D-%s' % name, 'check': 'A block missing on B', 'status': 'missing', 'item': name,
                    'detail': '%d line(s), e.g. %s' % (len(rs), rs[0].line) + (
                        '; A allows above it that B lacks: %s' % ', '.join(d['rule'] for d in deps) if deps else ''),
                    'line': getattr(rs[0], 'lineno', 0), 'deps': deps, '_rules': rs})
    done = set()
    for d, x in equal:
        name = d.rule_name or d.rule_id or d.line
        diff = position_diff(a_rules, b_rules, d, x, prof)
        if diff and name not in done:
            done.add(name)
            q = diff[0]
            out.append({'id': 'FW-P-%s' % name, 'check': 'Rule position differs', 'status': 'position', 'item': name,
                        'detail': 'A has block "%s" above its allow rules; on B the same block "%s" sits below allow rule '
                                  '"%s" (line %s), so B allows %s -> %s (%s) that A blocks' % (
                                      name, x.rule_name or x.seq, q.rule_name or q.seq, getattr(q, 'lineno', 0),
                                      q.src_ref, q.dst_ref, q.svc_ref),
                        'line': getattr(d, 'lineno', 0), 'b_rule': x.rule_name or str(x.seq),
                        'b_allows': [r.rule_name or str(r.seq) for r in diff]})
    b_mapped, b_real = IPSet(), IPSet()
    for n in B.nats:
        if n.kind == 'static' and n.mapped is not None and not n.mapped.is_any() and n.mapped != n.real:
            b_mapped, b_real = b_mapped | n.mapped, b_real | n.real
    outs = set(prof.outside_a)
    for n in A.nats:
        if n.kind != 'static' or n.inactive or n.mapped is None or n.mapped.is_any() or n.mapped == n.real \
                or n.mapped_ifc not in outs or not is_public(n.mapped) or n.mapped.issubset(b_mapped) \
                or n.real.issubset(b_real):
            continue
        out.append({'id': 'FW-N-%s' % repr(n.mapped), 'check': 'published on A, no NAT on B', 'status': 'missing',
                    'item': repr(n.mapped), 'detail': '%s (%s) -> %s' % (n.real_ref, repr(n.real), n.mapped_ref),
                    'real_ip': repr(n.real).split('-')[0].split('/')[0].split(',')[0],
                    'line': getattr(n, 'lineno', 0)})
    out += source_checks(A, B, prof, b_rules)
    return out


def dependent_allows(a_rules, b_rules, denies, prof):
    """A allows above the first of these blocks that overlap it and that B does not carry: copying the block alone
    would cut those hosts off"""
    first = min(denies, key=lambda r: a_rules.index(r) if r in a_rules else 10 ** 6)
    if first not in a_rules:
        return []
    out = {}
    for p in a_rules[:a_rules.index(first)]:
        if p.action not in PERMIT or l7_any(p):
            continue
        for d in denies:
            if d.src_ifc not in (None, p.src_ifc) and p.src_ifc is not None:
                continue
            if d.dst_ifc not in (None, p.dst_ifc) and p.dst_ifc is not None:
                continue
            src, dst, svc = p.src & d.src, p.dst & d.dst, p.svc & d.svc
            if not (src and dst and svc):
                continue
            st, m, det = eval_slice(b_rules, prof.map_ifc(p.src_ifc), prof.map_ifc(p.dst_ifc), src, dst, svc)
            if st != 'covered':
                k = p.rule_name or p.rule_id or p.line
                out.setdefault(k, {'rule': k, 'line': getattr(p, 'lineno', 0), 'src': p.src_ref, 'dst': p.dst_ref,
                                   'service': p.svc_ref, 'b_status': st, '_rule': p, 'deny': d.rule_name or d.line})
            break
    return list(out.values())


def position_diff(a_rules, b_rules, d, x, prof):
    """B allows above block x that take part of d's traffic, where A has no allow above its equal block d"""
    if x not in b_rules or d not in a_rules:
        return []
    si, di = prof.map_ifc(d.src_ifc), prof.map_ifc(d.dst_ifc)
    above_a = a_rules[:a_rules.index(d)]
    out = []
    for q in b_rules[:b_rules.index(x)]:
        if q.action not in PERMIT or l7_any(q):
            continue
        if not (_ifc_ok(q.src_ifc, si)[0] and _ifc_ok(q.dst_ifc, di)[0]):
            continue
        src, dst, svc = q.src & d.src, q.dst & d.dst, q.svc & d.svc
        if not (src and dst and svc):
            continue
        st, m, det = eval_slice(above_a, False, False, src, dst, svc)
        if st != 'covered':
            out.append(q)
    return out


def source_checks(A, B, prof, b_rules):
    """B rules whose source is not behind their source interface. Such a rule may still carry traffic that arrives
    from the other site today (the source's own interface on B is shut): then the fix is to add the new zone and keep
    the old one. A rule whose traffic another rule carries, or whose source only exists at A, is optional cleanup."""
    from .detect import route_split, route_split_up, specific_ifc
    out, done = [], set()
    for r in b_rules:
        if r.action not in PERMIT or not r.src_ifc or r.src.is_any() or r.src_ifc in prof.outside_b:
            continue
        parts = route_split(B, r.src)
        ifcs = {i for i, x in parts}
        name = r.rule_name or r.rule_id
        if r.src_ifc in ifcs or name in done:
            continue
        done.add(name)
        detail = 'source interface %s, but %s routes via %s' % (r.src_ifc, r.src_ref, ', '.join(sorted(i or 'nothing' for i in ifcs)))
        row = {'id': 'FW-R-%s' % name, 'check': 'B rule source not behind its interface', 'status': 'never matches',
               'item': name, 'detail': detail, 'line': getattr(r, 'lineno', 0), 'src_ifc': r.src_ifc}
        today = {i for i, x in route_split_up(B, r.src)}
        moved = sorted(i for i in ifcs if i and i != r.src_ifc)
        bi = B.interfaces.get(r.src_ifc)
        held = bi is not None and not bi.shutdown and moved and all(
            B.interfaces.get(i) is not None and B.interfaces[i].shutdown for i in moved)
        if (r.src_ifc in today or held) and moved:
            row.update(check='B rule source moves at takeover', status='add zone', add_zone=moved,
                       detail='%s carries %s from the other site today; once %s %s up, B routes it via %s' % (
                           r.src_ifc, r.src_ref, ', '.join(moved), 'is' if len(moved) == 1 else 'are', ', '.join(moved)))
        else:
            main = max(parts, key=lambda x: x[1].size())[0] if parts else ''
            st, m, det = eval_slice([x for x in b_rules if x is not r], main or None, r.dst_ifc, r.src, r.dst, r.svc)
            if st == 'covered' and m:
                row.update(status='optional cleanup', carried_by=m[0].rule_name or str(m[0].seq),
                           detail=detail + '; rule "%s" carries this traffic' % (m[0].rule_name or m[0].seq))
            elif specific_ifc(A, r.src) and not specific_ifc(B, r.src):
                row.update(status='optional cleanup', failed_site_only=True,
                           detail=detail + '; the source only exists at A')
        out.append(row)
    return out


def _crossing(cfg, s, d):
    """the parts of s x d that cross cfg: source and destination routed out of different interfaces"""
    from .detect import route_split, routed_via
    out = []
    for ifc, ss in route_split(cfg, s):
        dd = d - routed_via(cfg, d, ifc) if ifc else d
        if dd:
            out.append((ss, dd))
    return out


def b_public(B, prof):
    if prof.public_b:
        s = IPSet()
        for p in prof.public_b:
            s = s | IPSet.parse(p)
        return s
    s = IPSet()
    outs = prof.outside_b or [n for n in B.interfaces if 'out' in n.lower()]
    for n in outs:
        i = B.interfaces.get(n)
        if i and i.ip:
            s = s | IPSet.net(i.ip, i.mask)
    for n in B.nats:
        if n.mapped is not None and n.mapped_ifc in outs and not n.mapped.is_any():
            s = s | n.mapped
    return s


class Pool:
    """free B public addresses: the profile pool, else the B public ranges minus network/broadcast,
    interface addresses, route next hops and every mapped address B already uses"""
    def __init__(self, prof, B, used):
        self.free = []
        self.used = set(used)
        self.assumed = not prof.public_pool_b
        if prof.public_pool_b:
            src = [IPSet.parse(p) for p in prof.public_pool_b]
        else:
            src = []
            for p in prof.public_b:
                n = ipaddress.IPv4Network(p, strict=False) if '/' in p else None
                if n is not None and n.prefixlen <= 30:
                    src.append(IPSet.range(str(n.network_address + 1), str(n.broadcast_address - 1)))
            for i in B.interfaces.values():
                if i.ip:
                    self.used.add(i.ip)
                    if i.standby:
                        self.used.add(i.standby)
            for r in B.routes:
                self.used.add(r.nexthop)
        for s in src:
            for a, b in s.iv:
                self.free += [str(ipaddress.IPv4Address(x)) for x in range(a, min(b, a + 65535) + 1)]
        self.available = len([x for x in self.free if x not in self.used])

    def take(self):
        for ip in self.free:
            if ip not in self.used:
                self.used.add(ip)
                return ip
        return ''


def inbound_rules(cfg, real, outs):
    """active permits from an outside interface toward `real` (rules without an interface count only when
    part of their source is routed out of an outside interface)"""
    from .detect import route_split
    key = tuple(outs)
    cache = getattr(cfg, '_inb', None)
    if cache is None or cache[0] != key:
        cand = []
        for r in effective_rules(cfg):
            if r.action not in PERMIT or r.dst.is_any() or getattr(r, 'wide', False):
                continue
            if r.src_ifc is not None:
                if r.src_ifc in outs:
                    cand.append(r)
            elif any(i in outs for i, s in route_split(cfg, r.src)):
                cand.append(r)
        cache = cfg._inb = (key, cand)
    return [r for r in cache[1] if r.dst.overlaps(real)]


def nat_kind(n):
    if n.kind == 'static' and n.mapped is not None and n.mapped == n.real and \
            (n.dst_real is None or n.dst_real == n.dst_mapped):
        k = 'identity'
    elif n.kind == 'static':
        k = 'static'
    else:
        k = 'dynamic PAT' if n.pat else 'dynamic'
    return k + (' twice' if n.dst_real is not None else '')


def _same_dst(a, b):
    return (a.dst_real is None and b.dst_real is None) or (
        a.dst_real is not None and b.dst_real is not None and a.dst_real == b.dst_real and a.dst_mapped == b.dst_mapped)


def _first_host(s):
    return s.hosts()[0] if s is not None and s.hosts() else (repr(s) if s is not None else '')


def pub_size(n):
    """public addresses a static NAT uses: the size of its mapped object (a /26 to one host is 1 address)"""
    return n.mapped.size() if n.mapped is not None and not n.mapped.is_any() else n.real.size()


def b_real_ifc(B, prof, n):
    """the B interface that holds the real addresses of A NAT n: A's real interface mapped to B when B routes them
    there (or has no specific route for them), else the interface B routes them to; '' when neither is known.
    Never the interface of another network."""
    from .detect import specific_ifc
    want = prof.map_ifc(n.real_ifc) if n.real_ifc not in (None, '', 'any') else ''
    routed = specific_ifc(B, n.real) or ''
    if want in B.interfaces and (not routed or routed == want):
        return want
    return routed


def b_mapped_ifc(B, prof, n, outs_b):
    m = prof.map_ifc(n.mapped_ifc)
    return m if m in B.interfaces else (outs_b[0] if outs_b else '')


def inbound_status(b_rules, a_in, n, prof, outs_b, ri, a_rules=None):
    """each A rule toward the server, with its own source, ports and interfaces, walked on B by first match; a B
    block equal to an A block above the rule is not a difference: (covered | partial | missing, matched B rules)"""
    sts, matched = [], []
    bidx = block_index(a_rules) if a_rules else None
    for r in a_in:
        skip = same_blocks(b_rules, a_blocks_above(a_rules, r, bidx), prof) if a_rules and id(r) in bidx else ()
        dst = r.dst & n.real
        sis = [prof.map_ifc(r.src_ifc)] if r.src_ifc else list(outs_b) or [None]
        di = ri or prof.map_ifc(r.dst_ifc)
        best, hit = 'missing', []
        for si in sis:
            st, m, det = eval_slice(b_rules, si, di, r.src, dst, r.svc, skip)
            if ORDER.index(st) < ORDER.index(best):
                best, hit = st, m
        if best == 'partial' and _same_on_b(r, b_rules, sis[0], di) is not None:
            best = 'covered'
        sts.append(best)
        matched += [x for x in hit if x not in matched and x.action in PERMIT]
    if sts and all(x == 'covered' for x in sts):
        return 'covered', matched
    if any(x in ('covered', 'partial') for x in sts):
        return 'partial', matched
    return 'missing', matched


def same_nat_group(nats, m):
    """the lines of one FMC NAT rule on several source interfaces: same addresses, same mapped interface"""
    return [x for x in nats if not x.inactive and x.real == m.real and x.mapped == m.mapped
            and x.mapped_ifc == m.mapped_ifc and x.dst_real == m.dst_real and x.dst_mapped == m.dst_mapped]


def compare_nat(A, B, prof):
    scope = prof.scope_set()
    pub_b = b_public(B, prof)
    outs_a = prof.outside_a or [n for n in A.interfaces if 'out' in n.lower()]
    outs_b = prof.outside_b or [n for n in B.interfaces if 'out' in n.lower()]
    shared = prof.type == 'shared-edge'
    b_mapped_use, b_reserved = {}, set()
    for n in B.nats:
        if n.kind == 'static' and n.mapped is not None and not n.mapped.is_any():
            b_reserved.update(n.mapped.hosts())
            if not n.inactive and nat_kind(n) == 'static':
                for h in n.mapped.hosts():
                    b_mapped_use.setdefault(h, []).append(n)
    pool = Pool(prof, B, b_reserved)
    b_rules = effective_rules(B)
    a_eff = effective_rules(A)
    alias = {repr(n.raw_real): repr(n.real) for n in A.nats if getattr(n, 'raw_real', None) is not None}

    def hosts_on(pub):
        """distinct inside hosts B maps pub to; A's own address and its site translation are one host"""
        return {alias.get(repr(x.real), repr(x.real)) for x in b_mapped_use.get(pub, [])}
    nats, inbound, dns = [], [], []
    for n in A.nats:
        if not n.real.overlaps(scope) or n.real.is_any():
            continue
        kind = nat_kind(n)
        row = {'id': 'N%d' % n.seq, 'section': n.section, 'kind': kind,
               'a_ifc': '%s->%s' % (n.real_ifc, n.mapped_ifc), 'real_ref': n.real_ref, 'real': repr(n.real),
               'a_mapped': 'interface' if n.mapped_interface else repr(n.mapped),
               'a_dst': '' if n.dst_real is None else '%s -> %s' % (repr(n.dst_real), repr(n.dst_mapped)),
               'a_inactive': n.inactive, 'description': n.description, 'scope': prof.scope_label(n.real),
               'scopes': prof.scope_keys(n.real), 'line': n.line, '_nat': n}
        if kind == 'static':
            a_in = inbound_rules(A, n.real, outs_a) if not n.inactive else []
            row['outbound_only'] = not a_in
            raw = getattr(n, 'raw_real', None)
            cands = [m for m in B.nats if nat_kind(m) == 'static' and (m.real == n.real or (raw is not None and m.real == raw))]
            active = [m for m in cands if not m.inactive]
            a_pub = _first_host(n.mapped)
            b_pub = ''
            ri, mo = b_real_ifc(B, prof, n), b_mapped_ifc(B, prof, n, outs_b)
            row.update(b_real_ifc=ri, b_mapped_ifc=mo)
            if active:
                # one FMC rule on an interface group is one NAT line per member: judge the line on the server's interface
                m = next((x for x in active if ri and x.real_ifc in ('any', ri) and x.mapped_ifc in ('any', mo)), active[0])
                group = sorted({x.real_ifc for x in same_nat_group(active, m)})
                b_pub = _first_host(m.mapped)
                status, notes = 'match', ['B NAT is on %s' % ', '.join(group)] if len(group) > 1 else []
                twin = raw is not None and raw != n.real and m.real == n.real and m.mapped != n.mapped
                if twin:
                    status, notes = 'each site has its own', ['B has its own server and public IP for this site address']
                elif shared and m.mapped != n.mapped:
                    status, notes = 'mapped conflict', ['shared public subnet: B must use the same public IP as A']
                elif not shared:
                    if m.mapped is not None and pub_b and not m.mapped.issubset(pub_b):
                        status = 'mapped outside B public'
                    if m.mapped == n.mapped and n.mapped is not None:
                        status = 'mapped reuse'
                        notes.append('B uses the same public IP as A')
                if b_pub and len(hosts_on(b_pub)) > 1:
                    status = 'mapped conflict'
                    notes.append('%d B NATs map %s to different hosts' % (len(hosts_on(b_pub)), b_pub))
                if status != 'mapped conflict' and not twin and ri and (m.real_ifc not in ('any', ri) or
                                                                      m.mapped_ifc not in ('any', mo)):
                    status = 'wrong interface'
                    notes = ['B NAT is on (%s,%s); the server is behind %s' % (', '.join(group) if len(group) > 1 else m.real_ifc, m.mapped_ifc, ri)]
                row.update(status=status, b_nat='#%d %s' % (m.seq, m.real_ref), b_mapped=b_pub, detail='; '.join(notes), _b_nat=m)
            elif cands:
                m = cands[0]
                row.update(status='inactive on B', b_nat='#%d %s' % (m.seq, m.real_ref), b_mapped=_first_host(m.mapped),
                           detail='B has the NAT but it is inactive', _b_nat=m)
            else:
                detail = 'no B static NAT for %s' % repr(n.real)
                if shared:
                    b_pub = a_pub
                    other = [m for m in b_mapped_use.get(a_pub, []) if alias.get(repr(m.real), repr(m.real)) != repr(n.real)]
                    if other:
                        row.update(status='mapped conflict', b_nat='', b_mapped='', proposed_b_mapped=a_pub,
                                   detail='%s already maps %s on B' % (a_pub, other[0].real_ref))
                        nats.append(row)
                        continue
                elif a_in:
                    b_pub = prof.public_map.get(a_pub) or pool.take()
                    if not b_pub:
                        detail += '; no free B public address'
                else:
                    b_pub = prof.public_map.get(a_pub, '')
                    detail += '; no inbound rule on A (outbound identity only)'
                row.update(status='missing', b_nat='', b_mapped='', proposed_b_mapped=b_pub, detail=detail)
            nats.append(row)
            if not n.inactive:
                if a_in:
                    svc = Service()
                    for r in a_in:
                        svc = svc | r.svc
                    st_rule, b_in = inbound_status(b_rules, a_in, n, prof, outs_b, row.get('b_real_ifc', ''), a_eff)
                    nat_ok = row['status'] in ('match', 'mapped reuse', 'mapped outside B public')
                    ready = 'ready' if nat_ok and st_rule == 'covered' else (
                        'nat %s, rule %s' % ('ok' if nat_ok else row['status'], st_rule))
                    if row['status'] == 'each site has its own':
                        ready = 'ready: each site has its own'
                    ports = sorted({r.svc_ref for r in a_in})
                    bp = row.get('b_mapped') or row.get('proposed_b_mapped', '')
                    inbound.append({'id': 'I%d' % n.seq, 'object': n.real_ref, 'real': repr(n.real),
                                    'a_public': a_pub, 'b_public': bp, 'ports': ', '.join(ports),
                                    'a_rules': ', '.join(sorted({r.rule_name or r.rule_id for r in a_in})),
                                    'b_rules': ', '.join(sorted({r.rule_name or str(r.seq) for r in b_in})),
                                    'status': ready, 'scope': row['scope'], 'scopes': row['scopes'], 'nat_id': row['id'],
                                    '_nat': n, '_svc': svc, '_a_rules': a_in, '_b_rules': b_in, '_b_nat': row.get('_b_nat'),
                                    'nat_status': row['status'], 'rule_status': st_rule, 'description': n.description,
                                    'b_real_ifc': row.get('b_real_ifc', ''), 'b_mapped_ifc': row.get('b_mapped_ifc', '')})
                    dns.append({'host': n.real_ref, 'description': n.description, 'real_ip': repr(n.real),
                                'a_public_ip': a_pub, 'b_public_ip': bp, 'b_status': row['status'], 'ports': ', '.join(ports),
                                'scope': row['scope']})
        elif kind.startswith('identity') or kind.endswith('twice'):
            same = [m for m in B.nats if nat_kind(m) == kind and n.real.issubset(m.real) and _same_dst(n, m)
                    and (kind.startswith('identity') or m.mapped == n.mapped)]
            near = [m for m in B.nats if nat_kind(m).split()[0] == kind.split()[0] and m.real.overlaps(n.real)]
            act = [m for m in same if not m.inactive]
            st = 'match' if act else 'inactive on B' if same else 'differs' if near else 'missing'
            m = (act or same or near or [None])[0]
            row.update(status=st, b_nat='#%d %s' % (m.seq, m.real_ref) if m else '',
                       b_mapped=(_first_host(m.mapped) if m else ''),
                       detail='' if st != 'differs' else 'B NAT for an overlapping source differs (mapped or destination)')
            nats.append(row)
        else:
            dyn = [m for m in B.nats if nat_kind(m).startswith('dynamic') and not nat_kind(m).endswith('twice')]
            cov = [m for m in dyn if not m.inactive and n.real.issubset(m.real)]
            part = [m for m in dyn if not m.inactive and n.real.overlaps(m.real)]
            ina = [m for m in dyn if m.inactive and n.real.overlaps(m.real)]
            st = 'match' if cov else 'partial' if part else 'inactive on B' if ina else 'missing'
            m = (cov or part or ina or [None])[0]
            row.update(status=st, b_nat='#%d %s' % (m.seq, m.real_ref) if m else '',
                       b_mapped=('interface' if m and m.mapped_interface else repr(m.mapped)) if m else '', detail='')
            nats.append(row)
    pat, detail = [], []
    sides = (('A', A, outs_a), ('B', B, outs_b))
    shadow = {side: natorder.shadowed(cfg) for side, cfg, o in sides}
    for p in prof.scope:
        s = IPSet.parse(p)
        for side, cfg, outs in sides:
            if side == 'A':
                si = a_si = natorder.src_ifc(cfg, s)
            else:
                si = prof.map_ifc(a_si) if a_si else None
                si = si if si in cfg.interfaces else None
            eff, so = natorder.best_effective(cfg, s, si, outs)
            hit = [(part, n) for part, n in eff if n is not None]
            cov = IPSet()
            for part, n in hit:
                cov = cov | part
            if not any(natorder.shared(n) for part, n in hit):
                st = 'missing'
            elif cov == s:
                st = 'covered'
            else:
                pct = 100.0 * cov.size() / s.size()
                st = 'partial %s%%' % ('%.0f' % pct if pct >= 1 else '<1')
            pat.append({'id': 'P-%s-%s' % (side, p), 'side': side, 'firewall': cfg.name, 'subnet': p,
                        'scope': prof.scope_names.get(p, p), 'scopes': [p], 'status': st,
                        'nat': '; '.join('#%d %s -> %s (line %s)' % (n.seq, n.real_ref, 'interface' if n.mapped_interface
                                                                     else n.mapped_ref, natorder.line_of(n))
                                         for part, n in hit[:4]),
                        'section': hit[0][1].section if hit else '', 'out_ifc': so or ''})
            for part, n in eff:
                row = {'id': 'PD-%s-%s-%s' % (side, n.seq if n else 'none', p), 'side': side, 'firewall': cfg.name,
                       'subnet': p, 'scope': prof.scope_names.get(p, p), 'addresses': repr(part), 'count': part.size()}
                if n is None:
                    row.update(status='not translated', object='', mapped='', section='', line='')
                else:
                    row.update(status='translated', kind='shared' if natorder.shared(n) else '1:1',
                               object=n.real_ref, mapped='interface' if n.mapped_interface else n.mapped_ref,
                               section=n.section, line=natorder.line_of(n), order=getattr(n, 'order', 0))
                detail.append(row)
            for n in natorder.ordered(cfg):
                if id(n) in shadow[side] and n.real.overlaps(s):
                    detail.append({'id': 'PD-%s-%s-%s-shadow' % (side, n.seq, p), 'side': side, 'firewall': cfg.name,
                                   'subnet': p, 'scope': prof.scope_names.get(p, p), 'addresses': repr(n.real & s),
                                   'count': (n.real & s).size(), 'status': shadow[side][id(n)][1], 'object': n.real_ref,
                                   'mapped': 'interface' if n.mapped_interface else n.mapped_ref, 'section': n.section,
                                   'line': natorder.line_of(n), 'order': getattr(n, 'order', 0)})
    used = {}
    for m in B.nats:
        if m.kind == 'static' and m.mapped is not None and not m.mapped.is_any() and m.mapped_ifc in outs_b:
            for h in m.mapped.hosts():
                used.setdefault(h, []).append('%s%s' % (m.real_ref, ' (inactive)' if m.inactive else ''))
    public = []
    tot_new = tot_ina = 0
    for p in prof.scope:
        s = IPSet.parse(p)
        rows = [r for r in nats if r['kind'] == 'static' and r['_nat'].real.overlaps(s) and not r['a_inactive']]
        if not rows:
            continue
        miss = [r for r in rows if r['status'] == 'missing']
        ina = [r for r in rows if r['status'] == 'inactive on B']
        pub_a = [r for r in miss if not r.get('outbound_only')]
        pub_b = [r for r in miss if r.get('outbound_only')]
        tot_new += sum(pub_size(r['_nat']) for r in pub_a)
        tot_ina += len(ina)
        public.append({'id': 'PUB-%s' % p, 'scope': prof.scope_names.get(p, p), 'subnet': p, 'scopes': [p],
                       'a_static_active': len(rows), 'b_missing': len(miss), 'b_inactive': len(ina),
                       'b_public_needed': len(pub_a) + len(ina), 'b_public_new': len(pub_a),
                       'pub_a': sum(pub_size(r['_nat']) for r in pub_a), 'pub_b': sum(pub_size(r['_nat']) for r in pub_b),
                       'pub_b_nats': len(pub_b),
                       'pub_b_hosts': ['%s (%s)' % (r['real_ref'], r['real']) for r in pub_b],
                       'status': 'ok' if not pub_a and not ina else 'needs %d' % (len(pub_a) + len(ina))})
    avail = pool.available
    public.append({'id': 'PUB-TOTAL', 'scope': 'total', 'subnet': ', '.join(prof.public_b), 'a_static_active': '',
                   'b_missing': tot_new, 'b_inactive': tot_ina, 'b_public_needed': tot_new + tot_ina, 'b_public_new': tot_new,
                   'b_public_available': 'shared subnet' if shared else avail,
                   'status': ('shared public subnet: same IPs' if shared else
                              ('ok' if avail >= tot_new else 'short by %d' % (tot_new - avail))) +
                   (' (B ranges assumed from config)' if pool.assumed and not shared else '')})
    nets = {}
    for h in used:
        n = str(ipaddress.IPv4Network(h + '/24', strict=False))
        nets.setdefault(n, []).append(h)
    for n, hs in sorted(nets.items()):
        public.append({'id': 'PUB-B-%s' % n, 'scope': 'B used', 'subnet': n, 'a_static_active': '', 'b_missing': '',
                       'b_inactive': '', 'b_public_needed': '', 'b_public_new': '',
                       'status': '%d used: %s' % (len(hs), ', '.join(sorted(hs, key=lambda x: int(ipaddress.IPv4Address(x)))))})
    return nats, pat, inbound, dns, detail, public


def compare_nat_reverse(A, B, prof):
    """B -> A: B NATs in scope that A does not have"""
    scope = prof.scope_set()
    out = []
    for m in B.nats:
        if m.real.is_any() or not m.real.overlaps(scope):
            continue
        k = nat_kind(m)
        same = [n for n in A.nats if nat_kind(n) == k and n.real == m.real and _same_dst(n, m)]
        if k.startswith('dynamic'):
            same = same or [n for n in A.nats if nat_kind(n) == k and m.real.issubset(n.real)]
        st = 'also on A' if same else 'B only'
        if same and k == 'static' and same[0].mapped != m.mapped:
            st = 'also on A (other public IP)'
        out.append({'id': 'BN%d' % m.seq, 'kind': k, 'b_ifc': '%s->%s' % (m.real_ifc, m.mapped_ifc), 'real_ref': m.real_ref,
                    'real': repr(m.real), 'b_mapped': 'interface' if m.mapped_interface else repr(m.mapped),
                    'b_inactive': m.inactive, 'status': st, 'a_nat': '#%d %s' % (same[0].seq, same[0].real_ref) if same else '',
                    'scope': prof.scope_label(m.real), 'scopes': prof.scope_keys(m.real), 'line': m.line})
    return out


def compare_routing(A, B, prof):
    """does B route every scope subnet out of the interface the A side implies?"""
    from .detect import roles, route_split
    ra, rb = roles(A), roles(B)
    if prof.outside_a:
        ra = {k: ('outside' if k in prof.outside_a else 'inside', '') for k in ra}
    if prof.outside_b:
        rb = {k: ('outside' if k in prof.outside_b else 'inside', '') for k in rb}
    out = []
    for p in prof.scope:
        s = IPSet.parse(p)
        a_parts = route_split(A, s)
        a_ifc = max(a_parts, key=lambda x: x[1].size())[0] if a_parts else ''
        want_role = ra.get(a_ifc, ('inside',))[0]
        want = prof.map_ifc(a_ifc) if a_ifc else ''
        ign = set(A.ignored or ()) | {prof.interface_map.get(x) for x in (A.ignored or ()) if prof.interface_map.get(x)}
        parts = [(ifc, sub) for ifc, sub in route_split(B, s) if ifc not in ign]     # left out on A as well
        desc, worst = [], 'ok'
        for ifc, sub in parts:
            role = rb.get(ifc, ('',))[0]
            # each part is judged against A's route for that same part (a subnet A splits over two interfaces)
            same = [(ai, x) for ai, x in a_parts if ai and x.overlaps(sub)]
            w_role, w_ifc = (ra.get(same[0][0], ('inside',))[0], prof.map_ifc(same[0][0])) if len(same) == 1 else \
                (want_role, want)
            if not ifc:
                st = 'no route on B'
            elif role != w_role:
                st = 'wrong way'
            elif ifc != w_ifc:
                st = 'other %s interface' % role
            else:
                st = 'ok'
            desc.append('%s via %s (%s)' % (repr(sub), ifc or 'nothing', st))
            rank = ['ok', 'other inside interface', 'other outside interface', 'wrong way', 'no route on B']
            if rank.index(st) > rank.index(worst):
                worst = st
        own = next((n for n, i in B.interfaces.items() if i.ip and s.issubset(IPSet.net(i.ip, i.mask)) and
                    ra.get(a_ifc, ('',))[0] == 'inside' and rb.get(n, ('',))[0] == 'outside'), None)
        pool = any(s.overlaps(x) for x in getattr(B, 'pools', []))
        pub_b, pub_a = IPSet.parse(','.join(prof.public_b)), IPSet.parse(','.join(prof.public_a))
        public = prof.public_b and s.issubset(pub_b) and not s.overlaps(pub_a)
        b_own = ('%s subnet' % own) if own else 'VPN pool' if pool else 'public range' if public else ''
        if b_own:
            worst, desc = 'ok', ['belongs to B itself (%s)' % b_own]
        nh = [r for r in _routes_for(B, s)]
        out.append({'id': 'RT-%s' % p, 'scope': prof.scope_names.get(p, p), 'scopes': [p], 'subnet': p,
                    'a_ifc': a_ifc, 'a_role': want_role, 'expected_b_ifc': want, 'b_route': '; '.join(desc),
                    'b_next_hop': ', '.join(nh), 'status': worst, 'b_own': b_own,
                    'detail': ('B also runs %s: routes may be learned dynamically' % ', '.join(B.dynamic_routing))
                    if B.dynamic_routing and worst != 'ok' else ''})
    return out


def _routes_for(cfg, s):
    from .detect import route_table
    seen = []
    rest = s
    for r in route_table(cfg):
        part = rest & r['set']
        if part:
            seen.append('%s %s' % (r['net'], r['nexthop'] or 'connected'))
            rest = rest - part
        if not rest:
            break
    return seen[:4]


def compare_objects(A, B, prof):
    scope = prof.scope_set()
    by_val = {}
    for o in B.objects.values():
        if o.kind not in ('group', 'fqdn') and not o.name.startswith('FMC_INLINE_'):
            by_val.setdefault(o.addrs, []).append(o.name)
    out = []
    for o in A.objects.values():
        if o.kind == 'fqdn' or o.name.startswith('FMC_INLINE_'):
            continue
        addrs = o.addrs if o.kind != 'group' else _group_addrs(A, o)
        if not addrs.overlaps(scope) or addrs.is_any():
            continue
        bname = prof.rename_obj(o.name)
        b = B.objects.get(bname)
        if b is not None:
            bv = b.addrs if b.kind != 'group' else _group_addrs(B, b)
            same = bv == addrs or bv == raw_addrs(A, o)         # B may name A's own address on purpose
            superset = o.kind == 'group' and b.kind == 'group' and addrs.issubset(bv)
            st = 'same' if same else 'B has extra entries' if superset else 'same name, different value'
            other = repr(bv) if st != 'same' else ''
            a_missing, b_extra = ('' if same else repr(addrs - bv)), ('' if same else repr(bv - addrs))
        else:
            names = by_val.get(addrs, []) if o.kind != 'group' else []
            st = 'same value, different name' if names else 'missing on B'
            other = ', '.join(names[:5])
            a_missing = b_extra = ''
        out.append({'id': 'O-' + o.name, 'name': o.name, 'b_name': bname, 'kind': o.kind, 'value': o.value or repr(addrs),
                    'addrs': repr(addrs), 'status': st, 'b_value_or_names': other, 'a_missing': a_missing,
                    'b_extra': b_extra, 'scope': prof.scope_label(addrs),
                    'scopes': prof.scope_keys(addrs), 'description': o.description, '_obj': o})
    return out


def compare_objects_reverse(A, B, prof):
    scope = prof.scope_set()
    a_vals = {o.addrs for o in A.objects.values() if o.kind not in ('group', 'fqdn')}
    out = []
    for o in B.objects.values():
        if o.kind in ('fqdn', 'group') or o.name.startswith('FMC_INLINE_') or not o.addrs.overlaps(scope) or o.addrs.is_any():
            continue
        if o.name in A.objects or o.addrs in a_vals:
            continue
        out.append({'id': 'BO-' + o.name, 'name': o.name, 'kind': o.kind, 'value': o.value, 'status': 'B only',
                    'scope': prof.scope_label(o.addrs), 'scopes': prof.scope_keys(o.addrs), 'description': o.description})
    return out


def _group_addrs(cfg, o, seen=None, raw=False):
    """expanded addresses of a group; raw = before site translation"""
    seen = seen or set()
    s = IPSet()
    for m in (getattr(o, 'raw_members', o.members) if raw else o.members):
        if m.startswith('obj:'):
            x = cfg.objects.get(m[4:])
            if x is None or x.name in seen:
                continue
            s = s | (raw_addrs(cfg, x, seen | {o.name}) if raw else
                     x.addrs if x.kind != 'group' else _group_addrs(cfg, x, seen | {o.name}))
        else:
            s = s | IPSet.parse(m)
    return s


def raw_addrs(cfg, o, seen=None):
    """an object's expanded value as configured, before site translation"""
    if o.kind == 'group':
        return _group_addrs(cfg, o, seen, raw=True)
    return getattr(o, 'raw_addrs', o.addrs)


SECTIONS = ('rules', 'nat', 'pat', 'pat_detail', 'public', 'inbound', 'dns', 'routing', 'objects',
            'b_rules', 'b_nat', 'b_objects', 'held_rules', 'firewide')


def compare(A, B, prof, parts=('rules', 'nat', 'objects', 'routing', 'reverse')):
    if prof.type == 'auto':
        prof.type = 'standard'
    res = {'a': A.summary(), 'b': B.summary(), 'profile': prof.name, 'scope': prof.scope,
           'scope_names': {p: prof.scope_names.get(p, p) for p in prof.scope}}
    for k in SECTIONS:
        res[k] = []
    if 'rules' in parts:
        res['rules'] = compare_rules(A, B, prof)
    if 'nat' in parts:
        res['nat'], res['pat'], res['inbound'], res['dns'], res['pat_detail'], res['public'] = compare_nat(A, B, prof)
    if 'objects' in parts:
        res['objects'] = compare_objects(A, B, prof)
    if 'routing' in parts:
        res['routing'] = compare_routing(A, B, prof)
    if 'reverse' in parts:
        res['b_rules'] = compare_rules_reverse(A, B, prof)
        res['b_nat'] = compare_nat_reverse(A, B, prof)
        res['b_objects'] = compare_objects_reverse(A, B, prof)
    if 'rules' in parts:
        res['firewide'] = compare_firewide(A, B, prof)
    res['counts'] = counts(res)
    res['counts']['l7_actions'] = l7_counts(res)
    res['summary'] = summary(res, prof)
    return res


def l7_counts(res):
    d = {}
    for r in res.get('rules', []):
        k = r.get('action_check')
        if k and not r.get('row_state'):
            d[k] = d.get(k, 0) + 1
    return d


COUNTED = ('rules', 'nat', 'pat', 'inbound', 'routing', 'objects', 'b_rules', 'b_nat', 'b_objects', 'held_rules')


def _key(k, r):
    return r['status'] if k != 'pat' else '%s %s' % (r['side'], r['status'].split()[0])


def counts(res):
    c = {}
    for k in COUNTED:
        d = {}
        for r in res.get(k, []):
            if r.get('row_state'):
                continue
            d[_key(k, r)] = d.get(_key(k, r), 0) + 1
        c[k] = d
    return c


def summary(res, prof):
    """counts per category per scope subnet; rules that reach a subnet only through any / a /8+ range are counted
    separately (<category>_any)"""
    rows = {p: {'subnet': p, 'scope': prof.scope_names.get(p, p)} for p in prof.scope}
    for k in COUNTED:
        for r in res.get(k, []):
            if r.get('row_state'):
                continue
            for field, kk in (('scopes', k), ('scopes_any', k + '_any')):
                for p in r.get(field, []):
                    if p in rows:
                        d = rows[p].setdefault(kk, {})
                        d[_key(k, r)] = d.get(_key(k, r), 0) + 1
    return list(rows.values())
