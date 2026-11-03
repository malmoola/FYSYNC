"""Compare engine: A vs B by value (address/port sets), first-match rule semantics on B.
Both directions in one run: A -> B (what B is missing) and B -> A (what B has or allows beyond A)."""
import ipaddress
from . import natorder
from .netset import IPSet, Service

PERMIT = ('permit', 'trust', 'allow', 'fastpath')
L7 = 'L7 rule: LINA shows permit, Snort applies the real action (check FMC)'
ORDER = ['covered', 'partial', 'shadowed', 'denied', 'missing']


def effective_rules(cfg):
    """Rules that are applied: ACLs bound by access-group (interface ACLs get their ingress nameif),
    or CSM_FW_ACL_ when there is no access-group line."""
    out = []
    groups = cfg.access_groups or {'CSM_FW_ACL_': 'global'}
    for r in cfg.rules:
        if r.inactive or r.acl not in groups or r.action in ('unknown', 'l7block', 'ignore'):
            continue
        g = groups[r.acl].split()
        if g and g[0] == 'in' and len(g) >= 3 and r.src_ifc is None:
            r.src_ifc = g[2]
        out.append(r)
    return out


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


def _sub(cubes, S, D):
    out = []
    for s, d in cubes:
        if not (s.overlaps(S) and d.overlaps(D)):
            out.append((s, d))
            continue
        a = s - S
        if a:
            out.append((a, d))
        b = d - D
        if b:
            out.append((s & S, b))
    return out


def eval_slice(b_rules, src_ifc, dst_ifc, src, dst, svc):
    """First-match walk of B for traffic (src_ifc,dst_ifc,src,dst,svc). src_ifc/dst_ifc False = ignore interfaces.
    Returns (status, matched B rules, detail)."""
    cubes = [(src, dst)]
    permits, denies = [], []
    for r in b_rules:
        m1, f1 = _ifc_ok(r.src_ifc, src_ifc)
        m2, f2 = _ifc_ok(r.dst_ifc, dst_ifc)
        if not (m1 and m2):
            continue
        if not any(s.overlaps(r.src) and d.overlaps(r.dst) for s, d in cubes):
            continue
        if not svc.overlaps(r.svc):
            continue
        full_svc = svc.covered_by(r.svc)
        if _is_default(r):
            break                                   # default action: what is left is simply not permitted
        if r.action in PERMIT:
            permits.append(r)
            if full_svc and f1 and f2:
                cubes = _sub(cubes, r.src, r.dst)
        else:
            denies.append(r)
            if full_svc:
                cubes = _sub(cubes, r.src, r.dst)
        if not cubes:
            break
    remaining = sum(s.size() * d.size() for s, d in cubes)
    if not permits:
        return ('denied' if denies else 'missing'), denies, 'no B permit'
    first_deny_before = denies and permits and denies[0].seq < permits[0].seq
    if remaining == 0 and not denies:
        return 'covered', permits, ''
    if first_deny_before:
        return 'shadowed', denies[:1] + permits, 'earlier B deny %s' % (denies[0].rule_name or denies[0].seq)
    return 'partial', permits + denies, 'not all traffic or services permitted'


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


def compare_rules(A, B, prof):
    scope = prof.scope_set()
    b_rules = effective_rules(B)
    out = []
    for r in effective_rules(A):
        if r.action not in PERMIT:
            continue
        slices = _slices(r, scope)
        if not slices:
            continue
        si, di = prof.map_ifc(r.src_ifc), prof.map_ifc(r.dst_ifc)
        results = []
        for label, s, d in slices:
            st, matched, det = eval_slice(b_rules, si, di, s, d, r.svc)
            results.append((label, st, matched, det))
        worst = max(results, key=lambda x: ORDER.index(x[1]))
        out.append({
            'id': 'R%d' % r.seq, 'path': getattr(r, 'path', ''), 'policy': r.policy, 'rule': r.rule_name, 'rule_id': r.rule_id,
            'action': r.action, 'src_ifc': r.src_ifc or 'any', 'dst_ifc': r.dst_ifc or 'any',
            'b_src_ifc': si or 'any', 'b_dst_ifc': di or 'any',
            'src': r.src_ref, 'dst': r.dst_ref, 'service': r.svc_ref, 'svc': repr(r.svc),
            'scope': prof.scope_label(r.src | r.dst), 'scopes': scope_split(prof, r.src, r.dst)[0],
            'scopes_any': scope_split(prof, r.src, r.dst)[1],
            'direction': ' + '.join(x[0] for x in results), 'status': worst[1],
            'detail': worst[3], 'l7': getattr(r, 'l7', False), 'action_check': _action_check(r),
            'b_rules': sorted({'%s %s' % (m.rule_name or m.rule_id or '', '#%d' % m.seq) for x in results for m in x[2]})[:8],
            'line': r.line, '_rule': r, '_b': [m for x in results for m in x[2]][:8],
        })
    return _merge_origin(out, prof.scope_names)


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
    """B -> A: every B permit in scope, checked against A by address and service (interfaces ignored)"""
    scope = prof.scope_set()
    a_rules = effective_rules(A)
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
            cubes += _crossing(A, s, d)
        if not cubes:
            continue
        results = [eval_slice(a_rules, False, False, s, d, r.svc) for s, d in cubes]
        worst = max(results, key=lambda x: ORDER.index(x[0]))
        out.append({'id': 'BR%d' % r.seq, 'policy': r.policy, 'rule': r.rule_name, 'rule_id': r.rule_id,
                    'src_ifc': r.src_ifc or 'any', 'dst_ifc': r.dst_ifc or 'any', 'src': r.src_ref, 'dst': r.dst_ref,
                    'service': r.svc_ref, 'scope': prof.scope_label(r.src | r.dst), 'scopes': scope_split(prof, r.src, r.dst)[0],
                    'scopes_any': scope_split(prof, r.src, r.dst)[1], 'status': names[worst[0]],
                    'a_rules': sorted({'%s #%d' % (m.rule_name or m.rule_id or '', m.seq) for x in results for m in x[1]})[:8],
                    'line': r.line, '_rule': r})
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
            cands = [m for m in B.nats if nat_kind(m) == 'static' and m.real == n.real]
            active = [m for m in cands if not m.inactive]
            a_pub = _first_host(n.mapped)
            b_pub = ''
            if active:
                m = active[0]
                b_pub = _first_host(m.mapped)
                status, notes = 'match', []
                if shared and m.mapped != n.mapped:
                    status, notes = 'mapped conflict', ['shared public subnet: B must use the same public IP as A']
                elif not shared:
                    if m.mapped is not None and pub_b and not m.mapped.issubset(pub_b):
                        status = 'mapped outside B public'
                    if m.mapped == n.mapped and n.mapped is not None:
                        status = 'mapped reuse'
                        notes.append('B uses the same public IP as A')
                if b_pub and len(b_mapped_use.get(b_pub, [])) > 1:
                    status = 'mapped conflict'
                    notes.append('%d B NATs map to %s' % (len(b_mapped_use[b_pub]), b_pub))
                row.update(status=status, b_nat='#%d %s' % (m.seq, m.real_ref), b_mapped=b_pub, detail='; '.join(notes), _b_nat=m)
            elif cands:
                m = cands[0]
                row.update(status='inactive on B', b_nat='#%d %s' % (m.seq, m.real_ref), b_mapped=_first_host(m.mapped),
                           detail='B has the NAT but it is inactive', _b_nat=m)
            else:
                detail = 'no B static NAT for %s' % repr(n.real)
                if shared:
                    b_pub = a_pub
                    other = [m for m in b_mapped_use.get(a_pub, []) if m.real != n.real]
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
                    b_in = []
                    st_rule = 'missing'
                    for o in outs_b:
                        st, matched, det = eval_slice(b_rules, o, prof.map_ifc(n.real_ifc), IPSet.any(), n.real, svc)
                        if st in ('covered', 'partial'):
                            st_rule, b_in = st, matched
                            break
                    nat_ok = row['status'] in ('match', 'mapped reuse', 'mapped outside B public')
                    ready = 'ready' if nat_ok and st_rule == 'covered' else (
                        'nat %s, rule %s' % ('ok' if nat_ok else row['status'], st_rule))
                    ports = sorted({r.svc_ref for r in a_in})
                    bp = row.get('b_mapped') or row.get('proposed_b_mapped', '')
                    inbound.append({'id': 'I%d' % n.seq, 'object': n.real_ref, 'real': repr(n.real),
                                    'a_public': a_pub, 'b_public': bp, 'ports': ', '.join(ports),
                                    'a_rules': ', '.join(sorted({r.rule_name or r.rule_id for r in a_in})),
                                    'b_rules': ', '.join(sorted({r.rule_name or str(r.seq) for r in b_in})),
                                    'status': ready, 'scope': row['scope'], 'scopes': row['scopes'], 'nat_id': row['id'],
                                    '_nat': n, '_svc': svc, '_a_rules': a_in, '_b_rules': b_in, '_b_nat': row.get('_b_nat'),
                                    'nat_status': row['status'], 'rule_status': st_rule, 'description': n.description})
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
            so = natorder.out_ifc(cfg, outs)
            if side == 'A':
                si = a_si = natorder.src_ifc(cfg, s)
            else:
                si = prof.map_ifc(a_si) if a_si else None
                si = si if si in cfg.interfaces else None
            eff = natorder.effective(cfg, s, si, so)
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
        parts = route_split(B, s)
        desc, worst = [], 'ok'
        for ifc, sub in parts:
            role = rb.get(ifc, ('',))[0]
            if not ifc:
                st = 'no route on B'
            elif role != want_role:
                st = 'wrong way'
            elif ifc != want:
                st = 'other %s interface' % role
            else:
                st = 'ok'
            desc.append('%s via %s (%s)' % (repr(sub), ifc or 'nothing', st))
            rank = ['ok', 'other inside interface', 'other outside interface', 'wrong way', 'no route on B']
            if rank.index(st) > rank.index(worst):
                worst = st
        nh = [r for r in _routes_for(B, s)]
        out.append({'id': 'RT-%s' % p, 'scope': prof.scope_names.get(p, p), 'scopes': [p], 'subnet': p,
                    'a_ifc': a_ifc, 'a_role': want_role, 'expected_b_ifc': want, 'b_route': '; '.join(desc),
                    'b_next_hop': ', '.join(nh), 'status': worst,
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
            st = 'same' if bv == addrs else 'same name, different value'
            other = repr(bv) if st != 'same' else ''
        else:
            names = by_val.get(addrs, []) if o.kind != 'group' else []
            st = 'same value, different name' if names else 'missing on B'
            other = ', '.join(names[:5])
        out.append({'id': 'O-' + o.name, 'name': o.name, 'b_name': bname, 'kind': o.kind, 'value': o.value or repr(addrs),
                    'addrs': repr(addrs), 'status': st, 'b_value_or_names': other, 'scope': prof.scope_label(addrs),
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


def _group_addrs(cfg, o, seen=None):
    seen = seen or set()
    s = IPSet()
    for m in o.members:
        if m.startswith('obj:'):
            x = cfg.objects.get(m[4:])
            if x is None or x.name in seen:
                continue
            s = s | (x.addrs if x.kind != 'group' else _group_addrs(cfg, x, seen | {o.name}))
        else:
            s = s | IPSet.parse(m)
    return s


SECTIONS = ('rules', 'nat', 'pat', 'pat_detail', 'public', 'inbound', 'dns', 'routing', 'objects',
            'b_rules', 'b_nat', 'b_objects', 'held_rules')


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
