"""2:1 mode: combine an edge firewall (A1) and an inner firewall (A2) into one virtual firewall A*.

Path from routing: an address A2 routes to one of its inside interfaces, and that A1 routes to one of its
inside interfaces, sits behind both (chained). Address regions:
  I  chained A2-inside        J  A2-inside that A1 does not route inside (A2 only)
  R  A1-inside (campus etc.)  N  everything else (internet, beyond A1's outside)
Flows I<->N cross both firewalls: the effective policy is the intersection (A2 first-match permits, each
walked through A1 first-match). Flows touching J, or I<->R / I<->I, cross only A2. All other flows cross only A1.
NAT and objects come from both; interface names are qualified A1:<nameif> / A2:<nameif>. A2's outside
(its default route) is the same segment as A1's interface toward A2 and gets A1's name."""
import dataclasses

from .detect import roles, route_split, route_table, ifc_subnets, main_ifc
from .model import Config, Interface, Rule, Nat, Route
from .netset import IPSet, Service, is_public
from .compare import effective_rules, PERMIT


def clone(obj, **changes):
    """dataclasses.replace that keeps extra attributes (line numbers, overrides)"""
    new = dataclasses.replace(obj, **changes)
    names = {f.name for f in dataclasses.fields(obj)}
    new.__dict__.update({k: v for k, v in obj.__dict__.items() if k not in names})
    return new


def _public_nats(cfg):
    return sum(1 for n in cfg.nats if n.mapped is not None and not n.mapped.is_any() and is_public(n.mapped)
               and n.real_ifc != n.mapped_ifc)


def order_edge(A1, A2):
    """returns (edge, inner, note): the firewall doing more public NAT is the edge"""
    if _public_nats(A2) > _public_nats(A1):
        return A2, A1, 'swapped: %s does the public NAT, so it is the edge (A1)' % A2.name
    return A1, A2, ''


def inside_set(cfg, rl):
    s = IPSet()
    for ifc, (role, why) in rl.items():
        if role == 'inside':
            for cidr, kind in ifc_subnets(cfg, ifc):
                s = s | IPSet.parse(cidr)
    return s


def _q(tag, ifc):
    return None if ifc is None else ('%s:%s' % (tag, ifc) if ifc not in ('any', '') else ifc)


def geometry(cfg, rules):
    """rule -> (src, dst) restricted to the addresses that really use the rule's interfaces (by routing)"""
    out = []
    for r in rules:
        s, d = r.src, r.dst
        if r.src_ifc:
            s = _via(cfg, s, r.src_ifc)
        if r.dst_ifc:
            d = _via(cfg, d, r.dst_ifc)
        out.append((r, s, d))
    return out


def _via(cfg, ipset, ifc):
    out = IPSet()
    for i, s in route_split(cfg, ipset):
        if i == ifc:
            out = out | s
    return out


def walk(geo, S, D, svc, only=None):
    """first-match walk: permitted cubes [(src, dst, svc, rule)] of the traffic S x D x svc.
    A rule that matches only some of the services removes nothing (conservative)."""
    cubes = [(S, D)]
    out = []
    for r, rs, rd in geo:
        if not cubes:
            break
        if not svc.overlaps(r.svc):
            continue
        hit = [(s & rs, d & rd) for s, d in cubes if s.overlaps(rs) and d.overlaps(rd)]
        if not hit:
            continue
        full = svc.covered_by(r.svc)
        if r.action in PERMIT and (only is None or r is only):
            sv = svc if full else (svc & r.svc)
            out += [(s, d, sv, r) for s, d in hit]
        if only is not None and r is only:
            break
        if full:
            new = []
            for s, d in cubes:
                if not (s.overlaps(rs) and d.overlaps(rd)):
                    new.append((s, d))
                    continue
                if s - rs:
                    new.append((s - rs, d))
                if d - rd:
                    new.append((s & rs, d - rd))
            cubes = new
    return out


def _name(tag, r):
    return '%s:%s' % (tag, r.rule_name or r.rule_id or '#%d' % r.seq)


def build(A1, A2, a1_tag='A1', a2_tag='A2', link=None, uplink=None):
    """returns (A*, info). A1 must be the edge (see order_edge)."""
    r1, r2 = roles(A1), roles(A2)
    I2 = inside_set(A2, r2)
    R1all = inside_set(A1, r1)
    chained = IPSet()
    a1_toward = {}
    for ifc, s in route_split(A1, I2):
        if ifc and r1.get(ifc, ('',))[0] == 'inside':
            chained = chained | s
            a1_toward[ifc] = a1_toward.get(ifc, 0) + s.size()
    link1 = max(a1_toward, key=a1_toward.get) if a1_toward else ''
    if link and link in A1.interfaces:
        link1 = link
    J = I2 - chained
    I = chained
    R = R1all - I2
    X = getattr(A1, '_ignored_set', IPSet()) | getattr(A2, '_ignored_set', IPSet())
    R = R - X
    N = IPSet.any() - I2 - R - X
    a2_out = [n for n, (r, w) in r2.items() if r == 'outside']
    a2_default = [rt['ifc'] for rt in route_table(A2) if rt['plen'] == 0]
    a2_up = (a2_default or a2_out or [''])[0]
    if uplink and uplink in A2.interfaces:
        a2_up = uplink

    def q2(ifc):
        if ifc is None:
            return None
        if ifc == a2_up and link1:
            return _q(a1_tag, link1)
        return _q(a2_tag, ifc)

    def q1(ifc):
        return _q(a1_tag, ifc)

    star = Config(name='%s + %s' % (A1.name, A2.name), vendor=A1.vendor, hostname='%s + %s' % (A1.hostname, A2.hostname))
    for n, i in A1.interfaces.items():
        star.interfaces[q1(n)] = clone(i, nameif=q1(n))
    for n, i in A2.interfaces.items():
        if n == a2_up and link1:
            continue
        star.interfaces[q2(n)] = clone(i, nameif=q2(n))
    star.ignored = {q1(n) for n in A1.ignored} | {q2(n) for n in A2.ignored}
    for rt in A1.routes:
        star.routes.append(clone(rt, ifc=q1(rt.ifc)))
    for rt in A2.routes:
        if rt.ifc != a2_up:
            star.routes.append(clone(rt, ifc=q2(rt.ifc)))

    def rfn(ipset):
        out = {}
        for ifc, s in route_split(A2, ipset & I2):
            out[q2(ifc) if ifc else ''] = out.get(q2(ifc) if ifc else '', IPSet()) | s
        for ifc, s in route_split(A1, ipset - I2):
            out[q1(ifc) if ifc else ''] = out.get(q1(ifc) if ifc else '', IPSet()) | s
        return list(out.items())
    star.route_fn = rfn

    for cfg, tag in ((A1, a1_tag), (A2, a2_tag)):
        for k, o in cfg.objects.items():
            if k in star.objects and star.objects[k].addrs != o.addrs:
                star.warnings.append('object %s differs between %s and %s; %s value kept' % (k, a1_tag, a2_tag, a1_tag))
                continue
            star.objects.setdefault(k, o)
        for k, o in cfg.services.items():
            star.services.setdefault(k, o)
    star.dynamic_routing = ['%s %s' % (a1_tag, x) for x in A1.dynamic_routing] + ['%s %s' % (a2_tag, x) for x in A2.dynamic_routing]
    star.warnings = ['%s: %s' % (a1_tag, w) for w in A1.warnings] + ['%s: %s' % (a2_tag, w) for w in A2.warnings] + star.warnings
    seq = [0]
    for cfg, tag, q in ((A1, a1_tag, q1), (A2, a2_tag, q2)):
        for n in cfg.nats:
            seq[0] += 1
            star.nats.append(clone(n, seq=seq[0], real_ifc=q(n.real_ifc) if n.real_ifc != 'any' else 'any',
                                   mapped_ifc=q(n.mapped_ifc) if n.mapped_ifc != 'any' else 'any'))
            star.nats[-1].device = tag
    star.nats.sort(key=lambda n: ({'manual-before': 0, 'auto': 1, 'manual-after': 2}[n.section], n.seq))

    # ---- rules
    e1, e2 = effective_rules(A1), effective_rules(A2)
    out = []

    def add(r, tag, q, s, d, svc=None, name=None, src_ifc=None, dst_ifc=None, path=''):
        out.append(Rule(seq=len(out) + 1, acl='FWSYNC_COMBINED', action=r.action,
                        src_ifc=src_ifc if src_ifc is not None else q(r.src_ifc),
                        dst_ifc=dst_ifc if dst_ifc is not None else q(r.dst_ifc),
                        src=s, dst=d, svc=svc if svc is not None else r.svc,
                        src_ref=_ref(r.src, r.src_ref, s, N), dst_ref=_ref(r.dst, r.dst_ref, d, N),
                        svc_ref=r.svc_ref if svc is None else repr(svc), rule_id=r.rule_id,
                        policy='%s %s' % (tag, r.policy) if r.policy else tag, rule_name=name or _name(tag, r),
                        line=r.line if not name else '%s | %s' % (r.line, path)))
        out[-1].path = path or tag
        out[-1].origin = '%s#%d' % (tag, r.seq)
        out[-1].evidence = [(tag, getattr(r, 'lineno', 0), r.line)]
        out[-1].wide = r.dst.is_any() or getattr(r, 'wide', False)
        out[-1].l7 = getattr(r, 'l7', False)
        out[-1].override = getattr(r, 'override', '')
        out[-1].via = [] if not name else [name.split(' ∩ ', 1)[1]]

    A2_pairs = [(I, R), (R, I), (I, I), (J, IPSet.any()), (IPSet.any() - J, J)]
    A1_pairs = [(R, N), (N, R), (R, R), (N, N)]
    g1, g2 = geometry(A1, e1), geometry(A2, e2)
    for geo, pairs, tag, q in ((g2, A2_pairs, a2_tag, q2), (g1, A1_pairs, a1_tag, q1)):
        for r, rs, rd in geo:
            if _is_default(r):
                continue
            for S, D in pairs:
                s, d = rs & S, rd & D
                if s and d:
                    add(r, tag, q, s, d)
    nchain = 0
    for r in e2:
        if r.action not in PERMIT:
            continue
        for S, D in ((N, I), (I, N)):
            s, d = r.src & S, r.dst & D
            if not (s and d):
                continue
            for s2, d2, sv2, _ in walk(g2, s, d, r.svc, only=r):
                for s1, d1, sv1, r1x in walk(g1, s2, d2, sv2):
                    for si, ss in rfn(s1):
                        for di, dd in rfn(d1):
                            nchain += 1
                            add(r, a2_tag, q2, ss, dd, svc=sv1, name='%s ∩ %s' % (_name(a2_tag, r), _name(a1_tag, r1x)),
                                src_ifc=si or 'any', dst_ifc=di or 'any', path='%s∩%s' % (a2_tag, a1_tag))
                            out[-1].evidence = [(a2_tag, getattr(r, 'lineno', 0), r.line),
                                                (a1_tag, getattr(r1x, 'lineno', 0), r1x.line)]
                            parts = [x for x in (r, r1x) if getattr(x, 'l7', False)]
                            out[-1].l7 = bool(parts)
                            out[-1].override = 'permit' if parts and all(getattr(x, 'override', '') == 'permit'
                                                                         for x in parts) else ''
    dflt = Rule(seq=len(out) + 1, acl='FWSYNC_COMBINED', action='deny', src_ifc=None, dst_ifc=None, src=IPSet.any(),
                dst=IPSet.any(), svc=Service.any(), src_ref='any', dst_ref='any', svc_ref='ip', rule_name='default deny')
    dflt.path = 'both'
    dflt.origin, dflt.via = 'default', []
    out.append(dflt)
    star.rules = out
    star.access_groups = {'FWSYNC_COMBINED': 'global'}

    def first(x):
        return repr(x) if x else '-'
    paths = []
    for ifc, s in route_split(A2, I2):
        a1i = main_ifc(A1, s)
        ch = s & I
        paths.append({'subnets': repr(s), 'a2_ifc': ifc, 'a1_ifc': a1i, 'chained': repr(ch) if ch else '',
                      'path': ('internet -> %s:%s (outside) -> %s:%s -> %s:%s -> %s:%s' % (
                          a1_tag, main_ifc(A1, IPSet.host('8.8.8.8')), a1_tag, a1i, a2_tag, a2_up, a2_tag, ifc)) if ch else
                      '%s only (%s routes it via %s)' % (a2_tag, a1_tag, a1i or 'nothing')})
    info = {'edge': A1.name, 'inner': A2.name, 'a1_toward_a2': link1, 'a2_uplink': a2_up,
            'regions': {'I chained (both)': first(I), 'J A2 only': first(J), 'R A1 inside (campus)': first(R),
                        'N outside (internet)': first(N)},
            'paths': paths, 'chain_rules': nchain, 'rules': len(out)}
    return star, info


def _ref(orig, ref, now, N):
    """keep the configured name when the set is unchanged; 'any' when an 'any' was cut down to the outside region"""
    if now == orig:
        return ref
    if orig.is_any() and now == N:
        return 'any'
    return repr(now)


def _is_default(r):
    return r.action not in PERMIT and r.src.is_any() and r.dst.is_any() and r.svc.is_any() and r.src_ifc is None \
        and r.dst_ifc is None
