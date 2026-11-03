"""Auto-detect what a compare needs from the configs alone: interface roles, routed subnets, interface map,
public ranges, site type and scope. The result is a Profile plus a plain dict for the UI / report."""
import ipaddress
import re

from .netset import IPSet, PRIVATE, is_public
from .profile import Profile

MGMT = re.compile(r'^(diagnostic|management|mgmt)', re.I)
DEFAULT = IPSet.net('0.0.0.0/0')


def usable_ifcs(cfg):
    return {n: i for n, i in cfg.interfaces.items()
            if (i.ip or i.planned) and not i.management_only and not MGMT.match(n)}


def _net(addr, mask):
    return ipaddress.IPv4Network('%s/%s' % (addr, mask), strict=False)


def route_table(cfg):
    """connected + static routes, longest prefix first (connected wins a tie, then lower distance)"""
    rt = getattr(cfg, '_rt', None)
    if rt is not None:
        return rt
    u = usable_ifcs(cfg)
    rt = []
    for n, i in u.items():
        if not i.ip:
            continue
        net = _net(i.ip, i.mask)
        rt.append({'net': str(net), 'set': IPSet.net(str(net)), 'plen': net.prefixlen, 'ifc': n, 'nexthop': '',
                   'kind': 'connected', 'distance': 0})
    for r in cfg.routes:
        if r.ifc not in u:
            continue
        try:
            net = _net(r.network, r.mask)
        except ValueError:
            continue
        rt.append({'net': str(net), 'set': IPSet.net(str(net)), 'plen': net.prefixlen, 'ifc': r.ifc, 'nexthop': r.nexthop,
                   'kind': 'static' + (' tracked' if r.track else ''), 'distance': r.distance,
                   'lineno': getattr(r, 'lineno', 0), 'text': getattr(r, 'text', '')})
    rt.sort(key=lambda x: (-x['plen'], x['distance']))
    cfg._rt = rt
    return rt


def route_split(cfg, ipset):
    """longest-prefix-match partition of ipset: [(ifc, subset)]; unrouted addresses get ifc ''"""
    if cfg.route_fn is not None:
        return cfg.route_fn(ipset)
    out, rest = {}, ipset
    for r in route_table(cfg):
        if not rest:
            break
        part = rest & r['set']
        if part:
            out[r['ifc']] = out.get(r['ifc'], IPSet()) | part
            rest = rest - part
    if rest:
        out[''] = rest
    return list(out.items())


def routed_via(cfg, ipset, ifc):
    """the part of ipset that cfg routes out of ifc"""
    for i, s in route_split(cfg, ipset):
        if i == ifc:
            return s
    return IPSet()


def main_ifc(cfg, ipset):
    """the interface that routes most of ipset"""
    parts = route_split(cfg, ipset)
    return max(parts, key=lambda x: x[1].size())[0] if parts else ''


def roles(cfg):
    """{nameif: (role, reason)}: outside = holds the default route or the public mapped side of a NAT"""
    u = {n: i for n, i in usable_ifcs(cfg).items() if n not in cfg.ignored}
    out = {}
    for r in cfg.routes:
        if r.network == '0.0.0.0' and r.mask == '0.0.0.0' and r.ifc in u:
            out.setdefault(r.ifc, ('outside', 'default route'))
    for n in cfg.nats:
        if n.mapped_ifc in u and n.real_ifc != n.mapped_ifc and n.mapped is not None and not n.mapped.is_any() \
                and is_public(n.mapped) and n.mapped_ifc not in out and n.real_ifc != 'any':
            out[n.mapped_ifc] = ('outside', 'public NAT mapped addresses')
    for n in u:
        out.setdefault(n, ('inside', 'no default route, no public NAT'))
    return out


def ifc_subnets(cfg, ifc):
    """[(cidr, kind)] connected and statically routed via ifc, default route excluded"""
    return [(r['net'], r['kind']) for r in route_table(cfg) if r['ifc'] == ifc and r['plen'] > 0]


def _name_index(cfg):
    idx = {}
    for o in cfg.objects.values():
        if o.kind in ('host', 'subnet', 'range') and o.addrs and not o.name.startswith('FMC_INLINE_'):
            idx.setdefault(o.addrs, []).append(o.name)
    return idx


def friendly(cfg, cidr, ifc, kind, idx):
    parts = []
    i = cfg.interfaces.get(ifc)
    if kind == 'connected' and i is not None:
        if i.vlan:
            parts.append('VLAN %d' % i.vlan)
        parts.append(ifc)
    names = idx.get(IPSet.parse(cidr), [])
    if names:
        parts.append(sorted(names, key=len)[0])
    elif kind != 'connected':
        parts.append('via ' + ifc)
    return ' '.join(parts)


def scope_candidates(cfg, rl):
    """every inside subnet (connected + routed), with friendly names"""
    idx = _name_index(cfg)
    out, seen = [], set()
    for ifc, (role, why) in rl.items():
        if role != 'inside':
            continue
        for cidr, kind in ifc_subnets(cfg, ifc):
            if cidr in seen:
                continue
            seen.add(cidr)
            out.append({'subnet': cidr, 'ifc': ifc, 'kind': kind, 'name': friendly(cfg, cidr, ifc, kind, idx)})
    return out


def _cover(lo, hi):
    for plen in range(32, -1, -1):
        n = ipaddress.IPv4Network((lo, plen), strict=False)
        if int(n.broadcast_address) >= hi:
            return n
    return ipaddress.IPv4Network('0.0.0.0/0')


def public_ranges(cfg, outs):
    """outside interface subnets + public NAT mapped addresses; mapped addresses are summarised per /24
    to the smallest covering prefix (an assumption: the real allocation may be larger)"""
    ifs = IPSet()
    for o in outs:
        i = cfg.interfaces.get(o)
        if i and i.ip and is_public(IPSet.net(i.ip, i.mask)):
            ifs = ifs | IPSet.net(i.ip, i.mask)
    mapped = IPSet()
    for n in cfg.nats:
        if n.mapped_ifc in outs and n.mapped is not None and not n.mapped.is_any() and n.real_ifc != n.mapped_ifc \
                and n.mapped != n.real:
            mapped = mapped | (n.mapped - PRIVATE)
    ranges = ifs
    blocks = {}
    for a, b in mapped.iv:
        for x in (a, b):
            blocks.setdefault(x >> 8, []).append(x)
    for k, xs in blocks.items():
        part = mapped & IPSet([(k << 8, (k << 8) + 255)])
        if part:
            lo, hi = part.iv[0][0], part.iv[-1][1]
            ranges = ranges | IPSet.net(str(_cover(lo, hi)))
    return {'interfaces': ifs.cidrs(), 'mapped': mapped.cidrs(), 'mapped_count': mapped.size(), 'ranges': ranges.cidrs()}


def _match_b(a, a_cfg, b_cfg, cands, ra):
    if len(cands) == 1:
        return cands[0], 'role', ''
    if not cands:
        return '', 'none', 'B has no %s interface' % ra
    low = {c.lower(): c for c in cands}
    if a.lower() in low:
        return low[a.lower()], 'role + name', ''
    sl = a_cfg.interfaces[a].security_level
    same = [c for c in cands if b_cfg.interfaces[c].security_level == sl]
    levels = {b_cfg.interfaces[c].security_level for c in cands}
    if len(same) == 1 and len(levels) > 1:
        return same[0], 'role + security level', ''
    subs = IPSet()
    for cidr, kind in ifc_subnets(a_cfg, a):
        subs = subs | IPSet.parse(cidr)
    if subs:
        votes = {}
        for i, s in route_split(b_cfg, subs):
            if i in cands:
                votes[i] = votes.get(i, 0) + s.size()
        if votes:
            return max(votes, key=votes.get), 'role + B routing', ''
    return cands[0], 'guess', 'ambiguous: %d B %s interfaces, no name/level/routing match' % (len(cands), ra)


def map_interfaces(A, B, ra, rb):
    rows = []
    for a, (role, why) in ra.items():
        cands = [n for n, (r, w) in rb.items() if r == role]
        b, how, flag = _match_b(a, A, B, cands, role)
        rows.append({'a': a, 'a_role': role, 'a_reason': why, 'b': b, 'b_role': rb.get(b, ('', ''))[0], 'how': how,
                     'flag': flag, 'note': ''})
    per_b = {}
    for r in rows:
        per_b.setdefault(r['b'], []).append(r['a'])
    for r in rows:
        if r['b'] and len(per_b[r['b']]) > 1:
            r['note'] = 'merged: %s all map to %s' % (', '.join(per_b[r['b']]), r['b'])
    return rows


VPN_NAME = re.compile(r'(?i)vpn|tunnel|ipsec|\bgre\b|vti|dmvpn|s2s|anyconnect')


def ignore_hint(cfg, ifc):
    """(apply, why): VPN / tunnel names are ignored by default; a small transfer subnet with only a few specific
    routes behind it is only hinted (real transfer links look the same)"""
    base = ifc.split(':', 1)[-1]
    if VPN_NAME.search(base):
        return True, 'name looks like a VPN / tunnel interface (%s)' % base
    i = cfg.interfaces.get(ifc)
    if i is None or not i.ip:
        return False, ''
    plen = _net(i.ip, i.mask).prefixlen
    routed = [r for r in route_table(cfg) if r['ifc'] == ifc and r['kind'] != 'connected' and r['plen'] > 0]
    if plen >= 29 and len(routed) <= 2 and all(r['plen'] >= 24 for r in routed):
        why = '/%d transfer subnet' % plen + (' with %d specific route(s) behind it' % len(routed) if routed else
                                               ' with nothing routed behind it')
        return False, why + ': ignore if it is a VPN / tunnel'
    return False, ''


def detect(A, B, prof=None):
    """fill every profile field that is empty from the configs; returns (Profile, info)"""
    prof = prof or Profile()
    for n in list(A.interfaces):
        if n in A.ignored or n not in usable_ifcs(A):
            continue
        apply, why = ignore_hint(A, n)
        if apply and n not in prof.interface_map and n not in (prof.roles_a or {}):
            from . import ignore as _ign
            _ign.apply(A, {n})
            A.suggested = getattr(A, 'suggested', {})
            A.suggested[n] = why
    ra, rb = roles(A), roles(B)
    for k, v in (prof.roles_a or {}).items():
        if k in ra and v in ('outside', 'inside'):
            ra[k] = (v, 'set in profile')
    imap = map_interfaces(A, B, ra, rb)
    outs_a = prof.outside_a or [n for n, (r, w) in ra.items() if r == 'outside']
    outs_b = prof.outside_b or [n for n, (r, w) in rb.items() if r == 'outside']
    pa, pb = public_ranges(A, outs_a), public_ranges(B, outs_b)
    site = 'shared-edge' if IPSet.parse(','.join(pa['ranges'])).overlaps(IPSet.parse(','.join(pb['ranges']))) else 'standard'
    cands = scope_candidates(A, ra)
    auto = {r['a']: r['b'] for r in imap if r['b']}
    auto.update(prof.interface_map)
    prof.interface_map = auto
    for r in imap:
        if r['a'] in prof.interface_map and prof.interface_map[r['a']] != r['b']:
            r['b'], r['how'], r['flag'] = prof.interface_map[r['a']], 'profile', ''
    sugg = getattr(A, 'suggested', {})
    for n in sorted(A.ignored):
        imap.append({'a': n, 'a_role': 'ignored', 'a_reason': sugg.get(n, 'mapped to ignore'), 'b': 'ignore', 'b_role': '',
                     'how': 'suggested (override in the profile)' if n in sugg else 'profile', 'flag': '',
                     'note': 'rules and NAT on this interface dropped', 'suggest': 'ignore' if n in sugg else ''})
    for r in imap:
        if r.get('a_role') != 'ignored':
            apply, why = ignore_hint(A, r['a'])
            if why:
                r['suggest'], r['suggest_why'] = 'ignore?', why
    prof.outside_a, prof.outside_b = outs_a, outs_b
    if not prof.public_b:
        prof.public_b = pb['ranges']
    if not prof.public_a:
        prof.public_a = pa['ranges']
    if not prof.type or prof.type == 'auto':
        prof.type = site
    if not prof.scope:
        prof.scope = [c['subnet'] for c in cands]
    for c in cands:
        prof.scope_names.setdefault(c['subnet'], c['name'])
    info = {'roles_a': {k: list(v) for k, v in ra.items()}, 'roles_b': {k: list(v) for k, v in rb.items()},
            'interface_map': imap, 'public_a': pa, 'public_b': pb, 'site_type': site, 'scope_candidates': cands,
            'dynamic_routing_b': B.dynamic_routing, 'dynamic_routing_a': A.dynamic_routing}
    return prof, info
