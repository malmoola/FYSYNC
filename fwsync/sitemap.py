"""Site translation. When a subnet is site-specific (A 10.1.1.0/24 is B 10.2.1.0/24 on the mapped interface), A is
rewritten into B's addresses before the compare, so a rule, NAT or object is judged by what it must be on B."""
import ipaddress
import re

from .netset import IPSet, is_public


def _net(i):
    return ipaddress.IPv4Network('%s/%s' % (i.ip, i.mask), strict=False)


def net_pairs(A, B, imap):
    """[(A cidr, B cidr)] for mapped private interfaces with different subnets of the same size"""
    out = []
    for a, b in (imap or {}).items():
        x, y = A.interfaces.get(a), B.interfaces.get(b)
        if x is None or y is None or not x.ip or not y.ip:
            continue
        n, m = _net(x), _net(y)
        if n != m and n.prefixlen == m.prefixlen and n.prefixlen <= 28 and not is_public(IPSet.net(str(n))) \
                and not is_public(IPSet.net(str(m))):
            out.append((str(n), str(m)))
    return out


def edge_pairs(A, B, imap, outs):
    """(A cidr, B cidr) of outside interfaces: used only to compare text such as gateways, never rules"""
    out = []
    for a in outs:
        x, y = A.interfaces.get(a), B.interfaces.get((imap or {}).get(a, a))
        if x is not None and y is not None and x.ip and y.ip and _net(x) != _net(y) and _net(x).prefixlen == _net(y).prefixlen:
            out.append((str(_net(x)), str(_net(y))))
    return out


def _ranges(pairs):
    r = []
    for a, b in pairs:
        x, y = ipaddress.IPv4Network(a), ipaddress.IPv4Network(b)
        r.append((int(x.network_address), int(x.broadcast_address), int(y.network_address) - int(x.network_address)))
    return r


def map_set(s, pairs):
    """translate the parts of s that lie inside an A prefix; anything wider (any, 10/8) stays as it is"""
    if s is None or not getattr(s, 'iv', None):
        return s
    r = _ranges(pairs)
    iv = []
    for lo, hi in s.iv:
        for a, b, d in r:
            if a <= lo and hi <= b:
                lo, hi = lo + d, hi + d
                break
        iv.append((lo, hi))
    return IPSet(iv)


def map_ip(text, pairs):
    try:
        a = int(ipaddress.IPv4Address(text))
    except ValueError:
        return text
    for x, y, d in _ranges(pairs):
        if x <= a <= y:
            return str(ipaddress.IPv4Address(a + d))
    return text


def map_prefix(p, pairs):
    for a, b in pairs:
        if p == a:
            return b
    return p


def translate(A, pairs):
    """rewrite A in place. Original text stays in the *_ref, line and value fields used as evidence."""
    if not pairs:
        return
    for r in A.rules:
        r.src, r.dst = map_set(r.src, pairs), map_set(r.dst, pairs)
    for n in A.nats:
        n.raw_real = n.real
        n.real, n.mapped = map_set(n.real, pairs), map_set(n.mapped, pairs)
        n.dst_real, n.dst_mapped = map_set(n.dst_real, pairs), map_set(n.dst_mapped, pairs)
    for o in A.objects.values():
        o.raw_addrs, o.raw_members = o.addrs, list(o.members)
        o.addrs = map_set(o.addrs, pairs)
        o.members = [m if m.startswith('obj:') else _member(m, pairs) for m in o.members]
    for i in A.interfaces.values():
        if i.ip:
            i.ip = map_ip(i.ip, pairs)
    for r in A.routes:
        r.network, r.nexthop = map_ip(r.network, pairs), map_ip(r.nexthop, pairs)
    for k in ('_rt', '_nat_order'):
        if hasattr(A, k):
            delattr(A, k)


def _member(m, pairs):
    try:
        return ','.join(map_set(IPSet.parse(m), pairs).cidrs())
    except (ValueError, AttributeError):
        return m


POOL = re.compile(r'^ip local pool (\S+) (\S+)-(\S+) mask (\S+)', re.M)


def pools(text):
    """[{name, range, net}] of the remote-access VPN pools in a config: net is the pool's subnet (from its mask)"""
    out = []
    for name, lo, hi, mask in POOL.findall(text or ''):
        try:
            rng = IPSet.parse('%s-%s' % (lo, hi))
            net = ipaddress.IPv4Network('%s/%s' % (lo, mask), strict=False)
        except ValueError:
            continue
        ok = ipaddress.IPv4Address(hi) in net and net.prefixlen >= 16
        out.append({'name': name, 'range': rng, 'net': IPSet.parse(str(net)) if ok else rng})
    return out


def pool_pairs(pa, pb):
    """A pool -> B pool: by order when both have as many, else every A pool to B's only pool. A pool both share is
    not translated"""
    if not pa or not pb:
        return []
    pp = list(zip(pa, pb)) if len(pa) == len(pb) else [(a, pb[0]) for a in pa] if len(pb) == 1 else []
    return [(a, b) for a, b in pp if a['range'] != b['range'] and not a['net'].overlaps(b['net'])]


def map_pools(s, pp):
    """A's pool addresses in s become B's pool: A's pool subnet maps to B's subnet, a part of it to B's range"""
    if s is None or not getattr(s, 'iv', None) or s.is_any():
        return s
    for a, b in pp:
        if s.overlaps(a['net']):
            part = s & a['net']
            s = (s - a['net']) | (b['net'] if part == a['net'] else b['range'])
    return s


def translate_pools(A, pp):
    """rewrite A's VPN pool addresses into B's pool, in place (raw values kept as evidence). Objects that hold A's
    pool remember B's pool name, so a new object is named after B's pool, never A's"""
    if not pp:
        return
    for r in A.rules:
        r.src, r.dst = map_pools(r.src, pp), map_pools(r.dst, pp)
    for n in A.nats:
        if getattr(n, 'raw_real', None) is None:
            n.raw_real = n.real
        n.real, n.mapped = map_pools(n.real, pp), map_pools(n.mapped, pp)
        n.dst_real, n.dst_mapped = map_pools(n.dst_real, pp), map_pools(n.dst_mapped, pp)
    for o in A.objects.values():
        if o.addrs is None:
            continue
        new = map_pools(o.addrs, pp)
        if new != o.addrs:
            if getattr(o, 'raw_addrs', None) is None:
                o.raw_addrs, o.raw_members = o.addrs, list(o.members)
            o.pool_b = next(b['name'] for a, b in pp if o.addrs.overlaps(a['net']))
            o.addrs = new
        o.members = [m if m.startswith('obj:') else _pool_member(m, pp) for m in o.members]
    A.pools = [b['range'] for a, b in pp]
    for k in ('_rt', '_nat_order'):
        if hasattr(A, k):
            delattr(A, k)


def _pool_member(m, pp):
    try:
        return ','.join(map_pools(IPSet.parse(m), pp).cidrs())
    except (ValueError, AttributeError):
        return m
