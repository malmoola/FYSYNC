"""Site translation. When a subnet is site-specific (A 10.1.1.0/24 is B 10.2.1.0/24 on the mapped interface), A is
rewritten into B's addresses before the compare, so a rule, NAT or object is judged by what it must be on B."""
import ipaddress

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
        n.real, n.mapped = map_set(n.real, pairs), map_set(n.mapped, pairs)
        n.dst_real, n.dst_mapped = map_set(n.dst_real, pairs), map_set(n.dst_mapped, pairs)
    for o in A.objects.values():
        o.raw_addrs = o.addrs
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
