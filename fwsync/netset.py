"""Address and port sets compared by value (integer interval lists)."""
import ipaddress

MAXV4 = 2 ** 32 - 1


def _merge(iv):
    iv = sorted(iv)
    out = []
    for a, b in iv:
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


class IntervalSet:
    """Immutable set of integers stored as merged closed intervals."""
    __slots__ = ('iv',)

    def __init__(self, iv=()):
        self.iv = tuple(_merge(iv))

    def __or__(self, o):
        return type(self)(self.iv + o.iv)

    def __and__(self, o):
        out, i, j = [], 0, 0
        while i < len(self.iv) and j < len(o.iv):
            a = max(self.iv[i][0], o.iv[j][0])
            b = min(self.iv[i][1], o.iv[j][1])
            if a <= b:
                out.append((a, b))
            if self.iv[i][1] < o.iv[j][1]:
                i += 1
            else:
                j += 1
        return type(self)(out)

    def __sub__(self, o):
        out = []
        for a, b in self.iv:
            cur = a
            for c, d in o.iv:
                if d < cur or c > b:
                    continue
                if c > cur:
                    out.append((cur, c - 1))
                cur = max(cur, d + 1)
                if cur > b:
                    break
            if cur <= b:
                out.append((cur, b))
        return type(self)(out)

    def __eq__(self, o):
        return isinstance(o, IntervalSet) and self.iv == o.iv

    def __hash__(self):
        return hash(self.iv)

    def __bool__(self):
        return bool(self.iv)

    def size(self):
        return sum(b - a + 1 for a, b in self.iv)

    def issubset(self, o):
        return not (self - o)

    def overlaps(self, o):
        return bool(self & o)


class IPSet(IntervalSet):
    """IPv4 address set. IPv6 entries are ignored by the LINA adapter (recorded as warnings)."""

    @classmethod
    def any(cls):
        return cls([(0, MAXV4)])

    @classmethod
    def host(cls, ip):
        v = int(ipaddress.IPv4Address(ip))
        return cls([(v, v)])

    @classmethod
    def net(cls, addr, mask=None):
        n = ipaddress.IPv4Network(addr if mask is None else '%s/%s' % (addr, mask), strict=False)
        return cls([(int(n.network_address), int(n.broadcast_address))])

    @classmethod
    def range(cls, a, b):
        return cls([(int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)))])

    @classmethod
    def parse(cls, text):
        """'10.0.0.0/8', '10.1.1.1', '10.0.0.1-10.0.0.9', comma separated"""
        s = cls()
        for part in str(text).replace(' ', '').split(','):
            if not part:
                continue
            if '-' in part:
                a, b = part.split('-', 1)
                s = s | cls.range(a, b)
            elif '/' in part:
                s = s | cls.net(part)
            else:
                s = s | cls.host(part)
        return s

    def cidrs(self):
        out = []
        for a, b in self.iv:
            out += [str(n) for n in ipaddress.summarize_address_range(ipaddress.IPv4Address(a), ipaddress.IPv4Address(b))]
        return out

    def is_any(self):
        return self.iv == ((0, MAXV4),)

    def __repr__(self):
        if self.is_any():
            return 'any'
        c = self.cidrs()
        return ', '.join(c[:6]) + (' ...(+%d)' % (len(c) - 6) if len(c) > 6 else '')

    def hosts(self):
        """single addresses (for /32 statics)"""
        return [str(ipaddress.IPv4Address(a)) for a, b in self.iv if a == b]


PRIVATE = IPSet.parse('0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,'
                      '192.0.0.0/24,192.168.0.0/16,198.18.0.0/15,224.0.0.0-255.255.255.255')


def is_public(ipset):
    """True when the set holds at least one globally routable address (documentation ranges count as public)"""
    return bool(ipset - PRIVATE)


class PortSet(IntervalSet):
    @classmethod
    def any(cls):
        return cls([(0, 65535)])

    def is_any(self):
        return self.iv == ((0, 65535),)

    def __repr__(self):
        if self.is_any():
            return 'any'
        return ','.join(str(a) if a == b else '%d-%d' % (a, b) for a, b in self.iv)


class Service:
    """Set of (protocol, dst ports, src ports) triples. proto 'ip' = any protocol."""

    def __init__(self, items=()):
        self.items = []
        for p, d, s in items:
            self.add(p, d, s)

    def add(self, proto, dports=None, sports=None):
        proto = str(proto).lower()
        if proto in ('tcp-udp', 'tcpudp'):
            self.add('tcp', dports, sports)
            self.add('udp', dports, sports)
            return self
        self.items.append((proto, dports if dports is not None else PortSet.any(),
                           sports if sports is not None else PortSet.any()))
        return self

    @classmethod
    def any(cls):
        return cls([('ip', None, None)])

    def __or__(self, o):
        return Service(self.items + o.items)

    def is_any(self):
        return any(p == 'ip' for p, d, s in self.items)

    def __and__(self, other):
        """intersection (protocol 'ip' meets anything)"""
        out = Service()
        for p, d, s in self.items:
            for q, e, t in other.items:
                if p == 'ip':
                    out.items.append((q, e, t))
                elif q == 'ip' or p == q:
                    if p in ('tcp', 'udp'):
                        dd, ss = d & e, s & t
                        if dd and ss:
                            out.items.append((p, dd, ss))
                    else:
                        out.items.append((p, d, s))
        return out

    def __bool__(self):
        return bool(self.items)

    def covered_by(self, other):
        """True when every triple here is inside the union of other's triples."""
        return all(other._covers_one(p, d, s) for p, d, s in self.items)

    def overlaps(self, other):
        for p, d, s in self.items:
            for q, e, t in other.items:
                if (q == 'ip' or p == 'ip' or p == q) and (p not in ('tcp', 'udp') or q not in ('tcp', 'udp') or
                                                          (d.overlaps(e) and s.overlaps(t))):
                    return True
        return False

    def _covers_one(self, p, d, s):
        if any(q == 'ip' for q, e, t in self.items):
            return True
        if p == 'ip':
            return False
        rem_d = d
        for q, e, t in self.items:
            if q == p and (p not in ('tcp', 'udp') or s.issubset(t)):
                if p not in ('tcp', 'udp'):
                    return True
                rem_d = rem_d - e
        return not rem_d if p in ('tcp', 'udp') else False

    def __repr__(self):
        if self.is_any():
            return 'ip'
        return ' '.join(p if p not in ('tcp', 'udp') or d.is_any() else '%s/%r' % (p, d) for p, d, s in self.items)
