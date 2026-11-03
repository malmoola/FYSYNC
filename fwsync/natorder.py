"""NAT first-match order (0.4.2), as the firewall evaluates it for traffic leaving through a given interface pair:
manual NAT section 1 in configuration order, then auto (object) NAT - static before dynamic, then the smaller real
range first, then the lower first address, then the object name - then manual after-auto in order.
A rule matches when its interfaces are (real, mapped) or any. Twice NAT with a destination only applies to that
destination, so it neither translates nor shadows general (any destination) traffic."""
from .netset import IPSet

SECTION = {'manual-before': 0, 'auto': 1, 'manual-after': 2}


def _auto_key(n):
    return (0 if n.kind == 'static' else 1, n.real.size(), n.real.iv[0][0] if n.real.iv else 0, n.real_ref or '')


def ordered(cfg):
    """all NAT rules in evaluation order (cached)"""
    cached = getattr(cfg, '_nat_order', None)
    if cached is not None:
        return cached
    nats = list(cfg.nats)
    before = [n for n in nats if n.section == 'manual-before']
    auto = sorted([n for n in nats if n.section == 'auto'], key=_auto_key)
    after = [n for n in nats if n.section == 'manual-after']
    out = before + auto + after
    for i, n in enumerate(out, 1):
        n.order = i
    cfg._nat_order = out
    return out


def _ifc_ok(rule_ifc, ifc):
    return rule_ifc in (None, '', 'any') or ifc is None or rule_ifc == ifc


def general(n):
    """translates any-destination traffic: active, no destination part; real 'any' only when tied to a real interface"""
    if n.inactive or n.dst_real is not None or n.real is None:
        return False
    return not n.real.is_any() or n.real_ifc not in (None, '', 'any')


def shared(n):
    """many hosts share the translated address: dynamic / PAT, or a static whose mapped range is smaller"""
    if n.kind != 'static':
        return True
    return n.mapped is not None and n.mapped.size() < n.real.size()


def effective(cfg, s, src_ifc=None, dst_ifc=None):
    """first-match partition of s for outbound traffic src_ifc -> dst_ifc: [(part, rule)] + [(rest, None)]"""
    out, rest = [], s
    for n in ordered(cfg):
        if not rest:
            break
        if not general(n) or not _ifc_ok(n.real_ifc, src_ifc) or not _ifc_ok(n.mapped_ifc, dst_ifc):
            continue
        part = rest & n.real
        if part:
            out.append((part, n))
            rest = rest - part
    if rest:
        out.append((rest, None))
    return out


def line_of(n):
    return getattr(n, 'lineno', 0) or 0


def shadowed(cfg):
    """{id(rule): (covering rules, text)} for rules that never match outbound: every real address is taken by
    earlier general rules on the same or a wider interface pair"""
    out = {}
    seen = []
    for n in ordered(cfg):
        if n.inactive or n.real is None or n.real.is_any():
            continue
        prior = [m for m in seen if _ifc_ok(m.real_ifc, n.real_ifc) and _ifc_ok(m.mapped_ifc, n.mapped_ifc)]
        cov, by = IPSet(), []
        for m in prior:
            if m.real.overlaps(n.real) and not (n.real & m.real).issubset(cov):
                by.append(m)
                cov = cov | (m.real & n.real)
        if n.real.issubset(cov) and by:
            lines = ', '.join(str(line_of(m)) for m in by[:4]) + (' (+%d)' % (len(by) - 4) if len(by) > 4 else '')
            txt = 'never hit%s: covered by line%s %s' % (
                ' outbound' if n.kind == 'static' else '', 's' if len(by) > 1 else '', lines)
            if n.kind == 'static':
                txt += ' (inbound to its mapped address still applies)'
            out[id(n)] = (by, txt)
        if general(n):
            seen.append(n)
    return out


def out_ifc(cfg, outs):
    """the outside interface general outbound traffic uses: the one holding the default route, else the first"""
    from .detect import route_table
    for r in route_table(cfg):
        if r['plen'] == 0 and r['ifc'] in outs:
            return r['ifc']
    return outs[0] if outs else None


def best_effective(cfg, s, src, outs):
    """(first-match partition, outside interface) for the default-route exit that translates the most of s: with two
    ISPs a subnet may have PAT on only one of them, and that is still outbound PAT"""
    from .detect import route_table
    exits = [r['ifc'] for r in route_table(cfg) if r['plen'] == 0 and r['ifc'] in outs]
    exits = list(dict.fromkeys(exits)) or [out_ifc(cfg, outs)]

    def done(eff):
        return sum(p.size() for p, r in eff if r is not None and shared(r))
    return max(((effective(cfg, s, src, o), o) for o in exits), key=lambda x: done(x[0]))


def src_ifc(cfg, s):
    from .detect import route_split
    parts = sorted(route_split(cfg, s), key=lambda x: -x[1].size())
    return parts[0][0] if parts and parts[0][0] else None
