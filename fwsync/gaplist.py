"""Gap list (0.5.4): only what B is missing compared to A, one row per gap, with the columns
Gap | When | Address | Object | A (line) | B today (line) | Required on B | Config.

NAT is judged by a first-match walk, not by names: every active A NAT line is placed where its real subnet lives on
B (B's connected interfaces, also shut ones, then B's static routes, then the interface map, then inside) and walked
through B's NAT in evaluation order (manual before auto, auto static first then longest prefix, manual after auto),
honouring real and mapped interfaces (also any) and destination-limited rules. A second walk with the proposed
fixes applied finds the exemptions a fix makes necessary.

Rules come from the compare rows, one result per A rule name. L7 rules are never copied from LINA, a Block* rule
that shows permit is an L7 block, and "B allows more than A" is a review item, never a gap.

When values: Now, Now disabled, At outage, Decision, Confirm use, If route needed, Compare in FMC, Only if
allow-listed. Rows sort by When, then Gap; the verdict counts are the rows."""
import ipaddress
import re
from collections import Counter
from dataclasses import replace

from . import natorder
from .compare import PERMIT, _is_default, any_any, tunnel_default, block_name, effective_rules, fqdn_names, fqdn_value
from .detect import route_split, route_split_up, route_table
from .netset import IPSet, is_public

WHEN = ('Now', 'Now disabled', 'At outage', 'Decision', 'Confirm use', 'If route needed', 'Compare in FMC',
        'Only if allow-listed')
COLS = [('gap', 'Gap'), ('when', 'When'), ('address', 'Address'), ('object', 'Object'), ('a_line', 'A (line)'),
        ('b_line', 'B today (line)'), ('required', 'Required on B'), ('config', 'Config')]
BLOCKS = ('deny', 'unknown', 'l7block')
PLACEHOLDER = re.compile(r'<[^>]*(public|address|\bip\b|object)[^>]*>|\b(PUB(LIC)?_NEW|NEW_PUB\w*|TBD|PLACEHOLDER)\b|'
                         r'x\.x\.x\.x', re.I)


# ---------------------------------------------------------------- NAT walk
def _any_ifc(x):
    return x in (None, '', 'any')


def _ifc_ok(rule_ifc, ifc):
    return _any_ifc(rule_ifc) or _any_ifc(ifc) or rule_ifc == ifc


def identity(n):
    """source identity with no destination translation: a NAT exemption. Destination translation is real
    translation even when the source stays the same"""
    return n.kind == 'static' and n.real is not None and n.mapped is not None and n.mapped == n.real and \
        (n.dst_real is None or n.dst_mapped == n.dst_real)


def dst_xlate(n):
    return n.dst_real is not None and n.dst_mapped is not None and n.dst_mapped != n.dst_real


def order(nats):
    """B's NAT in evaluation order"""
    before = [n for n in nats if n.section == 'manual-before']
    auto = sorted([n for n in nats if n.section == 'auto'], key=natorder._auto_key)
    after = [n for n in nats if n.section == 'manual-after']
    return before + auto + after


def walk(seq, s, ifc, out, dst=None, svc=''):
    """first match for traffic from s entering ifc and leaving out (to dst): [(part, rule or None)]. A rule limited
    to a destination only takes traffic to that destination; a rule limited to a service only that service"""
    res, rest = [], s
    for m in seq:
        if not rest:
            break
        if m.inactive or m.real is None or not _ifc_ok(m.real_ifc, ifc) or not _ifc_ok(m.mapped_ifc, out):
            continue
        if m.dst_real is not None and not m.dst_real.is_any() and (dst is None or dst.is_any() or not dst.issubset(m.dst_real)):
            continue
        if m.service and m.service != svc:
            continue
        part = rest & m.real
        if part:
            res.append((part, m))
            rest = rest - part
    if rest:
        res.append((rest, None))
    return res


def homes(B, s, mapped, default, outs_b):
    """where s lives on B: [(interface, part)]. Connected subnets (also on shut interfaces) first, then static routes
    (not via outside), then the interface map, then inside"""
    out, rest = {}, s
    for kinds in (('connected',), ('static', 'static tracked')):
        for e in route_table(B):
            if not rest:
                break
            if e['plen'] == 0 or e['kind'] not in kinds or (kinds[0] == 'static' and e['ifc'] in outs_b):
                continue
            part = rest & e['set']
            if part:
                out[e['ifc']] = out.get(e['ifc'], IPSet()) | part
                rest = rest - part
    if rest:
        k = mapped or default
        out[k] = out.get(k, IPSet()) | rest
    return list(out.items())


def lno(x):
    return getattr(x, 'lineno', 0) or 0


def ref(x, dev=''):
    """'<line>: <text>' for a config line"""
    if x is None:
        return ''
    return '%s%d: %s' % (dev + ' ' if dev else '', lno(x), x.line)


def _cidrs(s):
    return ', '.join(s.cidrs()[:4]) + (' (+%d)' % (len(s.cidrs()) - 4) if len(s.cidrs()) > 4 else '')


class Gaps:
    def __init__(self, res, prof, A, B, info, a_text='', b_text=''):
        from .findings import Ctx
        self.res, self.prof, self.A, self.B, self.a_text, self.b_text = res, prof, A, B, a_text, b_text
        self.ctx = Ctx(res, prof, A, B, info)
        self.n = self.ctx.n
        self.a, self.b = self.n['A_short'], self.n['B_short']
        self.outs_a = list(prof.outside_a or [])
        self.outs_b = list(prof.outside_b or ['OUTSIDE'])
        self.b_out = self.outs_b[0]
        self.b_in = self.ctx.b_in
        self.imap = dict(prof.interface_map or {})
        self.pools = list(getattr(A, 'pools', []) or []) + list(getattr(B, 'pools', []) or [])
        self.rows, self.nat_ref, self.rule_ref, self.review, self.objects = [], [], [], [], {}
        self.fixed = []          # (kind, data) proposed NAT changes for the second pass
        self.pending = []        # PAT proposals, merged in pats()
        self.later = []          # statics with no inbound rule, judged once the PAT proposals are known
        self.b_seq = order(B.nats)
        self.site_mapped = []    # public IPs of A lines found to be site devices
        self.exempts = {}        # missing exemptions, one row per A line and interface pair
        self.decisions = []      # (A line, addresses) whose public IP on B is a decision
        self.a_seq = order(A.nats)

    # ------------------------------------------------------------ helpers
    def row(self, gap, when, address, obj, a_line, b_line, required, config, kind, objects=(), note=''):
        r = {'gap': gap, 'when': when, 'address': address, 'object': obj, 'a_line': a_line, 'b_line': b_line,
             'required': required, 'config': list(config), 'kind': kind, 'objects': [o['name'] for o in objects],
             'note': note}
        for o in objects:
            self.objects.setdefault(o['name'], dict(o, used_by=[]))['used_by'].append(gap)
        self.rows.append(r)
        return r

    def b_ifc(self, a_ifc):
        if _any_ifc(a_ifc):
            return 'any'
        if a_ifc in self.imap and self.imap[a_ifc] and self.imap[a_ifc] != 'ignore':
            return self.imap[a_ifc]
        if a_ifc in self.outs_a:
            return self.b_out
        return a_ifc if a_ifc in self.B.interfaces else self.b_in

    def up(self, ifc):
        i = self.B.interfaces.get(ifc)
        return i is not None and not i.shutdown and not i.planned

    def obj(self, s, a_ref=''):
        """B object for s: A's object name (B's name when B has it by value), else a NET_ name; [definition] when B
        lacks it"""
        from .findings import net_resolve, obj_line, safe
        if s.is_any():
            return 'any', []
        b = self.B.objects.get(a_ref) if a_ref else None
        clash = b is not None and net_resolve(self.B, a_ref) != s
        if a_ref and a_ref in self.A.objects and net_resolve(self.A, a_ref) == s and not clash:
            name, on_b = self.ctx.bname(a_ref)
        else:
            hits = self.ctx.bvals.get(repr(s), [])
            if hits:
                return sorted(hits, key=len)[0], []
            c = s.cidrs()
            name, on_b = safe(('NET_%s' % c[0].replace('/32', '').replace('/', '_')) if len(c) == 1 else
                              'NET_%s_group' % c[0].split('/')[0]), False
        if on_b or name in self.B.objects:
            return name, []
        o = self.A.objects.get(a_ref) if a_ref else None
        if o is not None and o.kind == 'range' and len(o.value.split()) >= 2:
            lo, hi = o.value.split()[-2:]
            return name, [{'name': name, 'type': 'Range', 'value': '%s-%s' % (lo, hi), '_addrs': s,
                           'cli': ['object network %s' % name, ' range %s %s' % (lo, hi)]}]
        return name, [dict(obj_line(name, s), _addrs=s)]

    def a_subnets(self, ifc):
        """A's subnets behind ifc (any = every inside interface): what a catch-all real 'any' stands for"""
        s = IPSet()
        for e in route_table(self.A):
            if e['plen'] == 0 or e['ifc'] in self.outs_a or e['ifc'] in (self.A.ignored or ()):
                continue
            if _any_ifc(ifc) or e['ifc'] == ifc:
                s = s | e['set']
        return s

    def vpn(self, s):
        return any(s.overlaps(p) for p in self.pools if p)

    def gateways(self):
        """next hops of A's and B's routes out of their outside interfaces: the ISP edge routers"""
        g = getattr(self, '_gw', None)
        if g is None:
            g = IPSet()
            for cfg, outs in ((self.A, self.outs_a), (self.B, self.outs_b)):
                for r in cfg.routes:
                    if r.ifc in outs and r.nexthop:
                        try:
                            g = g | IPSet.parse(r.nexthop)
                        except ValueError:
                            pass
            self._gw = g
        return g

    def b_outside_nets(self):
        """B's own outside subnets (a subnet A has too is shared, not B's own)"""
        a = [IPSet.net('%s/%s' % (i.ip, i.mask)) for i in self.A.interfaces.values() if i.ip and i.mask]
        return [b for b in (IPSet.net('%s/%s' % (i.ip, i.mask)) for i in self.B.interfaces.values()
                            if i.ip and i.nameif in self.outs_b) if not any(b.overlaps(x) for x in a)]

    def site_reason(self, n, kind):
        """why A line n belongs to A's site and needs nothing on B ('' when it does not): it only reaches A's edge or
        gateway, its public IP is in B's own block, its only inbound rules come from the edge routers, it shares its
        public IP with such a line, or B has a twin host in the same rules with its own public NAT"""
        gw = self.gateways()
        if n.dst_real is not None and not n.dst_real.is_any() and gw and n.dst_real.issubset(gw):
            return 'it only reaches the ISP edge or gateway'
        if kind not in ('static', 'internal') or n.kind != 'static' or n.real.is_any():
            return ''
        if n.mapped is not None and is_public(n.mapped) and any(n.mapped.issubset(b) for b in self.b_outside_nets()):
            return 'its public IP %s is in %s\'s own block' % (_cidrs(n.mapped), self.b)
        if n.mapped is not None and any(n.mapped == x for x in self.site_mapped):
            return 'it shares its public IP %s with a site device line' % _cidrs(n.mapped)
        inb = self.a_inbound(n.real)
        if inb and gw and all(not r.src.is_any() and r.src.issubset(gw) for r in inb):
            return 'its only inbound rules come from the ISP edge routers (monitoring)'
        twin = self.b_twin(n, inb)
        if twin is not None:
            return '%s has its own host %s in the same rules, with its own public NAT (line %d)' % (
                self.b, _cidrs(twin.real), lno(twin))
        return ''

    def b_twin(self, n, inb):
        """a B static NAT for another host that B's rules of the same names allow next to n's host"""
        names = {r.rule_name for r in inb if r.rule_name}
        if not names:
            return None
        a_reals = [x.real for x in self.A.nats if x.real is not None and not x.real.is_any() and x.kind == 'static']
        for b in self.B.rules:
            if b.rule_name not in names or b.dst.is_any():
                continue
            for m in self.b_seq:
                if m.inactive or m.kind != 'static' or identity(m) or natorder.shared(m) or m.real is None or \
                        m.real.is_any() or m.real.overlaps(n.real) or not m.real.issubset(b.dst):
                    continue
                if not any(m.real.overlaps(x) for x in a_reals):
                    return m
        return None

    def sibling_exempt(self, ifc, out, x):
        """a B identity NAT from ifc to another of B's shared interfaces (B's copy shut until takeover) whose source
        group holds x: B exempts this traffic for the sibling interfaces, so the one toward out is missing"""
        shared = {b for a, b in self.shared_ifcs()}
        if out not in shared:
            return None
        for m in self.b_seq:
            if not m.inactive and identity(m) and m.real_ifc == ifc and m.mapped_ifc in shared and m.mapped_ifc != out \
                    and m.real is not None and x.issubset(m.real) and m.real_ref:
                return m
        return None

    def b_own(self, m):
        """B rule m is B's own NAT for one host: a static on every interface, or for a host A has no NAT for"""
        if m is None or m.kind != 'static' or identity(m) or natorder.shared(m) or m.real is None or m.real.is_any():
            return False
        if _any_ifc(m.real_ifc) and _any_ifc(m.mapped_ifc):
            return True
        return not any(x.real is not None and not x.real.is_any() and x.kind == 'static' and not identity(x)
                       and not natorder.shared(x) and x.real.overlaps(m.real) for x in self.A.nats)

    def a_kind(self, n):
        if identity(n):
            return 'exempt'
        if n.real is not None and not n.real.is_any() and self.vpn(n.real):
            return 'vpn'
        if not _any_ifc(n.real_ifc) and n.real_ifc == n.mapped_ifc:
            return 'hairpin'
        if not _any_ifc(n.mapped_ifc) and n.mapped_ifc not in self.outs_a:
            return 'internal'
        if n.kind == 'static' and not natorder.shared(n):
            return 'static'
        return 'pat'

    def a_inbound(self, real):
        """A permits from an outside interface to these real addresses"""
        return [r for r in effective_rules(self.A) if r.action in PERMIT and not r.dst.is_any() and r.dst.overlaps(real)
                and r.src_ifc in self.outs_a]

    def sibling_pat(self, ifc, out):
        """the PAT address B's sibling subnets use toward out: from the same interface first, then any interface"""
        for same in (True, False):
            c = Counter()
            for m in self.b_seq:
                if m.inactive or m.kind != 'dynamic' or not _ifc_ok(m.mapped_ifc, out) or identity(m):
                    continue
                if same and m.real_ifc != ifc:
                    continue
                c[('pat-pool ' + m.mapped_ref) if ' pat-pool ' in ' %s ' % m.line else
                  'interface' if m.mapped_interface else m.mapped_ref] += 1
            if c:
                return c.most_common(1)[0][0]
        return 'interface'

    def same_ip(self, n, m):
        if n.mapped is None or m.mapped is None:
            return False
        return n.mapped == m.mapped or (natorder.shared(m) and n.mapped.issubset(m.mapped))

    def live(self, m, part=None):
        """traffic for the rule's real addresses reaches its real interface today"""
        if _any_ifc(m.real_ifc):
            return True
        return any(i == m.real_ifc for i, x in route_split_up(self.B, part if part is not None else m.real))

    def site_twin(self, n, m):
        return m is not None and n.real_ref and m.real_ref == n.real_ref and m.real != n.real

    # ------------------------------------------------------------ NAT
    def nats(self):
        for n in natorder.ordered(self.A):
            self.nat_line(n)
        self.pats()
        self.optional_statics()
        self.second_pass()
        self.flush_exempts()
        self.backhaul()
        self.shared_block()

    def _ref_row(self, n, kind, result, b_lines, gaps=()):
        self.nat_ref.append({'line': lno(n), 'text': n.line, 'section': n.section, 'kind': kind, 'result': result,
                             'b_match': '; '.join(dict.fromkeys(b_lines)) or '(none)', 'gaps': list(gaps)})

    def nat_line(self, n):
        if n.inactive:
            return self._ref_row(n, n.kind, 'Inactive on %s: not checked' % self.a, [])
        if n.real_ifc in (self.A.ignored or ()) or n.mapped_ifc in (self.A.ignored or ()):
            return self._ref_row(n, n.kind, 'Not checked: interface ignored', [])
        if n.real is None:
            return self._ref_row(n, n.kind, 'Not checked: real address not resolved', [])
        kind = self.a_kind(n)
        twin = next((m for m in self.b_seq if kind in ('static', 'internal') and self.site_twin(n, m)
                     and not m.inactive and not identity(m)), None)
        if twin is not None:
            return self._ref_row(n, kind, 'OK, site device', [ref(twin)])
        why = self.site_reason(n, kind)
        if why:
            if n.mapped is not None and n.kind == 'static':
                self.site_mapped.append(n.mapped)
            return self._ref_row(n, kind, 'OK, site device: %s' % why, [])
        real = n.real if not n.real.is_any() or not _any_ifc(n.real_ifc) else self.a_subnets(n.real_ifc)
        out = self.b_ifc(n.mapped_ifc)
        mapped_home = self.b_ifc(n.real_ifc)
        if kind == 'hairpin' or real.is_any() or (kind == 'vpn' and _any_ifc(n.real_ifc)):
            # source any (or a VPN pool on any interface): the traffic entering that real interface, kept as it is
            parts = [(mapped_home, real)]
        else:
            parts = homes(self.B, real, mapped_home if not _any_ifc(n.real_ifc) else None, self.b_in, self.outs_b) \
                if not real.is_any() else [(mapped_home, real)]
        results, b_lines, gaps = [], [], []
        own = set(self.imap.values()) | {self.b_in, self.b_out}
        if self.imap and any(ifc not in own and not _any_ifc(ifc) for ifc, p in parts):
            for ifc, p in parts:
                if ifc not in own and not _any_ifc(ifc):
                    results.append('OK, site network: %s reaches %s through its own %s' % (self.b, _cidrs(p), ifc))
            parts = [(ifc, p) for ifc, p in parts if ifc in own or _any_ifc(ifc)]
        cidrs = [(ifc, IPSet.parse(c)) for ifc, p in parts for c in p.cidrs()] if kind == 'exempt' else parts
        dsts = [n.dst_real]
        if kind in ('exempt', 'internal') and (n.dst_real is None or n.dst_real.is_any()) and \
                (out not in self.outs_b or out not in self.default_ifcs()):
            dsts = self.nets_via(out) or dsts      # to any = to the networks behind that interface
        for ifc, part in cidrs:
            full, other = part, None
            if kind not in ('static', 'internal') or n.kind != 'static':      # a static still works inbound
                part, other = self.hit_on_a(n, part)
            if other is not None:
                results.append('OK, not hit on %s (%s)' % (self.a, 'part of it is routed to another interface on %s' % self.a
                                                       if other is n else 'line %d takes it first' % lno(other)))
            if not part:
                continue
            bad, first = IPSet(), None
            w_ifc = ifc
            if kind == 'vpn' and _any_ifc(ifc):    # the pool's traffic enters B on its VPN interface
                w_ifc = (list(getattr(self.B, 'ra_ifcs', []) or []) or [self.b_out])[0]
            for x, m in [y for d in dsts for y in walk(self.b_seq, part, w_ifc, out, d, n.service)]:
                b_lines.append(ref(m) if m is not None else '(no NAT on %s for %s from %s)' % (self.b, _cidrs(x), ifc))
                if kind != 'exempt' and (m is None or identity(m) or (dst_xlate(n) and m.dst_mapped != n.dst_mapped)):
                    bad, first = bad | x, first or m
                    continue
                st, g = self.judge(n, kind, ifc, out, x, m)
                results.append(st)
                if g:
                    gaps.append(g)
            if bad:
                st, g = self.judge(n, kind, ifc, out, full if kind == 'pat' else bad, first)
                results.append(st)
                if g:
                    gaps.append(g)
        bad = [r for r in results if not r.startswith('OK')]
        result = bad[0] if bad else max(results, key=results.count) if results else 'OK'
        self._ref_row(n, kind, result, b_lines, gaps)

    def default_ifcs(self):
        return {r.ifc for r in self.B.routes if r.network == '0.0.0.0' and r.mask == '0.0.0.0'}

    def nets_via(self, ifc):
        """the networks B routes out of ifc (connected and static, no default)"""
        out = [e['set'] for e in route_table(self.B) if e['ifc'] == ifc and e['plen'] > 0]
        i = self.B.interfaces.get(ifc)
        if i is not None and i.ip and i.mask:              # also a shut interface: its subnet is what it serves
            c = IPSet.net('%s/%s' % (i.ip, i.mask))
            if not any(c == x for x in out):
                out.append(c)
        return out

    def hit_on_a(self, n, part):
        """(the part of `part` whose first match on A is n, the A rule that takes the rest first): an A line that never
        matches some traffic on A is not a gap for that traffic on B"""
        from .detect import route_split
        mine, other = IPSet(), None
        split = route_split(self.A, part)
        if _any_ifc(n.real_ifc) and self.a_kind(n) == 'vpn':
            split = [(self.a_vpn_ifc(), part)]          # VPN clients arrive on A's VPN interface
        elif self.A.dynamic_routing:            # A learns routes we cannot see: only its connected subnets are certain
            split = self._connected_split(split, n)
        if not _any_ifc(n.real_ifc):          # addresses A routes elsewhere never enter this rule's interface on A
            here = IPSet()
            for i, p in split:
                if i in (n.real_ifc, ''):
                    here = here | p
                elif other is None:
                    other = n
            split = [(n.real_ifc, here)] if here else []
        for a_in, p in split:
            for x, m in walk(self.a_seq, p, a_in or None, n.mapped_ifc, n.dst_real, n.service):
                if m is n or m is None:
                    mine = mine | x
                elif other is None:
                    other = m
        return mine, other

    def a_vpn_ifc(self):
        """the interface A's remote-access VPN listens on (webvpn / ikev2 client-services), else its outside"""
        m = re.findall(r'^ enable (\S+)', '\n'.join(re.findall(r'^webvpn\n((?: .*\n)+)', self.a_text, re.M)), re.M) + \
            re.findall(r'^crypto ikev2 enable (\S+) client-services', self.a_text, re.M)
        return m[0] if m else (self.outs_a[0] if self.outs_a else None)

    def _connected_split(self, split, n):
        """route_split for a config with dynamic routing: an address is placed on another interface only when it is
        connected there, everything else is assumed to enter the rule's own interface"""
        conn = [e for e in route_table(self.A) if e['kind'] == 'connected']
        out, rest = {}, IPSet()
        for i, p in split:
            for e in conn:
                part = p & e['set']
                if part:
                    out[e['ifc']] = out.get(e['ifc'], IPSet()) | part
                    p = p - part
            rest = rest | p
        if rest:
            k = '' if _any_ifc(n.real_ifc) else n.real_ifc
            out[k] = out.get(k, IPSet()) | rest
        return list(out.items())

    def judge(self, n, kind, ifc, out, x, m):
        """(result, gap name or '') for part x of A line n entering ifc, whose first match on B is m"""
        a_line, addr = ref(n, self.a), _cidrs(x)
        if kind == 'exempt':
            if m is None or identity(m):
                return ('OK, no translation on %s' % self.b if m is None else 'OK, same exemption'), ''
            sib = self.sibling_exempt(ifc, out, x) if _any_ifc(m.real_ifc) and _any_ifc(m.mapped_ifc) else None
            if sib is not None:           # B exempts this traffic toward its other shared interfaces: one is missing
                r = self.missing_exempt(n, ifc, out, x, m)
                e = self.exempts[(id(n), ifc, out)]
                e['src_obj'], e['src_set'] = sib.real_ref, sib.real
                return r
            if self.b_own(m):
                return 'OK, site device: %s\'s own static NAT for this host (line %d)' % (self.b, lno(m)), ''
            return self.missing_exempt(n, ifc, out, x, m)
        if m is not None and not identity(m) and (not dst_xlate(n) or m.dst_mapped == n.dst_mapped):
            if self.site_twin(n, m) or (kind != 'vpn' and getattr(n, 'raw_real', None) is not None and
                                        n.raw_real != n.real):
                return 'OK, site device', ''
            if kind == 'static' and natorder.shared(m) and not natorder.shared(n):
                inb = self.b_static(x, ifc, out)
                if inb is not None:
                    return ('OK, same IP' if self.same_ip(n, inb) else 'OK, %s public IP' % self.b) + ' (inbound)', ''
                moved = self.moved_static(n, ifc, out, x)
                if moved is not None:
                    return self.edit_ifc(n, kind, ifc, out, x, moved)
                if self.a_inbound(n.real):
                    return self.missing_static(n, ifc, out, x, m)
                if self.same_ip(n, m):
                    return 'OK, same IP (no inbound rule on %s)' % self.a, ''
                g = 'Static NAT (optional)'
                self.row(g, 'Only if allow-listed', addr, n.real_ref, a_line, ref(m, self.b),
                         'Nothing needed: %s has no inbound rule to %s, and %s translates it with PAT (line %d). Add '
                         'a static NAT only if a partner allow-lists %s\'s public IP %s.' % (
                             self.a, addr, self.b, lno(m), self.a, _cidrs(n.mapped) if n.mapped else 'interface'),
                         [], 'nat')
                return 'OK, %s public IP (PAT)' % self.b, g
            if n.kind == 'static' and natorder.shared(n) and natorder.shared(m) and not self.same_ip(n, m):
                g = 'Static NAT (optional)'               # a fixed public IP for a group: only for allow-lists
                self.row(g, 'Only if allow-listed', addr, n.real_ref, a_line, ref(m, self.b),
                         'Nothing needed: %s translates %s with PAT (line %d). %s gives them the fixed public IP %s; '
                         'add the same only if a partner allow-lists it.' % (self.b, addr, lno(m), self.a,
                                                                             _cidrs(n.mapped) if n.mapped else '?'),
                         [], 'nat')
                return 'OK, %s public IP (PAT)' % self.b, g
            return ('OK, same IP' if self.same_ip(n, m) else 'OK, %s public IP' % self.b), ''
        wrong = self.wrong_ifc(n, ifc, out, x) if kind != 'hairpin' else None
        if wrong is not None and kind == 'static' and natorder.shared(wrong) and not natorder.shared(n):
            moved = self.moved_static(n, ifc, out, x)      # a static stays its own row, the PAT line gets the edit
            if moved is not None:
                return self.edit_ifc(n, kind, ifc, out, x, moved)
            if self.a_inbound(n.real):
                return self.missing_static(n, ifc, out, x, m)
            g = 'Static NAT (optional)'
            self.row(g, 'Only if allow-listed', _cidrs(x), n.real_ref, ref(n, self.a), ref(wrong, self.b),
                     'Nothing needed: %s has no inbound rule to %s, and line %d translates it with PAT once its source '
                     'interface is fixed (see Wrong source interface). Add a static NAT only if a partner allow-lists '
                     '%s\'s public IP %s.' % (self.a, _cidrs(x), lno(wrong), self.a,
                                              _cidrs(n.mapped) if n.mapped else 'interface'), [], 'nat')
            return g, g
        if wrong is not None:
            if any(k == 'edit' and y is wrong and i == ifc for k, y, i in self.fixed):
                return 'Wrong source interface (same edit as line %d)' % lno(wrong), ''
            return self.edit_ifc(n, kind, ifc, out, x, wrong)
        if kind == 'static' and m is None and not self.a_inbound(n.real) and self._inactive_b(x, out) is None:
            self.later.append((n, ifc, out, x))
            return 'Static NAT (optional)', ''
        if m is not None and identity(m) and m.section == 'manual-before' and kind in ('static', 'internal'):
            return 'Change at outage', ''          # an identity above the server's rule: backhaul() lists it
        if kind == 'static':
            inb = self.b_static(x, ifc, out)
            if inb is not None:                    # its outbound is taken first, inbound to its address still works
                return ('OK, same IP' if self.same_ip(n, inb) else 'OK, %s public IP' % self.b) + ' (inbound)', ''
        return {'pat': self.missing_pat, 'static': self.missing_static, 'vpn': self.missing_vpn,
                'internal': self.missing_internal, 'hairpin': self.missing_hairpin}[kind](n, ifc, out, x, m)

    def b_static(self, x, ifc, out):
        """a B static for these addresses: its outbound may be taken first, inbound to its address still works"""
        return next((y for y in self.b_seq if not y.inactive and y.kind == 'static' and not identity(y)
                     and not natorder.shared(y) and y.real is not None and not y.real.is_any() and x.issubset(y.real)
                     and _ifc_ok(y.real_ifc, ifc) and _ifc_ok(y.mapped_ifc, out)), None)

    def moved_static(self, n, ifc, out, x):
        """a B static for the same host and public IP on another real interface: edit it, never add a duplicate"""
        for m in self.b_seq:
            if m.inactive or m.kind != 'static' or identity(m) or natorder.shared(m) or m.real is None or \
                    m.real.is_any() or _any_ifc(m.real_ifc) or m.real_ifc == ifc:
                continue
            if _ifc_ok(m.mapped_ifc, out) and x.issubset(m.real) and n.mapped is not None and m.mapped == n.mapped:
                return m
        return None

    def wrong_ifc(self, n, ifc, out, x):
        """a translating B rule for these addresses toward out, on another real interface"""
        for m in self.b_seq:
            if m.inactive or m.real is None or m.real.is_any() or identity(m) or _any_ifc(m.real_ifc):
                continue
            if m.real_ifc != ifc and _ifc_ok(m.mapped_ifc, out) and x.issubset(m.real) and m.dst_real is None:
                return m
        return None

    def edit_ifc(self, n, kind, ifc, out, x, m):
        """B has the rule on another interface: edit that rule (never a second rule), keep its translated address.
        When the subnet's own interface is shut and the traffic reaches the rule's interface today, the rule is right
        today and changes at outage"""
        a_line, addr = ref(n, self.a), _cidrs(x)
        today = self.live(m, x) and not self.up(ifc)
        fmc = ('%sDevices > NAT > %s > edit line %d (%s): Interface Objects: Source %s instead of %s; keep its '
               'Translated Source (%s). Then Deploy.' % ('At outage: ' if today else '', self.ctx.natp, lno(m),
                                                       m.real_ref, ifc, m.real_ifc,
                                                       'interface' if m.mapped_interface else m.mapped_ref))
        verify = 'packet-tracer input %s tcp %s 40000 8.8.8.8 443' % (ifc, _host(x))
        if today:
            self.row('Change at outage', 'At outage', addr, m.real_ref, a_line, ref(m, self.b),
                     '%s reaches %s through %s today, while %s is shut, so line %d is right today. At outage, when %s '
                     'comes up, change its source interface to %s. Failback: set it back to %s.' % (
                         addr, self.b, m.real_ifc, ifc, lno(m), ifc, ifc, m.real_ifc),
                     [fmc, verify, 'Failback: Devices > NAT > %s > edit line %d: Source %s again. Then Deploy.' % (
                         self.ctx.natp, lno(m), m.real_ifc)], 'nat')
            self.fixed.append(('edit', m, ifc))
            return 'Change at outage', 'Change at outage'
        self.row('Wrong source interface', 'Now', addr, m.real_ref, a_line, ref(m, self.b),
                 '%s lives behind %s on %s, but line %d translates it from %s. Edit that rule: source interface %s, '
                 'same translated address. Do not add a second rule.' % (addr, ifc, self.b, lno(m), m.real_ifc, ifc),
                 [fmc, verify], 'nat')
        self.fixed.append(('edit', m, ifc))
        return 'Wrong source interface', 'Wrong source interface'

    def _add(self, section, kind, ifc, out, s, mapped_ref, mapped, a_ref='', pat=True, dst=None, n=None):
        """a new B rule for the second pass"""
        from .model import Nat
        r = Nat(seq=99000 + len(self.fixed), section=section, real_ifc=ifc, mapped_ifc=out, kind=kind, pat=pat,
                real=s, mapped=mapped, real_ref=a_ref, mapped_ref=mapped_ref, mapped_interface=mapped_ref == 'interface',
                dst_real=dst, dst_mapped=dst, line='(proposed)')
        self.fixed.append(('add', r, ifc))

    def missing_pat(self, n, ifc, out, x, m):
        name, objs = self.obj(x, n.real_ref if x == n.real else '')
        self.pending.append({'n': n, 'ifc': ifc, 'out': out, 'x': x, 'm': m, 'name': name, 'objs': objs,
                             'mapped': self.sibling_pat(ifc, out)})
        return 'Missing PAT', 'Missing PAT'

    def pats(self):
        """one PAT per subnet: a proposal inside another proposal for the same interfaces is left out"""
        for p in self.pending:
            wide = next((q for q in self.pending if q is not p and q['ifc'] == p['ifc'] and q['out'] == p['out'] and
                         p['x'].issubset(q['x']) and (q['x'] != p['x'] or self.pending.index(q) < self.pending.index(p))),
                        None)
            r = next((y for y in self.nat_ref if y['line'] == lno(p['n']) and y['text'] == p['n'].line), None)
            if wide is not None:
                if r is not None:
                    r['result'] = 'Missing PAT (the PAT for %s covers it)' % _cidrs(wide['x'])
                continue
            n, ifc, out, x, m, name, objs, mapped = (p[k] for k in ('n', 'ifc', 'out', 'x', 'm', 'name', 'objs', 'mapped'))
            cli = ['nat (%s,%s) after-auto source dynamic %s %s' % (ifc, out, name, mapped)]
            why = ('B today: %s' % ref(m, self.b)) if m is not None else '%s has no NAT for it from %s' % (self.b, ifc)
            self.row('Missing PAT', 'Now', _cidrs(x), name, ref(n, self.a), why,
                     'Add a dynamic PAT for %s from %s to %s, with the address %s\'s other subnets use (%s).' % (
                         _cidrs(x), ifc, out, self.b, mapped),
                     ['Devices > NAT > %s > Add Rule: Manual, Dynamic, After Auto NAT; Source %s -> Destination %s; '
                      'Original Source %s; Translated Source %s.' % (
                          self.ctx.natp, ifc, out, name, 'Destination Interface IP' if mapped == 'interface' else mapped)]
                     + [c for o in objs for c in o['cli']] + cli, 'nat', objs)
            bm = None if mapped == 'interface' else self.B.objects.get(mapped.replace('pat-pool ', ''))
            self._add('manual-after', 'dynamic', ifc, out, x, mapped, bm.addrs if bm is not None else None, name)

    def optional_statics(self):
        """a static NAT with no inbound rule on A: optional when a proposed PAT translates it, else missing"""
        for n, ifc, out, x in self.later:
            pat = next((p for p in self.pending if p['ifc'] == ifc and p['out'] == out and x.issubset(p['x'])), None)
            r = next((y for y in self.nat_ref if y['line'] == lno(n) and y['text'] == n.line), None)
            if pat is None:
                st, g = self.missing_static(n, ifc, out, x, None)
            else:
                st = g = 'Static NAT (optional)'
                self.row(g, 'Only if allow-listed', _cidrs(x), n.real_ref, ref(n, self.a), '(none)',
                         'Nothing needed beyond the PAT proposed for %s: %s has no inbound rule to %s. Add a static NAT '
                         'only if a partner allow-lists %s\'s public IP %s.' % (
                             _cidrs(pat['x']), self.a, _cidrs(x), self.a, _cidrs(n.mapped) if n.mapped else 'interface'),
                         [], 'nat')
            if r is not None:
                r['result'], r['gaps'] = st, r['gaps'] + [g]

    def _inactive_b(self, x, out):
        return next((m for m in self.b_seq if m.inactive and m.real is not None and not m.real.is_any()
                     and x.issubset(m.real) and _ifc_ok(m.mapped_ifc, out)), None)

    def public_choice(self, n):
        """(reuse A's public IP?, block, B lines in the block): reuse when B already has NATs in that block"""
        if n.mapped is None:
            return False, '', []
        blk = self.a_block(n.mapped)
        lines = [m for m in self.b_seq if not m.inactive and m.mapped is not None and not m.mapped.is_any()
                 and m.mapped.overlaps(IPSet.parse(blk))]
        return len(lines) > 1, blk, lines       # one isolated B line does not show that the block moves

    def a_block(self, s):
        for i in self.A.interfaces.values():
            if i.ip and i.nameif in self.outs_a:
                net = ipaddress.IPv4Network('%s/%s' % (i.ip, i.mask), strict=False)
                if s.issubset(IPSet.net(str(net))):
                    return str(net)
        c = s.cidrs()[0]
        return str(ipaddress.IPv4Network(c, strict=False).supernet(new_prefix=24)) if int(c.split('/')[1]) > 24 else c

    def dst_clause(self, n):
        """A's destination part as B objects: (cli, FMC text, objects); empty when A has none"""
        mm = re.search(r'\bdestination static (\S+) (\S+)', n.line)
        if not mm or n.dst_real is None:
            return '', '', []
        d1, o1 = self.obj(n.dst_real, mm.group(1))
        d2, o2 = self.obj(n.dst_mapped if n.dst_mapped is not None else n.dst_real, mm.group(2))
        return (' destination static %s %s' % (d1, d2), '; Original Destination %s, Translated Destination %s' % (d1, d2),
                o1 + o2)

    def b_pool(self):
        """(object name, addresses, objects) of B's active VPN pool: the pool a tunnel group hands out, else B's first"""
        used = re.findall(r'^ address-pool (\S+)', self.b_text, re.M)
        pools = re.findall(r'^ip local pool (\S+) (\S+)-(\S+) mask (\S+)', self.b_text, re.M)
        pick = [p for p in pools if p[0] in used] or pools
        if not pick:
            return None
        nm, lo, hi, mask = pick[0]
        try:
            net = IPSet.net(str(ipaddress.IPv4Network('%s/%s' % (lo, mask), strict=False)))
        except ValueError:
            return None
        name, objs = self.obj(net, '')
        return name, net, objs

    def main_out(self):
        """B's main path: the outside interface of its default route with the lowest distance"""
        d = [(r.distance, r.ifc) for r in self.B.routes if r.network == '0.0.0.0' and r.mask == '0.0.0.0'
             and r.ifc in self.outs_b]
        return min(d)[1] if d else self.b_out

    def missing_static(self, n, ifc, out, x, m):
        a_line, addr = ref(n, self.a), _cidrs(x)
        name, objs = self.obj(x, n.real_ref)
        off = self._inactive_b(x, out)
        if off is not None:
            self.row('Missing static NAT', 'At outage', addr, off.real_ref, a_line, ref(off, self.b),
                     '%s has this NAT but it is disabled (line %d). Enable it at outage: it would answer ARP for %s '
                     'today.' % (self.b, lno(off), off.mapped_ref),
                     ['At outage: Devices > NAT > %s > edit line %d: tick Enable. Then Deploy.' % (self.ctx.natp, lno(off)),
                      'show nat detail | include %s' % off.real_ref], 'nat')
            return 'Missing static NAT', 'Missing static NAT'
        reuse, blk, lines = self.public_choice(n)
        dst, dfmc, dobjs = self.dst_clause(n)
        objs = objs + dobjs
        opts = _opts(n)
        what = 'Missing static NAT'
        why = ('B today: %s' % ref(m, self.b)) if m is not None else '%s has no NAT for it' % self.b
        if reuse or not is_public(n.mapped or IPSet()):
            pub = n.mapped_ref
            pobjs = []
            if n.mapped is not None and pub not in self.B.objects and not pub[0].isdigit():
                pub, pobjs = self.obj(n.mapped, n.mapped_ref)
            when = 'Now disabled' if reuse else 'Now'
            cli = 'nat (%s,%s) %ssource static %s %s%s%s%s' % (ifc, out, _sec(n), name, pub, dst, _opt_cli(opts),
                                                               ' inactive' if reuse else '')
            req = ('Add a static NAT for %s to %s\'s public IP %s%s. %s already has %d NAT line%s in %s, so the block '
                   'moves with it; add it disabled and enable it at outage (it would answer ARP for an address %s '
                   'uses today).' % (addr, self.a, _cidrs(n.mapped), ' (destination translation kept)' if dst else '',
                                     self.b, len(lines), '' if len(lines) == 1 else 's', blk, self.a)) if reuse else \
                'Add a static NAT for %s to %s%s.' % (addr, _cidrs(n.mapped) if n.mapped else n.mapped_ref,
                                                      ' (destination translation kept)' if dst else '')
            self.row(what, when, addr, name, a_line, why, req,
                     ['Devices > NAT > %s > Add Rule: Manual, Static, %s; Source %s -> Destination %s; '
                      'Original Source %s; Translated Source %s%s%s%s.' % (self.ctx.natp, _sec_fmc(n), ifc, out, name,
                                                                            pub, dfmc, _opt_fmc(opts),
                                                                            '; untick Enable' if reuse else '')]
                     + [c for o in objs + pobjs for c in o['cli']] + [cli], 'nat', objs + pobjs)
            self._add('manual-before', 'static', ifc, out, x, pub, n.mapped, name, pat=False)
            return what, what
        self.decisions.append((n, x))
        self.row(what, 'Decision', addr, name, a_line, why,
                 'Choose a %s public IP for %s: %s\'s %s is in %s, and %s has no NAT in that block. Then add a static '
                 'NAT for %s to it.' % (self.b, addr, self.a, _cidrs(n.mapped), blk, self.b, addr),
                 ['Decision: pick a free %s public address and create its object; no command until it is chosen.' %
                  self.b] + [c for o in objs for c in o['cli']], 'nat', objs)
        return what, what

    def missing_vpn(self, n, ifc, out, x, m):
        """A's NAT for its VPN pool, copied as A's rule: same section and options, B's active pool as one object (never
        A's pool object), A's destination part. A PAT out of another interface than B's main path: confirm its use"""
        a_line = ref(n, self.a)
        pool = self.b_pool()
        if pool is not None:
            name, px, objs = pool
        else:
            (name, objs), px = self.obj(x, n.real_ref), x
        addr = _cidrs(px)
        dst, dfmc, dobjs = self.dst_clause(n)
        opts = _opts(n)
        if n.kind == 'dynamic':
            mapped = self.sibling_pat(ifc, out)
            mobjs = []
        elif n.mapped is not None and n.mapped == n.real:
            mapped, mobjs = name, []
        else:
            mapped, mobjs = self.obj(n.mapped, n.mapped_ref) if n.mapped is not None else (n.mapped_ref, [])
        main = self.main_out()
        confirm = n.kind == 'dynamic' and out in self.outs_b and out != main
        cli = 'nat (%s,%s) %ssource %s %s %s%s%s inactive' % (
            ifc, out, _sec(n) or ('after-auto ' if n.section == 'auto' else ''), n.kind, name, mapped, dst, _opt_cli(opts))
        req = 'Add %s\'s NAT for the VPN pool on %s: %s (%s\'s pool) from %s to %s%s, disabled; enable it at outage ' \
              '(%s\'s VPN users use this pool today).' % (self.a, self.b, name, self.b, ifc, out,
                                                       ' with the same destination translation' if dst else '', self.b)
        if confirm:
            req = '%s also translates its VPN pool out of %s, but %s\'s main path is %s (its default route). Confirm ' \
                  'that VPN users need this on %s before adding it. Then: %s' % (self.a, out, self.b, main, out, req)
        self.row('Missing VPN NAT', 'Confirm use' if confirm else 'Now disabled', addr, name, a_line,
                 ref(m, self.b) if m else '(none)', req,
                 ['Devices > NAT > %s > Add Rule: Manual, %s, %s; Source %s -> Destination %s; Original Source %s; '
                  'Translated Source %s%s%s; untick Enable.' % (
                      self.ctx.natp, n.kind.title(), _sec_fmc(n) if n.section != 'auto' else 'After Auto NAT', ifc, out,
                      name, 'Destination Interface IP' if mapped == 'interface' else mapped, dfmc, _opt_fmc(opts))]
                 + [c for o in objs + mobjs + dobjs for c in o['cli']] + [cli, 'show nat detail | include %s' % name],
                 'nat', objs + mobjs + dobjs)
        return 'Missing VPN NAT', 'Missing VPN NAT'

    def missing_internal(self, n, ifc, out, x, m):
        a_line, addr = ref(n, self.a), _cidrs(x)
        name, objs = self.obj(x, n.real_ref)
        pub, pobjs = (n.mapped_ref, []) if n.mapped is None else self.obj(n.mapped, n.mapped_ref)
        arp = n.mapped is not None and any(
            e['kind'] == 'connected' and e['ifc'] == out and n.mapped.overlaps(e['set']) for e in route_table(self.B)) \
            and self.up(out)
        down = not self.up(ifc)          # the host is reached another way today: the NAT would divert its traffic
        sec = _sec(n)
        off = arp or down
        dst, dfmc, dobjs = self.dst_clause(n)
        pobjs = pobjs + dobjs
        opts = _opts(n)
        cli = 'nat (%s,%s) %ssource %s %s %s%s%s%s' % (ifc, out, sec, n.kind, name, pub, dst, _opt_cli(opts),
                                                     ' inactive' if off else '')
        self.row('Missing internal NAT', 'Now disabled' if off else 'Now', addr, name, a_line,
                 ref(m, self.b) if m else '(none)',
                 'Add the internal NAT %s -> %s between %s and %s%s.' % (
                     addr, _cidrs(n.mapped) if n.mapped else n.mapped_ref, ifc, out,
                     ' disabled; enable it at outage (its address is on %s\'s %s subnet, so it would answer ARP '
                     'today)' % (self.b, out) if arp else
                     ' disabled; enable it at outage (%s is shut on %s today, so the NAT would send this traffic '
                     'there)' % (ifc, self.b) if down else ''),
                 ['Devices > NAT > %s > Add Rule: Manual, %s, %s; Source %s -> Destination %s; Original Source %s; '
                  'Translated Source %s%s%s%s.' % (self.ctx.natp, n.kind.title(), _sec_fmc(n), ifc, out, name, pub, dfmc,
                                                   _opt_fmc(opts), '; untick Enable' if off else '')]
                 + [c for o in objs + pobjs for c in o['cli']] + [cli], 'nat', objs + pobjs)
        self._add(n.section if n.section != 'auto' else 'manual-before', n.kind, ifc, out, x, pub, n.mapped, name,
                  pat=n.kind == 'dynamic', dst=n.dst_real if n.dst_real is not None and not n.dst_real.is_any() else None)
        return 'Missing internal NAT', 'Missing internal NAT'

    def missing_hairpin(self, n, ifc, out, x, m):
        a_line, addr = ref(n, self.a), _cidrs(x)
        name, objs = self.obj(x, n.real_ref)
        self.row('Hairpin PAT', 'Confirm use', addr, name, a_line, ref(m, self.b) if m else '(none)',
                 'Confirm the hairpin PAT (%s in and out of %s) is still in use. If yes, add it on %s.' % (
                     addr, n.real_ifc, self.b),
                 ['show nat detail | include %s' % (n.real_ref or addr), 'Check its hit count on %s first.' % self.a],
                 'nat', objs)
        return 'Hairpin PAT', 'Hairpin PAT'

    def missing_exempt(self, n, ifc, out, x, m, because=''):
        """collected per A line and interface pair: one row however many CIDRs and B lines it splits into"""
        k = (id(n), ifc, out)
        if k not in self.exempts:
            self.exempts[k] = {'n': n, 'ifc': ifc, 'out': out, 'parts': [], 'because': []}
        self.exempts[k]['parts'].append((x, m))
        if because and because not in self.exempts[k]['because']:
            self.exempts[k]['because'].append(because)
        return 'Missing NAT exemption', 'Missing NAT exemption'

    def _above(self, ms):
        """'line N' for the first B line (evaluation order) of ms, or 'the proposed rule'"""
        real = [m for m in ms if m is not None and m.line != '(proposed)' and lno(m)]
        if real:
            first = min(real, key=lambda m: (natorder.SECTION.get(m.section, 0), self.b_order(m)))
            return 'line %d' % lno(first)
        return 'the proposed rule'

    def b_order(self, m):
        for i, y in enumerate(self.b_seq):
            if y is m or (y.line == m.line and lno(y) == lno(m)):
                return i
        return len(self.b_seq)

    def a_static_route(self, s, ifc):
        """A has its own static route (not the default) for part of s out of ifc"""
        return any(e['kind'].startswith('static') and e['plen'] > 0 and e['ifc'] == ifc and e['set'].overlaps(s)
                   for e in route_table(self.A))

    def flush_exempts(self):
        for e in self.exempts.values():
            n, ifc, out = e['n'], e['ifc'], e['out']
            x = IPSet()
            for p, m in e['parts']:
                x = x | p
            ms = list({id(m): m for p, m in e['parts'] if m is not None}.values())
            a_line, addr = ref(n, self.a), _cidrs(x)
            name, objs = self.obj(x, '' if x != n.real else n.real_ref)
            dn, dobjs = self.obj(n.dst_real, '') if n.dst_real is not None else ('any', [])
            routed = n.dst_real is None or n.dst_real.is_any() or any(
                i == out for i, p in route_split(self.B, n.dst_real)) or not self.a_static_route(n.dst_real, n.mapped_ifc)
            live = (any(i == ifc for i, p in route_split_up(self.B, x)) and self.up(ifc)) or not self.up(ifc) or \
                any(m.line == '(proposed)' or getattr(m, 'inactive', False) for m in ms) or bool(e['because'])
            above = self._above(ms)
            if e.get('src_obj'):
                name, objs = e['src_obj'], []
                x = e['src_set']
                addr = _cidrs(x)
            dst, dfmc, dobjs2 = self.dst_clause(n)
            if dst:
                dobjs = dobjs2
            opts = _opts(n)
            cli = 'nat (%s,%s) %ssource static %s %s%s%s%s' % (
                ifc, out, _sec(n), name, name, dst, _opt_cli(opts), ' inactive' if live else '')
            when = 'If route needed' if not routed else 'Now disabled' if live else 'Now'
            req = 'Add a NAT exemption for %s -> %s from %s to %s above %s%s.' % (
                addr, _cidrs(n.dst_real) if n.dst_real is not None else 'any', ifc, out, above,
                ', disabled; enable it at outage (%s)' % (
                    'it goes with a fix that is added disabled' if e['because'] else
                    'this traffic flows through %s today' % self.b if self.up(ifc) else
                    '%s is shut on %s today' % (ifc, self.b)) if live else '')
            if not routed:
                req = '%s routes %s another way than %s today, so this only matters if it gets %s\'s route (see ' \
                      'Route on %s). Then: %s' % (self.b, _cidrs(n.dst_real), out, self.a, self.b, req)
            if e['because']:
                req += ' Needed because of the fix: %s.' % '; '.join(e['because'])
            self.row('Missing NAT exemption', when, addr, name, a_line,
                     '%s translates it: %s' % (self.b, '; '.join(ref(m, self.b) if m.line != '(proposed)' else
                                                                 'the proposed rule' for m in ms[:4])), req,
                     ['Devices > NAT > %s > Add Rule: Manual, Static, %s, above %s; Source %s -> Destination %s; '
                      'Original Source %s, Translated Source %s%s%s%s.' % (self.ctx.natp, _sec_fmc(n), above, ifc, out,
                                                                          name, name, dfmc, _opt_fmc(opts),
                                                                          '; untick Enable' if live else '')]
                     + [c for o in objs + dobjs for c in o['cli']] + [cli], 'nat', objs + dobjs,
                     note='second pass' if e['because'] else '')

    def second_pass(self):
        """walk A's exemptions again with the proposed fixes applied: an exemption the fixes make necessary"""
        if not self.fixed:
            return
        seq = []
        for m in self.B.nats:
            ed = next((ifc for k, x, ifc in self.fixed if k == 'edit' and x is m), None)
            if ed:
                c = replace(m, real_ifc=ed)
                c.lineno = lno(m)
                seq.append(c)
            else:
                seq.append(m)
        seq += [x for k, x, ifc in self.fixed if k == 'add']
        seq = order(seq)
        for n in natorder.ordered(self.A):
            if n.inactive or n.real is None or not identity(n) or n.real.is_any():
                continue
            r = next((x for x in self.nat_ref if x['line'] == lno(n) and x['text'] == n.line), None)
            if r is not None and r['result'].startswith(('OK, site', 'Not checked')):
                continue
            out = self.b_ifc(n.mapped_ifc)
            for ifc, part in homes(self.B, n.real, self.b_ifc(n.real_ifc), self.b_in, self.outs_b):
                for c in part.cidrs():
                    x = IPSet.parse(c)
                    before = walk(self.b_seq, x, ifc, out, n.dst_real)
                    after = walk(seq, x, ifc, out, n.dst_real)
                    for (p, m) in after:
                        if m is None or identity(m) or self.b_own(m) or m.line != '(proposed)' and not any(
                                k == 'edit' and getattr(y, 'line', '') == m.line for k, y, i in self.fixed):
                            continue
                        if any(mb is not None and not identity(mb) for pb, mb in before if pb.overlaps(p)):
                            continue          # already reported in the first pass
                        self.missing_exempt(n, ifc, out, p, m, because='%s for %s' % (
                            'the proposed %s' % ('PAT' if m.kind == 'dynamic' else 'NAT') if m.line == '(proposed)' else
                            'the edited line %d' % lno(m), _cidrs(m.real)))
                        r = next((x for x in self.nat_ref if x['line'] == lno(n) and x['text'] == n.line), None)
                        if r is not None:
                            r['result'] = 'Missing NAT exemption (needed because of a fix)'
                            r['gaps'].append('Missing NAT exemption')

    def backhaul(self):
        """B identity NAT above static NATs that would catch traffic to them: a step at outage (moved below them),
        never a removal of a live rule"""
        for t in self.res.get('takeover', []):
            if not t['id'].startswith('T-NATBACK-'):
                continue
            m = next((x for x in self.B.nats if x.real_ref == t['subject'] and identity(x)), None)
            fmc = [x for x in t.get('fmc', [])]
            self.row('Change at outage', 'At outage', _cidrs(m.real) if m else t['subject'], t['subject'], '',
                     ref(m, self.b), t['detail'], fmc + ['Failback: ' + x for x in (t.get('undo') or {}).get('fmc', [])],
                     'nat')

    def shared_block(self):
        """B NAT lines whose public address is in a block routed to A's ISP: one dependency item"""
        b_nets = [IPSet.net('%s/%s' % (i.ip, i.mask)) for i in self.B.interfaces.values() if i.ip and i.nameif in self.outs_b]
        for i in self.A.interfaces.values():
            if not i.ip or i.nameif not in self.outs_a:
                continue
            blk = IPSet.net('%s/%s' % (i.ip, i.mask))
            if not is_public(blk) or any(blk.overlaps(b) for b in b_nets):
                continue
            lines = [m for m in self.b_seq if not m.inactive and m.mapped is not None and not m.mapped.is_any()
                     and m.mapped.overlaps(blk)]
            if not lines:
                continue
            c = blk.cidrs()[0]
            self.row('Public block routed to %s\'s ISP' % self.a, 'At outage', c, '', '%s outside %s' % (self.a, c),
                     '%d %s NAT line%s use %s (e.g. line %d)' % (len(lines), self.b, '' if len(lines) == 1 else 's', c,
                                                               lno(lines[0])),
                     'At outage %s\'s ISP must route %s to %s. packet-tracer cannot prove this: confirm it with the ISP.'
                     % (self.a, c, self.b), ['show route %s' % c.split('/')[0],
                                             'show nat detail | include %s' % c.split('/')[0]], 'other')

    # ------------------------------------------------------------ rules
    def rules(self):
        groups = {}
        for r in self.res.get('rules', []):
            groups.setdefault(r['rule'] or r['rule_id'] or r['id'], []).append(r)
        fnd = {}
        for f in self.res.get('findings', []):
            if f['category'] == 'rules' and f.get('rule') and f.get('level') != 'review':
                fnd.setdefault(f['rule'], f)
        held = {}
        for h in self.res.get('held_rules', []):
            held.setdefault(h['rule'], []).append(h)
        done = set()
        for name, rows in groups.items():
            done.add(name)
            self.rule_name(name, rows, fnd.get(name))
        for name, hs in held.items():
            if name not in done:
                done.add(name)
                self.block_rule(name, [], [x for x in self.A.rules if (x.rule_name or x.rule_id) == name])
        byname = {}
        for x in self.A.rules:
            byname.setdefault(x.rule_name or x.rule_id, []).append(x)
        for name, xs in byname.items():
            if name not in done and any(x.action in PERMIT and not x.inactive and fqdn_names(self.A, x) for x in xs):
                done.add(name)
                self.fqdn_rule(name, xs)
        self.decision_rules(byname, done)
        self.a_blocks(done)
        self.zone_moves()
        self.every_rule(groups, held)
        for r in self.res.get('b_rules', []):
            if r['status'].startswith('over-permitted') and not r.get('row_state'):
                self.review.append({'rule': r['rule'], 'line': lno(r.get('_rule')), 'src': r['src'], 'dst': r['dst'],
                                    'service': r['service'], 'status': '%s allows more than %s' % (self.b, self.a),
                                    'detail': r.get('a_rules', '')})

    def decision_rules(self, byname, done):
        """A inbound rules (not compared) to a host whose public IP is a decision: the allow waits for that choice"""
        seen = set()
        for n, x in self.decisions:
            for r in self.a_inbound(x):
                name = r.rule_name or r.rule_id
                if name in done or name in seen:
                    continue
                seen.add(name)
                xs = [y for y in byname.get(name, []) if not y.inactive]
                self.row('Missing allow', 'Decision', _flow(xs), name, self._lines_ref(xs), '(none)',
                         'Rule "%s" allows inbound traffic to %s, whose public IP on %s is a decision (see Missing '
                         'static NAT). Once the address is chosen, add the allow for %s on %s%s.' % (
                             name, n.real_ref or _cidrs(x), self.b, _cidrs(x), self.b,
                             ' (copy it in FMC with its conditions: it is an L7 rule)' if any(
                                 getattr(y, 'l7', False) for y in xs) else ''),
                         ['Decision: after the public IP for %s is chosen, Policies > Access Control > %s > add rule '
                          '"%s" for %s as on %s.' % (n.real_ref or _cidrs(x), self.ctx.acp, name, _cidrs(x), self.a)],
                         'rule')

    def _rule_line(self, rows):
        x = rows[0]['_rule'] if rows else None
        return ref(x, self.a) + (' (+%d lines)' % (len(rows) - 1) if len(rows) > 1 else '') if x is not None else ''

    def _b_line(self, rows):
        bs = [m for r in rows for m in r.get('_b', [])]
        return ref(bs[0], self.b) if bs else '(none)'

    def rule_name(self, name, rows, f):
        rules = [r['_rule'] for r in rows]
        sts = [r['status'] for r in rows]
        addr = _flow(rules)
        a_line = self._rule_line(rows)
        shows_permit = any(getattr(x, 'orig_action', x.action) in PERMIT for x in rules)
        if block_name(name, self.prof.l7_suspect) and shows_permit and not any(
                getattr(x, 'override', '') == 'permit' for x in rules):
            return self.block_rule(name, rows, rules)
        if all(s == 'covered' for s in sts):
            return
        if self.site_rule(rules):
            return
        l7 = any(getattr(x, 'l7', False) for x in rules)
        if 'compare in FMC' in sts or any(any_any(x) for x in rules) or (l7 and any(_broad(x) for x in rules)):
            add = self.zones_to_add(name, rules)
            self.row('L7 rule', 'Compare in FMC', addr, name, a_line, self._b_line(rows),
                     ('%s has rule "%s" but not on zone%s %s: add %s to it in FMC (keep its other zones and its '
                      'conditions).' % (self.b, name, 's' if len(add) > 1 else '', ', '.join(add), ', '.join(add))
                      if add else
                      'Compare rule "%s" in FMC: its URL, application or other L7 conditions are not in this config. '
                      'Copy it in FMC with its conditions, never as a plain L3/L4 rule.' % name),
                     ['FMC: Policies > Access Control > rule "%s" on %s%s: %sApplications, URLs, Geolocation.' % (
                         name, self.b, ' (compare with %s)' % self.a,
                         'add Zone%s %s; ' % ('s' if len(add) > 1 else '', ', '.join(add)) if add else '')], 'rule')
            return
        fq = rows[0].get('fqdn')
        if fq:
            return self.fqdn_rule(name, rules, f)
        if any(s == 'not compared (FQDN)' for s in sts):
            return
        bad = [r for r in rows if r['status'] not in ('covered',) and not self.mapped_cover(r['_rule'])]
        if not bad:
            return
        cfg, objs = self._fix(f) if f is not None else self._spec(name, bad)
        if f is not None and f.get('edit'):
            self.row('Wrong zone', 'Now', addr, name, a_line, self._b_line(rows) if any(r.get('_b') for r in rows) else
                     ref((bad[0].get('_b_other') or [None])[0], self.b),
                     '%s has rule "%s" for these addresses, but not on the interface where they live on %s (%s). Add '
                     'that zone to the existing rule; keep its other zones. Do not add a new rule.' % (
                         self.b, name, self.b, bad[0]['b_src_ifc']), cfg, 'rule', objs)
            return
        st = max((r['status'] for r in bad), key=lambda s: ('partial', 'missing', 'shadowed', 'denied').index(s)
                 if s in ('partial', 'missing', 'shadowed', 'denied') else 0)
        if st in ('shadowed', 'denied'):
            gap, req = 'Blocked on %s' % self.b, '%s blocks it with an earlier rule (%s). Add the allow above that ' \
                'block.' % (self.b, self._b_line(bad))
        elif st == 'partial':
            gap, req = 'Partial allow', '%s allows only part of rule "%s". Add the rest.' % (self.b, name)
        else:
            gap, req = 'Missing allow', 'Add rule "%s" on %s.' % (name, self.b)
        if not cfg:
            cfg = ['Policies > Access Control > add rule "%s" as on %s (%s -> %s, %s).' % (
                name, self.a, rows[0]['src'], rows[0]['dst'], rows[0]['service'])]
        if l7:
            cfg = [c.replace('Logging: at end of connection.', 'Logging: at end of connection; copy its Applications, '
                             'URLs and other conditions from %s\'s rule in FMC.' % self.a) for c in cfg
                   if not c.startswith('access-list ')]
            req += ' It is an L7 rule: copy it in FMC with its conditions (no LINA line is given).'
        self.row(gap, 'Now', addr, name, a_line, self._b_line(bad), req, cfg, 'rule', objs)

    def _spec(self, name, rows):
        """the access rule alone (no NAT or DNS steps), for a rule folded into a published server finding"""
        from .findings import new_spec, spec_cli, spec_fmc, spec_objects
        rules = [r['_rule'] for r in rows]
        si = list(dict.fromkeys(r['b_src_ifc'].split(', ')[0] for r in rows))
        di = list(dict.fromkeys(r['b_dst_ifc'].split(', ')[0] for r in rows))
        sp = new_spec(self.ctx, name, rules, si, di)
        objs = [o for o in spec_objects(self.ctx, sp) if o['name'] not in self.B.objects]
        return [spec_fmc(self.ctx, sp)] + [c for o in objs for c in o.get('cli', [])] + spec_cli(self.ctx, sp), objs

    def _fix(self, f):
        if f is None:
            return [], []
        objs = list(f['fix'].get('objects', []))
        cfg = list(f['fix'].get('fmc', [])) + [c for o in objs for c in o.get('cli', [])] + list(f['fix'].get('cli', []))
        return cfg, objs

    def fqdn_rule(self, name, rules, f=None):
        """an A FQDN allow, line by line: B's first rule for the line is a block (an L4 deny; an L7 block's LINA line
        cannot prove it stops this traffic) and B has no rule naming the FQDN. One Missing allow row, above that block"""
        groups = self.B.access_groups or {'CSM_FW_ACL_': 'global'}
        blocked, first = [], None
        for x in rules:
            fq = fqdn_names(self.A, x)
            if x.inactive or x.action not in PERMIT or not fq:
                continue
            want = {s: set(v) | {fqdn_value(self.A, n) for n in v if fqdn_value(self.A, n)} for s, v in fq.items()}
            si, di = self.b_ifc(x.src_ifc), self.b_ifc(x.dst_ifc)
            si, di = (None if si == 'any' else si), (None if di == 'any' else di)
            for b in self.B.rules:
                if b.acl not in groups or b.action == 'ignore' or b.inactive:
                    continue
                if not _ifc_ok(b.src_ifc, si) or not _ifc_ok(b.dst_ifc, di) or not b.svc.overlaps(x.svc):
                    continue
                bf = fqdn_names(self.B, b)
                if b.action in PERMIT and all(want[s] & (set(bf.get(s, [])) | {fqdn_value(self.B, n) for n in bf.get(s, [])})
                                              for s in fq):
                    break                                        # B names the same FQDN
                if any(not getattr(x, s).overlaps(getattr(b, s)) for s in ('src', 'dst') if s not in fq):
                    continue
                if any(not getattr(b, s).is_any() and not bf.get(s) for s in fq):
                    continue                                     # a rule for other addresses, not this FQDN
                l7b = b.action != 'deny' and (b.action not in PERMIT or block_name(b.rule_name, self.prof.l7_suspect))
                if l7b and any_any(b):
                    continue                                     # an any-to-any L7 block: its conditions are only in FMC
                if b.action in PERMIT and not l7b:
                    if x.svc.covered_by(b.svc) or b.svc.is_any():
                        break                                    # B allows it with a broader rule
                    continue
                blocked.append(x)
                if first is None or b.seq < first.seq:
                    first = b
                break
        if not blocked:
            return
        names = ', '.join(dict.fromkeys(n for x in blocked for v in fqdn_names(self.A, x).values() for n in v))
        cfg, objs = self._fix(f)
        pos = 'above rule "%s" (line %d)' % (first.rule_name or first.rule_id, lno(first))
        self.row('Missing allow', 'Now', names, name, self._lines_ref(blocked), ref(first, self.b),
                 '%s rule "%s" (line %d) would stop %d of %d line%s of this FQDN allow, and %s has no rule naming %s. '
                 'Add the FQDN allow %s.' % (self.b, first.rule_name or first.rule_id, lno(first), len(blocked),
                                             len([x for x in rules if not x.inactive]),
                                             '' if len(rules) == 1 else 's', self.b, names, pos),
                 cfg or ['Policies > Access Control > %s > Add Rule %s: Name "%s", Action Allow, Zones %s -> %s, '
                         'Networks %s -> %s, Ports %s (all lines of %s\'s rule).' % (
                             self.ctx.acp, pos, name, self.b_ifc(blocked[0].src_ifc), self.b_ifc(blocked[0].dst_ifc),
                             blocked[0].src_ref, blocked[0].dst_ref,
                             ', '.join(dict.fromkeys(x.svc_ref for x in blocked)), self.a)], 'rule', objs)

    def mapped_cover(self, x):
        """A rule line x is covered on B on the zones it maps to: same or broader addresses and ports, rule names
        ignored"""
        from .compare import eval_slice
        si, di = self.b_ifc(x.src_ifc), self.b_ifc(x.dst_ifc)
        st = eval_slice(effective_rules(self.B), None if si == 'any' else si, None if di == 'any' else di,
                        x.src, x.dst, x.svc)
        return st[0] == 'covered'

    def site_rule(self, rules):
        """every source is an ISP edge router or gateway: monitoring of A's own edge, nothing for B"""
        gw = self.gateways()
        return bool(gw) and all(not x.src.is_any() and x.src.issubset(gw) for x in rules)

    def zones_to_add(self, name, rules):
        """B has a rule of this name: the mapped zones of A's lines it lacks"""
        same = [b for b in self.B.rules if not b.inactive and (b.rule_name or '') == name]
        if not same:
            return []
        add = []
        for x in rules:
            if x.inactive:
                continue
            if not any(self.zones_ok(b, x) for b in same):
                for side in ('src_ifc', 'dst_ifc'):
                    z = self.b_ifc(getattr(x, side))
                    if z != 'any' and not any(_any_ifc(getattr(b, side)) or getattr(b, side) == z for b in same) \
                            and z not in add:
                        add.append(z)
        return add

    def block_rule(self, name, rows, rules):
        """a Block* rule whose LINA line shows permit is an L7 block: never covered, shadowed or an allow. Its LINA line
        any to any: compare in FMC. Otherwise it matches only a B block on the same mapped zones that holds its
        addresses and ports"""
        rules = [x for x in (rules or [x for x in self.A.rules if (x.rule_name or x.rule_id) == name]) if not x.inactive]
        if not rules:
            return
        x = rules[0]
        addr = _flow(rules)
        if any(any_any(y) for y in rules):
            same = [b for b in self.B.rules if not b.inactive and (b.rule_name or '') == name]
            if same and all(any(_ace(b.line) == _ace(self._mapped_line(y)) for b in same) for y in rules):
                return                    # the same rule with the same LINA lines on the mapped zones
            site = [b for b in self.B.rules if not b.inactive and b.rule_name and self.site_name(name) == _norm(b.rule_name)
                    and (b.action in ('unknown', 'l7block') or block_name(b.rule_name, self.prof.l7_suspect))]
            if site and all(any(self.zones_ok(b, y) and _ace(b.line) == _ace(self._mapped_line(y)) for b in site)
                            for y in rules):
                return                    # B's block for the mapped site interface, named the same way
            self.row('L7 rule' if same else 'Missing block', 'Compare in FMC', addr, name, self._lines_ref(rules),
                     ref(same[0], self.b) if same else '(none)',
                     'Compare block "%s" in FMC: its LINA line is any to any, so its conditions (applications, URLs, '
                     'countries) are only in FMC. %s' % (name, 'B has a rule of the same name: confirm its zones and '
                                                         'conditions match.' if same else
                                                         'B has no rule of that name: copy it with its conditions.'),
                     ['FMC: Policies > Access Control > rule "%s" on %s and %s: zones, Applications, URLs, '
                      'Geolocation.' % (name, self.a, self.b)], 'rule')
            return
        if all(self.equal_block(y) is not None for y in rules):
            return
        pos = self.position(rules)
        objs = self._block_objs(rules)
        self.row('Missing block', 'Now', addr, name, self._lines_ref(rules), '(no equal block)',
                 '%s blocks this with "%s" (an L7 block: LINA shows permit). %s has no block on the same zones for these '
                 'addresses. Add the same block on %s, %s.' % (self.a, name, self.b, self.b, pos),
                 ['Policies > Access Control > %s > Add Rule %s: Name "%s", Action Block, Zones %s -> %s, Networks %s -> '
                  '%s, Ports %s; copy its Applications, URLs and other conditions from %s\'s rule in FMC.' % (
                      self.ctx.acp, pos, name, self.b_ifc(x.src_ifc), self.b_ifc(x.dst_ifc), x.src_ref, x.dst_ref,
                      x.svc_ref, self.a)] + [c for o in objs for c in o['cli']], 'rule', objs)

    def site_name(self, name):
        """a rule name with A's site interface names replaced by the B interfaces they map to (normalised)"""
        out = _norm(name)
        for a, b in self.imap.items():
            if b and b != 'ignore' and a != b:
                out = re.sub(r'(^|_)%s(_|$)' % re.escape(_norm(a)), lambda m: m.group(1) + _norm(b) + m.group(2), out)
        return out

    def _mapped_line(self, x):
        return re.sub(r'\bifc (\S+)', lambda mm: 'ifc %s' % self.b_ifc(mm.group(1)), x.line)

    def _lines_ref(self, rules):
        return ref(rules[0], self.a) + (' (+%d lines)' % (len(rules) - 1) if len(rules) > 1 else '')

    def zones_ok(self, b, x):
        """B rule b is on the zones A rule x maps to (any on B holds every zone)"""
        for side in ('src_ifc', 'dst_ifc'):
            want = getattr(x, side)
            if _any_ifc(want):
                if not _any_ifc(getattr(b, side)):
                    return False
                continue
            if not _any_ifc(getattr(b, side)) and getattr(b, side) != self.b_ifc(want):
                return False
        return True

    def equal_block(self, x):
        """a B block (deny, L7 block) on the same mapped zones that holds A block line x's addresses and ports"""
        groups = self.B.access_groups or {'CSM_FW_ACL_': 'global'}
        for b in self.B.rules:
            if b.inactive or b.acl not in groups:
                continue
            l7b = b.action in ('unknown', 'l7block') or (b.action in PERMIT and block_name(b.rule_name, self.prof.l7_suspect))
            if b.action != 'deny' and not l7b:
                continue
            if l7b and (not (getattr(x, 'l7', False) or x.action in ('unknown', 'l7block')) or any_any(b)):
                continue                  # an L4 block needs an L4 block; an any-to-any L7 block proves nothing
            if _is_default(b):
                continue                  # the default action sits below every allow: it is not an equal block
            if not self.zones_ok(b, x):
                continue
            if _cover(b, x):
                return b
            rest = x.dst - b.dst
            if rest and _cover(replace(b, dst=b.dst | rest), x) and self.unreachable(rest):
                return b                  # what it lacks B cannot reach anyway
        return None

    def unreachable(self, s):
        """addresses B can only send to the internet by its default route, and that are not routable there (private or
        shared address space), with no VPN (crypto map) that carries them: a block for them changes nothing on B"""
        if is_public(s) or re.search(r'^crypto map \S+ \d+ match address ', self.b_text, re.M):
            return False
        for i, p in route_split(self.B, s):
            if i not in self.outs_b or any(e['plen'] > 0 and e['ifc'] == i and e['set'].overlaps(p)
                                           for e in route_table(self.B)):
                return False
        return True

    def _block_objs(self, rules):
        from .findings import net_objects
        out = []
        for x in rules:
            for nm in list(getattr(x, 'src_names', []) or []) + list(getattr(x, 'dst_names', []) or []):
                for o in net_objects(self.ctx, nm):
                    if o['name'] not in [y['name'] for y in out]:
                        out.append(o)
        return out

    def position(self, rules):
        """in A's order: below the B rules that carry A's narrower allows above this block, then above the first B rule
        that would allow all of this traffic (else part of it), else above B's anchor rule. A broad B allow that holds
        the whole block is never a reason to put the block under it: there it would never match"""
        rules = rules if isinstance(rules, (list, tuple)) else [rules]
        first_a = min(x.seq for x in rules)
        groups = self.B.access_groups or {'CSM_FW_ACL_': 'global'}
        allows = [b for b in self.B.rules if not b.inactive and b.acl in groups and b.action in PERMIT and
                  not block_name(b.rule_name, self.prof.l7_suspect) and not tunnel_default(b)]

        def hits(b, full):
            return any(self.zones_ok(b, x) and (_cover(b, x) if full else (
                b.src.overlaps(x.src) and b.dst.overlaps(x.dst) and b.svc.overlaps(x.svc))) for x in rules)
        def same_zones(a, x):
            return all(_any_ifc(getattr(a, k)) or _any_ifc(getattr(x, k)) or getattr(a, k) == getattr(x, k)
                       for k in ('src_ifc', 'dst_ifc'))

        def above(a):                     # an A allow before the block in A's order that takes some of its traffic
            return a.action in PERMIT and a.acl == rules[0].acl and a.seq < first_a and any(
                same_zones(a, x) and a.src.overlaps(x.src) and a.dst.overlaps(x.dst) and a.svc.overlaps(x.svc)
                for x in rules)
        carriers = [(m, r['_rule']) for r in self.res.get('rules', []) if above(r['_rule']) for m in r.get('_b', [])
                    if m in allows and hits(m, False) and not hits(m, True) and m.src.overlaps(r['_rule'].src)
                    and m.dst.overlaps(r['_rule'].dst) and m.svc.overlaps(r['_rule'].svc)]
        last, a_allow = max(carriers, key=lambda c: c[0].seq) if carriers else (None, None)
        below = ('below rule "%s" (line %d), which carries %s\'s allow "%s" (line %d, above this block on %s), and ' % (
            last.rule_name or last.rule_id, lno(last), self.a, a_allow.rule_name or a_allow.rule_id, lno(a_allow),
            self.a)) if last is not None else ''
        after = [b for b in allows if last is None or b.seq > last.seq]
        first = next((b for b in after if hits(b, False)), None)
        if first is not None:
            txt = '%sabove rule "%s" (line %d), the first %s rule that would allow %s traffic' % (
                below, first.rule_name or first.rule_id, lno(first), self.b, 'this' if hits(first, True) else 'part of this')
            if not hits(first, True):
                full = next((b for b in after if b.seq > first.seq and hits(b, True)), None)
                if full is not None:
                    txt += ', and so also above rule "%s" (line %d), which allows all of it' % (
                        full.rule_name or full.rule_id, lno(full))
            return txt
        if last is not None:
            return below[:-len(', and ')]
        name, sect = self.ctx.anchor
        return 'above rule "%s"' % name if name else 'at the top of the Mandatory section'

    def a_blocks(self, done):
        """A L4 blocks with no equal block on B (firewide check), with their position and objects"""
        for r in self.res.get('firewide', []):
            if not r['id'].startswith('FW-D-'):
                continue
            rs = r.get('_rules') or []
            if not rs:
                continue
            rs = [y for y in rs if not y.inactive]
            if not rs or all(self.equal_block(y) is not None for y in rs) or self.site_rule(rs):
                continue
            x = rs[0]
            pos = self.position(rs)
            objs = self._block_objs(rs)
            cli = []
            for y in rs[:8]:
                line = re.sub(r'\bifc (\S+)', lambda mm: 'ifc %s' % self.b_ifc(mm.group(1)), y.line)
                cli.append(re.sub(r'\s+rule-id \d+.*$', '', line))
            deps = r.get('deps') or []
            req = 'Add the same block on %s, %s.' % (self.b, pos)
            if deps:
                req += ' On %s, rule%s %s above this block take%s part of its traffic first: check that %s still ' \
                       'lets that traffic through above the new block.' % (
                           self.a, 's' if len(deps) > 1 else '', ', '.join('"%s"' % d['rule'] for d in deps[:4]),
                           '' if len(deps) > 1 else 's', self.b)
            self.row('Missing block', 'Now', _flow(rs), r['item'], ref(x, self.a),
                     '(no equal block)', req,
                     ['Policies > Access Control > %s > Add Rule %s: Name "%s", Action Block, the same zones, networks '
                      'and ports.' % (self.ctx.acp, pos, r['item'])] + [c for o in objs for c in o['cli']] + cli,
                     'rule', objs)

    def zone_moves(self):
        """B rules whose source moves to another interface at takeover: add the zone, keep the old one"""
        for r in self.res.get('firewide', []):
            if r.get('status') != 'add zone':
                continue
            b = next((x for x in self.B.rules if (x.rule_name or x.rule_id) == r['item']), None)
            need = self.zone_needed(b, r.get('add_zone') or [])
            if b is None or not need:
                continue                  # no A rule needs the zone on this B rule: never a Wrong zone
            self.row('Wrong zone', 'Now', b.src_ref if b else '', r['item'], '', ref(b, self.b),
                     'Add Source Zone %s to rule "%s" and keep %s: %s.' % (', '.join(r['add_zone']), r['item'],
                                                                           r.get('src_ifc'), r['detail']),
                     ['Policies > Access Control > %s > edit rule "%s": add Source Zone %s; keep %s.' % (
                         self.ctx.acp, r['item'], ', '.join(r['add_zone']), r.get('src_ifc'))], 'rule')

    def zone_needed(self, b, zones):
        """A rules B does not carry today whose traffic, on B's own path, rule b would carry once a zone is added"""
        out = []
        for x in self.res.get('rules', []):
            if x['status'] == 'covered' or x.get('b_src_ifc') not in zones or x.get('fqdn') or \
                    not x['_rule'].src or not x['_rule'].dst:
                continue
            if not _any_ifc(b.dst_ifc) and b.dst_ifc != x.get('b_dst_ifc'):
                continue
            if b.action in PERMIT and _cover(b, x['_rule']):
                out.append(x)
        return out

    def every_rule(self, groups, held):
        """reference: every A rule name, also those with no active lines"""
        names = {}
        for x in self.A.rules:
            names.setdefault(x.rule_name or x.rule_id or 'line %d' % lno(x), []).append(x)
        for m in re.finditer(r'^access-list \S+ remark rule-id (\d+): (?:L[47] RULE|RULE): (.*)$', self.a_text, re.M):
            names.setdefault(m.group(2).strip(), [])
        gaps = {}
        for r in self.rows:
            if r['kind'] == 'rule':
                gaps.setdefault(r['object'], []).append(r['gap'])
        for name, xs in names.items():
            rows = groups.get(name, [])
            lines = ', '.join(str(lno(x)) for x in xs[:6]) + (' (+%d)' % (len(xs) - 6) if len(xs) > 6 else '')
            if not xs:
                res = 'No lines in this config (empty rule, or not deployed)'
            elif all(x.inactive for x in xs):
                res = 'No active lines (inactive)'
            elif name in gaps:
                res = ', '.join(dict.fromkeys(gaps[name]))
            elif rows and all(r['status'] == 'covered' for r in rows):
                res = 'OK' + (', confirm in FMC' if any(r.get('confirm_fmc') for r in rows) else '')
            elif rows:
                res = 'OK (%s)' % ', '.join(dict.fromkeys(r['status'] for r in rows))
            elif name in held:
                res = 'OK, %s has an equal block' % self.b if block_name(name) else held[name][0]['status']
            elif all(x.action not in PERMIT for x in xs):
                res = 'Block: OK (equal block on %s)' % self.b
            else:
                res = 'Not compared (outside the networks checked)'
            bm = sorted({m for r in rows for m in r.get('b_rules', [])})
            self.rule_ref.append({'rule': name, 'lines': lines, 'action': xs[0].action if xs else '',
                                  'b_match': ', '.join(bm[:4]) or '', 'result': res})

    # ------------------------------------------------------------ other checks
    def routes(self):
        """a network B would route another way than A: a route, if B does not learn one. A next hop B does not know
        is taken from A's route when it is on B's subnet, else it is a decision"""
        for f in self.res.get('findings', []):
            if f['category'] != 'routing' or f.get('level') == 'review' or not f['fix']['cli']:
                continue
            cli, when = [], 'If route needed'
            for c in f['fix']['cli']:
                m = re.match(r'^route (\S+) (\S+) (\S+) <next hop on \S+>(.*)$', c)
                if m:
                    nh = self._a_nexthop(m.group(1), m.group(2), m.group(3))
                    if nh is None:
                        when = 'Decision'
                        continue
                    c = 'route %s %s %s %s%s' % (m.group(1), m.group(2), m.group(3), nh, m.group(4))
                cli.append(c)
            ev = [e for e in f.get('evidence', []) if e.get('device') == self.n['A']]
            self.row('Route on %s' % self.b, when, f.get('subject') or f['scope'], '',
                     '%s %s: %s' % (self.a, ev[0]['line'], ev[0]['text']) if ev else '', f.get('plain_status', ''),
                     f['what'] + (' Choose the next hop on %s.' % self.b if when == 'Decision' else
                                  ' Add it unless %s learns this route.' % self.b),
                     [x for x in f['fix']['fmc'] if '<next hop' not in x and 'NAT exemption' not in x] +
                     [c for c in cli if not c.lstrip().startswith(('nat ', 'no nat '))], 'route')
            # the NAT a route depends on is judged by the NAT walk (its own rows), not copied here

    def _a_nexthop(self, ifc, net, mask):
        try:
            want = ipaddress.IPv4Network('%s/%s' % (net, mask), strict=False)
        except ValueError:
            return None
        for r in self.A.routes:
            try:
                if ipaddress.IPv4Network('%s/%s' % (r.network, r.mask), strict=False) != want:
                    continue
                nh = ipaddress.IPv4Address(r.nexthop)
            except ValueError:
                continue
            i = self.B.interfaces.get(ifc)
            if i is not None and i.ip and nh in ipaddress.IPv4Network('%s/%s' % (i.ip, i.mask), strict=False):
                return str(nh)
        return None

    def ospf_default(self):
        for m in re.finditer(r'^router ospf (\S+)\n((?: .*\n?)*)', self.a_text, re.M):
            if re.search(r'^ default-information originate always', m.group(2), re.M):
                no = self.a_text[:m.start()].count('\n') + 1 + next(
                    i for i, l in enumerate(m.group(2).split('\n'), 1) if l.startswith(' default-information originate always'))
                self.row('Default route always advertised by %s' % self.a, 'At outage', '0.0.0.0/0', 'router ospf %s' %
                         m.group(1), '%s %d: default-information originate always' % (self.a, no), '',
                         'With %s\'s firewalls up and its internet down, OSPF keeps sending inside traffic to %s. At '
                         'outage shut %s\'s shared inside interfaces first (or stop the OSPF default) so traffic moves to %s.'
                         % (self.a, self.a, self.a, self.b),
                         ['On %s at outage: router ospf %s / no default-information originate always, or shut the '
                          'shared interfaces.' % (self.a, m.group(1)),
                          'Later: default-information originate without "always", so the default follows %s\'s '
                          'tracked default route.' % self.a], 'other')

    def shared_ifcs(self):
        """[(A nameif, B nameif)]: the same IP address and subnet on both firewalls (compared by address, not by name),
        with B's copy shut until takeover. The same addresses up on both are two separate site networks"""
        out = []
        for a in self.A.interfaces.values():
            if not a.ip or not a.mask or a.shutdown or a.nameif in (self.A.ignored or ()):
                continue
            for b in self.B.interfaces.values():
                if b.ip == a.ip and b.mask == a.mask and (b.shutdown or b.planned):
                    out.append((a.nameif, b.nameif))
        return out

    def outage(self):
        shared = self.shared_ifcs()
        steps1 = ['Shut %s\'s shared interfaces first (same address and subnet as a shut %s interface): %s.' % (
            self.a, self.b, ', '.join(a for a, b in shared) or 'none found')] + \
            ['interface %s / shutdown (on %s)' % (self.A.interfaces[a].name, self.a) for a, b in shared] + \
            ['interface %s / no shutdown (on %s)' % (self.B.interfaces[b].name, self.b) for a, b in shared]
        at = [r for r in self.rows if r['when'] in ('Now disabled', 'At outage')]
        common = ['Do every "Now disabled" and "At outage" row (%d).' % len(at),
                  'Check with packet-tracer on %s, then move DNS and the ISP route for shared blocks.' % self.b]
        self.cases = [{'case': '%s internet down, firewalls up' % self.a, 'steps': steps1 + common},
                      {'case': '%s firewalls lost' % self.a, 'steps': common}]

    def object_list(self):
        """every object a gap needs, and the A objects missing on B that no gap uses"""
        out = []
        for name, o in self.objects.items():
            out.append({'name': name, 'type': o.get('type', ''), 'value': o.get('value', ''), 'status': 'needed',
                        'used_by': ', '.join(dict.fromkeys(o['used_by']))})
        for r in self.res.get('objects', []):
            if r.get('status') not in ('missing', 'missing on B') or r['name'] in self.objects:
                continue
            out.append({'name': r['name'], 'type': r.get('kind', ''), 'value': r.get('value', ''),
                        'status': 'not needed (no gap uses it)', 'used_by': ''})
        return out

    def build(self):
        self.nats()
        self.rules()
        self.routes()
        self.ospf_default()
        self.outage()
        rows = sorted(self.rows, key=lambda r: (WHEN.index(r['when']), r['gap'], r['address']))
        for i, r in enumerate(rows, 1):
            r['id'] = 'G%d' % i
        counts = Counter(r['when'] for r in rows)
        fix = counts['Now'] + counts['Now disabled']
        text = ('%s has no gaps compared to %s.' % (self.b, self.a) if not rows else
                '%d gap%s: ' % (len(rows), '' if len(rows) == 1 else 's') + ', '.join(
                    '%d %s' % (counts[w], w) for w in WHEN if counts[w]) + '.')
        not_hit = sum(1 for x in self.nat_ref if 'not hit on' in x['result'])
        return {'rows': rows, 'cols': COLS, 'counts': {w: counts[w] for w in WHEN if counts[w]}, 'total': len(rows),
                'stats': {'not_hit_on_a': not_hit, 'a_dynamic_routing': bool(self.A.dynamic_routing)},
                'verdict': {'ready': fix == 0, 'text': text}, 'nat_ref': self.nat_ref, 'rule_ref': self.rule_ref,
                'review': self.review, 'objects': self.object_list(), 'outage': self.cases}


def _broad(x):
    """the LINA line is broad: any (also a narrowed any) or a /8-size range on a side"""
    from .compare import BROAD, _any_side
    return any(_any_side(getattr(x, k), getattr(x, k + '_ref')) or getattr(x, k).size() >= BROAD for k in ('src', 'dst'))


def _flow(rules):
    """'10.1.0.0/24 -> any' for the addresses of rule lines (as they are judged on B)"""
    from .compare import _any_side

    def side(k):
        v = IPSet()
        for x in rules:
            if _any_side(getattr(x, k), getattr(x, k + '_ref')):
                return 'any'
            v = v | getattr(x, k)
        return _cidrs(v) if v else 'none'
    return '%s -> %s' % (side('src'), side('dst'))


OPTS = ('dns', 'unidirectional', 'no-proxy-arp', 'route-lookup')
OPT_FMC = {'dns': 'tick Translate DNS replies', 'unidirectional': 'tick Unidirectional',
           'no-proxy-arp': 'tick Do not proxy ARP on Destination Interface',
           'route-lookup': 'tick Perform Route Lookup for Destination Interface'}


def _opts(n):
    """the NAT options A's line has (copied as they are, none added)"""
    t = (n.line or '').split(' description ')[0].split()
    return [o for o in OPTS if o in t]


def _opt_cli(opts):
    return ''.join(' ' + o for o in opts)


def _opt_fmc(opts):
    return ''.join('; ' + OPT_FMC[o] for o in opts)


def _sec(n):
    return 'after-auto ' if n.section == 'manual-after' else ''


def _sec_fmc(n):
    return 'After Auto NAT' if n.section == 'manual-after' else 'Before Auto NAT'


def _norm(name):
    return re.sub(r'[\s_\-]+', '_', (name or '').lower()).strip('_')


def _ace(line):
    """an access-list line without its rule-id and logging tail, for comparing the same rule on two firewalls"""
    return re.sub(r'\s+rule-id \d+.*$', '', line or '').strip()


def _host(s):
    from .findings import sample
    return sample(s)


def _cover(b, x):
    """B rule b holds A rule x's traffic: addresses (any by reference) and service"""
    from .compare import _any_side
    for s in ('src', 'dst'):
        bs, xs = getattr(b, s), getattr(x, s)
        if not (_any_side(bs, getattr(b, s + '_ref')) or xs.issubset(bs)):
            return False
    return x.svc.covered_by(b.svc) or b.svc.is_any()


def build(res, prof, A, B, info, a_text='', b_text=''):
    g = Gaps(res, prof, A, B, info, a_text, b_text)
    res['gaplist'] = g.build()
    return res['gaplist']


def align_verdict(res):
    """the top verdict is the gap list's: the older runbook keeps its items, but its own counts are not a verdict"""
    g, v = res.get('gaplist'), res.get('verdict')
    if not g or not isinstance(v, dict) or 'text' not in v:
        return
    v['runbook_text'] = v['text']
    v['ready'] = g['verdict']['ready']
    v['text'] = g['verdict']['text'] + ' This is the gap list\'s verdict; the older views below keep their items for ' \
        'reference only.'
    if res.get('go_nogo'):
        v['text'] += ' Go/no-go: %s.' % '; '.join(x.split(': ', 1)[1] for x in res['go_nogo'])


def config_lines(gl):
    return [c for r in gl['rows'] for c in r['config']]


def unsafe(gl, B=None):
    """lines a gap list must never hold: any-to-any permits, a Block* rule as an allow, placeholder public objects,
    'no nat' on a B rule that carries traffic today"""
    from . import safety
    out = []
    live = set()
    if B is not None:
        for m in B.nats:
            if not m.inactive and (_any_ifc(m.real_ifc) or any(i == m.real_ifc for i, x in route_split_up(B, m.real or IPSet()))):
                live.add(m.line)
    for r in gl['rows']:
        for c in r['config']:
            if safety.bad(c):
                out.append(('any-to-any', c))
            if PLACEHOLDER.search(c):
                out.append(('placeholder', c))
            if c.startswith('no nat') and (B is None or c[3:] in live):
                out.append(('no nat on a live rule', c))
            if block_name(r['object']) and re.search(r'Action Allow|\bpermit\b', c):
                out.append(('block as allow', c))
    return out
