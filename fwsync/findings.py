"""Findings view (0.4.0, 0.4.1): turns the compare tables into findings an engineer can act on.
Each finding: what (one sentence), why it matters, evidence (config lines with line numbers), fix (FMC steps, LINA
reference CLI, objects to create first), verify (packet-tracer / show), state (open | fix | not needed | later).
Also: readiness cards per scope subnet, decisions the tool cannot make, and the remediation plan (state = fix)."""
import hashlib
import ipaddress
import re

from . import natorder
from .netset import IPSet, Service

ORDER = {'routing': 0, 'pat': 1, 'inbound': 2, 'rules': 3, 'objects': 4}
GROUPS = ['Objects', 'Routing', 'NAT', 'Access Control', 'DNS']
FQDN = re.compile(r'([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.[A-Za-z]{2,})')
TEST_NAME = re.compile(r'(?i)(^|[^a-z])(test|tst|qa|dev)([^a-z]|$)|test')
VERIFY_NAME = re.compile(r'(?i)\[\s*0 hits\s*\]|\[\s*verify\s*\]')
FLOATING = 250
NOT_A_NAME = re.compile(r'(?i)^(obj|net|grp|host|range|pat|nat)[-_]|no_?nat|^(FMC|DM)_INLINE|^\d+\.\d+\.\d+\.\d+(/\d+)?$')
LEVELS = ('fix', 'choice', 'check', 'review')          # thing to fix, your choice needed, check on the firewall, review later

GLOSSARY = {
    'covered': 'Same on both: {B} permits all of this traffic.',
    'partial': 'Only partly allowed: {B} permits only part of this traffic (some addresses or ports are missing).',
    'shadowed': 'Blocked by an earlier rule: an earlier {B} rule blocks this traffic before a permit is reached.',
    'denied': '{B} has a rule that blocks this traffic.',
    'missing': '{B} has no rule for this traffic; its default action drops it.',
    'wrong way': '{B} uses a different path than {A}: it would send this network to the internet, not inside.',
    'no route on B': '{B} has no route for this subnet.',
    'other inside interface': '{B} routes this subnet inside, but out of a different inside interface.',
    'ok': 'Ready.',
    'over-permitted': '{B} allows more than {A}.',
    'over-permitted (partial)': '{B} allows part of this traffic that {A} does not.',
    'also on A': '{A} allows this traffic too.',
    'inactive on B': '{B} has the NAT but it is disabled.',
    'match': '{B} has the same NAT.',
    'mapped conflict': 'The public IP is already used by a different inside host on {B}.',
    'mapped reuse': '{B} uses the same public IP as {A} (only valid when both share the public subnet).',
    'mapped outside B public': "{B}'s NAT uses a public IP outside {B}'s public ranges.",
    'differs': '{B} has a NAT for this host, but with different addresses.',
    'action unknown (L7)': 'The rule has application/URL/user conditions; its real action (allow or block) is only in FMC.',
    'blocked (L7)': 'Marked as a block rule: left out of the compare and the plan.',
    'B only': 'Only {B} has this.',
    'same name, different value': 'The object exists on both, but {B} lacks addresses that {A} has.',
    'B has extra entries': '{B} has every address {A} has, plus more.',
}

# what users read instead of the internal status values (JSON keys and CSV values keep the internal ones)
LABELS = {
    'covered': 'same on both',
    'partial': 'only partly allowed',
    'shadowed': 'blocked by an earlier rule',
    'wrong way': 'uses a different path than {A}',
    'over-permitted': '{B} allows more than {A}',
    'over-permitted (partial)': '{B} allows more than {A} (in part)',
    'other inside interface': 'uses a different inside interface than {A}',
    'Decision needed': 'your choice needed',
}

HOW_TO_READ = [
    ('Ready', 'Nothing in this config stops {B} from carrying this network when {A} fails.'),
    ('Not ready', 'At least one thing must be fixed (or chosen) on {B} before failover.'),
    ('Check on firewall', 'The config cannot prove it, for example a route {B} may learn by OSPF. Run the shown command '
                          'on {B}; it tells you whether a change is needed.'),
    ('Thing to fix', 'A change to make on {B} in FMC. Each one lists the FMC path, the CLI and how to verify it.'),
    ('Your choice needed', 'The tool cannot decide, for example whether to keep a public IP. Pick an option; the '
                           'choice is saved in the profile.'),
    ('Scope', 'The networks checked: every subnet {A} serves, unless you changed the list in Setup.'),
    ('Translated address', "A site-specific {A} address rewritten into {B}'s matching address, so both are compared "
                           "as they must be on {B}."),
]


def plain(status, names):
    return GLOSSARY.get(status, status).format(A=names['A'], B=names['B'])


def named(text, names):
    """'inactive on B', 'earlier B deny x' -> the real firewall names (only for status and detail strings)"""
    a, b = names.get('A_short', names['A']), names.get('B_short', names['B'])
    return re.sub(r'(?<![\w.-])([AB])(?![\w.-])', lambda m: a if m.group(1) == 'A' else b, str(text))


def label(status, names):
    """user-facing text for an internal status value"""
    if status in LABELS:
        return LABELS[status].format(A=names.get('A_short', names['A']), B=names.get('B_short', names['B']))
    return named(status, names)


def many(n, one, more):
    return '%d %s' % (n, one if n == 1 else more)


def _key(*parts):
    return hashlib.sha1('|'.join(str(p) for p in parts).encode()).hexdigest()[:12]


def device_names(prof, A, B, info):
    n = dict(prof.names or {})
    chain = info.get('chain')
    if chain:
        n.setdefault('A1', 'Edge (%s)' % chain['edge'].rsplit('.', 1)[0])
        n.setdefault('A2', 'DC firewall (%s)' % chain['inner'].rsplit('.', 1)[0])
        n.setdefault('A', '%s + %s' % (n['A1'].split(' (')[0], n['A2'].split(' (')[0]))
    n.setdefault('A', A.hostname or A.name)
    n.setdefault('B', B.hostname or B.name)
    n.setdefault('A1', n['A'])
    n.setdefault('A2', n['A'])
    n['A_short'] = n.get('A_short', n['A'].split(' (')[0])
    n['B_short'] = n.get('B_short', n['B'].split(' (')[0])
    return n


def host_name(ref, desc=''):
    for t in (ref or '', desc or ''):
        m = FQDN.search(t)
        if m:
            return m.group(1)
    return ref or desc


def sample(ipset):
    if ipset is None or not ipset.iv:
        return '192.0.2.1'
    a, b = ipset.iv[0]
    return str(ipaddress.IPv4Address(a + 1 if b - a >= 2 else a))


def port_of(svc):
    for p, d, s in getattr(svc, 'items', []):
        if p in ('tcp', 'udp') and not d.is_any():
            return p, d.iv[0][0]
        if p in ('tcp', 'udp'):
            return p, 443
        if p == 'icmp':
            return 'icmp', None
    return 'tcp', 443


def tracer(ifc, svc, src, dst):
    p, port = port_of(svc)
    if p == 'icmp':
        return 'packet-tracer input %s icmp %s 8 0 %s' % (ifc, src, dst)
    return 'packet-tracer input %s %s %s 40000 %s %s' % (ifc, p, src, dst, port)


def acl_lines(svc, si, src, di, dst, limit=12):
    """one LINA ACL line per protocol / port range"""
    out = []
    if svc is None or svc.is_any():
        return ['access-list CSM_FW_ACL_ advanced permit ip ifc %s %s ifc %s %s' % (si, src, di, dst)]
    for p, d, s in svc.items:
        if p in ('tcp', 'udp'):
            for a, b in (d.iv if not d.is_any() else [(0, 65535)]):
                port = '' if (a, b) == (0, 65535) else (' eq %d' % a if a == b else ' range %d %d' % (a, b))
                out.append('access-list CSM_FW_ACL_ advanced permit %s ifc %s %s ifc %s %s%s' % (p, si, src, di, dst, port))
        else:
            out.append('access-list CSM_FW_ACL_ advanced permit %s ifc %s %s ifc %s %s' % (p, si, src, di, dst))
    out = list(dict.fromkeys(out))
    return out[:limit] + (['! ... %d more lines' % (len(out) - limit)] if len(out) > limit else [])


def ports_text(svc):
    """'tcp 80, 443, 8444; icmp' from a Service"""
    if svc is None or svc.is_any():
        return 'all ports'
    by = {}
    for p, d, s in svc.items:
        if p in ('tcp', 'udp'):
            by.setdefault(p, [])
            by[p] += ['%d' % a if a == b else '%d-%d' % (a, b) for a, b in d.iv] if not d.is_any() else ['any']
        else:
            by.setdefault(p, [])
    return '; '.join('%s %s' % (p, ', '.join(sorted(set(v), key=lambda x: int(x.split('-')[0]) if x[0].isdigit() else 0)))
                     if v else p for p, v in sorted(by.items()))


def ev(device, obj, fallback=''):
    """evidence line: (device name, line number, text)"""
    if obj is None:
        return None
    return {'device': device, 'line': getattr(obj, 'lineno', 0) or 0, 'text': getattr(obj, 'line', '') or fallback}


def obj_line(name, ipset):
    hosts = ipset.hosts()
    if len(ipset.iv) == 1 and hosts:
        return {'name': name, 'type': 'Host', 'value': hosts[0], 'cli': ['object network %s' % name, ' host %s' % hosts[0]]}
    c = ipset.cidrs()
    if len(c) == 1:
        n = ipaddress.IPv4Network(c[0])
        return {'name': name, 'type': 'Network', 'value': c[0],
                'cli': ['object network %s' % name, ' subnet %s %s' % (n.network_address, n.netmask)]}
    return {'name': name, 'type': 'Group', 'value': ', '.join(c[:8]),
            'cli': ['object-group network %s' % name] + [' network-object %s' % x for x in c[:8]]}


def safe(name):
    return re.sub(r'[^A-Za-z0-9_.\-]', '_', name)[:60]


class Ctx:
    def __init__(self, res, prof, A, B, info):
        self.res, self.prof, self.A, self.B, self.info = res, prof, A, B, info
        self.n = device_names(prof, A, B, info)
        self.acp = prof.fmc.get('access_policy') or self._acp_name() or '<%s access policy>' % self.n['B_short']
        self.natp = prof.fmc.get('nat_policy') or '<%s NAT policy>' % self.n['B_short']
        outs = prof.outside_b or ['OUTSIDE']
        self.b_out = outs[0]
        ins = [v for k, v in prof.interface_map.items() if v not in outs and v != 'ignore']
        self.b_in = max(set(ins), key=ins.count) if ins else 'INSIDE'
        self.outs_a = set(prof.outside_a or [n for n in A.interfaces if 'out' in n.lower()])
        self.pub_reals = IPSet()
        for i in res.get('inbound', []):
            self.pub_reals = self.pub_reals | IPSet.parse(i['real'])
        self.anchor = self._anchor()
        self.specs = {}
        self.owned_map = {r['subnet']: r['b_own'] for r in res.get('routing', []) if r.get('b_own')}

    def _anchor(self):
        """first broad B access permit (e.g. Site-Default-Out) and its section: new rules go above it"""
        for r in self.B.rules:
            if getattr(r, 'policy_kind', 'access') != 'access' and 'Mandatory' not in (r.policy or '') and \
                    'Default' not in (r.policy or ''):
                continue
            if r.action in ('permit', 'trust') and r.rule_name and not r.rule_name.upper().startswith('DEFAULT ') and \
                    (r.src.is_any() or r.dst.is_any()):
                return r.rule_name, 'Default' if (r.policy or '').endswith('Default') else 'Mandatory'
        return '', ''

    def _acp_name(self):
        names = [re.sub(r'\s+-\s+(Mandatory|Default)$', '', r.policy) for r in self.B.rules
                 if r.policy and getattr(r, 'policy_kind', '') == 'access']
        return max(set(names), key=names.count) if names else ''

    def dev(self, tag):
        return self.n.get(tag, self.n['A']) if tag else self.n['A']

    def b_nexthop(self, ifc):
        """next hop of the lowest-distance route on ifc, broadest non-default route first; never a floating route
        (distance 250+, or a backup for a prefix that another route already carries with a lower distance)"""
        from .detect import route_table
        rt = [r for r in route_table(self.B) if r['kind'] != 'connected']
        best = {}
        for r in rt:
            best[r['net']] = min(best.get(r['net'], FLOATING), r['distance'])
        good = [r for r in rt if r['ifc'] == ifc and r['nexthop'] and r['nexthop'] != 'planned'
                and r['distance'] < FLOATING and r['distance'] <= best[r['net']]]
        if not good:
            return '<next hop on %s>' % ifc
        return min(good, key=lambda r: (r['distance'], r['plen'] == 0, r['plen']))['nexthop']

    def label(self, p):
        return self.prof.scope_names.get(p, p)

    def name(self, p):
        """a real name for p, or '': route labels ('via inside') and object names (obj-NO_NAT-x) are not names"""
        n = self.prof.scope_names.get(p, '') or ''
        n = re.sub(r'\(A (\S+)\)', lambda m: '(%s on %s)' % (m.group(1), self.n['A_short']), n)
        n = re.sub(r'\bvia \S+', '', n)
        n = re.sub(r'\b(A[12]):(\S+)', lambda m: '%s on %s' % (m.group(2), self.n.get(m.group(1), m.group(1)).split(' (')[0]), n)
        n = ' '.join(w for w in n.split() if not NOT_A_NAME.search(w.strip('(),')))
        n = re.sub(r'\(\s*\)', '', n).strip(' ,')
        return '' if not n or n == p else n

    def title(self, p):
        """'192.0.2.0/24 (VLAN 20 dmz)': the subnet first, then a real name if there is one"""
        n = self.name(p)
        return '%s (%s)' % (p, n) if n else p

    def kind(self, p):
        """'VLAN' only for a connected subnet; 'host' for a /32; otherwise 'network'"""
        from .detect import route_table
        net = ipaddress.IPv4Network(p, strict=False)
        if net.prefixlen == 32:
            return 'host'
        conn = any(e['net'] == str(net) and e['kind'] == 'connected' for cfg in (self.A, self.B) for e in route_table(cfg))
        return 'VLAN' if conn else 'network'

    def owned(self, p):
        return self.owned_map.get(p, '')


PROTOS = ('tcp', 'udp', 'icmp', 'ip', 'esp', 'ah', 'gre', 'sctp')


def port_names(r):
    """FMC Ports entries of one A rule line: 'TCP 9200', a port object by name, 'ICMP'; [] = any"""
    if r.svc is None or r.svc.is_any():
        return []
    t = (r.svc_ref or '').split()
    if len(t) >= 3 and t[0] in PROTOS and t[1] in ('eq', 'range', 'gt', 'lt', 'neq'):
        v = '-'.join(t[2:4]) if t[1] == 'range' else t[2] if t[1] == 'eq' else '%s %s' % (t[1], t[2])
        return ['%s %s' % (t[0].upper(), v)]
    if len(t) == 2 and t[0] in PROTOS and re.match(r'^[A-Za-z]', t[1]):
        return [t[1]]
    if len(t) == 1 and t[0] in PROTOS:
        return ['%s (all ports)' % t[0].upper()] if t[0] in ('tcp', 'udp') else [t[0].upper()]
    if len(t) == 1 and re.match(r'^[A-Za-z]', t[0]):
        return [t[0]]
    return [ports_text(r.svc)]


def addr_names(r, side):
    names = getattr(r, side + '_names', None)
    if names:
        return list(names)
    ref = r.src_ref if side == 'src' else r.dst_ref
    return ['any'] if ref in ('any', 'any4') else [x.strip() for x in (ref or 'any').split(', ')]


def cli_addr(cfg, name):
    if name == 'any':
        return 'any'
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
        return 'host ' + name
    if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', name):
        n = ipaddress.IPv4Network(name, strict=False)
        return '%s %s' % (n.network_address, n.netmask) if n.prefixlen < 32 else 'host %s' % n.network_address
    o = cfg.objects.get(name)
    return ('object-group ' if o is not None and o.kind == 'group' else 'object ') + name


def _union(lists):
    out = []
    for lst in lists:
        for x in lst:
            if x not in out:
                out.append(x)
    return out


def new_spec(ctx, name, rules, si, di, dst_names=None):
    """one B access rule to create, from the A rule lines `rules` (same FMC rule): same name, same source
    objects (FMC_INLINE groups expanded), same ports; destination = dst_names or the A destinations"""
    src = _union(addr_names(r, 'src') for r in rules)
    if 'any' in src:
        src = ['any']
    ports = [] if any(r.svc is None or r.svc.is_any() for r in rules) else _union(port_names(r) for r in rules)
    dst = list(dst_names) if dst_names else _union(addr_names(r, 'dst') for r in rules)
    if 'any' in dst:
        dst = ['any']
    svc = None
    for r in rules:
        svc = r.svc if svc is None else svc | r.svc
    spec = {'name': name, 'si': list(si), 'di': list(di), 'src': src, 'dst': dst, 'ports': ports, 'svc': svc,
            'seq': min(r.seq for r in rules), 'src_any': src == ['any']}
    cur = ctx.specs.get(name)
    if cur:
        for k in ('si', 'di', 'src', 'dst', 'ports'):
            cur[k] = _union([cur[k], spec[k]])
        cur['svc'] = cur['svc'] | svc if cur['svc'] is not None and svc is not None else cur['svc'] or svc
        cur['seq'] = min(cur['seq'], spec['seq'])
        return cur
    ctx.specs[name] = spec
    return spec


def spec_objects(ctx, spec):
    out = []
    for n in spec['src'] + spec['dst']:
        out += net_objects(ctx, n)
    for p in spec['ports']:
        out += port_objects(ctx, p)
    return out


def net_resolve(cfg, name, seen=()):
    o = cfg.objects.get(name)
    if o is None or name in seen:
        return IPSet()
    if o.kind != 'group':
        return o.addrs
    s = IPSet()
    for m in o.members:
        s = s | (net_resolve(cfg, m[4:], seen + (name,)) if m.startswith('obj:') else IPSet.parse(m))
    return s


def net_objects(ctx, name, seen=()):
    """an A network object / group to create on B, members first"""
    o = ctx.A.objects.get(name)
    if o is None or name in seen or name in ('any', 'any4') or net_resolve(ctx.A, name).is_any():
        return []
    if o.kind != 'group':
        return [obj_line(safe(name), o.addrs)] if o.addrs and not o.addrs.is_any() else []
    out = []
    subs = [m[4:] for m in o.members if m.startswith('obj:')]
    lits = [m for m in o.members if not m.startswith('obj:')]
    for m in subs:
        out += net_objects(ctx, m, seen + (name,))
    out.append({'name': safe(name), 'type': 'Group', 'value': 'group of %s' % ', '.join(subs + lits),
                'cli': ['object-group network %s' % name] + [' network-object object %s' % m for m in subs] +
                [' network-object %s' % cli_addr(ctx.A, l) for l in lits]})
    return out


def svc_resolve(cfg, name, seen=()):
    o = cfg.services.get(name)
    if o is None or name in seen:
        return Service()
    if o.kind not in ('group', 'port-group'):
        return o.svc
    s = Service()
    for m in o.members:
        s = s | (svc_resolve(cfg, m[4:], seen + (name,)) if isinstance(m, str) and m.startswith('obj:') else m)
    return s


def port_objects(ctx, name, seen=()):
    """A port object / group to create on B, members first"""
    so = ctx.A.services.get(name)
    if so is None or name in seen:
        return []
    out = []
    subs = [m[4:] for m in so.members if isinstance(m, str) and m.startswith('obj:')]
    for m in subs:
        out += port_objects(ctx, m, seen + (name,))
    value = ('group of %s' % ', '.join(subs)) if subs else ports_text(svc_resolve(ctx.A, name))
    out.append({'name': name, 'type': 'Port', 'value': value, 'cli': []})
    return out


def spec_cli(ctx, spec, limit=16):
    out = []
    for si in spec['si'][:2]:
        for di in spec['di'][:2]:
            for s_ in spec['src']:
                for d_ in spec['dst']:
                    for line in acl_lines(spec['svc'], si, cli_addr(ctx.A, s_), di, cli_addr(ctx.A, d_), limit=limit):
                        if not line.startswith('!') and line not in out:
                            out.append(line)
    return out[:limit] + (['... %d more lines' % (len(out) - limit)] if len(out) > limit else [])


def spec_fmc(ctx, spec, pos=None, total=None):
    name, sect = ctx.anchor
    where = ('Mandatory section, above %s' % name if sect == 'Mandatory' else
             'Mandatory section, so above %s (it is in the Default section)' % name if name else 'Mandatory section, at the top')
    order = ', new rule %d of %d' % (pos, total) if pos else ", in %s's rule order" % ctx.n['A_short']
    return ('Policies > Access Control > %s > Add Rule (%s%s): Name "%s", Action Allow, Zones: Source %s -> '
            'Destination %s, Networks: Source %s, Destination %s, Ports: %s, Logging: at end of connection.' % (
                ctx.acp, where, order, spec['name'], ', '.join(spec['si']), ', '.join(spec['di']),
                ', '.join(spec['src']), ', '.join(spec['dst']), ', '.join(spec['ports']) or 'any'))


def _f(ctx, cat, key, scopes, what, why, evidence, fmc, cli, objects, verify, extra=None):
    st = (ctx.prof.finding_state or {}).get(key, {})
    d = {'id': 'F-' + key, 'key': key, 'category': cat, 'order': ORDER[cat], 'scopes': scopes,
         'scope': ', '.join(ctx.label(p) for p in scopes), 'what': what, 'why': why,
         'evidence': [e for e in evidence if e], 'fix': {'fmc': fmc, 'cli': cli, 'objects': objects},
         'verify': verify, 'state': st.get('state', 'open'), 'reason': st.get('reason', ''), 'level': 'fix', 'short': what}
    d.update(extra or {})
    return d


def routing_findings(ctx):
    from .detect import route_table
    out = []
    for r in ctx.res.get('routing', []):
        if r['status'] == 'ok' or r.get('row_state'):
            continue
        p, ifc = r['subnet'], r['expected_b_ifc'] or ctx.b_in
        nh = ctx.b_nexthop(ifc)
        t, kind, bs = ctx.title(p), ctx.kind(p), ctx.n['B_short']
        net = ipaddress.IPv4Network(p)
        if r['status'] == 'wrong way':
            what = '%s: %s would send it to the internet, not inside. It has no route for this %s and uses its default route.' % (
                t, ctx.n['B'], kind)
            why = 'Return traffic for this %s would leave %s toward the internet, so sessions to and from it fail when %s takes over.' % (
                kind, bs, bs)
            short = 'No static route on %s; it would use the default route to the internet' % bs
        elif r['status'] == 'no route on B':
            what = '%s: %s has no route for this %s.' % (t, ctx.n['B'], kind)
            why = '%s drops all traffic to this %s.' % (bs, kind)
            short = 'No route on %s for this %s' % (bs, kind)
        else:
            what = '%s: %s routes it out of %s, expected %s.' % (t, ctx.n['B'], r['b_route'], ifc)
            why = 'Traffic for this %s may take the wrong path through %s.' % (kind, bs)
            short = '%s routes it out of a different interface than %s' % (bs, ctx.n['A_short'])
        hit = next((e for e in route_table(ctx.B) if IPSet.parse(p).issubset(e['set'])), None)
        conn = ctx.B.interfaces.get(ifc)
        on_ifc = bool(conn and conn.ip) and IPSet.parse(p).issubset(IPSet.net(conn.ip, conn.mask))
        a_vlan = any(e['net'] == p and e['kind'] == 'connected' for e in route_table(ctx.A))
        re_ip = a_vlan and conn is not None and bool(conn.ip) and not on_ifc
        if hit is not None and hit['plen'] > 0:
            what = '%s: %s routes it via %s (%s), not %s.' % (t, ctx.n['B'], hit['ifc'], hit['net'], ifc)
            why = 'Traffic for this %s follows that route, not the interface %s uses.' % (kind, ctx.n['A_short'])
            short = '%s routes it via %s (%s), not %s' % (bs, hit['ifc'], hit['net'], ifc)
        if re_ip:
            what += ' %s on %s is %s, a different subnet.' % (ifc, bs, ipaddress.IPv4Interface(
                '%s/%s' % (conn.ip, conn.mask)).network)
            why += ' A static route is not the fix: decide whether this subnet moves to %s or each site keeps its own.' % bs
            short = '%s on %s is a different subnet: decide whether this %s moves' % (ifc, bs, kind)
        check = bool(ctx.B.dynamic_routing) and not re_ip
        if check:
            what = '%s: the %s config has no static route for this %s to %s. %s runs %s, so the route may be learned.' % (
                t, bs, kind, ifc, bs, ', '.join(ctx.B.dynamic_routing))
            why = 'If %s has not learned it, return traffic for this %s follows another route and sessions fail.' % (bs, kind)
            short = 'No static route on %s; %s may learn it by %s. Run show route on %s' % (
                bs, bs, ', '.join(x.split()[1] if len(x.split()) > 1 else x for x in ctx.B.dynamic_routing).upper(), bs)
        evid = []
        rest = IPSet.parse(p)
        for e in route_table(ctx.B):
            if e['set'].overlaps(rest) and e['kind'] != 'connected':
                evid.append({'device': ctx.n['B'], 'line': e.get('lineno', 0), 'text': e.get('text') or 'route %s %s %s' % (
                    e['ifc'], e['net'], e['nexthop'])})
                if e['set'].issubset(rest) is False and rest.issubset(e['set']):
                    break
        for e in route_table(ctx.A):
            if e['set'].overlaps(rest) and rest.issubset(e['set']):
                evid.append({'device': ctx.n['A'], 'line': e.get('lineno', 0), 'text': e.get('text') or '%s %s (%s)' % (
                    e['kind'], e['net'], e['ifc'])})
                break
        oname = safe('NET_%s' % p.replace('/', '_'))
        ob = obj_line(oname, IPSet.parse(p))
        ip = sample(IPSet.parse(p))
        add = ('Devices > Device Management > %s > Routing > Static Route > Add Route: Interface %s, Available Network %s, '
               'Gateway %s, Metric 1.' % (bs, ifc, oname, nh))
        fmc = [add]
        cli = ['route %s %s %s %s 1' % (ifc, net.network_address, net.netmask, nh)]
        level = 'fix'
        if check:
            fmc = ['First, on %s run: show route %s. If it points to %s, no change is needed. If it points elsewhere, '
                   'add this route: %s' % (bs, ip, ifc, add)]
            cli = ['show route %s' % ip] + cli
            level = 'check'
        if re_ip:
            fmc = ['No route to add. Re-address %s on %s only if the subnet really moves there: Devices > Device '
                   'Management > %s > Interfaces > edit %s > IPv4.' % (ifc, bs, bs, ifc)]
            cli, ob, level = ['show route %s' % ip, 'show interface %s' % ifc], None, 'choice'
        verify = ['show route %s' % ip]
        out.append(_f(ctx, 'routing', _key('routing', p), [p], what, why, evid, fmc, cli, [ob] if ob else [], verify,
                      {'status': r['status'], 'plain_status': plain(r['status'], ctx.n), 'fmc_group': 'Routing',
                       'level': level, 'short': short, 'subject': p}))
    return out


def pat_mode(ctx, key):
    c = ((ctx.prof.decision_state or {}).get('D-pat-' + key, {}).get('choice') or '').lower()
    return 'match' if c.startswith('match') else 'interface'


def pat_findings(ctx):
    """outbound PAT on B for the sources A translates (not the whole scope subnet); B's interface PAT by default,
    A's dedicated PAT address only when the decision says 'match A's address'"""
    out = []
    pats = {(x['side'], x['subnet']): x for x in ctx.res.get('pat', [])}
    for p in ctx.prof.scope:
        b, a = pats.get(('B', p)), pats.get(('A', p))
        if not b or b['status'] == 'covered' or b.get('row_state') or (a and a['status'] == 'missing'):
            continue                                    # no outbound NAT on A either: nothing to carry over
        s = IPSet.parse(p)
        name = ctx.label(p)
        key = _key('pat', p)
        a_src = natorder.src_ifc(ctx.A, s)
        eff, _ = natorder.best_effective(ctx.A, s, a_src, sorted(ctx.outs_a))
        b_in = ctx.prof.map_ifc(a_src) if a_src else ctx.b_in
        b_in = b_in if b_in in ctx.B.interfaces else ctx.b_in
        hit = [(part, n) for part, n in eff if n is not None]
        dyn = [n for part, n in hit if natorder.shared(n)]
        cov = IPSet()
        for part, n in hit:
            cov = cov | part
        objects = []
        if not hit or cov == s:
            oname = safe('NET_%s' % p.replace('/', '_'))
            objects.append(obj_line(oname, s))
            srcs = [oname]
        else:
            srcs = []
            for part, n in hit:
                if not natorder.shared(n):
                    continue
                nm = safe(n.real_ref) if part == n.real and re.match(r'^[A-Za-z]', n.real_ref or '') else \
                    safe('NET_%s' % repr(part).split(',')[0].replace('/', '_'))
                if nm not in srcs:
                    srcs.append(nm)
                    objects.append(obj_line(nm, part))
        dedicated = sorted({h for n in dyn if not n.mapped_interface and n.mapped is not None for h in n.mapped.hosts()},
                           key=lambda x: int(ipaddress.IPv4Address(x)))
        shadow = natorder.shadowed(ctx.A)
        shadowed = [(n, shadow[id(n)][1]) for n in natorder.ordered(ctx.A) if id(n) in shadow and n.real.overlaps(s)]
        mode = pat_mode(ctx, key)
        if hit:
            a_txt = '%s translates %s today (first match: %s).' % (
                ctx.n['A_short'], 'all of it' if cov == s else 'only %s' % repr(cov),
                '; '.join('%s -> %s line %s' % (n.real_ref, 'interface' if n.mapped_interface else n.mapped_ref,
                                                natorder.line_of(n)) for n in (dyn or [x for _, x in hit])[:4]))
            if shadowed:
                a_txt += ' Never hit: %s.' % '; '.join('%s -> %s (line %s, %s)' % (
                    n.real_ref, 'interface' if n.mapped_interface else n.mapped_ref, natorder.line_of(n),
                    t.split(': ', 1)[1].split(' (')[0]) for n, t in shadowed[:3])
        else:
            a_txt = '%s does not translate it either.' % ctx.n['A_short']
        what = '%s: %s has no outbound PAT for it (source %s). %s' % (ctx.title(p), ctx.n['B'], ', '.join(srcs), a_txt)
        why = 'Hosts in this %s cannot reach the internet through %s.' % (
            ctx.kind(p) if cov == s or not hit else 'part of the %s (%s)' % (ctx.kind(p), repr(cov)), ctx.n['B_short'])
        evid = [ev(ctx.dev(getattr(n, 'device', '')), n) for n in (dyn or [x for _, x in hit])[:4]]
        for n, txt in shadowed[:3]:
            e = ev(ctx.dev(getattr(n, 'device', '')), n)
            e['text'] += '   <- %s' % txt
            evid.append(e)
        evid.append({'device': ctx.n['B'], 'line': 0, 'text': '(no dynamic NAT covering %s)' % ', '.join(srcs)})
        if mode == 'match' and dedicated:
            tname = safe('PAT_%s_%s' % (name.replace(' ', ''), ctx.n['B_short'].replace(' ', '')))
            trans = 'Translated Source %s (new %s public IP%s, matching %s\'s dedicated PAT address%s %s)' % (
                tname, ctx.n['B_short'], 's' if len(dedicated) > 1 else '', ctx.n['A_short'],
                'es' if len(dedicated) > 1 else '', ', '.join(dedicated))
            cli_t = tname
        else:
            trans = 'Translated Source Destination Interface IP (%s interface PAT, like its existing PAT rules)' % ctx.b_out
            cli_t = 'interface'
        fmc = ['Devices > NAT > %s > Add Rule: NAT Rule Manual, Type Dynamic, Insert In Category After Auto NAT; '
               'Interface Objects: Source %s, Destination %s; Translation: Original Source %s, %s.' % (
                   ctx.natp, b_in, ctx.b_out, ', '.join(srcs), trans)]
        cli = ['nat (%s,%s) after-auto source dynamic %s %s' % (b_in, ctx.b_out, x, cli_t) for x in srcs]
        h = sample(cov if hit and cov != s else s)
        verify = ['packet-tracer input %s tcp %s 40000 8.8.8.8 443' % (b_in, h), 'show xlate local %s' % h]
        out.append(_f(ctx, 'pat', key, [p], what, why, evid, fmc, cli, objects, verify,
                      {'status': b['status'], 'plain_status': 'no outbound PAT on %s' % ctx.n['B_short'], 'fmc_group': 'NAT',
                       'short': 'No outbound PAT on %s; hosts cannot reach the internet' % ctx.n['B_short'], 'subject': p,
                       'pat_sources': srcs, 'pat_mode': mode, 'pat_dedicated': dedicated,
                       'pat_pool': len(dedicated) if mode == 'match' else 0}))
    return out


def inbound_findings(ctx):
    from .compare import effective_rules, eval_slice
    b_rules = effective_rules(ctx.B)
    out = []
    for i in ctx.res.get('inbound', []):
        if i['status'] == 'ready' or i.get('row_state'):
            continue
        n = i['_nat']
        host = host_name(i['object'], i.get('description', ''))
        real = i['real']
        ports = ports_text(i.get('_svc'))
        nat_st, rule_st = i.get('nat_status', ''), i.get('rule_status', '')
        nat_txt = {'missing': 'no NAT', 'inactive on B': 'the NAT but it is disabled',
                   'mapped conflict': 'a NAT whose public IP conflicts with another host'}.get(nat_st, 'the NAT')
        rule_txt = {'missing': 'no access rule', 'partial': 'an access rule for only part of the ports'}.get(rule_st, 'the access rule')
        tail = ('%s has %s and %s.' % (ctx.n['B_short'], nat_txt, rule_txt) if rule_st != 'covered' else
                '%s has %s; the access rule is in place.' % (ctx.n['B_short'], nat_txt))
        if nat_st in ('match', 'mapped reuse', 'mapped outside B public'):
            tail = '%s has the NAT but %s.' % (ctx.n['B_short'], rule_txt)
        what = '%s (%s) is published at %s on %s %s. %s' % (real, host, ctx.n['A_short'], i['a_public'] or '?', ports, tail)
        why = 'During %s %s internet outage this server is unreachable from the internet.' % (
            'an' if ctx.n['A_short'][:1].lower() in 'aeiou' else 'a', ctx.n['A_short'])
        evid = [ev(ctx.dev(getattr(n, 'device', '')), n)]
        evid += [ev(ctx.dev(getattr(r, 'evidence', [('',)])[0][0] if getattr(r, 'evidence', None) else ''), r)
                 for r in i.get('_a_rules', [])[:4]]
        if i.get('_b_nat') is not None:
            evid.append(ev(ctx.n['B'], i['_b_nat']))
        evid += [ev(ctx.n['B'], r) for r in i.get('_b_rules', [])[:3]]
        if i.get('_b_nat') is None:
            evid.append({'device': ctx.n['B'], 'line': 0, 'text': '(no static NAT for %s)' % real})
        b_pub = i['b_public']
        real_obj = safe(n.real_ref if re.match(r'^[A-Za-z]', n.real_ref or '') else 'SRV_' + real.replace('/', '_'))
        pub_obj = safe('PUB_%s_%s' % (host.split('.')[0], ctx.n['B_short'])) if b_pub else '<public IP object>'
        objects = [obj_line(real_obj, n.real)]
        if b_pub and nat_st == 'missing':
            objects.append(obj_line(pub_obj, IPSet.parse(b_pub)))
        pre, cli = [], []
        if nat_st == 'inactive on B':
            m = i['_b_nat']
            pre.append('Devices > NAT > %s > edit the rule for %s -> %s: tick Enable.' % (ctx.natp, m.real_ref, m.mapped_ref))
            cli.append('%s   (remove "inactive")' % (m.line or 'nat ... inactive'))
        elif nat_st == 'missing':
            pre.append('Devices > NAT > %s > Add Rule: NAT Rule Manual, Type Static, Insert In Category Before Auto NAT; '
                       'Interface Objects: Source %s, Destination %s; Translation: Original Source %s, Translated Source %s.'
                       % (ctx.natp, ctx.b_in, ctx.b_out, real_obj, pub_obj if b_pub else '<choose a public IP: see Your choices>'))
            cli.append('nat (%s,%s) source static %s %s' % (ctx.b_in, ctx.b_out, real_obj, pub_obj))
        specs = []
        if rule_st != 'covered':
            by = {}
            for r in i.get('_a_rules', []):
                by.setdefault(r.rule_name or r.rule_id or '#%d' % r.seq, []).append(r)
            di = ctx.prof.map_ifc(n.real_ifc) or ctx.b_in
            for rname, rs in by.items():
                src, svc = IPSet(), None
                for r in rs:
                    src = src | r.src
                    svc = r.svc if svc is None else svc | r.svc
                st, _, _ = eval_slice(b_rules, ctx.b_out, di, src, n.real, svc)
                if st == 'covered':
                    continue
                specs.append(new_spec(ctx, rname, rs, [ctx.b_out], [di], [real_obj])['name'])
        dns = b_pub != i['a_public']
        post = []
        if dns:
            post.append('DNS: failover record for %s: %s -> %s (lower the TTL first).' % (
                host, i['a_public'], b_pub or 'pending public IP (see Your choices)'))
        verify = [tracer(ctx.b_out, i.get('_svc'), '8.8.8.8', b_pub or '<B public>'),
                  'show xlate global %s' % (b_pub or '<B public>'), 'show nat detail | include %s' % real_obj]
        dec = 'test' if TEST_NAME.search(host) or TEST_NAME.search(i['object'] or '') else ''
        out.append(_f(ctx, 'inbound', _key('inbound', i['object'], real), i['scopes'], what, why, evid, pre, cli, objects,
                      verify, {'status': i['status'], 'plain_status': '%s has %s and %s' % (ctx.n['B_short'], nat_txt, rule_txt),
                               'fmc_group': 'NAT' if nat_st != 'match' else 'Access Control', 'host': host, 'real': real,
                               'a_public': i['a_public'], 'b_public': b_pub, 'ports': ports, 'dns_change': dns,
                               'suggest': 'not needed: test/dev server' if dec else '', 'nat_status': nat_st,
                               'rule_status': rule_st, 'acp_rules': specs, '_fmc_pre': pre, '_fmc_post': post,
                               'short': 'Published server %s (%s): %s has %s and %s' % (real, host, ctx.n['B_short'], nat_txt, rule_txt),
                               'subject': real,
                               'folded_rules': specs}))
    return out


SEVERITY = {'denied': 0, 'shadowed': 1, 'missing': 2, 'partial': 3}


def rule_findings(ctx):
    """one finding per A rule name (FMC rule), not per CLI line. A rule whose in-scope destinations are all
    published servers is folded into those servers' inbound findings"""
    out = []
    scope = ctx.prof.scope_set()
    groups = {}
    for r in ctx.res.get('rules', []):
        if r['status'] == 'covered' or r.get('row_state'):
            continue
        groups.setdefault(r['rule'] or r['rule_id'] or r['id'], []).append(r)
    folded = []
    for name, rows in groups.items():
        rules = [r['_rule'] for r in rows]
        if ctx.pub_reals and all(r['src_ifc'] in ctx.outs_a and (x.dst & scope) and (x.dst & scope).issubset(ctx.pub_reals)
                                 for r, x in zip(rows, rules)):
            folded.append(name)
            continue
        st = min((r['status'] for r in rows), key=lambda x: SEVERITY.get(x, 9))
        first = rules[0]
        def few(vals):
            v = list(dict.fromkeys(x for x in vals if x))
            return ', '.join(v[:3]) + (' (+%d more)' % (len(v) - 3) if len(v) > 3 else '') if v else 'any'
        src_t, dst_t, svc_t = few(r['src'] for r in rows), few(r['dst'] for r in rows), few(r['service'] for r in rows)
        tag = getattr(first, 'origin', 'A').split('#')[0] if rows[0].get('path') else ''
        scopes = sorted({p for r in rows for p in r.get('scopes', [])})
        verb = {'missing': 'has no matching permit', 'partial': 'allows only part of it',
                'shadowed': 'blocks it with an earlier rule (%s)' % named(rows[0].get('detail', ''), ctx.n),
                'denied': 'denies it'}.get(st, st)
        what = '%s%s rule "%s" (%d line%s) allows %s -> %s (%s); %s %s.' % (
            subnets(ctx, scopes), ctx.dev(tag), name, len(rows), '' if len(rows) == 1 else 's', src_t, dst_t, svc_t,
            ctx.n['B_short'], verb)
        why = 'When %s takes over, this traffic is dropped%s.' % (ctx.n['B_short'], ' in part' if st == 'partial' else '')
        evid = []
        for x in rules[:4]:
            for t, no, line in (getattr(x, 'evidence', []) or [('', getattr(x, 'lineno', 0), x.line)])[:1]:
                evid.append({'device': ctx.dev(t), 'line': no, 'text': line})
        for r in rows[:2]:
            evid += [ev(ctx.n['B'], m) for m in r.get('_b', [])[:2]]
        si = list(dict.fromkeys(r['b_src_ifc'].split(', ')[0] for r in rows))
        di = list(dict.fromkeys(r['b_dst_ifc'].split(', ')[0] for r in rows))
        spec = new_spec(ctx, name, rules, si, di)
        verify = [tracer(si[0] if si[0] != 'any' else ctx.b_out, first.svc, sample(first.src if not first.src.is_any() else None),
                         sample(first.dst if not first.dst.is_any() else None))]
        flags = []
        if any(r.get('action_check') == 'action unknown (L7)' for r in rows):
            flags.append('L7 rule: confirm in FMC that it is an Allow rule')
        if VERIFY_NAME.search(name or ''):
            flags.append('rule name says [0 hits] / [VERIFY]')
        scopes_any = sorted({p for r in rows for p in r.get('scopes_any', [])})
        out.append(_f(ctx, 'rules', _key('rulename', name), scopes, what, why, evid, [], [], [], verify,
                      {'status': st, 'plain_status': plain(st, ctx.n), 'fmc_group': 'Access Control',
                       'short': 'Rule "%s": %s %s' % (name, ctx.n['B_short'], verb),
                       'subject': ', '.join((scopes or scopes_any)[:3]) or 'rule "%s"' % name,
                       'scopes_any': scopes_any, 'flags': flags, 'rule': name, 'lines': len(rows),
                       'acp_rules': [spec['name']], '_fmc_pre': [], '_fmc_post': []}))
    ctx.folded_rules = folded
    bgroups = {}
    for r in ctx.res.get('b_rules', []):
        if not r['status'].startswith('over-permitted') or r.get('row_state'):
            continue
        bgroups.setdefault(r['rule'] or r['id'], []).append(r)
    for name, rows in bgroups.items():
        r = rows[0]
        bsc = sorted({p for x in rows for p in x.get('scopes', [])})
        what = '%s%s rule "%s" (%d line%s) allows %s -> %s (%s), which %s does not allow%s.' % (
            subnets(ctx, bsc), ctx.n['B_short'], name, len(rows), '' if len(rows) == 1 else 's', r['src'], r['dst'],
            r['service'], ctx.n['A_short'], ' in full' if all(x['status'].endswith('(partial)') for x in rows) else '')
        why = '%s would expose more than %s does today.' % (ctx.n['B_short'], ctx.n['A_short'])
        fmc = ['Policies > Access Control > %s > rule "%s": narrow Source/Destination/Ports to what %s allows, or disable it.'
               % (ctx.acp, name, ctx.n['A_short'])]
        out.append(_f(ctx, 'rules', _key('brulename', name), sorted({p for x in rows for p in x.get('scopes', [])}), what, why,
                      [ev(ctx.n['B'], x.get('_rule')) for x in rows[:4] if x.get('_rule') is not None], fmc,
                      ['show access-list CSM_FW_ACL_ | include %s' % (r['rule_id'] or name)] +
                      ['(review) ' + x['line'] for x in rows[:4]], [],
                      ['show access-list CSM_FW_ACL_ | include %s' % (r['rule_id'] or name)],
                      {'status': r['status'], 'plain_status': plain(r['status'], ctx.n), 'fmc_group': 'Access Control',
                       'level': 'review', 'short': '%s allows more than %s in rule "%s"' % (ctx.n['B_short'], ctx.n['A_short'], name),
                       'subject': ', '.join(bsc[:3]) or 'rule "%s"' % name,
                       'scopes_any': sorted({p for x in rows for p in x.get('scopes_any', [])}), 'flags': [], 'rule': name,
                       'lines': len(rows)}))
    return out


def finalize(ctx, findings):
    """render the new B access rules once all findings are known: one per A rule name (destinations merged),
    numbered in A's rule order, placed in the Mandatory section above the anchor rule"""
    order = sorted(ctx.specs.values(), key=lambda x: x['seq'])
    for k, sp in enumerate(order, 1):
        sp['pos'] = k
    for f in findings:
        if 'acp_rules' not in f:
            continue
        acp, cli, objs = [], [], list(f['fix']['objects'])
        for nm in f['acp_rules']:
            sp = ctx.specs[nm]
            acp.append(spec_fmc(ctx, sp))
            cli += spec_cli(ctx, sp)
            for o in spec_objects(ctx, sp):
                if o['name'] not in [x['name'] for x in objs]:
                    objs.append(o)
        f['fix']['fmc'] = f.pop('_fmc_pre', []) + acp + f.pop('_fmc_post', []) if '_fmc_pre' in f else f['fix']['fmc'] + acp
        f['fix']['cli'] = f['fix']['cli'] + [c for c in cli if c not in f['fix']['cli']]
        f['fix']['objects'] = objs
        f['acp_specs'] = [{k: v for k, v in ctx.specs[nm].items() if k != 'svc'} for nm in f['acp_rules']]


def subnets(ctx, scopes):
    """'192.0.2.0/24, 198.51.100.0/24: ' so a finding leads with the networks it is about"""
    if not scopes:
        return ''
    return '%s%s: ' % (', '.join(scopes[:3]), ' (+%d more)' % (len(scopes) - 3) if len(scopes) > 3 else '')


def object_findings(ctx):
    """only A addresses missing from the B object are a thing to fix; a B object with every A address plus more is
    a low-priority note (rules that use it on B allow a little more)"""
    out = []
    for o in ctx.res.get('objects', []):
        if o['status'] not in ('same name, different value', 'B has extra entries') or o.get('row_state'):
            continue
        extra = o['status'] == 'B has extra entries' or not o.get('a_missing')
        sc = o.get('scopes', [])
        kw = 'object-group' if o.get('kind') == 'group' else 'object'
        if extra:
            what = '%sObject %s on %s has every address it has on %s (%s), plus %s.' % (
                subnets(ctx, sc), o['name'], ctx.n['B_short'], ctx.n['A_short'], o['addrs'], o.get('b_extra') or 'more')
            why = 'Nothing is lost at takeover. Rules that use %s on %s allow a little more than on %s.' % (
                o['name'], ctx.n['B_short'], ctx.n['A_short'])
            fmc = ['Optional: Objects > Object Management > Network > %s: remove the extra entries if %s should match %s '
                   'exactly.' % (o['name'], ctx.n['B_short'], ctx.n['A_short'])]
            short = 'Object %s has extra entries on %s (low priority)' % (o['name'], ctx.n['B_short'])
        else:
            what = '%sObject %s is %s on %s but %s on %s: %s is missing on %s.' % (
                subnets(ctx, sc), o['name'], o['addrs'], ctx.n['A_short'], o['b_value_or_names'], ctx.n['B_short'],
                o.get('a_missing') or 'part of it', ctx.n['B_short'])
            why = 'Rules that use %s on %s do not match all the addresses they match on %s.' % (
                o['name'], ctx.n['B_short'], ctx.n['A_short'])
            fmc = ['Objects > Object Management > Network > %s > Edit: add %s (or use a new name if the %s value is '
                   'right).' % (o['name'], o.get('a_missing') or 'the missing addresses', ctx.n['B_short'])]
            short = 'Object %s lacks %s on %s' % (o['name'], o.get('a_missing') or 'addresses', ctx.n['B_short'])
        obj = o.get('_obj')
        cli = ['show running-config %s %s' % (kw, o['name'])]
        if not extra and o.get('a_missing'):
            cli += ['%s network %s' % (kw, o['name'])] + [
                (' network-object %s' % cli_net(x)) if kw == 'object-group' else
                (' %s' % cli_net(x) if cli_net(x).startswith('host') else ' subnet %s' % cli_net(x))
                for x in o['a_missing'].split(', ')[:8] if '/' in x]
        out.append(_f(ctx, 'objects', _key('obj', o['name']), sc, what, why,
                      [{'device': ctx.n['A'], 'line': getattr(obj, 'lineno', 0), 'text': '%s network %s' % (kw, o['name'])}],
                      fmc, cli, [], ['show running-config %s %s' % (kw, o['name'])],
                      {'status': o['status'], 'plain_status': plain(o['status'], ctx.n), 'fmc_group': 'Objects',
                       'level': 'review' if extra else 'fix', 'short': short, 'subject': ', '.join(sc[:3]) or o['name']}))
    return out


def cli_net(cidr):
    n = ipaddress.IPv4Network(cidr, strict=False)
    return 'host %s' % n.network_address if n.prefixlen == 32 else '%s %s' % (n.network_address, n.netmask)


def public_need(ctx, findings, states=('open', 'fix', 'later')):
    """new B public IPs per scope: (a) published servers with no B NAT, (b) outbound-only static NATs kept on B
    (decision), (c) PAT addresses when 'match A's address' is chosen. Readiness and plan both use this."""
    st = ctx.prof.decision_state or {}
    rows = {x['subnet']: x for x in ctx.res.get('public', []) if x['id'].startswith('PUB-') and x['id'] != 'PUB-TOTAL'}
    out = {}
    for p in ctx.prof.scope:
        a = [f for f in findings if f['category'] == 'inbound' and p in f['scopes'] and f.get('nat_status') == 'missing'
             and f['state'] in states]
        c = sum(f.get('pat_pool', 0) for f in findings if f['category'] == 'pat' and p in f['scopes'] and f['state'] in states)
        bn = (rows.get(p) or {}).get('pub_b', 0) or 0
        bnats = (rows.get(p) or {}).get('pub_b_nats', 0) or 0
        keep = (st.get('D-ident-' + _key(p), {}).get('choice') or '').lower().startswith('keep')
        out[p] = {'a': len(a), 'b': bn if keep else 0, 'b_total': bn, 'b_nats': bnats, 'b_kept': keep, 'c': c,
                  'total': len(a) + (bn if keep else 0) + c}
    return out


def decisions(ctx, findings):
    out = []
    pub = [x for x in ctx.res.get('public', []) if x['id'] == 'PUB-TOTAL']
    need = public_need(ctx, findings)
    rows = {x['subnet']: x for x in ctx.res.get('public', []) if x['id'].startswith('PUB-') and x['id'] != 'PUB-TOTAL'}
    for p in ctx.prof.scope:
        r = rows.get(p) or {}
        if r.get('pub_b'):
            nn = r.get('pub_b_nats', r['pub_b'])
            out.append({'id': 'D-ident-' + _key(p), 'kind': 'outbound identity', 'title': '%s: %d static NAT%s with no inbound rule' % (
                ctx.label(p), nn, '' if nn == 1 else 's'),
                'text': 'Keep the outbound identity on %s? %s maps %s to a fixed public IP but allows no inbound traffic to %s. '
                        'Needed only if partners allow-list this IP. Keeping %s costs %d new public IP%s.' % (
                            ctx.n['B_short'], ctx.n['A_short'], '; '.join(r.get('pub_b_hosts', [])[:8]),
                            'it' if nn == 1 else 'them', 'it' if nn == 1 else 'them', r['pub_b'],
                            '' if r['pub_b'] == 1 else 's'),
                'options': ['not needed', 'keep on %s' % ctx.n['B_short']], 'scopes': [p], 'blocking': False,
                'hosts': r.get('pub_b_hosts', [])})
    for f in findings:
        if f['category'] == 'pat' and f.get('pat_dedicated'):
            out.append({'id': 'D-pat-' + f['key'], 'kind': 'PAT address', 'title': '%s outbound PAT' % f['scope'],
                        'text': '%s PATs %s to dedicated address%s %s. Default on %s: its %s interface (like its existing '
                                'PAT). Choose "match %s\'s address" only if partners allow-list that address (costs %d public IP%s).' % (
                                    ctx.n['A_short'], ', '.join(f['pat_sources']), 'es' if len(f['pat_dedicated']) > 1 else '',
                                    ', '.join(f['pat_dedicated']), ctx.n['B_short'], ctx.b_out, ctx.n['A_short'],
                                    len(f['pat_dedicated']), '' if len(f['pat_dedicated']) == 1 else 's'),
                        'options': ['%s interface (default)' % ctx.n['B_short'], "match %s's address" % ctx.n['A_short']], 'scopes': f['scopes'],
                        'finding': f['key'], 'blocking': False, 'default': '%s interface (default)' % ctx.n['B_short']})
    if pub:
        p = pub[0]
        used = sum(len(x['status'].split(': ', 1)[1].split(', ')) for x in ctx.res.get('public', []) if x['id'].startswith('PUB-B-'))
        avail = p.get('b_public_available')
        tot = {k: sum(v[k] for v in need.values()) for k in ('a', 'b', 'b_total', 'c', 'total')}
        math = ['(a) published servers with no %s NAT: %s = %d' % (ctx.n['B_short'], ', '.join(
                    '%s %d' % (ctx.label(q), need[q]['a']) for q in ctx.prof.scope), tot['a']),
                '(b) outbound identities kept: %d of %d addresses (%d static NATs; your choice per network)' % (
                    tot['b'], tot['b_total'], sum(v['b_nats'] for v in need.values())),
                "(c) PAT addresses (only with \"match %s's address\"): %d" % (ctx.n['A_short'], tot['c']),
                'needed = %d; free in %s: %s%s' % (tot['total'], ', '.join(ctx.prof.public_b) or '-', avail,
                                                     ('; short by %d' % (tot['total'] - avail)) if isinstance(avail, int)
                                                     and tot['total'] > avail else '')]
        short = isinstance(avail, int) and tot['total'] > avail
        if tot['total'] or short:
            out.append({'id': 'D-pool', 'kind': 'public pool', 'title': '%s public IP pool' % ctx.n['B_short'],
                        'text': '%s public ranges %s: %s used; %d new public IPs needed; %s free.%s' % (
                            ctx.n['B_short'], ', '.join(ctx.prof.public_b) or '-', used, tot['total'], avail,
                            ' The ranges are a guess from the config: enter the real allocation or an extra pool.'
                            if 'assumed' in p['status'] else ''),
                        'math': math, 'per_scope': need,
                        'options': ['enter an extra pool', 'keep the current ranges'], 'scopes': [q for q in ctx.prof.scope
                                                                                                 if need[q]['total']],
                        'needed': tot['total'], 'available': avail, 'used': used, 'blocking': short})
    held_seen = set()
    for h in ctx.res.get('held_rules', []):
        if h.get('row_state') or h['rule'] in held_seen:
            continue
        held_seen.add(h['rule'])
        out.append({'id': 'D-held-' + _key(h['rule']), 'kind': 'L7 action', 'title': h['rule'],
                    'text': 'Rule "%s" (%s -> %s %s) shows permit in the config text, but its name says block. '
                            'Confirm its action in FMC.' % (h['rule'], h['src'], h['dst'], h['service']),
                    'options': ['block', 'permit'], 'rule': h['rule'].split(' ∩ ')[0], 'scopes': h.get('scopes', []),
                    'blocking': True})
    seen = set()
    for f in findings:
        if f['category'] == 'inbound' and f.get('suggest') and f['state'] == 'open':
            out.append({'id': 'D-test-' + f['key'], 'kind': 'test server', 'title': f['host'],
                        'text': '%s looks like a test / QA / dev server. Suggested: Not needed - test.' % f['host'],
                        'options': ['not needed - test', 'keep'], 'finding': f['key'], 'scopes': f['scopes'],
                        'blocking': True})
        if f['category'] == 'rules' and any('VERIFY' in x for x in f.get('flags', [])) and f['rule'] not in seen:
            seen.add(f['rule'])
            out.append({'id': 'D-verify-' + f['key'], 'kind': 'rule to verify', 'title': f['rule'],
                        'text': 'Rule "%s" is named [0 hits] / [VERIFY]: replicate it or drop it?' % f['rule'],
                        'options': ['replicate (fix)', 'not needed'], 'finding': f['key'], 'scopes': f['scopes'],
                        'blocking': True})
    by_pub = {}
    for m in ctx.B.nats:
        if m.kind == 'static' and m.mapped is not None and not m.mapped.is_any() and not m.real.is_any() and m.mapped != m.real:
            for h in m.mapped.hosts():
                by_pub.setdefault(h, []).append(m)
    for h, ms in sorted(by_pub.items()):
        reals = {repr(m.real) for m in ms}
        if len(reals) > 1:
            out.append({'id': 'D-conflict-' + h, 'kind': 'public IP conflict', 'title': h,
                        'text': '%s public IP %s is mapped to %d different inside hosts: %s.' % (
                            ctx.n['B_short'], h, len(reals), '; '.join('%s (%s%s)' % (m.real_ref, repr(m.real),
                                                                                       ', disabled' if m.inactive else '')
                                                                         for m in ms)),
                        'options': ['keep one, move the other to a free IP', 'not an issue'],
                        'evidence': [ev(ctx.n['B'], m) for m in ms], 'blocking': True})
    used = sorted(int(ipaddress.IPv4Address(h)) for h in by_pub)
    for f in findings:
        bp = f.get('b_public')
        if f['category'] != 'inbound' or not bp or f.get('nat_status') != 'missing' or not used:
            continue
        v = int(ipaddress.IPv4Address(bp))
        blk = [u for u in used if u >> 8 == v >> 8]
        if blk and blk[0] < v < blk[-1]:
            out.append({'id': 'D-gap-' + f['key'], 'kind': 'public IP conflict', 'title': '%s for %s' % (bp, f['host']),
                        'text': 'Proposed %s public IP %s for %s is a gap inside the used block %s-%s: it may already be '
                                'used by a host or device not in this config. Verify before using it.' % (
                                    ctx.n['B_short'], bp, f['host'], ipaddress.IPv4Address(blk[0]), ipaddress.IPv4Address(blk[-1])),
                        'options': ['verified free', 'choose another public IP'], 'finding': f['key'],
                        'scopes': f['scopes'], 'blocking': True})
    for f in findings:
        if f['category'] == 'inbound' and f.get('nat_status') == 'mapped conflict':
            out.append({'id': 'D-conflict-f-' + f['key'], 'kind': 'public IP conflict', 'title': f['host'],
                        'text': 'The public IP for %s is already used by a different inside host on %s.' % (
                            f['host'], ctx.n['B_short']), 'options': ['choose another public IP', 'not an issue'],
                        'finding': f['key'], 'scopes': f['scopes'], 'blocking': True})
    st = ctx.prof.decision_state or {}
    for d in out:
        d['choice'] = st.get(d['id'], {}).get('choice', '') or d.get('default', '')
        d['open'] = not d['choice'] and (d.get('blocking', True) or d['kind'] == 'outbound identity')
    return out


CARD_ORDER = {'not ready': 0, 'check': 1, 'ready': 2, 'own': 3}
LINE_LABEL = {'Ready': 'Ready', 'Action needed': 'Not ready', 'Decision needed': 'Your choice needed',
              'Check first': 'Check on firewall'}


def readiness(ctx, findings, decs):
    """one card per scope subnet: 'Not ready: 1 thing to fix', 'Check on firewall: 1 thing to verify', 'Ready', or
    B's own network; not-ready cards first. Counts: level fix = thing to fix, check = to verify on the firewall,
    choice + open decisions = your choice needed; review-level notes are not counted"""
    cards = []
    need = public_need(ctx, findings)
    bs = ctx.n['B_short']
    for p in ctx.prof.scope:
        live = [f for f in findings if p in f['scopes'] and f['state'] != 'not needed' and f['level'] != 'review']
        dd = [d for d in decs if d['open'] and p in d.get('scopes', [])]

        def line(name, fs, decn=0, note=''):
            acts = sum(f['level'] == 'fix' for f in fs)
            chk = sum(f['level'] == 'check' for f in fs)
            decn += sum(f['level'] == 'choice' for f in fs)
            st = 'Decision needed' if decn else 'Action needed' if acts else 'Check first' if chk else 'Ready'
            return {'name': name, 'actions': acts, 'decisions': decn, 'checks': chk, 'state': st,
                    'label': LINE_LABEL[st], 'note': note}
        nd = need[p]
        cat = lambda *c: [f for f in live if f['category'] in c]
        lines = [
            line('Routing', cat('routing')),
            line('Outbound internet (PAT)', cat('pat')),
            line('Published servers (inbound)', cat('inbound'),
                 sum(d['kind'] in ('test server', 'public IP conflict') for d in dd)),
            line('Access rules', cat('rules', 'objects'), sum(d['kind'] in ('L7 action', 'rule to verify') for d in dd)),
            line('DNS changes', [f for f in live if f.get('dns_change')]),
            line('Public IPs', [], sum(d['kind'] in ('public pool', 'outbound identity') for d in dd),
                 '%d new needed: (a) %d published servers, (b) %d outbound identity (%d NAT%s, %d address%s, %s), (c) %d PAT' % (
                     nd['total'], nd['a'], nd['b'], nd['b_nats'], '' if nd['b_nats'] == 1 else 's', nd['b_total'],
                     '' if nd['b_total'] == 1 else 'es', 'kept' if nd['b_kept'] else 'not kept', nd['c'])),
        ]
        acts = sum(l['actions'] for l in lines if l['name'] != 'DNS changes')
        decn = sum(l['decisions'] for l in lines)
        chk = sum(l['checks'] for l in lines if l['name'] != 'DNS changes')
        own = ctx.owned(p)
        t = ctx.title(p)
        first = lambda lv: next((f['short'] for f in live if f['level'] == lv), '')
        if own:
            state, text = 'own', "%s - %s's own network, not part of takeover" % (t, bs)
            reason = 'It is %s on %s, so nothing has to move from %s.' % (
                {'VPN pool': 'a VPN pool', 'public range': "in %s's public range" % bs}.get(own, 'the %s' % own), bs,
                ctx.n['A_short'])
            acts = decn = chk = 0
        elif acts or decn:
            parts = [x for x in (acts and many(acts, 'thing to fix', 'things to fix'),
                                 decn and many(decn, 'choice needed', 'choices needed'),
                                 chk and many(chk, 'thing to verify', 'things to verify')) if x]
            state, text = 'not ready', '%s - Not ready: %s' % (t, ', '.join(parts))
            reason = first('fix') or first('choice') or next((d['title'] for d in dd), '')
        elif chk:
            state, text = 'check', '%s - Check on firewall: %s' % (t, many(chk, 'thing to verify', 'things to verify'))
            reason = first('check')
        else:
            state, text, reason = 'ready', '%s - Ready' % t, 'Nothing in the configs stops %s from carrying this %s.' % (
                bs, ctx.kind(p))
        cards.append({'subnet': p, 'scope': ctx.label(p), 'title': t, 'name': ctx.name(p), 'lines': lines,
                      'actions': acts, 'decisions': decn, 'checks': chk, 'state': state, 'own': own,
                      'ready': state in ('ready', 'own'), 'verdict': text, 'reason': reason})
    cards.sort(key=lambda c: CARD_ORDER[c['state']])
    return cards


def plan(ctx, findings):
    fixes = [f for f in findings if f['state'] == 'fix']
    groups = {g: [] for g in GROUPS}
    objs, seen = [], set()
    for f in fixes:
        for o in f['fix']['objects']:
            if o['name'] not in seen:
                seen.add(o['name'])
                objs.append(o)
    for o in objs:
        kind = 'Port' if o['type'] == 'Port' else 'Network'
        grp = o['type'] == 'Group' or str(o['value']).startswith('group of')
        groups['Objects'].append({'finding': '', 'fmc': 'Objects > Object Management > %s > Add %s: Name %s, Value %s.' % (
            kind, 'Group' if grp else 'Object', o['name'], o['value']), 'cli': o['cli'], 'verify': []})
    specs, why = [], {}
    for f in sorted(fixes, key=lambda x: x['order']):
        for nm in f.get('acp_rules', []):
            if nm not in [x['name'] for x in specs]:
                specs.append(ctx.specs[nm])
            why.setdefault(nm, []).append(f['what'])
    specs.sort(key=lambda x: x['seq'])
    for k, sp in enumerate(specs, 1):
        groups['Access Control'].append({'finding': ' | '.join(why[sp['name']][:3]), 'fmc': spec_fmc(ctx, sp, k, len(specs)),
                                         'cli': spec_cli(ctx, sp), 'verify': [], 'rule': sp['name']})
    for f in sorted(fixes, key=lambda x: x['order']):
        fmc = [x for x in f['fix']['fmc'] if not x.startswith('Policies > Access Control') or 'Add Rule (' not in x]
        nat = [x for x in fmc if x.startswith('Devices > NAT')]
        acp = [x for x in fmc if x.startswith('Policies > Access')]
        dns = [x for x in fmc if x.startswith('DNS:')]
        other = [x for x in fmc if x not in nat and x not in acp and x not in dns]
        if f['category'] == 'inbound' and f.get('dns_change'):
            groups['DNS'].append({'finding': f['what'], 'fmc': 'DNS: %s: %s -> %s (lower the TTL first).' % (
                f['host'], f['a_public'], f['b_public'] or 'pending public IP (see Your choices)'), 'cli': [],
                'verify': ['nslookup %s 8.8.8.8' % f.get('host', '')]})
        if nat:
            groups['NAT'].append({'finding': f['what'], 'fmc': ' '.join(nat), 'cli': [c for c in f['fix']['cli'] if c.startswith('nat ')],
                                  'verify': f['verify']})
        if acp:
            groups['Access Control'].append({'finding': f['what'], 'fmc': ' '.join(acp),
                                             'cli': [c for c in f['fix']['cli'] if c.startswith('(review)')],
                                             'verify': f['verify']})
        if other:
            gg = 'Routing' if f['category'] == 'routing' else (f.get('fmc_group') or 'Access Control')
            groups.setdefault(gg, []).append({'finding': f['what'], 'fmc': ' '.join(other),
                                              'cli': [c for c in f['fix']['cli'] if not c.startswith(('nat ', 'access-list'))],
                                              'verify': f['verify']})
    need = public_need(ctx, fixes, states=('fix',))
    tot = {k: sum(v[k] for v in need.values()) for k in ('a', 'b', 'c', 'total')}
    return {'groups': [{'name': g, 'count': len(groups[g]), 'items': groups[g]} for g in GROUPS],
            'total': sum(len(v) for v in groups.values()), 'findings': len(fixes), 'public_ips': tot,
            'public_text': '%d new %s public IPs for these changes: (a) %d published servers, (b) %d outbound identities, '
                           '(c) %d PAT addresses' % (tot['total'], ctx.n['B_short'], tot['a'], tot['b'], tot['c'])}


def build(res, prof, A, B, info):
    ctx = Ctx(res, prof, A, B, info)
    fs = routing_findings(ctx) + pat_findings(ctx) + inbound_findings(ctx) + rule_findings(ctx) + object_findings(ctx)
    finalize(ctx, fs)
    for f in fs:
        keep = []
        for o in f['fix']['objects']:
            b = B.objects.get(o['name'])
            if o['type'] == 'Port':
                if o['name'] in B.services:
                    f.setdefault('objects_on_b', []).append(o['name'])
                    continue
                keep.append(o)
                continue
            if b is not None and b.kind != 'group' and b.addrs.cidrs() and ', '.join(b.addrs.cidrs()[:8]) in (o['value'], o['value'] + '/32'):
                f.setdefault('objects_on_b', []).append(o['name'])
                continue
            keep.append(o)
        f['fix']['objects'] = keep
    for f in fs:
        if f['scopes'] and all(ctx.owned(p) for p in f['scopes']):
            f['level'], f['b_own'] = 'review', True
            f['why'] += " %s is %s's own network, not part of takeover." % (
                ', '.join(f['scopes'][:3]), ctx.n['B_short'])
    fs.sort(key=lambda f: (f['order'], f['scope'], f['what']))
    for i, f in enumerate(fs, 1):
        f['n'] = i
    decs = decisions(ctx, fs)
    res['names'] = ctx.n
    res['folded_rules'] = getattr(ctx, 'folded_rules', [])
    res['glossary'] = {k: plain(k, ctx.n) for k in GLOSSARY}
    res['labels'] = {k: label(k, ctx.n) for k in set(LABELS) | set(GLOSSARY) | {
        'missing on B', 'B only', 'also on A', 'inactive on B', 'mapped outside B public', 'no route on B'}}
    res['how_to_read'] = [{'term': t, 'meaning': m.format(A=ctx.n['A_short'], B=ctx.n['B_short'])} for t, m in HOW_TO_READ]
    res['b_owned'] = dict(ctx.owned_map)
    res['findings'] = fs
    res['decisions'] = decs
    res['readiness'] = readiness(ctx, fs, decs)
    res['plan'] = plan(ctx, fs)
    return res


def plan_markdown(res):
    p, n = res['plan'], res['names']
    out = ['# Change plan: %s -> %s' % (n['A'], n['B']), '',
           '%d changes from %d findings marked Fix. Nothing is pushed; apply in FMC in this order.' % (p['total'], p['findings']),
           '', p.get('public_text', ''), '']
    for g in p['groups']:
        out += ['## %s (%d)' % (g['name'], g['count']), '']
        for i, it in enumerate(g['items'], 1):
            out.append('%d. %s' % (i, it['fmc']))
            if it['finding']:
                out.append('   - Finding: %s' % it['finding'])
            for c in it['cli']:
                out.append('   - CLI: `%s`' % c)
            for v in it['verify']:
                out.append('   - Verify: `%s`' % v)
        out.append('')
    return '\n'.join(out)


def plan_csv_rows(res):
    rows = [['group', 'n', 'fmc_change', 'finding', 'cli', 'verify']]
    for g in res['plan']['groups']:
        for i, it in enumerate(g['items'], 1):
            rows.append([g['name'], i, it['fmc'], it['finding'], ' | '.join(it['cli']), ' | '.join(it['verify'])])
    return rows
