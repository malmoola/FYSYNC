"""Whole-config takeover check for LINA text (show running-config). Every running-config line lands in exactly one
category of a coverage ledger, so nothing is skipped silently. Lines are normalised through the interface map, the
site subnets and the site name tag, then compared; what differs is judged by what it means when A fails."""
import ipaddress
import re
from collections import Counter

from .sitemap import map_ip

CATS = [  # category, head pattern, impact when different, why it matters at takeover
    ('Access rules', r'access-list CSM_FW_ACL_|access-group ', 'engine', 'Compared rule by rule'),
    ('NAT', r'nat ', 'engine', 'Compared rule by rule'),
    ('Objects', r'object |object-group |names$', 'engine', 'Compared object by object'),
    ('Static routes', r'route ', 'engine', 'Compared route by route'),
    ('Interfaces', r'interface |mtu |monitor-interface |no monitor-interface |arp |no arp ', 'high', 'Link state, addressing, PBR and OSPF on the wire'),
    ('OSPF', r'router ', 'high', 'Who advertises the subnets after takeover'),
    ('Policy routing', r'route-map |prefix-list |access-list \S*(pbr|PBR|acl|ospf|static|connected)', 'high', 'Source-based exit and route redistribution'),
    ('Path tracking', r'sla |track ', 'high', 'Which ISP is used and when it fails over'),
    ('High availability', r'failover|prompt ', 'info', 'Pair health inside each site'),
    ('Site-to-site VPN', r'crypto ikev|crypto ipsec|crypto map|tunnel-group \d|group-policy \.Default', 'high', 'Tunnels that must exist after takeover'),
    ('Remote access VPN', r'ip local pool|tunnel-group |group-policy |webvpn|dynamic-access-policy|anyconnect|access-list split-tunnel|ssl ', 'high', 'User VPN at the surviving site'),
    ('Certificates', r'crypto ca ', 'review', 'Trust points used by VPN and management'),
    ('AAA and identity', r'aaa|user-identity|access-list ISE|ldap|time-range', 'high', 'Authentication during takeover'),
    ('DNS', r'dns', 'high', 'Name resolution, FQDN objects'),
    ('Inspection', r'class-map|policy-map|service-policy|tcp-map', 'high', 'Protocol behaviour, connection limits'),
    ('Management access', r'ssh |http|telnet |console |icmp |management-interface|enable |no asdm', 'review', 'Admin reach to the surviving firewall'),
    ('Logging', r'logging |no logging ', 'review', 'Visibility'),
    ('SNMP and flow export', r'snmp-server|no snmp-server|flow-export', 'review', 'Monitoring'),
    ('Timeouts and limits', r'timeout |threat-detection|no threat-detection|tcpproxy|snort|sysopt|service-module|ngips|no pager|no object-group-search|call-home|ftp |no mac-address|hostname', 'review', 'Platform behaviour'),
]
RUNTIME_USED = {'show failover': 'pair state', 'show arp': 'live hosts', 'show int ip brief': 'link state',
                'show running-config failover': 'pair config'}


def split(text):
    """(running-config lines, {show command: line count})"""
    lines = [x.rstrip('\r') for x in text.splitlines()]
    shows, cfg, cur = {}, [], None
    marked = any(x.startswith('> ') for x in lines)
    if not marked:
        return lines, shows
    for x in lines:
        if x.startswith('> '):
            cur = x[2:].strip()
            shows.setdefault(cur, 0)
            continue
        if cur == 'show running-config':
            cfg.append(x)
        elif cur is not None:
            shows[cur] += 1
    return cfg, shows


def stanzas(lines):
    out, cur = [], None
    for x in lines:
        s = x.strip()
        if not s or s == '!' or s.startswith(':') or s.startswith('Cryptochecksum') or set(s) == {'-'}:
            continue
        if x[0] in ' \t':
            if cur is not None:
                cur[1].append(s)
            continue
        cur = (s, [])
        out.append(cur)
    return out


def category(head):
    for c, pat, imp, why in CATS:
        if re.match(pat, head):
            return c
    return 'Other'


def impact(c):
    for n, pat, imp, why in CATS:
        if n == c:
            return imp, why
    return 'review', 'No specific rule: compared as text'


class Norm:
    def __init__(self, imap, pairs, edge, tag):
        self.imap, self.pairs, self.tag = dict(imap), list(pairs) + list(edge), tag

    def __call__(self, s):
        s = re.sub(r'(ProxySG_ExtendedACL)_\d+', r'\1', s)
        s = re.sub(r'FMC_(INLINE_\w+?_rule|IPSEC_PROFILE)_\d+', r'FMC_\1', s)
        s = re.sub(r'[0-9a-f]{8}( [0-9a-f]{8})+', 'HEX', s)
        s = re.sub(r'\b\d+\.\d+\.\d+\.\d+\b', lambda m: map_ip(m.group(0), self.pairs), s)
        t = s.split(' ')
        s = ' '.join(self.imap.get(x, x) for x in t)
        if self.tag:
            s = re.sub(r'(?<![A-Za-z])%s(?=[_-])' % self.tag[0], self.tag[1], s)
        return s.strip()


def site_tag(cfg_lines):
    """the site prefix on route maps and ACLs, e.g. ABC in ABC_pbr"""
    c = Counter(m.group(1) for x in cfg_lines for m in [re.match(r'route-map ([A-Z]{2,6})[_-]', x)] if m)
    return c.most_common(1)[0][0] if c else ''


def _key(head):
    return re.sub(r'\s+', ' ', head)


def compare_text(sa, sb, na, nb):
    """{category: [(side, stanza, line)]}: lines on one side only, after normalising"""
    def index(st, n):
        d = {}
        for h, ch in st:
            c = category(h)
            if c in ('Access rules', 'NAT', 'Objects', 'Static routes'):
                continue
            d.setdefault((c, _key(n(h))), []).extend(n(x) for x in ch)
        return d
    ia, ib = index(sa, na), index(sb, nb)
    out = {}
    for k in sorted(set(ia) | set(ib)):
        c, h = k
        if k not in ib:
            out.setdefault(c, []).append(('A only', h, ''))
            continue
        if k not in ia:
            out.setdefault(c, []).append(('B only', h, ''))
            continue
        x, y = Counter(ia[k]), Counter(ib[k])
        for v in (x - y):
            out.setdefault(c, []).append(('A only', h, v))
        for v in (y - x):
            out.setdefault(c, []).append(('B only', h, v))
    return out


def _ifaces(st):
    out = {}
    for h, ch in st:
        if h.startswith('interface '):
            d = {'phys': h.split()[1], 'shut': 'shutdown' in ch, 'ch': ch}
            for x in ch:
                if x.startswith('nameif '):
                    d['nameif'] = x.split()[1]
                if x.startswith('ip address '):
                    d['ip'] = x.split()[2]
                    d['standby'] = 'standby' in x
                if x.startswith('policy-route route-map'):
                    d['pbr'] = x.split()[-1]
            if 'nameif' in d:
                out[d['nameif']] = d
    return out


def _live(shows_text, ifc):
    """hosts seen in show arp for one nameif"""
    return sorted({m.group(1) for m in re.finditer(r'^\s+%s (\d+\.\d+\.\d+\.\d+) ' % re.escape(ifc), shows_text, re.M)})


def _monitored(st):
    return {h.split()[-1]: not h.startswith('no ') for h, c in st if h.startswith(('monitor-interface', 'no monitor-interface'))}


def _ospf(st):
    out = {}
    for h, ch in st:
        if h.startswith('router ospf'):
            out[h] = [x for x in ch if x.startswith('network ')]
    return out


def _default(st):
    """(exit interface, distance) of the preferred default route"""
    best = None
    for h, c in st:
        t = h.split()
        if t[:1] == ['route'] and t[2:4] == ['0.0.0.0', '0.0.0.0'] and 'tunneled' not in t:
            d = int(t[5]) if len(t) > 5 and t[5].isdigit() else 1
            if best is None or d < best[1]:
                best = (t[1], d)
    return best


def _is_link(ifaces, line):
    """the /29 or smaller transit of an interface: each site has its own, so it is not compared"""
    t = line.split()
    net = ipaddress.IPv4Network('%s/%s' % (t[1], t[2]), strict=False)
    return net.prefixlen >= 29


def takeover_checks(sa, sb, ta, tb, prof, pairs, na, names):
    """plain findings about what must be true on B when A is gone: [{sev, area, title, detail, action}]"""
    a, b = _ifaces(sa), _ifaces(sb)
    out = []

    def add(sev, area, title, detail, action):
        out.append({'id': 'T-%d' % (len(out) + 1), 'severity': sev, 'area': area, 'title': title, 'detail': detail,
                    'action': action})
    down = []
    for n, d in a.items():
        m = prof.interface_map.get(n, n)
        x = b.get(m)
        if x is None or d.get('shut') or n in prof.ignored_ifcs:
            continue
        if x.get('shut'):
            down.append((n, m, d, x))
    if down:
        add('blocker', 'Interfaces', '%d %s interfaces are shut down: %s' % (len(down), names['B'], ', '.join(x[1] for x in down)),
            '; '.join('%s %s (%s), %d hosts live on A' % (x[1], x[3].get('ip', ''), x[3]['phys'], len(_live(ta, x[0]))) for x in down),
            'Add these to the failover runbook: no shutdown in FMC and deploy. They share addresses with A, so bring them up only after A is really gone. Traffic on them cannot pass until then.')
        miss = [x[1] for x in down if not x[3].get('standby')]
        if miss:
            add('high', 'Interfaces', 'No standby IP on %s' % ', '.join(miss), 'A has a standby address on these interfaces. %s has none, so the HA pair cannot monitor them.' % names['B'],
                'Add standby IPs in FMC before or during takeover, then enable interface monitoring.')
    pbr = [(n, prof.interface_map.get(n, n), d['pbr']) for n, d in a.items() if d.get('pbr') and n not in prof.ignored_ifcs
           and prof.interface_map.get(n, n) in b and not b[prof.interface_map.get(n, n)].get('pbr')]
    if pbr:
        add('high', 'Policy routing', 'Source-based routing on A has no match on %s for %d interfaces' % (names['B'], len(pbr)),
            ', '.join('%s -> %s (%s)' % x for x in pbr), 'Decide whether these subnets need a fixed exit on %s. Without PBR they follow the default route.' % names['B'])
    da, db = _default(sa), _default(sb)
    if da and db and prof.interface_map.get(da[0], da[0]) != db[0]:
        add('review', 'Routing', 'The preferred internet exit differs', '%s prefers %s, %s prefers %s.' % (names['A'], da[0], names['B'], db[0]),
            'Confirm this is intended. NAT and inbound rules for the preferred exit need to exist on that interface.')
    oa, ob = _ospf(sa), _ospf(sb)
    def nets(v):
        return [ipaddress.IPv4Network('%s/%s' % tuple(x.split()[1:3]), strict=False) for x in v]
    nb = [n for v in ob.values() for n in nets(v)]
    gone = sorted({na(x) for v in oa.values() for x in v if not any(nets([na(x)])[0].overlaps(n) for n in nb)
                   and not _is_link(a, x)})
    if gone:
        add('high', 'OSPF', '%d OSPF networks on A are not advertised by %s' % (len(gone), names['B']), '; '.join(gone),
            'Check each one. A network that nothing advertises after takeover cannot be reached from inside.')
    ma, mb = _monitored(sa), _monitored(sb)
    off = [prof.interface_map.get(k, k) for k, v in ma.items() if v and mb.get(prof.interface_map.get(k, k)) is False]
    if off:
        add('review', 'High availability', 'Interfaces monitored on A are not monitored on %s: %s' % (names['B'], ', '.join(off)), '', 'Enable monitoring when those interfaces go live.')
    s2s_a = [h for h, c in sa if re.match(r'tunnel-group \d+\S* type ipsec-l2l', h)]
    s2s_b = [h for h, c in sb if re.match(r'tunnel-group \d+\S* type ipsec-l2l', h)]
    if s2s_b and not s2s_a:
        add('good', 'Site-to-site VPN', 'Tunnels already end on %s' % names['B'], '; '.join(x.split()[1] for x in s2s_b),
            'No move needed. Pre-shared keys are masked in the config, so the tunnel state must be checked on the box: show crypto ikev2 sa.')
    pool = lambda st: [h for h, c in st if h.startswith('ip local pool')]
    if pool(sa) and pool(sb):
        add('good' if pool(sa) != pool(sb) else 'review', 'Remote access VPN', 'Each site has its own VPN pool', '%s / %s' % (pool(sa)[0], pool(sb)[0]),
            'Users reconnect to the %s headend. Confirm split-tunnel, group policy, certificate and DNS name for it.' % names['B'])
    wa = [x for h, c in sa if h == 'webvpn' for x in c if x.startswith('enable ')]
    wb = [x for h, c in sb if h == 'webvpn' for x in c if x.startswith('enable ')]
    if sorted(wa) != sorted(wb):
        add('review', 'Remote access VPN', 'VPN is enabled on different interfaces', 'A: %s. B: %s.' % (', '.join(wa) or 'none', ', '.join(wb) or 'none'), 'Enable it on every ISP that should serve users after takeover.')
    add('verify', 'Not visible in this config', 'These cannot be checked from show running-config',
        'Masked keys and passwords; Snort intrusion and file policies; URL, application and geolocation rule conditions; Security Intelligence; the upstream ISP or edge route for public ranges that move; FMC variable overrides.',
        'Export the FMC access policy or use an FMC snapshot, and confirm with the ISP that shared public ranges can be routed to %s.' % names['B'])
    return out


def verdict(res, names):
    """the one answer: can B take over, and what stands in the way, per area"""
    t = res.get('takeover', [])
    rules = [r for r in res.get('rules', []) if r['status'] != 'covered' and not r.get('row_state')]
    inb = [r for r in res.get('inbound', []) if not r['status'].startswith('ready') and not r.get('row_state')]
    missing_nat = [r for r in res.get('firewide', []) if r['check'].startswith('published')]
    blocks = [r for r in res.get('firewide', []) if r['check'].startswith('A block')]
    dead = [r for r in res.get('firewide', []) if r['check'].startswith('B rule')]
    pat = [f for f in res.get('findings', []) if f.get('category') == 'pat']
    rt = [f for f in res.get('findings', []) if f.get('category') == 'routing']
    objs = [o for o in res.get('objects_all', []) if o['status'] in ('different value',)]
    gaps = [('Interfaces up', sum(1 for x in t if x['severity'] == 'blocker')), ('Outbound PAT', len(pat)), ('Routing', len(rt)),
            ('Published servers', len(inb)), ('Other public addresses with no NAT on B', len(missing_nat)),
            ('Access rules not fully carried over', len(rules)), ('A blocks missing', len(blocks)),
            ('Rules that cannot match on B', len(dead)), ('Objects with another value', len(objs)),
            ('Settings to review', sum(1 for x in t if x['severity'] in ('high', 'review')))]
    open_ = sum(n for k, n in gaps)
    block = sum(n for k, n in gaps[:4])
    return {'ready': block == 0, 'text': '%s can%s take over from %s: %d must be fixed first, %d items open in total.' % (
        names['B'], '' if block == 0 else 'not yet', names['A'], block, open_), 'areas': [{'area': k, 'open': n} for k, n in gaps]}


def object_table(A, B, tag, used_text):
    """every A network object: same, translated, different or missing on B, and whether anything references it"""
    rows = []

    def val(cfg, o):
        from .compare import _group_addrs
        return o.addrs if o.kind != 'group' else _group_addrs(cfg, o)
    by_val = {}
    for o in B.objects.values():
        if not o.name.startswith('FMC_INLINE_') and o.kind != 'group':
            by_val.setdefault(repr(o.addrs), []).append(o.name)
    for o in A.objects.values():
        if o.name.startswith('FMC_INLINE_'):
            continue
        alt = re.sub(r'(?<![A-Za-z])%s(?=[_-])' % tag[0], tag[1], o.name) if tag else o.name
        alt = re.sub(r'%s' % tag[0], tag[1], alt) if tag else alt
        b = B.objects.get(o.name) or B.objects.get(alt)
        v = val(A, o)
        refs = len(re.findall(r'(?<![\w.-])%s(?![\w.-])' % re.escape(o.name), used_text)) - 1
        if o.kind == 'fqdn':
            st = 'same' if b is not None and b.value == o.value else ('different value' if b is not None else 'missing on B')
            other = b.value if b is not None else ''
            bn = b.name if b is not None else ''
        elif b is not None:
            same = repr(val(B, b)) == repr(v) or o.kind != 'group' and val(B, b) == getattr(o, 'raw_addrs', None)
            st = 'same' if same else 'different value'
            other, bn = repr(val(B, b)), b.name
        elif repr(v) in by_val:
            st, bn, other = 'same value, other name', by_val[repr(v)][0], repr(v)
        else:
            st, bn, other = 'missing on B', '', ''
        rows.append({'id': 'OBJ-' + o.name, 'name': o.name, 'kind': o.kind, 'a_value': o.value or repr(v), 'translated': repr(v) if o.kind != 'fqdn' else o.value,
                     'b_name': bn, 'b_value': other, 'status': st, 'in_use': 'yes' if refs > 0 else 'no'})
    return rows


def build(a_text, b_text, A, B, prof, pairs, edge, names):
    la, sha = split(a_text)
    lb, shb = split(b_text)
    sa, sb = stanzas(la), stanzas(lb)
    ta, tb = site_tag(la), site_tag(lb)
    tag = (ta, tb) if ta and tb and ta != tb else None
    imap = {k: v for k, v in prof.interface_map.items() if v and v != 'ignore'}
    na, nb = Norm(imap, pairs, edge, tag), Norm({}, [], [], None)
    diffs = compare_text(sa, sb, na, nb)
    ca, cb = Counter(), Counter()
    for st, c in ((sa, ca), (sb, cb)):
        for h, ch in st:
            c[category(h)] += 1 + len(ch)
    blank_a = len([x for x in la if x.strip()]) - sum(ca.values())
    blank_b = len([x for x in lb if x.strip()]) - sum(cb.values())
    ledger, rows = [], []
    for c in [x[0] for x in CATS] + ['Other']:
        imp, why = impact(c)
        d = diffs.get(c, [])
        ledger.append({'category': c, 'a_lines': ca[c], 'b_lines': cb[c], 'how': 'engine' if imp == 'engine' else 'line by line',
                       'differences': len(d), 'impact': imp, 'why': why})
        for i, (side, h, v) in enumerate(d):
            rows.append({'id': 'S-%s-%d' % (c, i), 'category': c, 'side': side, 'stanza': h, 'line': v, 'impact': imp, 'status': 'differs'})
    ledger.append({'category': 'Comments and separators', 'a_lines': blank_a, 'b_lines': blank_b, 'how': 'not config', 'differences': 0, 'impact': 'none', 'why': ''})
    for k in sorted(set(sha) | set(shb)):
        used = RUNTIME_USED.get(k)
        if k != 'show running-config':
            ledger.append({'category': 'Output: ' + k, 'a_lines': sha.get(k, 0), 'b_lines': shb.get(k, 0), 'how': 'read' if used else 'not config',
                           'differences': 0, 'impact': 'none', 'why': used or 'runtime counters, nothing to compare'})
    checks = takeover_checks(sa, sb, a_text, b_text, prof, pairs, na, names)
    return {'settings': rows, 'coverage': ledger, 'takeover': checks,
            'objects_all': object_table(A, B, tag, '\n'.join(la)), 'site_tag': list(tag or ())}
