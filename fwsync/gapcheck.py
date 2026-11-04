"""Takeover gap checks (0.5.4) that look at B as it will run after takeover, with every interface up: NAT first match
for published servers, NATs whose real addresses are not behind their interface, PAT per ISP, NATs a shared network
lacks next to its siblings or A, static routes whose next hop is on no B subnet, and what a config cannot prove (FMC
reach, how servers start at B). Each result is a takeover item for the runbook; the group says whether the change
could alter traffic that works today."""
import ipaddress
import re

from . import natorder
from .compare import BROAD, nat_kind
from .detect import route_split, route_split_up, route_table, specific_ifc
from .findings import Ctx, _key, map_nat_line, sample
from .netset import IPSet, is_public


def _ifc_ok(rule_ifc, ifc):
    return rule_ifc in (None, '', 'any') or rule_ifc == ifc


def _item(out, check, sev, area, title, detail, action, group, subject, fmc, cli, verify, undo=None):
    out.append({'id': 'T-%s-%s' % (check, _key(title, subject)), 'severity': sev, 'area': area, 'title': title,
                'detail': detail, 'action': action, 'group': group, 'subject': subject, 'fmc': fmc, 'cli': cli,
                'verify': verify, 'undo': undo})


def _move(line, ifc, mo=None):
    """the same NAT line on another real interface"""
    if ' / ' in line:
        head, rest = line.split(' / ', 1)
        return [head, ' ' + re.sub(r'^nat \(([^,]+),([^)]+)\)', lambda m: 'nat (%s,%s)' % (ifc, mo or m.group(2)), rest)]
    return ['no ' + line, re.sub(r'^nat \(([^,]+),([^)]+)\)', lambda m: 'nat (%s,%s)' % (ifc, mo or m.group(2)), line)]


def nat_precedence(ctx, out):
    """for each published server: walk B's NAT first match from the interface the server is behind after takeover. A
    broader rule above the server's own rule (for example an identity NAT for the whole network, or one on any
    interface) takes its traffic first"""
    B, bs = ctx.B, ctx.n['B_short']
    for i in ctx.res.get('inbound', []):
        ri, mo = i.get('b_real_ifc'), i.get('b_mapped_ifc')
        if not ri or i.get('row_state') or i['status'].startswith('ready: each'):
            continue
        n, own = i['_nat'], i.get('_b_nat')
        for m in natorder.ordered(B):
            if own is not None and m is own:
                break
            if own is None and m.section != 'manual-before':
                break                                    # the new rule goes at the end of Before Auto NAT
            if m.inactive or not natorder.general(m) or not m.real.overlaps(n.real) or m.real == n.real:
                continue
            if not (_ifc_ok(m.real_ifc, ri) and _ifc_ok(m.mapped_ifc, mo)):
                continue
            others = m.real - n.real
            today = sorted({x for x, part in route_split_up(B, others) if x and x != ri}) if others else []
            line = natorder.line_of(m)
            where = 'Manual NAT Rules > Before Auto NAT, above line %d' % line
            what = ('%s (%s): on %s, NAT line %d (%s) is broader and comes first once %s is up, so it takes the '
                    'server\'s traffic instead of %s.' % (i['real'], i['object'], bs, line, m.line, ri,
                                                         'its own rule' if own is not None else 'the rule to add'))
            if today:
                new = today[0]
                fmc = ['During failover: Devices > NAT > %s > edit line %d: Interface Objects: Source %s (the interface '
                       'its other addresses use today) instead of %s, then Deploy. Or move the rule for %s to %s.' % (
                           ctx.natp, line, new, m.real_ifc or 'any', i['object'], where)]
                _item(out, 'NATORDER', 'high', 'NAT', 'NAT line %d overrides the published server %s' % (line, i['real']),
                      what, 'The broader rule is needed today (it serves %s), so change it during failover.' % ', '.join(
                          today), 'during', i['real'], fmc, _move(m.line, new), [
                          'packet-tracer input %s tcp %s 40000 8.8.8.8 443' % (ri, sample(n.real)),
                          'Expected: %s is translated by the rule for %s, not by line %d.' % (sample(n.real), i['object'], line)]
                      + ctx.shut_note(ri), {'fmc': ['Devices > NAT > %s > edit line %d: Source %s again, then Deploy.' % (
                          ctx.natp, line, m.real_ifc or 'any')], 'cli': [m.line]})
            else:
                _item(out, 'NATORDER', 'high', 'NAT', 'NAT line %d overrides the published server %s' % (line, i['real']),
                      what, 'Nothing else uses the broader rule today: put the server rule above it now.', 'before',
                      i['real'], ['Devices > NAT > %s: put the rule for %s in %s.' % (ctx.natp, i['object'], where)],
                      ['show nat detail'], ['show nat detail | include %s' % i['object']] + ctx.shut_note(ri))
            break


def nat_ifc_mismatch(ctx, out):
    """B NATs (static and dynamic, also PAT objects) whose real addresses are not behind their real interface"""
    B, bs = ctx.B, ctx.n['B_short']
    done = {id(i['_b_nat']) for i in ctx.res.get('inbound', []) if i.get('nat_status') == 'wrong interface'}
    for m in B.nats:
        if m.inactive or id(m) in done or m.real is None or m.real.is_any() or not m.real or \
                m.real_ifc in (None, '', 'any') or m.real_ifc not in B.interfaces:
            continue
        parts = [(x, part) for x, part in route_split(B, m.real) if x]
        ifcs = {x for x, part in parts}
        if not ifcs or m.real_ifc in ifcs:
            continue
        today = {x for x, part in route_split_up(B, m.real)}
        main = max(parts, key=lambda x: x[1].size())[0]
        kind = nat_kind(m)
        line = natorder.line_of(m)
        title = 'NAT line %d (%s %s) is on %s; its addresses are behind %s' % (line, kind, m.real_ref, m.real_ifc,
                                                                          ', '.join(sorted(ifcs)))
        detail = '%s on %s: %s (%s) is routed via %s, not %s.' % (m.line, bs, m.real_ref, repr(m.real),
                                                                ', '.join(sorted(ifcs)), m.real_ifc)
        cli = _move(m.line, main) if len(ifcs) == 1 else ['show nat detail', 'show route %s' % sample(m.real)]
        if m.real_ifc in today:
            _item(out, 'NATIFC', 'high', 'NAT', title, detail + ' Today it still works: the traffic arrives on %s.' %
                  m.real_ifc, 'Change the interface during failover, or set it to any now if it must work before and '
                  'after takeover.', 'during', m.real_ref,
                  ['During failover: Devices > NAT > %s > edit line %d: Source Interface %s (it is %s now). Option: '
                   'Source any, which works both before and after takeover and can be set now.' % (
                       ctx.natp, line, main if len(ifcs) == 1 else '<the interface B routes it to>', m.real_ifc)],
                  cli, ['show nat detail | include %s' % m.real_ref] + ctx.shut_note(main),
                  {'fmc': ['Devices > NAT > %s > edit line %d: Source Interface %s again, then Deploy.' % (
                      ctx.natp, line, m.real_ifc)], 'cli': [m.line]})
        else:
            _item(out, 'NATIFC', 'high', 'NAT', title, detail + ' It does not match this traffic today either.',
                  'Check its hit count first; then set the interface the addresses are behind.', 'check', m.real_ref,
                  ['Check first: show nat detail, line %d. Then Devices > NAT > %s > edit it: Source Interface %s.' % (
                      line, ctx.natp, main if len(ifcs) == 1 else '<the interface B routes it to>')],
                  cli, ['show nat detail | include %s' % m.real_ref] + ctx.shut_note(main))


def per_exit_pat(ctx, out):
    """A has outbound PAT on each ISP; B has it on only some: the subnet loses internet on the others"""
    A, B, prof, bs = ctx.A, ctx.B, ctx.prof, ctx.n['B_short']
    outs_a = [o for o in (prof.outside_a or []) if o in A.interfaces]
    outs_b = [o for o in (prof.outside_b or []) if o in B.interfaces]
    if len(outs_a) < 2 or not outs_b:
        return
    pat_scopes = {p for f in ctx.res.get('findings', []) if f['category'] == 'pat' for p in f['scopes']}
    for p in prof.scope:
        if p in pat_scopes or ctx.owned(p):
            continue
        s = IPSet.parse(p)
        a_src = natorder.src_ifc(A, s)
        b_src = prof.map_ifc(a_src) if a_src else None
        b_src = b_src if b_src in B.interfaces else ctx.b_in

        def has(cfg, src, o):
            return [n for part, n in natorder.effective(cfg, s, src, o) if n is not None and natorder.shared(n)]
        a_has = {o: has(A, a_src, o) for o in outs_a}
        b_has = {o: has(B, b_src, o) for o in outs_b}
        if sum(1 for v in a_has.values() if v) < 2 or not any(b_has.values()):
            continue
        for o, ns in a_has.items():
            ob = prof.map_ifc(o)
            if not ns or ob not in b_has or b_has[ob]:
                continue
            used = [n for n in B.nats if n.kind == 'dynamic' and n.mapped_ifc == ob and not n.inactive]
            reuse = ('interface' if used[0].mapped_interface else used[0].mapped_ref) if used else 'interface'
            src, on_b = ctx.bname('', s)
            src = src if on_b else 'NET_%s' % p.replace('/', '_')
            line = 'nat (%s,%s) after-auto source dynamic %s %s' % (b_src, ob, src, reuse)
            _item(out, 'PATEXIT', 'high', 'NAT', '%s has outbound PAT on %s only, not on %s' % (
                p, ', '.join(k for k, v in b_has.items() if v), ob),
                '%s translates %s on each ISP (%s); %s has no PAT for it on %s.' % (
                    ctx.n['A_short'], p, ', '.join(o for o, v in a_has.items() if v), bs, ob),
                'Traffic from this network that leaves through %s has no outbound address on %s.' % (ob, bs),
                'before', p, ['Devices > NAT > %s > Add Rule: NAT Rule Manual, Type Dynamic, Insert In Category After '
                              'Auto NAT; Interface Objects: Source %s, Destination %s; Translation: Original Source %s, '
                              'Translated Source %s (the PAT address %s already uses on %s).' % (
                                  ctx.natp, b_src, ob, src, 'Destination Interface IP' if reuse == 'interface' else reuse,
                                  bs, ob)],
                [line], ['packet-tracer input %s tcp %s 40000 8.8.8.8 443' % (b_src, sample(s)),
                         'Expected: translated to %s on %s.' % ('the %s interface address' % ob if reuse == 'interface'
                                                                else reuse, ob)] + ctx.shut_note(b_src))


KINDS = {'users': 'inside users to public addresses', 'pool-net': 'VPN pool to the network',
         'pool-public': 'VPN pool to public addresses', 'identity': 'identity NAT'}


def nat_kinds(cfg, q, pools, outs):
    """{kind: [NAT]} for network q: users to public (PAT / dynamic out of an outside interface), VPN pool to the
    network (exemption), VPN pool to the network's public addresses (hairpin), identity NAT"""
    out = {}
    pool = IPSet()
    for x in pools:
        pool = pool | x
    for n in cfg.nats:
        if n.inactive or n.real is None:
            continue
        k = nat_kind(n)
        covers = q.issubset(n.real) and n.real.size() < BROAD if not n.real.is_any() else \
            n.real_ifc not in (None, '', 'any') and any(x == n.real_ifc for x, part in route_split(cfg, q))
        if n.dst_real is None:
            if covers and k.startswith('dynamic') and n.mapped_ifc in outs:
                out.setdefault('users', []).append(n)
            elif covers and k == 'identity':
                out.setdefault('identity', []).append(n)
            continue
        if pool and covers and n.dst_real.overlaps(pool):
            out.setdefault('pool-net', []).append(n)
        elif pool and n.real.overlaps(pool) and n.dst_mapped is not None and n.dst_mapped.overlaps(q) and \
                is_public(n.dst_real):
            out.setdefault('pool-public', []).append(n)
        elif covers and k.startswith('identity'):
            out.setdefault('identity', []).append(n)
    return out


def sibling_nats(ctx, out):
    """a shared network that lacks NATs A has for it, or that its sibling networks have on B"""
    A, B, prof, bs = ctx.A, ctx.B, ctx.prof, ctx.n['B_short']
    outs_a, outs_b = list(prof.outside_a or []), list(prof.outside_b or [])
    pools_a, pools_b = getattr(A, 'pools', []) or [], getattr(B, 'pools', []) or []
    pat_scopes = {p for f in ctx.res.get('findings', []) if f['category'] == 'pat' for p in f['scopes']}
    sibs = [e['net'] for e in route_table(B) if e['kind'] == 'connected' and e['ifc'] not in outs_b and e['plen'] < 31
            and not any(IPSet.parse(e['net']).overlaps(x) for x in pools_b)]
    for p in prof.scope:
        s = IPSet.parse(p)
        if ctx.owned(p) or not specific_ifc(B, s) or specific_ifc(B, s) in outs_b:
            continue
        kb = nat_kinds(B, s, pools_b, outs_b)
        ka = nat_kinds(A, s, pools_a, outs_a)
        for k, label in KINDS.items():
            if k in kb or (k == 'users' and p in pat_scopes):
                continue
            if ka.get(k):
                n = ka[k][0]
                line, objs = map_nat_line(ctx, n.line) if not n.obj else (n.line, [])
                ri = re.match(r'^nat \(([^,]+),', line)
                ri = ri.group(1) if ri else ''
                live = ctx.up(ri) and ctx.routed_today(s, ri)
                fmc = ['Devices > NAT > %s > Add Rule: the same %s as %s line %d (%s), with %s\'s interface and '
                       'object names.' % (ctx.natp, label, ctx.n['A_short'], natorder.line_of(n), n.line, bs)]
                cli = [line]
                enable_cli = None
                if objs:
                    fmc.insert(0, 'Objects > Object Management > Network > Add: %s.' % '; '.join(
                        '%s = %s' % (o['name'], o['value']) for o in objs[:6]))
                    cli = [c for o in objs for c in o['cli']] + cli
                group = 'before'
                if live and not n.obj:
                    fmc[-1] += ' Untick Enable: create it disabled, it would change traffic %s passes today; enable ' \
                               'it during failover.' % bs
                    cli[-1] += ' inactive'
                    enable_cli = line
                _item(out, 'NATSIB', 'high', 'NAT', '%s: %s has no %s; %s has one' % (p, bs, label, ctx.n['A_short']),
                      '%s has %s for %s (line %d: %s); %s has none for it.' % (
                          ctx.n['A_short'], label, p, natorder.line_of(n), n.line, bs),
                      'After takeover this traffic is translated differently on %s than on %s.' % (bs, ctx.n['A_short']),
                      group, p, fmc, cli, ['show nat detail | include %s' % (n.real_ref or p)] + ctx.shut_note(ri))
                if enable_cli:
                    _item(out, 'NATSIBON', 'high', 'NAT', 'Enable the %s for %s' % (label, p),
                          'The %s for %s was created disabled on %s.' % (label, p, bs),
                          'Enable it when %s takes over.' % bs, 'during', p,
                          ['Devices > NAT > %s > edit the new rule for %s: tick Enable, then Deploy.' % (ctx.natp, p)],
                          [enable_cli], ['show nat detail | include %s' % (n.real_ref or p)],
                          {'fmc': ['Devices > NAT > %s > edit the rule for %s: untick Enable, then Deploy.' % (ctx.natp, p)],
                           'cli': [enable_cli + ' inactive']})
                continue
            have = []
            for q in sibs:
                if q == p:
                    continue
                kq = nat_kinds(B, IPSet.parse(q), pools_b, outs_b).get(k)
                if kq and not kq[0].real.is_any():
                    have.append((q, kq[0]))
            if have:
                q, n = have[0]
                _item(out, 'NATSIB', 'review', 'NAT', '%s: no %s on %s; sibling %s has one' % (p, label, bs, q),
                      'On %s, %s has %s (line %d: %s); %s has none.' % (bs, q, label, natorder.line_of(n), n.line, p),
                      'Check whether %s needs the same NAT after takeover. The tool cannot be sure, so it gives no '
                      'command.' % p, 'check', p,
                      ['Check: does %s need %s like %s (line %d)? If yes, add the same rule for %s in FMC: Devices > '
                       'NAT > %s.' % (p, label, q, natorder.line_of(n), p, ctx.natp)],
                      ['show nat detail | include %s' % (n.real_ref or q)], ['show nat detail'])


def next_hop_unreachable(ctx, out):
    """B static routes whose next hop is on no B subnet: B never installs or advertises them. A public range that
    relies on one is unreachable, and so is every outbound PAT address inside it"""
    B, bs = ctx.B, ctx.n['B_short']
    nets = [ipaddress.IPv4Network('%s/%s' % (i.ip, i.mask), strict=False) for i in B.interfaces.values() if i.ip]
    for r in B.routes:
        if getattr(r, 'tunneled', False) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', r.nexthop or ''):
            continue
        hop = ipaddress.IPv4Address(r.nexthop)
        if any(hop in n for n in nets):
            continue
        try:
            net = ipaddress.IPv4Network('%s/%s' % (r.network, r.mask), strict=False)
        except ValueError:
            continue
        rng = IPSet.parse(str(net))
        pats = [n for n in B.nats if not n.inactive and n.mapped is not None and not n.mapped_interface
                and not n.mapped.is_any() and n.mapped.overlaps(rng)]
        public = net.prefixlen > 0 and is_public(rng)
        detail = 'route %s %s %s %s: the next hop %s is on no %s subnet, so %s does not install this route%s.' % (
            r.ifc, r.network, r.mask, r.nexthop, r.nexthop, bs, bs,
            ' and does not advertise the public range' if public else '')
        if pats:
            detail += ' Outbound NAT that depends on this range: %s.' % '; '.join(
                'line %d %s -> %s' % (natorder.line_of(n), n.real_ref, n.mapped_ref) for n in pats[:6])
        _item(out, 'NEXTHOP', 'high', 'Routing', 'Next hop %s of the route for %s is on no %s subnet' % (
            r.nexthop, net, bs), detail,
            'Correct the next hop to a router on a %s subnet. The tool cannot know the right one, so it gives no '
            'command.' % bs, 'check', str(net),
            ['Check: which router on %s carries %s? Devices > Device Management > %s > Routing > Static Route: edit '
             'the route for %s and set that gateway.' % (r.ifc, net, bs, net)],
            ['show route %s' % net.network_address, 'show arp | include %s' % r.nexthop],
            ['show route %s' % net.network_address])


def unprovable(ctx, out):
    """what no config can prove: where FMC lives and whether it can deploy to B when A's site is lost, and how the
    servers on shared networks start at B. Go/no-go: FMC reaches B"""
    bs, a = ctx.n['B_short'], ctx.n['A_short']
    shared = [p for p in ctx.prof.scope if not ctx.owned(p) and specific_ifc(ctx.B, IPSet.parse(p))
              and specific_ifc(ctx.B, IPSet.parse(p)) not in (ctx.prof.outside_b or [])]
    _item(out, 'FMC', 'verify', 'Not visible in this config', "Go/no-go: FMC can reach and deploy to %s with %s's site "
          "down" % (bs, a), 'The config does not say where FMC lives. If it sits at %s\'s site, it is lost with it and '
          'no change in this runbook can be deployed to %s.' % (a, bs),
          'Confirm before failover that FMC (or its standby) is outside %s\'s site and reaches %s\'s management '
          'address. Do not start the takeover until it does.' % (a, bs), 'unprovable', 'FMC',
          ['FMC: Devices > Device Management: %s is healthy and was deployed recently; System > Integration > High '
           'Availability: the standby FMC is at another site.' % bs],
          ['show managers', 'sftunnel-status'], ['show managers'])
    _item(out, 'SERVERS', 'verify', 'Not visible in this config', 'How the servers on shared networks start at %s' % bs,
          'The config cannot show how servers on %s come up at %s (replication, storage, DR orchestration) or in what '
          'order.' % (', '.join(shared[:6]) + (' (+%d more)' % (len(shared) - 6) if len(shared) > 6 else '') or
                      'the shared networks', bs),
          'Confirm with the server team which servers start at %s, with the same addresses, and when.' % bs,
          'unprovable', 'servers on shared networks',
          ['Server team: list the servers and the order they start at %s; check each one against Published servers '
           'and the access rules in this report.' % bs], ['show arp'], ['show arp'])


def build(res, prof, A, B, info):
    """append the gap checks to res['takeover'] (created when settings did not run)"""
    ctx = Ctx(res, prof, A, B, info)
    out = []
    for fn in (nat_precedence, nat_ifc_mismatch, per_exit_pat, sibling_nats, next_hop_unreachable, unprovable):
        fn(ctx, out)
    res.setdefault('takeover', [])
    res['takeover'] += out
    res['go_nogo'] = [t['title'] for t in out if t['title'].startswith('Go/no-go')]
    return res

