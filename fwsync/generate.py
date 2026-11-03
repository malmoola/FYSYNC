"""Turn selected compare items into (a) an FMC REST payload bundle with a dry-run plan,
(b) a LINA CLI view, (c) a plain change list. Nothing here talks to a device."""
import re
from .netset import IPSet

PROTO = {'tcp': '6', 'udp': '17', 'icmp': '1'}


def safe(name):
    return re.sub(r'[^A-Za-z0-9_.\-]', '_', name)[:64]


class Bundle:
    def __init__(self, prof, b_name):
        self.prof = prof
        self.b = b_name
        self.ops = []          # FMC operations in dependency order
        self.cli = []
        self.changes = []
        self.names = set()

    # ------------------------------------------------------------ objects
    def net_obj(self, name, addrs, kind=None, value=None):
        """ensure a B network object for an IPSet; returns FMC reference dict"""
        name = safe(self.prof.rename_obj(name))
        if name in self.names:
            return {'type': 'Network', 'name': name}
        self.names.add(name)
        cidrs = addrs.cidrs()
        hosts = addrs.hosts()
        if len(addrs.iv) == 1 and hosts:
            typ, path, val = 'Host', '/object/hosts', hosts[0]
            cli = ['object network %s' % name, ' host %s' % val]
        elif len(cidrs) == 1:
            typ, path, val = 'Network', '/object/networks', cidrs[0]
            n = IPSet.parse(cidrs[0])
            import ipaddress
            net = ipaddress.IPv4Network(cidrs[0])
            cli = ['object network %s' % name, ' subnet %s %s' % (net.network_address, net.netmask)]
        elif len(addrs.iv) == 1:
            import ipaddress
            a, b = addrs.iv[0]
            typ, path, val = 'Range', '/object/ranges', '%s-%s' % (ipaddress.IPv4Address(a), ipaddress.IPv4Address(b))
            cli = ['object network %s' % name, ' range %s' % val.replace('-', ' ')]
        else:
            members = [{'type': 'Network', 'value': c} for c in cidrs]
            self.ops.append({'step': 'group', 'method': 'POST', 'path': '/object/networkgroups', 'name': name,
                             'payload': {'name': name, 'type': 'NetworkGroup', 'literals': members}})
            self.cli += ['object-group network %s' % name] + [' network-object %s' % self._cli_net(c) for c in cidrs]
            self.changes.append('Create network group %s (%s) on %s' % (name, ', '.join(cidrs), self.b))
            return {'type': 'NetworkGroup', 'name': name}
        self.ops.append({'step': 'object', 'method': 'POST', 'path': path, 'name': name,
                         'payload': {'name': name, 'type': typ, 'value': val}})
        self.cli += cli
        self.changes.append('Create %s object %s = %s on %s' % (typ.lower(), name, val, self.b))
        return {'type': typ, 'name': name}

    @staticmethod
    def _cli_net(c):
        import ipaddress
        n = ipaddress.IPv4Network(c)
        return 'host %s' % n.network_address if n.prefixlen == 32 else '%s %s' % (n.network_address, n.netmask)

    def zone(self, ifc):
        return {'type': 'SecurityZone', 'name': self.prof.zone_map.get(ifc, ifc)}

    def ports(self, svc):
        lits = []
        for p, d, s in svc.items:
            if p == 'ip':
                return []
            if p in ('tcp', 'udp'):
                for a, b in d.iv:
                    lits.append({'type': 'PortLiteral', 'protocol': PROTO[p], 'port': str(a) if a == b else '%d-%d' % (a, b)})
            elif p in PROTO:
                lits.append({'type': 'PortLiteral', 'protocol': PROTO[p]})
        return lits

    # ------------------------------------------------------------ items
    def _side(self, ref, addrs):
        """named object -> (FMC ref, CLI token list); literals (incl. FMC_INLINE_* values) stay literals"""
        if addrs.is_any() or ref == 'any':
            return None, ['any']
        if ref and re.match(r'^[A-Za-z]', ref) and ' ' not in ref and ',' not in ref:
            o = self.net_obj(ref, addrs)
            return {'objects': [o]}, ['object ' + o['name'] if o['type'] != 'NetworkGroup' else 'object-group ' + o['name']]
        cidrs = addrs.cidrs()
        return {'literals': [{'type': 'Host' if c.endswith('/32') else 'Network', 'value': c} for c in cidrs]}, \
            [self._cli_net(c) for c in cidrs]

    def access_rule(self, name, src_ifc, dst_ifc, src_ref, src, dst_ref, dst, svc, why):
        rname = safe('fwsync_' + name)[:30]
        sn, scli = self._side(src_ref, src)
        dn, dcli = self._side(dst_ref, dst)
        p = {'name': rname, 'action': 'ALLOW', 'enabled': True, 'type': 'AccessRule', 'logEnd': True}
        if src_ifc not in (None, 'any'):
            p['sourceZones'] = {'objects': [self.zone(src_ifc)]}
        if dst_ifc not in (None, 'any'):
            p['destinationZones'] = {'objects': [self.zone(dst_ifc)]}
        if sn:
            p['sourceNetworks'] = sn
        if dn:
            p['destinationNetworks'] = dn
        lits = self.ports(svc)
        if lits:
            p['destinationPorts'] = {'literals': lits}
        pol = self.prof.fmc.get('access_policy', '<ACCESS-POLICY>')
        self.ops.append({'step': 'access-rule', 'method': 'POST', 'path': '/policy/accesspolicies/{%s}/accessrules' % pol,
                         'name': rname, 'payload': p})
        num = {'6': 'tcp', '17': 'udp', '1': 'icmp'}
        svcs = ['%s eq %s' % (num.get(l['protocol'], l['protocol']), l['port'].replace('-', ' ')) if 'port' in l and '-' not in l['port']
                else ('%s range %s' % (num.get(l['protocol'], l['protocol']), l['port'].replace('-', ' ')) if 'port' in l
                      else num.get(l['protocol'], l['protocol'])) for l in lits] or ['ip']
        n = 0
        for sc in scli:
            for dc in dcli:
                for sv in svcs:
                    n += 1
                    if n > 24:
                        continue
                    proto, _, ports = sv.partition(' ')
                    self.cli.append('access-list CSM_FW_ACL_ advanced permit %s ifc %s %s ifc %s %s%s' % (
                        proto, src_ifc or 'any', sc, dst_ifc or 'any', dc, (' ' + ports) if ports else ''))
        if n > 24:
            self.cli.append('! ... %d more lines for %s (literal sets)' % (n - 24, rname))
        self.changes.append('Add access rule %s on %s: %s %s -> %s %s, %s (%s)' % (
            rname, pol, src_ifc or 'any', src_ref or 'any', dst_ifc or 'any', dst_ref or 'any', repr(svc), why))

    def static_nat(self, real_ref, real, real_ifc, out_ifc, pub, why, enable_existing=False):
        pol = self.prof.fmc.get('nat_policy', '<NAT-POLICY>')
        if enable_existing:
            self.ops.append({'step': 'nat', 'method': 'PUT', 'path': '/policy/ftdnatpolicies/{%s}/manualnatrules/{lookup}' % pol,
                             'name': 'enable static %s' % real_ref, 'payload': {'enabled': True},
                             'match': {'originalSource': real_ref}})
            self.changes.append('Enable the existing inactive static NAT for %s (%s) on %s' % (real_ref, repr(real), self.b))
            self.cli.append('! enable: nat (%s,%s) source static %s ... (remove "inactive")' % (real_ifc, out_ifc, real_ref))
            return
        r = self.net_obj(real_ref, real)
        if not pub:
            self.changes.append('NEEDS INPUT: no B public IP for %s; give one in the profile public_map or public_pool_b' % real_ref)
            return
        m = self.net_obj('pub_' + pub, IPSet.parse(pub))
        self.ops.append({'step': 'nat', 'method': 'POST', 'path': '/policy/ftdnatpolicies/{%s}/manualnatrules' % pol,
                         'name': 'static %s' % real_ref,
                         'payload': {'type': 'FTDManualNatRule', 'natType': 'STATIC', 'enabled': True,
                                     'sourceInterface': self.zone(real_ifc), 'destinationInterface': self.zone(out_ifc),
                                     'originalSource': r, 'translatedSource': m}})
        self.cli.append('nat (%s,%s) source static %s %s' % (real_ifc, out_ifc, r['name'], m['name']))
        self.changes.append('Add static NAT %s (%s) -> %s on %s (%s)' % (real_ref, repr(real), pub, self.b, why))

    def pat(self, subnet, label, in_ifc, out_ifc):
        pol = self.prof.fmc.get('nat_policy', '<NAT-POLICY>')
        r = self.net_obj('net_' + subnet, IPSet.parse(subnet))
        self.ops.append({'step': 'nat', 'method': 'POST', 'path': '/policy/ftdnatpolicies/{%s}/manualnatrules' % pol,
                         'name': 'pat %s' % subnet,
                         'payload': {'type': 'FTDManualNatRule', 'natType': 'DYNAMIC', 'enabled': True, 'section': 'AFTER_AUTO',
                                     'sourceInterface': self.zone(in_ifc), 'destinationInterface': self.zone(out_ifc),
                                     'originalSource': r, 'interfaceInTranslatedSource': True}})
        self.cli.append('nat (%s,%s) after-auto source dynamic %s interface' % (in_ifc, out_ifc, r['name']))
        self.changes.append('Add interface PAT for %s (%s) %s -> %s on %s' % (subnet, label, in_ifc, out_ifc, self.b))

    def plan(self):
        order = {'object': 0, 'group': 1, 'nat': 2, 'access-rule': 3}
        ops = sorted(self.ops, key=lambda o: order[o['step']])
        for i, o in enumerate(ops, 1):
            o['n'] = i
        return ops


def generate(res, selected, prof, b_cfg):
    """selected: list of item ids from res (R*, N*, P-B-*, I*, O-*)"""
    sel = set(selected)
    bd = Bundle(prof, b_cfg.name)
    for p in res.get('planned', []):
        bd.changes.append('PLANNED (what-if, assumed in the compare): %s' % p['detail'])
        if p['kind'] in ('route', 'nat pool'):
            bd.cli.append(p['detail'])
        elif p['kind'] == 'interface':
            bd.cli += ['interface <new-port>', ' nameif %s' % p['item']]
    outs_b = prof.outside_b or [n for n in b_cfg.interfaces if 'out' in n.lower()]
    out_b = outs_b[0] if outs_b else 'outside'
    for o in res['objects']:
        if o['id'] in sel and o['status'] in ('missing on B', 'same name, different value'):
            obj = o['_obj']
            if o['status'] == 'same name, different value':
                bd.changes.append('CHECK: %s exists on %s with value %s (A: %s); not changed' % (o['b_name'], bd.b, o['b_value_or_names'], o['addrs']))
                continue
            bd.net_obj(obj.name, IPSet.parse(','.join(IPSet.parse(x).cidrs()[0] for x in o['addrs'].split(', ') if x and x != 'any')) if obj.kind == 'group' else obj.addrs)
    for n in res['nat']:
        if n['id'] not in sel:
            continue
        nat = n['_nat']
        b_real_ifc = prof.map_ifc(nat.real_ifc)
        if n['kind'].startswith('static') and n['status'] == 'missing':
            bd.static_nat(nat.real_ref, nat.real, b_real_ifc, out_b, n.get('proposed_b_mapped', ''), 'A NAT %s' % n['id'])
        elif n['kind'].startswith('static') and n['status'] == 'inactive on B':
            bd.static_nat(nat.real_ref, nat.real, b_real_ifc, out_b, '', 'A NAT %s' % n['id'], enable_existing=True)
    for p in res['pat']:
        if p['id'] in sel and p['side'] == 'B' and p['status'] != 'covered':
            in_ifc = prof.map_ifc(prof.interface_map and list(prof.interface_map)[0] or 'inside')
            ins = [v for k, v in prof.interface_map.items() if 'in' in k.lower()] or ['inside']
            bd.pat(p['subnet'], p['scope'], ins[0], out_b)
    for i in res['inbound']:
        if i['id'] in sel and i['status'] != 'ready':
            nat = i['_nat']
            if 'rule covered' not in i['status']:
                bd.access_rule('in_' + nat.real_ref, out_b, prof.map_ifc(nat.real_ifc), 'any', IPSet.any(),
                               nat.real_ref, nat.real, i['_svc'], 'inbound for %s (A rules %s)' % (nat.real_ref, i['a_rules']))
    scope = prof.scope_set()
    for r in res['rules']:
        if r['id'] in sel and r['status'] != 'covered':
            for rule in r.get('_rules', [r['_rule']]):
                src = rule.src & scope if rule.src.overlaps(scope) and not rule.dst.overlaps(scope) else rule.src
                dst = rule.dst & scope if rule.dst.overlaps(scope) and not rule.src.overlaps(scope) else rule.dst
                bd.access_rule(r['rule'] or rule.rule_id or r['id'], prof.map_ifc(rule.src_ifc) or 'any',
                               prof.map_ifc(rule.dst_ifc) or 'any', rule.src_ref, src, rule.dst_ref, dst, rule.svc,
                               'A %s %s' % (r['id'], r['status']))
    return {'plan': bd.plan(), 'cli': bd.cli, 'changes': bd.changes}
