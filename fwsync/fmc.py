"""FMC REST API: read a device or policy into a snapshot (read-only), render it as the LINA CLI the FTD compiles, and
copy selected items between devices/policies (objects -> routes -> NAT -> rules) as a staged, disabled change.

Safety: the reader refuses every method except GET. The writer never deploys (any /deployment path is refused), runs
only with --allow-push and an FMC host on the allowlist, creates access rules disabled in the category
"fwsync-staged" and NAT rules disabled, and writes an undo file after every change."""
import datetime
import ipaddress
import json
import time

from .osutil import write_text
from .push import allowed, ALLOWLIST_FILE

STAGED_CATEGORY = 'fwsync-staged'
OBJECT_PATHS = ('hosts', 'networks', 'ranges', 'fqdns', 'networkgroups', 'protocolportobjects', 'portobjectgroups',
                'icmpv4objects')
PROTO_NUM = {'6': 'tcp', '17': 'udp', '1': 'icmp', 'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}
KEEP_OBJ = ('id', 'type', 'name', 'value', 'literals', 'objects', 'port', 'protocol', 'icmpType', 'code')
KEEP_RULE = ('id', 'name', 'action', 'enabled', 'sourceZones', 'destinationZones', 'sourceNetworks',
             'destinationNetworks', 'sourcePorts', 'destinationPorts', 'applications', 'urls', 'users',
             'sourceSecurityGroupTags', 'destinationSecurityGroupTags', 'vlanTags', 'logBegin', 'logEnd',
             'sendEventsToFMC', 'enableSyslog', 'ipsPolicy', 'filePolicy', 'variableSet', 'metadata')
L7_KEYS = ('applications', 'urls', 'users', 'sourceSecurityGroupTags', 'destinationSecurityGroupTags')


class Refused(PermissionError):
    pass


def new_session(verify=True):
    """requests session: TLS verification on unless verify is False; verify may be a CA bundle path (FMC or corporate
    CA). HTTPS_PROXY / HTTP_PROXY / NO_PROXY and REQUESTS_CA_BUNDLE from the environment are honoured."""
    import requests
    s = requests.Session()
    s.trust_env = True
    if verify is False:
        import warnings
        warnings.warn('TLS certificate verification is OFF (--insecure): use only on an isolated lab network',
                      stacklevel=2)
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass
        s.verify = False
    elif isinstance(verify, str) and verify:
        from pathlib import Path
        p = Path(verify).expanduser()
        if not p.is_file():
            raise FileNotFoundError('CA bundle %s not found' % p)
        s.verify = str(p)
    return s


class Client:
    """FMC REST client. write=False (default) allows GET only. Deployment endpoints are refused in every mode."""

    def __init__(self, url, user, password, write=False, verify=True, session=None):
        self.url = url.rstrip('/')
        self.user, self._pw, self.write = user, password, write
        self.s = session if session is not None else new_session(verify)
        self.relogged = False
        self.login()

    def login(self):
        r = self.s.post(self.url + '/api/fmc_platform/v1/auth/generatetoken', auth=(self.user, self._pw), timeout=120)
        if r.status_code >= 400:
            raise RuntimeError('FMC login as %s failed: %s (not retried)' % (self.user, r.status_code))
        self.s.headers.update({'X-auth-access-token': r.headers['X-auth-access-token'],
                               'Content-Type': 'application/json'})
        self.dom = r.headers['DOMAIN_UUID']

    def api(self, method, path, data=None, params=None):
        method = method.upper()
        if '/deployment' in path and method != 'GET':
            raise Refused('fwsync never deploys (%s %s refused)' % (method, path))
        if method != 'GET' and not self.write:
            raise Refused('read-only client: %s %s refused' % (method, path))
        u = path if path.startswith('http') else self.url + '/api/fmc_config/v1/domain/%s%s' % (self.dom, path)
        for _ in range(6):
            r = self.s.request(method, u, json=data, params=params, timeout=300)
            if r.status_code == 429:
                time.sleep(5)
                continue
            if r.status_code == 401 and not self.relogged:
                self.relogged = True
                self.login()
                continue
            break
        if r.status_code >= 400:
            raise RuntimeError('%s %s: %s %s' % (method, path, r.status_code, r.text[:400]))
        return r.json() if r.text.strip() else {}

    def all(self, path, expanded=True):
        out, off = [], 0
        while True:
            j = self.api('GET', path, params={'limit': 1000, 'offset': off, 'expanded': str(expanded).lower()})
            out += j.get('items', [])
            if not j.get('items') or len(out) >= j.get('paging', {}).get('count', 0):
                return out
            off = len(out)

    def find(self, path, name):
        return next((i for i in self.all(path, expanded=False) if i.get('name') == name), None)


def _trim(o, keep):
    return {k: v for k, v in o.items() if k in keep}


# ---------------------------------------------------------------------------------------------------- snapshot
def snapshot(c, device=None, policy=None, nat_policy=None):
    """device: read the device, its interfaces, static routes, assigned ACP and NAT policy.
    policy (no device): read only that ACP (and nat_policy if given); zone names stand in for interfaces."""
    snap = {'fwsync_fmc_snapshot': 1, 'fmc': c.url.split('//')[-1], 'user': c.user,
            'taken': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'device': None, 'interfaces': [],
            'routes': [], 'bgp': [], 'access_policy': None, 'prefilter': None, 'nat_policy': None, 'zones': {}, 'objects': {},
            'warnings': []}
    snap['zones'] = {z['id']: z['name'] for z in c.all('/object/securityzones', expanded=False)}
    acp_name, nat_name = policy, nat_policy
    if device:
        d = c.find('/devices/devicerecords', device)
        if not d:
            raise RuntimeError('device %s not found on FMC' % device)
        d = c.api('GET', '/devices/devicerecords/%s' % d['id'])
        snap['device'] = {'id': d['id'], 'name': d['name'], 'version': d.get('sw_version', ''),
                          'model': d.get('model', ''), 'hostName': d.get('hostName', '')}
        acp_name = acp_name or (d.get('accessPolicy') or {}).get('name')
        for kind in ('physicalinterfaces', 'subinterfaces', 'etherchannelinterfaces', 'vlaninterfaces'):
            try:
                items = c.all('/devices/devicerecords/%s/%s' % (d['id'], kind))
            except RuntimeError:
                continue
            for i in items:
                ip = ((i.get('ipv4') or {}).get('static') or {})
                snap['interfaces'].append({
                    'name': i['name'] + ('.%s' % i['subIntfId'] if i.get('subIntfId') else ''), 'ifname': i.get('ifname', ''),
                    'zone': snap['zones'].get((i.get('securityZone') or {}).get('id'), ''), 'ip': ip.get('address', ''),
                    'mask': ip.get('netmask', ''), 'vlan': i.get('vlanId'), 'enabled': i.get('enabled', True),
                    'management_only': i.get('managementOnly', False)})
        snap['routes'] = [_trim(r, ('interfaceName', 'selectedNetworks', 'gateway', 'metricValue', 'routeTracking', 'id'))
                          for r in c.all('/devices/devicerecords/%s/routing/ipv4staticroutes' % d['id'])]
        try:
            for b in c.all('/devices/devicerecords/%s/routing/bgpgeneralsettings' % d['id']):
                snap['bgp'].append('router bgp %s' % b.get('asNumber'))
        except RuntimeError:
            pass
        if not nat_name:
            for a in c.all('/assignment/policyassignments'):
                if a.get('policy', {}).get('type') == 'FTDNatPolicy' and \
                        any(t.get('id') == d['id'] for t in a.get('targets', [])):
                    nat_name = a['policy']['name']
    if acp_name:
        p = c.find('/policy/accesspolicies', acp_name)
        if not p:
            raise RuntimeError('access policy %s not found' % acp_name)
        da = c.all('/policy/accesspolicies/%s/defaultactions' % p['id'])
        pf = (c.api('GET', '/policy/accesspolicies/%s' % p['id']).get('prefilterPolicySetting') or {})
        if pf.get('id'):
            try:
                pp = c.api('GET', '/policy/prefilterpolicies/%s' % pf['id'])
                snap['prefilter'] = {'id': pf['id'], 'name': pp.get('name', pf.get('name', '')),
                                     'default_action': (pp.get('defaultAction') or {}).get('action', 'ANALYZE_TUNNELS'),
                                     'default_id': (pp.get('defaultAction') or {}).get('id', ''),
                                     'rules': c.all('/policy/prefilterpolicies/%s/prefilterrules' % pf['id'])}
            except RuntimeError as e:
                snap['warnings'].append('prefilter policy %s not read: %s' % (pf.get('name'), str(e)[:120]))
        snap['access_policy'] = {'id': p['id'], 'name': acp_name,
                                 'default_action': da[0].get('action') if da else 'BLOCK',
                                 'default_id': da[0].get('id', '') if da else '',
                                 'rules': [_trim(r, KEEP_RULE) for r in
                                           c.all('/policy/accesspolicies/%s/accessrules' % p['id'])]}
    if nat_name:
        p = c.find('/policy/ftdnatpolicies', nat_name)
        if p:
            snap['nat_policy'] = {'id': p['id'], 'name': nat_name,
                                  'manual': c.all('/policy/ftdnatpolicies/%s/manualnatrules' % p['id']),
                                  'auto': c.all('/policy/ftdnatpolicies/%s/autonatrules' % p['id'])}
    for k in OBJECT_PATHS:
        try:
            snap['objects'][k] = [_trim(o, KEEP_OBJ) for o in c.all('/object/%s' % k)]
        except RuntimeError as e:
            snap['warnings'].append('objects %s not read: %s' % (k, str(e)[:120]))
    return snap


def save(snap, path):
    write_text(path, json.dumps(snap, indent=1))
    return path


# ---------------------------------------------------------------------------------------------------- render
class Render:
    """snapshot -> LINA text in the form the FTD compiles from FMC (object / object-group, CSM_FW_ACL_ advanced lines
    with rule-id remarks, nat, route), so the LINA adapter and the whole compare engine read it unchanged"""

    def __init__(self, snap):
        self.s = snap
        self.obj = {}
        for k, items in snap.get('objects', {}).items():
            for o in items:
                self.obj[o['id']] = o
                self.obj.setdefault(('name', o['type'], o['name']), o)
        self.byname = {}
        for o in self.obj.values():
            self.byname.setdefault(o['name'], o)
        self.out, self.done, self.warn = [], set(), list(snap.get('warnings', []))
        self.policy_mode = not snap.get('device')
        self.zone_ifs = {}
        for i in snap.get('interfaces', []):
            if i.get('ifname') and i.get('zone'):
                self.zone_ifs.setdefault(i['zone'], []).append(i['ifname'])

    def ref(self, r):
        return self.obj.get(r.get('id')) or self.byname.get(r.get('name'))

    # objects -------------------------------------------------------------------------------------------------
    def net(self, o):
        if o['name'] in self.done:
            return o['name']
        t = o['type']
        if t == 'NetworkGroup':
            members = []
            for m in o.get('objects', []):
                mo = self.ref(m)
                if mo:
                    kw = 'group-object' if mo['type'] == 'NetworkGroup' else 'network-object object'
                    members.append(' %s %s' % (kw, self.net(mo)))
            for lit in o.get('literals', []):
                members.append(self.lit_member(lit.get('value', '')))
            self.done.add(o['name'])
            self.out += ['object-group network %s' % o['name']] + [m for m in members if m.strip()]
            return o['name']
        self.done.add(o['name'])
        v = o.get('value', '')
        if t == 'Host':
            body = ' host %s' % v
        elif t == 'Network':
            n = ipaddress.ip_network(v, strict=False)
            if n.version != 4:
                self.warn.append('IPv6 object %s skipped' % o['name'])
                body = ''
            else:
                body = ' subnet %s %s' % (n.network_address, n.netmask)
        elif t == 'Range':
            body = ' range %s' % v.replace('-', ' ')
        elif t == 'FQDN':
            body = ' fqdn %s' % v
        else:
            body = ''
        self.out += ['object network %s' % o['name']] + ([body] if body else [])
        return o['name']

    def lit_member(self, v):
        """group member line for a literal; a range becomes an object (LINA groups hold no ranges)"""
        if '-' in v:
            name = 'FMC_INLINE_range_%s' % v.replace('.', '_').replace('-', '_')
            if name not in self.done:
                self.done.add(name)
                self.out += ['object network %s' % name, ' range %s' % v.replace('-', ' ')]
            return ' network-object object %s' % name
        if ':' in v:
            self.warn.append('IPv6 literal %s skipped' % v)
            return ''
        return ' network-object %s' % _cli_net(v)

    def addr_side(self, rule, key, side):
        """(tokens, inline group lines) for a rule side: any | host | object | FMC_INLINE group"""
        blk = rule.get(key) or {}
        objs = [self.ref(r) for r in blk.get('objects', [])]
        missing = [r.get('name') for r, o in zip(blk.get('objects', []), objs) if o is None]
        for m in missing:
            self.warn.append('rule %s: %s object %s not in the snapshot (left out)' % (rule['name'], side, m))
        objs = [o for o in objs if o]
        lits = [l.get('value', '') for l in blk.get('literals', [])]
        if not objs and not lits:
            return ['any']
        if len(objs) == 1 and not lits:
            o = objs[0]
            self.net(o)
            return ['object-group' if o['type'] == 'NetworkGroup' else 'object', o['name']]
        if len(lits) == 1 and not objs and '-' not in lits[0]:
            return _addr_tokens(lits[0])
        g = 'FMC_INLINE_%s_rule_%s' % (side, _rule_id(rule))
        lines = ['object-group network %s' % g]
        for o in objs:
            lines.append(' network-object object %s' % self.net(o) if o['type'] != 'NetworkGroup'
                         else ' group-object %s' % self.net(o))
        for v in lits:
            lines.append(self.lit_member(v))
        self.out += [l for l in lines if l]
        return ['object-group', g]

    def ports(self, rule, key='destinationPorts'):
        """[(proto, 'eq 80' | 'range a b' | '')] for the destination ports; [('ip', '')] when none"""
        blk = rule.get(key) or {}
        items = []

        def add_obj(o):
            if o['type'] == 'PortObjectGroup':
                for m in o.get('objects', []):
                    mo = self.ref(m)
                    if mo:
                        add_obj(mo)
            elif o['type'] in ('ICMPV4Object', 'ICMPv4Object'):
                items.append(('icmp', ''))
            else:
                items.append((PROTO_NUM.get(str(o.get('protocol', '')).upper(), str(o.get('protocol', '')).lower()),
                              _port_op(o.get('port', ''))))
        for r in blk.get('objects', []):
            o = self.ref(r)
            if o:
                add_obj(o)
            else:
                self.warn.append('rule %s: port object %s not in the snapshot' % (rule['name'], r.get('name')))
        for lit in blk.get('literals', []):
            if lit.get('type', '').startswith('ICMP'):
                items.append(('icmp', ''))
            else:
                items.append((PROTO_NUM.get(str(lit.get('protocol', '')), str(lit.get('protocol', ''))),
                              _port_op(lit.get('port', ''))))
        return items or [('ip', '')]

    def zone_ifcs(self, rule, key):
        zs = [z.get('name') or self.s['zones'].get(z.get('id'), '') for z in (rule.get(key) or {}).get('objects', [])]
        if not zs:
            return [None]
        if self.policy_mode:
            return zs
        out = []
        for z in zs:
            out += self.zone_ifs.get(z, [])
        return out

    # sections ------------------------------------------------------------------------------------------------
    def interfaces(self):
        for i in self.s.get('interfaces', []):
            self.out.append('interface %s' % i['name'])
            if i.get('vlan'):
                self.out.append(' vlan %s' % i['vlan'])
            if i.get('ifname'):
                self.out.append(' nameif %s' % i['ifname'])
            if i.get('management_only'):
                self.out.append(' management-only')
            if i.get('ip'):
                self.out.append(' ip address %s %s' % (i['ip'], _mask(i['mask'])))
            if not i.get('enabled', True):
                self.out.append(' shutdown')
        if self.policy_mode:
            zs = set()
            ap = self.s.get('access_policy') or {}
            for r in ap.get('rules', []):
                for k in ('sourceZones', 'destinationZones'):
                    zs |= {z['name'] for z in (r.get(k) or {}).get('objects', [])}
            for z in sorted(zs):
                self.out += ['interface zone-%s' % z, ' nameif %s' % z]
            self.warn.append('policy snapshot: zone names stand in for interfaces (no addresses, no routes)')

    TUNNEL = {'GRE': [('gre', '')], 'IP_IN_IP': [('ipinip', '')], 'IPV6_IN_IP': [('41', '')],
              'TEREDO': [('udp', 'eq 3544')]}

    def prefilter(self):
        pf = self.s.get('prefilter')
        if not pf:
            return
        for r in pf.get('rules', []):
            act = r.get('action', 'ANALYZE')
            if act == 'ANALYZE':
                continue
            verb = 'trust' if act == 'FASTPATH' else 'deny'
            rid = _rule_id(r)
            self.out += ['access-list CSM_FW_ACL_ remark rule-id %s: PREFILTER POLICY: %s' % (rid, pf['name']),
                         'access-list CSM_FW_ACL_ remark rule-id %s: RULE: %s' % (rid, r['name'])]
            src = self.addr_side(r, 'sourceNetworks', 'src')
            dst = self.addr_side(r, 'destinationNetworks', 'dst')
            if r.get('ruleType') == 'TUNNEL':
                ports = []
                for e in (r.get('encapsulationPorts') or []):
                    ports += self.TUNNEL.get(e, [])
            else:
                ports = self.ports(r)
            for si in self.zone_ifcs(r, 'sourceInterfaces'):
                for di in self.zone_ifcs(r, 'destinationInterfaces'):
                    for proto, op in ports or [('ip', '')]:
                        toks = ['access-list', 'CSM_FW_ACL_', 'advanced', verb, proto]
                        toks += (['ifc', si] if si else []) + src + (['ifc', di] if di else []) + dst
                        toks += (op.split() if op else []) + ['rule-id', rid]
                        toks += [] if r.get('enabled', True) else ['inactive']
                        self.out.append(' '.join(toks))
        da = pf.get('default_action', 'ANALYZE_TUNNELS')
        rid = _rule_id({'id': pf.get('default_id', '9998')})
        verb = 'deny' if da == 'BLOCK_TUNNELS' else 'permit'
        self.out += ['access-list CSM_FW_ACL_ remark rule-id %s: PREFILTER POLICY: Default Tunnel and Priority Policy' % rid,
                     'access-list CSM_FW_ACL_ remark rule-id %s: RULE: DEFAULT TUNNEL ACTION RULE' % rid,
                     'access-list CSM_FW_ACL_ advanced %s ipinip any any rule-id %s' % (verb, rid),
                     'access-list CSM_FW_ACL_ advanced %s udp any eq 3544 any range 1025 65535 rule-id %s' % (verb, rid),
                     'access-list CSM_FW_ACL_ advanced %s udp any range 1025 65535 any eq 3544 rule-id %s' % (verb, rid),
                     'access-list CSM_FW_ACL_ advanced %s 41 any any rule-id %s' % (verb, rid),
                     'access-list CSM_FW_ACL_ advanced %s gre any any rule-id %s' % (verb, rid)]

    def acl(self):
        ap = self.s.get('access_policy')
        if not ap:
            return
        self.prefilter()
        for r in ap['rules']:
            act = r.get('action', 'ALLOW')
            l7 = [k for k in L7_KEYS if (r.get(k) or {}).get('objects') or (r.get(k) or {}).get('literals')]
            if act == 'MONITOR':
                self.warn.append('rule %s: Monitor does not end the match (left out)' % r['name'])
                continue
            if l7 and act.startswith('BLOCK'):
                self.warn.append('rule %s: block with %s conditions blocks only that traffic (left out of the L3/L4 '
                                 'compare)' % (r['name'], '/'.join(l7)))
                continue
            if l7:
                self.warn.append('rule %s: %s conditions ignored; treated as %s for L3/L4' % (r['name'], '/'.join(l7), act))
            verb = {'ALLOW': 'permit', 'TRUST': 'trust'}.get(act, 'deny')
            rid = _rule_id(r)
            self.out.append('access-list CSM_FW_ACL_ remark rule-id %s: ACCESS POLICY: %s - %s' %
                            (rid, ap['name'], (r.get('metadata') or {}).get('section', 'Mandatory')))
            self.out.append('access-list CSM_FW_ACL_ remark rule-id %s: L4 RULE: %s' % (rid, r['name']))
            src = self.addr_side(r, 'sourceNetworks', 'src')
            dst = self.addr_side(r, 'destinationNetworks', 'dst')
            for si in self.zone_ifcs(r, 'sourceZones'):
                for di in self.zone_ifcs(r, 'destinationZones'):
                    for proto, op in self.ports(r):
                        toks = ['access-list', 'CSM_FW_ACL_', 'advanced', verb, proto]
                        toks += (['ifc', si] if si else []) + src + (['ifc', di] if di else []) + dst
                        toks += op.split() if op else []
                        toks += ['rule-id', rid] + ([] if r.get('enabled', True) else ['inactive'])
                        self.out.append(' '.join(toks))
        da = ap.get('default_action', 'BLOCK')
        verb = 'deny' if da == 'BLOCK' else ('trust' if da == 'TRUST' else 'permit')
        rid = _rule_id({'id': ap.get('default_id') or '268434434'})
        self.out += ['access-list CSM_FW_ACL_ remark rule-id %s: ACCESS POLICY: %s - Default' % (rid, ap['name']),
                     'access-list CSM_FW_ACL_ remark rule-id %s: L4 RULE: DEFAULT ACTION RULE' % rid,
                     'access-list CSM_FW_ACL_ advanced %s ip any any rule-id %s' % (verb, rid),
                     'access-group CSM_FW_ACL_ global']

    def nat_ifcs(self, ref):
        if not ref:
            return ['any']
        z = ref.get('name') or self.s['zones'].get(ref.get('id'), '')
        if self.policy_mode:
            return [z]
        return self.zone_ifs.get(z, []) or [z]

    def nat_obj(self, ref):
        o = self.ref(ref) if ref else None
        if not o:
            return None
        return self.net(o)

    def nat(self):
        np_ = self.s.get('nat_policy')
        if not np_:
            return
        rules = sorted(np_.get('manual', []), key=lambda r: (r.get('metadata') or {}).get('index', 0))
        before = [r for r in rules if (r.get('metadata') or {}).get('section') != 'AFTER_AUTO']
        after = [r for r in rules if (r.get('metadata') or {}).get('section') == 'AFTER_AUTO']
        for r in before:
            self.manual(r, False)
        for r in np_.get('auto', []):
            real = self.nat_obj(r.get('originalNetwork'))
            if not real:
                continue
            mapped = 'interface' if r.get('interfaceInTranslatedNetwork') else self.nat_obj(r.get('translatedNetwork'))
            for si in self.nat_ifcs(r.get('sourceInterface')):
                for di in self.nat_ifcs(r.get('destinationInterface')):
                    self.out += ['object network %s' % real, ' nat (%s,%s) %s %s' % (
                        si, di, r.get('natType', 'STATIC').lower(), mapped or 'interface')]
        for r in after:
            self.manual(r, True)

    def manual(self, r, after):
        real = self.nat_obj(r.get('originalSource')) or 'any'
        if r.get('interfaceInTranslatedSource'):
            mapped = 'interface'
        else:
            mapped = self.nat_obj(r.get('translatedSource')) or real
        if r.get('patOptions') and (r['patOptions'].get('patPoolAddress') or {}).get('name'):
            self.warn.append('NAT %s: PAT pool kept as the mapped object' % real)
        tail = []
        if r.get('originalDestination'):
            od = self.nat_obj(r['originalDestination'])
            td = self.nat_obj(r.get('translatedDestination')) or od
            tail += ['destination', 'static', od, td]
        if r.get('originalSourcePort') or r.get('originalDestinationPort'):
            self.warn.append('NAT %s: service (port) translation not rendered' % real)
        if r.get('unidirectional') and r.get('natType') != 'DYNAMIC':
            tail.append('unidirectional')
        if r.get('noProxyArp'):
            tail.append('no-proxy-arp')
        if r.get('routeLookup'):
            tail.append('route-lookup')
        if not r.get('enabled', True):
            tail.append('inactive')
        if r.get('description'):
            tail += ['description', r['description']]
        for si in self.nat_ifcs(r.get('sourceInterface')):
            for di in self.nat_ifcs(r.get('destinationInterface')):
                self.out.append(' '.join(['nat (%s,%s)' % (si, di)] + (['after-auto'] if after else []) +
                                         ['source', r.get('natType', 'STATIC').lower(), real, mapped] + tail))

    def routes(self):
        for r in self.s.get('routes', []):
            gw = (r.get('gateway') or {})
            g = gw.get('literal', {}).get('value') if gw.get('literal') else None
            if not g and gw.get('object'):
                o = self.ref(gw['object'])
                g = o.get('value') if o else None
            if not g:
                self.warn.append('route on %s: gateway not resolved' % r.get('interfaceName'))
                continue
            for n in r.get('selectedNetworks', []):
                o = self.ref(n)
                vals = _values(self, o) if o else []
                for v in vals:
                    net = ipaddress.ip_network(v if '/' in v else v + '/32', strict=False)
                    if net.version == 4:
                        self.out.append('route %s %s %s %s %s%s' % (
                            r.get('interfaceName'), net.network_address, net.netmask, g, r.get('metricValue', 1),
                            ' track 1' if r.get('routeTracking') else ''))

    def text(self):
        d = self.s.get('device') or {}
        name = d.get('name') or (self.s.get('access_policy') or {}).get('name', 'policy')
        self.out = [': Saved', ': fwsync FMC snapshot of %s (FMC %s, %s)' % (name, self.s.get('fmc'), self.s.get('taken')),
                    'NGFW Version %s' % (d.get('version') or ''), 'hostname %s' % name.replace(' ', '_')]
        self.interfaces()
        for k in ('hosts', 'networks', 'ranges', 'fqdns', 'networkgroups'):
            for o in self.s.get('objects', {}).get(k, []):
                if o['name'] not in self.done and o['name'] != 'any':
                    try:
                        self.net(o)
                    except ValueError:
                        self.warn.append('object %s: value %r not read' % (o['name'], o.get('value')))
        self.acl()
        self.nat()
        self.routes()
        self.out += list(self.s.get('bgp', []))
        return '\n'.join(self.out) + '\n'


def _values(rnd, o, seen=None):
    seen = seen or set()
    if o['name'] in seen:
        return []
    if o['type'] == 'NetworkGroup':
        out = [l.get('value', '') for l in o.get('literals', [])]
        for m in o.get('objects', []):
            mo = rnd.ref(m)
            if mo:
                out += _values(rnd, mo, seen | {o['name']})
        return out
    return [o.get('value', '')] if o['type'] in ('Host', 'Network') else []


def _rule_id(r):
    tail = str(r.get('id', '')).split('-')[-1]
    return str(int(tail)) if tail.isdigit() else str(abs(hash(r.get('name', ''))) % 10 ** 9)


def _mask(m):
    m = str(m)
    return str(ipaddress.IPv4Network('0.0.0.0/%s' % m).netmask) if m.isdigit() else m


def _cli_net(v):
    n = ipaddress.ip_network(v if '/' in v else v + '/32', strict=False)
    return 'host %s' % n.network_address if n.prefixlen == 32 else '%s %s' % (n.network_address, n.netmask)


def _addr_tokens(v):
    if v in ('0.0.0.0/0', 'any', 'any4'):
        return ['any']
    return _cli_net(v).split()


def _port_op(p):
    p = str(p or '').strip()
    if not p or p.lower() == 'any':
        return ''
    if '-' in p:
        a, b = p.split('-', 1)
        return 'range %s %s' % (a, b)
    return 'eq %s' % p


def render(snap):
    r = Render(snap)
    text = r.text()
    return text, r.warn


# ---------------------------------------------------------------------------------------------------- copy
def _key_rule(r):
    return r['name']


def _key_nat(r, zones):
    def n(x):
        return (x or {}).get('name') or zones.get((x or {}).get('id'), '')
    return (n(r.get('sourceInterface')), n(r.get('destinationInterface')), r.get('natType'), n(r.get('originalSource')),
            n(r.get('translatedSource')), bool(r.get('interfaceInTranslatedSource')), n(r.get('originalDestination')))


def _key_route(r):
    return (r.get('interfaceName'), tuple(sorted(n.get('name', '') for n in r.get('selectedNetworks', []))),
            ((r.get('gateway') or {}).get('object') or {}).get('name') or
            ((r.get('gateway') or {}).get('literal') or {}).get('value'))


def plan_copy(a, b, parts=('objects', 'routes', 'nat', 'rules'), only_rules=None, ifc_map=None):
    """a, b: snapshots (b must be a device or have the target policies). Returns the ordered plan:
    [{n, step, method, path, name, payload, refs, note}] with {POLICY}/{NAT}/{DEVICE} placeholders, plus skips."""
    ifc_map = ifc_map or {}
    plan, skips = [], []
    a_obj = {o['name']: o for k in OBJECT_PATHS for o in a.get('objects', {}).get(k, [])}
    b_obj = {o['name']: o for k in OBJECT_PATHS for o in b.get('objects', {}).get(k, [])}
    b_ifnames = {i['ifname'] for i in b.get('interfaces', []) if i.get('ifname')}
    need = []

    def want(ref):
        if not ref or not ref.get('name') or ref['name'] in need or ref['name'] == 'any':
            return
        o = a_obj.get(ref['name'])
        if o is None:
            skips.append(('object', ref['name'], 'not in the A snapshot'))
            return
        for m in o.get('objects', []):
            want(m)
        need.append(ref['name'])

    rules, nats, routes = [], [], []
    ap = a.get('access_policy') or {}
    b_rules = {_key_rule(r) for r in (b.get('access_policy') or {}).get('rules', [])}
    if 'rules' in parts:
        for r in ap.get('rules', []):
            if only_rules and r['name'] not in only_rules:
                continue
            if r['name'] in b_rules:
                skips.append(('rule', r['name'], 'already on B (same name)'))
                continue
            rules.append(r)
            for k in ('sourceNetworks', 'destinationNetworks', 'sourcePorts', 'destinationPorts'):
                for o in (r.get(k) or {}).get('objects', []):
                    want(o)
    if 'nat' in parts and a.get('nat_policy'):
        bkeys = {_key_nat(r, b['zones']) for r in (b.get('nat_policy') or {}).get('manual', [])}
        for r in a['nat_policy'].get('manual', []):
            if _key_nat(r, a['zones']) in bkeys:
                skips.append(('nat', _key_nat(r, a['zones'])[3], 'already on B'))
                continue
            nats.append(r)
            for k in ('originalSource', 'translatedSource', 'originalDestination', 'translatedDestination'):
                want(r.get(k))
    if 'routes' in parts and b.get('device'):
        bkeys = {_key_route(r) for r in b.get('routes', [])}
        for r in a.get('routes', []):
            ifc = ifc_map.get(r.get('interfaceName'), r.get('interfaceName'))
            if _key_route(dict(r, interfaceName=ifc)) in bkeys:
                skips.append(('route', '%s %s' % (ifc, [n['name'] for n in r['selectedNetworks']]), 'already on B'))
                continue
            if ifc not in b_ifnames:
                skips.append(('route', '%s %s' % (ifc, [n['name'] for n in r['selectedNetworks']]),
                              'interface %s not on B (use --map)' % ifc))
                continue
            routes.append(dict(r, interfaceName=ifc))
            for n in r.get('selectedNetworks', []):
                want(n)
            want((r.get('gateway') or {}).get('object'))
    n = 0
    if 'objects' in parts or rules or nats or routes:
        for name in need:
            o = a_obj[name]
            if name in b_obj:
                same = _obj_value(a_obj, o) == _obj_value(b_obj, b_obj[name])
                skips.append(('object', name, 'on B, same value' if same else 'on B with ANOTHER value: check before use'))
                continue
            n += 1
            path = '/object/%s' % _path_of(o['type'])
            payload = {k: v for k, v in o.items() if k in ('type', 'name', 'value', 'port', 'protocol', 'icmpType', 'code',
                                                              'literals')}
            refs = [m['name'] for m in o.get('objects', [])]
            if refs:
                payload['objects'] = [{'type': m['type'], 'name': m['name']} for m in o['objects']]
            plan.append({'n': n, 'step': 'object', 'method': 'POST', 'path': path, 'name': name, 'payload': payload,
                         'refs': refs})
    for r in routes:
        n += 1
        payload = {'type': 'IPv4StaticRoute', 'interfaceName': r['interfaceName'], 'metricValue': r.get('metricValue', 1),
                   'selectedNetworks': [{'type': x['type'], 'name': x['name']} for x in r['selectedNetworks']],
                   'gateway': r['gateway']}
        if r.get('routeTracking'):
            skips.append(('route', r['interfaceName'], 'route tracking (SLA monitor) not copied: route added untracked'))
        plan.append({'n': n, 'step': 'route', 'method': 'POST', 'path': '/devices/devicerecords/{DEVICE}/routing/ipv4staticroutes',
                     'name': '%s %s' % (r['interfaceName'], ','.join(x['name'] for x in r['selectedNetworks'])),
                     'payload': payload, 'note': 'routes cannot be disabled in FMC: active on the next deploy'})
    for r in nats:
        n += 1
        sec = 'after_auto' if (r.get('metadata') or {}).get('section') == 'AFTER_AUTO' else 'before_auto'
        payload = {k: v for k, v in r.items() if k not in ('id', 'links', 'metadata')}
        payload['enabled'] = False
        plan.append({'n': n, 'step': 'nat', 'method': 'POST',
                     'path': '/policy/ftdnatpolicies/{NAT}/manualnatrules?section=%s' % sec,
                     'name': 'NAT %s %s -> %s' % (r.get('natType'), (r.get('originalSource') or {}).get('name'),
                                                  'interface' if r.get('interfaceInTranslatedSource') else
                                                  (r.get('translatedSource') or {}).get('name')),
                     'payload': payload, 'note': 'created disabled'})
    if rules:
        n += 1
        plan.append({'n': n, 'step': 'category', 'method': 'POST', 'path': '/policy/accesspolicies/{POLICY}/categories',
                     'name': STAGED_CATEGORY, 'payload': {'type': 'Category', 'name': STAGED_CATEGORY}})
    for r in rules:
        n += 1
        payload = {k: v for k, v in r.items() if k in KEEP_RULE and k not in ('id', 'metadata', 'variableSet', 'ipsPolicy',
                                                                             'filePolicy')}
        payload.update({'type': 'AccessRule', 'enabled': False})
        plan.append({'n': n, 'step': 'rule', 'method': 'POST',
                     'path': '/policy/accesspolicies/{POLICY}/accessrules?category=%s' % STAGED_CATEGORY,
                     'name': r['name'], 'payload': payload,
                     'note': 'created disabled in %s (was %s, %s)' % (STAGED_CATEGORY, r.get('action'),
                                                                      'enabled' if r.get('enabled', True) else 'disabled')})
    return plan, skips


def _path_of(t):
    return {'Host': 'hosts', 'Network': 'networks', 'Range': 'ranges', 'FQDN': 'fqdns', 'NetworkGroup': 'networkgroups',
            'ProtocolPortObject': 'protocolportobjects', 'PortObjectGroup': 'portobjectgroups',
            'ICMPV4Object': 'icmpv4objects'}.get(t, t.lower() + 's')


def _obj_value(objs, o, seen=None):
    seen = seen or set()
    if o.get('objects') or o.get('literals'):
        out = sorted(l.get('value', '') for l in o.get('literals', []))
        for m in o.get('objects', []):
            if m['name'] not in seen and m['name'] in objs:
                out += _obj_value(objs, objs[m['name']], seen | {o['name']})
        return sorted(out)
    return [str(o.get('value', '')), str(o.get('protocol', '')), str(o.get('port', ''))]


def _resolve_refs(c, payload, cache):
    """replace {type, name} references with the target FMC's ids (by name)"""
    def look(ref):
        if not isinstance(ref, dict) or 'name' not in ref or 'type' not in ref:
            return ref
        if ref['type'] in ('SecurityZone',):
            path = '/object/securityzones'
        elif ref['type'] in ('Application', 'Url', 'URLCategory', 'SGT', 'ISESecurityGroupTag', 'Realm'):
            return ref
        else:
            path = '/object/%s' % _path_of(ref['type'])
        key = (path, ref['name'])
        if key not in cache:
            o = c.find(path, ref['name'])
            if o is None:
                raise RuntimeError('reference %s %s not found on the target FMC' % (ref['type'], ref['name']))
            cache[key] = {'type': o['type'], 'id': o['id'], 'name': o['name']}
        return cache[key]

    def walk(x):
        if isinstance(x, dict):
            if 'name' in x and 'type' in x and set(x) <= {'name', 'type', 'id', 'overridable', 'subType', 'protocol',
                                                          'port'}:
                return look(x)
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v) for v in x]
        return x
    return {k: walk(v) for k, v in payload.items()}


def apply_copy(c, plan, b, undo_path, log=print, dry_run=True, allow_push=False, allowlist=ALLOWLIST_FILE):
    """run the plan against the target FMC. dry_run (default) only prints. The undo file is rewritten after every
    successful change so a partial run can always be undone."""
    if not dry_run:
        if not allow_push:
            raise Refused('copy disabled: start with --allow-push')
        if not allowed(c.url, allowlist):
            raise Refused('%s is not in %s' % (c.url, allowlist))
        if not c.write:
            raise Refused('the client is read-only')
    ids = {'DEVICE': (b.get('device') or {}).get('id', ''), 'POLICY': (b.get('access_policy') or {}).get('id', ''),
           'NAT': (b.get('nat_policy') or {}).get('id', '')}
    undo = {'fwsync_undo': 1, 'fmc': c.url, 'created': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target': (b.get('device') or {}).get('name') or (b.get('access_policy') or {}).get('name'), 'ops': []}
    results, cache = [], {}
    for op in plan:
        path = op['path']
        for k, v in ids.items():
            if '{%s}' % k in path:
                if not v:
                    results.append((op['n'], 'skip: target has no %s' % k.lower(), op['name']))
                    path = None
                    break
                path = path.replace('{%s}' % k, v)
        if path is None:
            continue
        if dry_run:
            results.append((op['n'], 'would POST %s' % path.split('?')[0].split('/')[-1], op['name']))
            continue
        if op['step'] == 'category':
            have = c.find(path, op['name'])
            if have:
                results.append((op['n'], 'exists', op['name']))
                continue
        try:
            payload = _resolve_refs(c, op['payload'], cache)
            j = c.api('POST', path, payload)
        except RuntimeError as e:
            results.append((op['n'], 'FAILED, stopped', '%s: %s' % (op['name'], str(e)[:300])))
            undo['stopped_at'] = {'n': op['n'], 'name': op['name'], 'error': str(e)[:500]}
            write_text(undo_path, json.dumps(undo, indent=1))
            break
        base = path.split('?')[0]
        undo['ops'].append({'n': op['n'], 'step': op['step'], 'name': op['name'], 'path': '%s/%s' % (base, j.get('id'))})
        write_text(undo_path, json.dumps(undo, indent=1))
        if op['step'] == 'object':
            cache[('/object/%s' % _path_of(op['payload']['type']), op['name'])] = \
                {'type': j.get('type', op['payload']['type']), 'id': j['id'], 'name': op['name']}
        results.append((op['n'], 'created', op['name']))
    for r in results:
        log('%3d %-28s %s' % r)
    return results, undo


def undo(c, undo_doc, log=print, dry_run=True, allow_push=False, allowlist=ALLOWLIST_FILE):
    """delete what a copy created, newest first; dry run by default"""
    if not dry_run:
        if not allow_push:
            raise Refused('undo changes FMC: start with --allow-push')
        if not allowed(c.url, allowlist):
            raise Refused('%s is not in %s' % (c.url, allowlist))
        if c.url.rstrip('/') != str(undo_doc.get('fmc', '')).rstrip('/'):
            raise Refused('undo file is for %s, not %s' % (undo_doc.get('fmc'), c.url))
    out = []
    for op in reversed(undo_doc.get('ops', [])):
        if dry_run:
            out.append((op['n'], 'would DELETE', op['name']))
            continue
        try:
            c.api('DELETE', op['path'])
            out.append((op['n'], 'deleted', op['name']))
        except RuntimeError as e:
            out.append((op['n'], 'FAILED %s' % str(e)[:80], op['name']))
    for r in out:
        log('%3d %-28s %s' % r)
    return out
