"""Cisco FTD (LINA view) / ASA 'show running-config' adapter."""
import re
from ..model import Config, Interface, Route, NetObject, SvcObject, Rule, Nat
from ..netset import IPSet, PortSet, Service
from .base import Adapter

PORTS = {
    'aol': 5190, 'bgp': 179, 'chargen': 19, 'cifs': 3020, 'citrix-ica': 1494, 'cmd': 514, 'ctiqbe': 2748,
    'daytime': 13, 'discard': 9, 'domain': 53, 'echo': 7, 'exec': 512, 'finger': 79, 'ftp': 21, 'ftp-data': 20,
    'gopher': 70, 'h323': 1720, 'hostname': 101, 'http': 80, 'https': 443, 'ident': 113, 'imap4': 143,
    'irc': 194, 'kerberos': 750, 'klogin': 543, 'kshell': 544, 'ldap': 389, 'ldaps': 636, 'login': 513,
    'lotusnotes': 1352, 'lpd': 515, 'netbios-ssn': 139, 'nfs': 2049, 'nntp': 119, 'pcanywhere-data': 5631,
    'pim-auto-rp': 496, 'pop2': 109, 'pop3': 110, 'pptp': 1723, 'rsh': 514, 'rtsp': 554, 'sip': 5060,
    'smtp': 25, 'sqlnet': 1521, 'ssh': 22, 'sunrpc': 111, 'tacacs': 49, 'talk': 517, 'telnet': 23, 'uucp': 540,
    'whois': 43, 'www': 80, 'biff': 512, 'bootpc': 68, 'bootps': 67, 'dnsix': 195, 'isakmp': 500,
    'mobile-ip': 434, 'nameserver': 42, 'netbios-dgm': 138, 'netbios-ns': 137, 'ntp': 123, 'pcanywhere-status': 5632,
    'radius': 1645, 'radius-acct': 1646, 'rip': 520, 'secureid-udp': 5510, 'snmp': 161, 'snmptrap': 162,
    'syslog': 514, 'tftp': 69, 'vxlan': 4789, 'who': 513, 'xdmcp': 177, 'kerberos-adm': 749, 'lpd-printer': 515,
}
PROTO_NUM = {'ip': 'ip', '0': 'ip', '1': 'icmp', '6': 'tcp', '17': 'udp', '47': 'gre', '50': 'esp', '51': 'ah',
             '4': 'ipinip', '41': '41', '58': 'icmp6', '88': 'eigrp', '89': 'ospf', '103': 'pim', '112': 'vrrp'}
NAT_LINE = re.compile(r'^nat \(([^,]+),([^)]+)\)\s+(.*)$')


def port(p):
    p = p.strip()
    if p.isdigit():
        return int(p)
    if p in PORTS:
        return PORTS[p]
    raise ValueError('unknown port name %r' % p)


def port_op(op, args):
    """returns (PortSet, tokens consumed)"""
    if op == 'eq':
        v = port(args[0])
        return PortSet([(v, v)]), 1
    if op == 'range':
        return PortSet([(port(args[0]), port(args[1]))]), 2
    if op == 'gt':
        return PortSet([(port(args[0]) + 1, 65535)]), 1
    if op == 'lt':
        return PortSet([(0, port(args[0]) - 1)]), 1
    if op == 'neq':
        v = port(args[0])
        return PortSet([(0, v - 1), (v + 1, 65535)]), 1
    raise ValueError(op)


def proto(p):
    p = p.lower()
    return PROTO_NUM.get(p, p)


def inline_ref(name, value):
    """FMC_INLINE_* groups are rule literals FMC generated, not user objects: show the values"""
    return repr(value) if name.startswith('FMC_INLINE_') else name


class LinaAdapter(Adapter):
    vendor = 'lina'

    @staticmethod
    def detect(text):
        head = text[:20000]
        return bool(re.search(r'^(: Saved|ASA Version|NGFW Version|hostname |interface )', head, re.M))

    # ------------------------------------------------------------------ helpers
    def warn(self, msg):
        self.cfg.warnings.append(msg)

    def addr(self, toks, i):
        """Parse one address spec at toks[i]; returns (IPSet, ref text, next index)."""
        t = toks[i]
        if t in ('any', 'any4'):
            return IPSet.any(), t, i + 1
        if t == 'any6':
            return IPSet(), t, i + 1
        if t == 'host':
            return IPSet.host(toks[i + 1]), toks[i + 1], i + 2
        if t in ('object', 'object-group'):
            s = self.resolve(toks[i + 1])
            return s, inline_ref(toks[i + 1], s), i + 2
        if t == 'interface':
            return IPSet(), 'interface ' + toks[i + 1], i + 2
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', t):
            if i + 1 < len(toks) and re.match(r'^\d+\.\d+\.\d+\.\d+$', toks[i + 1]):
                return IPSet.net(t, toks[i + 1]), '%s %s' % (t, toks[i + 1]), i + 2
            return IPSet.host(t), t, i + 1
        if ':' in t:
            return IPSet(), t, i + 1
        raise ValueError('address %r' % t)

    def names_of(self, toks):
        """the objects an address spec names, as FMC shows them: FMC_INLINE_* groups are expanded into their named
        members and literals; 'any' for any/any4"""
        if not toks:
            return []
        if toks[0] in ('any', 'any4'):
            return ['any']
        if toks[0] == 'host':
            return [toks[1]]
        if toks[0] in ('object', 'object-group'):
            o = self.cfg.objects.get(toks[1])
            if toks[1].startswith('FMC_INLINE_') and o is not None and o.members:
                return [m[4:] if m.startswith('obj:') else m for m in o.members]
            return [toks[1]]
        if len(toks) == 2:
            return [str(IPSet.net(toks[0], toks[1]).cidrs()[0])]
        return [' '.join(toks)]

    def resolve(self, name, seen=None):
        seen = seen or set()
        if name in seen:
            self.warn('object loop at %s' % name)
            return IPSet()
        o = self.cfg.objects.get(name)
        if o is None:
            self.warn('unknown network object %s' % name)
            return IPSet()
        if o.kind != 'group':
            return o.addrs
        s = IPSet()
        for m in o.members:
            if m.startswith('obj:'):
                s = s | self.resolve(m[4:], seen | {name})
            else:
                s = s | IPSet.parse(m)
        return s

    def resolve_svc(self, name, seen=None):
        seen = seen or set()
        o = self.cfg.services.get(name)
        if o is None or name in seen:
            self.warn('unknown service object %s' % name)
            return Service.any()
        if o.kind not in ('group', 'port-group'):
            return o.svc
        s = Service()
        for m in o.members:
            if isinstance(m, str) and m.startswith('obj:'):
                s = s | self.resolve_svc(m[4:], seen | {name})
            else:
                s = s | m
        return s

    # ------------------------------------------------------------------ parse
    def parse(self, text, name):
        self.cfg = Config(name=name, vendor=self.vendor)
        lines = text.replace('\r', '').split('\n')
        blocks, cur = [], None
        self.linenos = {}
        for no, l in enumerate(lines, 1):
            if not l.strip() or l.startswith(':') or l.strip() == '!':
                cur = None if not l.startswith(' ') else cur
                continue
            if not l.startswith(' '):
                cur = [l.rstrip(), []]
                blocks.append(cur)
                self.linenos.setdefault(l.rstrip(), no)
                self.cur_no = no
            elif cur is not None:
                cur[1].append(l.strip())
                self.linenos.setdefault((cur[0], l.strip()), no)
        # pass 1: objects (network objects may be referenced before definition inside groups)
        for head, body in blocks:
            if head.startswith('hostname '):
                self.cfg.hostname = head.split()[1]
            elif head.startswith('object network '):
                self.p_object(head, body)
            elif head.startswith('object service '):
                self.p_svc_object(head, body)
        for head, body in blocks:
            if head.startswith('object-group '):
                self.p_group(head, body)
        seq = {'rule': 0, 'nat': 0}
        remarks = {}
        for head, body in blocks:
            try:
                if head.startswith('interface '):
                    self.p_interface(head, body)
                elif head.startswith('route '):
                    self.p_route(head)
                elif re.match(r'^router (bgp|ospf|eigrp|rip|isis)\b', head):
                    self.cfg.dynamic_routing.append(head.strip())
                elif head.startswith('access-list '):
                    self.p_acl(head, seq, remarks)
                elif head.startswith('access-group '):
                    t = head.split()
                    self.cfg.access_groups[t[1]] = ' '.join(t[2:])
                elif head.startswith('nat '):
                    self.p_twice_nat(head, seq)
                elif head.startswith('object network '):
                    for b in body:
                        if b.startswith('nat '):
                            self.p_object_nat(head.split()[2], b, seq)
            except Exception as e:
                self.warn('unparsed: %s (%s)' % (head[:160], e))
        self.cfg.nats.sort(key=lambda n: ({'manual-before': 0, 'auto': 1, 'manual-after': 2}[n.section], n.seq))
        for r in self.cfg.rules:
            r.lineno = self.linenos.get(r.line, 0)
        for n in self.cfg.nats:
            if n.obj:
                n.lineno = self.linenos.get(('object network %s' % n.obj, n.line.split(' / ', 1)[1]), 0)
            else:
                n.lineno = self.linenos.get(n.line, 0)
        for r in self.cfg.routes:
            r.lineno = self.linenos.get(getattr(r, 'text', ''), 0)
        for o in self.cfg.objects.values():
            o.lineno = self.linenos.get('object network %s' % o.name) or self.linenos.get(
                'object-group network %s' % o.name, 0)
        self.p_failover_standby(blocks)
        return self.cfg

    def p_interface(self, head, body):
        itf = Interface(name=head.split(None, 1)[1])
        for b in body:
            t = b.split()
            if t[0] == 'nameif':
                itf.nameif = t[1]
            elif t[0] == 'vlan' and len(t) > 1 and t[1].isdigit():
                itf.vlan = int(t[1])
            elif t[0] == 'shutdown':
                itf.shutdown = True
            elif t[0] == 'security-level' and len(t) > 1 and t[1].isdigit():
                itf.security_level = int(t[1])
            elif t[0] == 'management-only':
                itf.management_only = True
            elif t[:2] == ['ip', 'address'] and len(t) >= 4 and re.match(r'\d', t[2]):
                itf.ip, itf.mask = t[2], t[3]
                if 'standby' in t:
                    itf.standby = t[t.index('standby') + 1]
        if itf.nameif:
            self.cfg.interfaces[itf.nameif] = itf

    def p_failover_standby(self, blocks):
        pass

    def p_route(self, head):
        t = head.split()
        if len(t) < 5 or ':' in t[2]:
            return
        r = Route(ifc=t[1], network=t[2], mask=t[3], nexthop=t[4])
        r.text = head.rstrip()
        if len(t) > 5 and t[5].isdigit():
            r.distance = int(t[5])
        if 'track' in t:
            r.track = int(t[t.index('track') + 1])
        self.cfg.routes.append(r)

    def p_object(self, head, body):
        name = head.split()[2]
        o = self.cfg.objects.get(name) or NetObject(name=name, kind='', value='')
        for b in body:
            t = b.split()
            try:
                if t[0] == 'host':
                    o.kind, o.value, o.addrs = 'host', t[1], IPSet.host(t[1])
                elif t[0] == 'subnet':
                    o.kind, o.value = 'subnet', '%s %s' % (t[1], t[2])
                    o.addrs = IPSet.net(t[1], t[2]) if ':' not in t[1] else IPSet()
                elif t[0] == 'range':
                    o.kind, o.value, o.addrs = 'range', '%s %s' % (t[1], t[2]), IPSet.range(t[1], t[2])
                elif t[0] == 'fqdn':
                    o.kind, o.value, o.addrs = 'fqdn', t[-1], IPSet()
                elif t[0] == 'description':
                    o.description = b.split(None, 1)[1] if len(t) > 1 else ''
            except Exception as e:
                self.warn('object %s: %s (%s)' % (name, b, e))
        if o.kind or name not in self.cfg.objects:
            self.cfg.objects[name] = o

    def p_svc_object(self, head, body):
        name = head.split()[2]
        o = SvcObject(name=name, kind='service', value='')
        for b in body:
            t = b.split()
            if t[0] == 'service':
                o.value = ' '.join(t[1:])
                o.svc = self.svc_tokens(t[1:])
        self.cfg.services[name] = o

    def svc_tokens(self, t):
        """service <proto> [source <op> ..] [destination <op> ..]"""
        p = proto(t[0])
        s, d = None, None
        i = 1
        while i < len(t):
            if t[i] in ('source', 'destination') and i + 1 < len(t):
                ps, n = port_op(t[i + 1], t[i + 2:])
                if t[i] == 'source':
                    s = ps
                else:
                    d = ps
                i += 2 + n
            elif t[i] in ('eq', 'range', 'gt', 'lt', 'neq'):
                d, n = port_op(t[i], t[i + 1:])
                i += 1 + n
            else:
                i += 1
        return Service([(p, d, s)])

    def p_group(self, head, body):
        t = head.split()
        kind, name = t[1], t[2]
        if kind == 'network':
            o = NetObject(name=name, kind='group', value='')
            for b in body:
                u = b.split()
                if u[0] == 'network-object':
                    if u[1] == 'object':
                        o.members.append('obj:' + u[2])
                    elif u[1] == 'host':
                        o.members.append(u[2])
                    elif ':' not in u[1]:
                        o.members.append(str(IPSet.net(u[1], u[2]).cidrs()[0]) if len(u) > 2 else u[1])
                elif u[0] == 'group-object':
                    o.members.append('obj:' + u[1])
                elif u[0] == 'description':
                    o.description = b.split(None, 1)[1] if len(u) > 1 else ''
            self.cfg.objects[name] = o
        elif kind in ('service', 'protocol', 'icmp-type'):
            base = t[3] if len(t) > 3 else None
            o = SvcObject(name=name, kind='group' if not base else 'port-group', value=base or '')
            for b in body:
                u = b.split()
                try:
                    if u[0] == 'service-object':
                        if u[1] == 'object':
                            o.members.append('obj:' + u[2])
                        else:
                            o.members.append(self.svc_tokens(u[1:]))
                    elif u[0] == 'port-object':
                        d, n = port_op(u[1], u[2:])
                        o.members.append(Service([(base or 'tcp', d, None)]))
                    elif u[0] == 'group-object':
                        o.members.append('obj:' + u[1])
                    elif u[0] == 'protocol-object':
                        o.members.append(Service([(proto(u[1]), None, None)]))
                    elif u[0] == 'icmp-object':
                        o.members.append(Service([('icmp', None, None)]))
                except Exception as e:
                    self.warn('group %s: %s (%s)' % (name, b, e))
            self.cfg.services[name] = o

    # ---------------------------------------------------------------- ACLs
    def p_acl(self, head, seq, remarks):
        t = head.split()
        acl = t[1]
        if t[2] == 'remark':
            m = re.match(r'rule-id (\d+): (ACCESS POLICY|PREFILTER POLICY|L[47] RULE|RULE): (.*)$', ' '.join(t[3:]))
            if m:
                r = remarks.setdefault((acl, m.group(1)), {})
                if 'POLICY' in m.group(2):
                    r['policy'] = m.group(3).strip()
                    r['policy_kind'] = 'prefilter' if 'PREFILTER' in m.group(2) else 'access'
                else:
                    r['rule'] = m.group(3).strip()
                    r['l7'] = m.group(2) == 'L7 RULE'
            return
        if t[2] in ('standard', 'webtype', 'ethertype') or (t[2] == 'extended' and len(t) < 5):
            return
        i = 2
        if t[i] in ('extended', 'advanced'):
            i += 1
        action = t[i]
        i += 1
        rule_id = ''
        if 'rule-id' in t:
            rule_id = t[t.index('rule-id') + 1]
        # protocol / service
        svc_ref = t[i]
        if t[i] in ('object-group', 'object'):
            svc = self.resolve_svc(t[i + 1])
            svc_ref = inline_ref(t[i + 1], svc)
            i += 2
            proto_is_obj = True
        else:
            svc = None
            p = proto(t[i])
            i += 1
            proto_is_obj = False
        src_ifc = dst_ifc = None
        if t[i] == 'ifc':
            src_ifc = t[i + 1]
            i += 2
        i0 = i
        src, src_ref, i = self.addr(t, i)
        src_names = self.names_of(t[i0:i])
        sports = None
        if not proto_is_obj and i < len(t) and t[i] in ('eq', 'range', 'gt', 'lt', 'neq'):
            sports, n = port_op(t[i], t[i + 1:])
            i += 1 + n
        elif i < len(t) and t[i] == 'object-group' and t[i + 1] in self.cfg.services and \
                self.cfg.services[t[i + 1]].kind == 'port-group':
            i += 2
        if t[i] == 'ifc':
            dst_ifc = t[i + 1]
            i += 2
        i0 = i
        dst, dst_ref, i = self.addr(t, i)
        dst_names = self.names_of(t[i0:i])
        if not proto_is_obj:
            dports = None
            if i < len(t) and t[i] in ('eq', 'range', 'gt', 'lt', 'neq'):
                dports, n = port_op(t[i], t[i + 1:])
                svc_ref += ' %s %s' % (t[i], ' '.join(t[i + 1:i + 1 + n]))
                i += 1 + n
            elif i < len(t) and t[i] in ('object-group', 'object') and t[i + 1] in self.cfg.services:
                g = self.resolve_svc(t[i + 1])
                svc = Service([(p, d, sports) for q, d, s in g.items])
                svc_ref += ' ' + inline_ref(t[i + 1], g)
                i += 2
            if svc is None:
                svc = Service([(p, dports, sports)])
        seq['rule'] += 1
        rem = remarks.get((acl, rule_id), {})
        self.cfg.rules.append(Rule(seq=seq['rule'], acl=acl, action=action, src_ifc=src_ifc, dst_ifc=dst_ifc,
                                   src=src, dst=dst, svc=svc, src_ref=src_ref, dst_ref=dst_ref, svc_ref=svc_ref,
                                   rule_id=rule_id, policy=rem.get('policy', ''), rule_name=rem.get('rule', ''),
                                   inactive='inactive' in t, line=head))
        self.cfg.rules[-1].l7 = rem.get('l7', False)
        self.cfg.rules[-1].src_names = src_names
        self.cfg.rules[-1].dst_names = dst_names
        self.cfg.rules[-1].policy_kind = rem.get('policy_kind', '')

    # ---------------------------------------------------------------- NAT
    def nat_addr(self, tok):
        if tok == 'any':
            return IPSet.any()
        if tok == 'interface':
            return None
        if tok in self.cfg.objects:
            return self.resolve(tok)
        if re.match(r'^\d+\.\d+\.\d+\.\d+', tok):
            return IPSet.parse(tok)
        self.warn('NAT reference %s not found' % tok)
        return IPSet()

    def p_twice_nat(self, head, seq):
        m = NAT_LINE.match(head)
        if not m:
            return
        real_ifc, mapped_ifc, rest = m.group(1), m.group(2), m.group(3)
        desc = ''
        if ' description ' in ' ' + rest:
            rest, desc = (' ' + rest).split(' description ', 1)
            rest = rest.strip()
        t = rest.split()
        section = 'manual-before'
        if t and t[0] == 'after-auto':
            section = 'manual-after'
            t = t[1:]
        if t and t[0].isdigit():
            t = t[1:]
        if t[0] != 'source':
            return
        kind = t[1]
        real, mapped = t[2], t[3]
        n = Nat(seq=0, section=section, real_ifc=real_ifc, mapped_ifc=mapped_ifc, kind=kind,
                pat=(kind == 'dynamic' and (mapped == 'interface' or 'pat-pool' in t or self._is_host(mapped))),
                real=self.nat_addr(real), mapped=self.nat_addr(mapped), real_ref=real, mapped_ref=mapped,
                mapped_interface=(mapped == 'interface'), inactive='inactive' in t, description=desc.strip(),
                line=head)
        if 'pat-pool' in t:
            n.pat = True
            n.mapped_ref = t[t.index('pat-pool') + 1]
            n.mapped = self.nat_addr(n.mapped_ref)
        if 'destination' in t:
            j = t.index('destination')
            n.dst_real, n.dst_mapped = self.nat_addr(t[j + 2]), self.nat_addr(t[j + 3])
        if 'service' in t:
            j = t.index('service')
            n.service = ' '.join(t[j + 1:j + 3])
        seq['nat'] += 1
        n.seq = seq['nat']
        self.cfg.nats.append(n)

    def _is_host(self, ref):
        o = self.cfg.objects.get(ref)
        if o is not None:
            return o.kind == 'host'
        return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', ref))

    def p_object_nat(self, objname, line, seq):
        m = re.match(r'^nat \(([^,]+),([^)]+)\)\s+(static|dynamic)\s+(\S+)(.*)$', line)
        if not m:
            self.warn('object nat %s: %s' % (objname, line))
            return
        real_ifc, mapped_ifc, kind, mapped, rest = m.groups()
        t = rest.split()
        n = Nat(seq=0, section='auto', real_ifc=real_ifc, mapped_ifc=mapped_ifc, kind=kind,
                pat=(kind == 'dynamic' and (mapped == 'interface' or self._is_host(mapped) or 'pat-pool' == mapped)),
                real=self.resolve(objname), mapped=self.nat_addr(mapped) if mapped != 'pat-pool' else None,
                real_ref=objname, mapped_ref=mapped, mapped_interface=(mapped == 'interface'),
                inactive='inactive' in t, obj=objname, line='object network %s / %s' % (objname, line))
        if mapped == 'pat-pool' and t:
            n.mapped_ref = t[0]
            n.mapped = self.nat_addr(t[0])
            n.pat = True
        if 'service' in t:
            j = t.index('service')
            n.service = ' '.join(t[j + 1:j + 4])
        seq['nat'] += 1
        n.seq = seq['nat']
        self.cfg.nats.append(n)
