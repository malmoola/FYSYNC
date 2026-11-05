"""FMC reader / renderer / staged copy. Synthetic snapshot (documentation and private addresses only) and a fake
FMC session: no network, no production data."""
import json

import pytest

from fwsync import fmc, gaps
from fwsync.adapters import load
from fwsync.osutil import is_protected
from fwsync.pipeline import run


def obj(i, t, name, **kw):
    return dict(id='o-%d' % i, type=t, name=name, **kw)


def snap(name='FW-A', rules=None, nat=None, routes=None, default='BLOCK', objects=None, device=True):
    objs = objects or {
        'hosts': [obj(1, 'Host', 'SRV.web', value='10.1.1.10'), obj(2, 'Host', 'PUB.web', value='203.0.113.10'),
                  obj(3, 'Host', 'GW.out', value='192.0.2.1'), obj(4, 'Host', 'PARTNER.1', value='198.51.100.7')],
        'networks': [obj(5, 'Network', 'NET.inside', value='10.1.1.0/24'), obj(6, 'Network', 'NET.far', value='10.9.0.0/16')],
        'networkgroups': [obj(7, 'NetworkGroup', 'GRP.partners', objects=[{'type': 'Host', 'id': 'o-4', 'name': 'PARTNER.1'}],
                              literals=[{'type': 'Host', 'value': '198.51.100.8'}])],
        'protocolportobjects': [obj(8, 'ProtocolPortObject', 'tcp_8443', protocol='TCP', port='8443')],
        'portobjectgroups': [obj(9, 'PortObjectGroup', 'GRP.web', objects=[{'type': 'ProtocolPortObject', 'id': 'o-8',
                                                                              'name': 'tcp_8443'}])],
    }
    z = lambda n: {'objects': [{'type': 'SecurityZone', 'name': n, 'id': 'z-' + n}]}
    r = rules if rules is not None else [
        {'id': '000-000268435456', 'name': 'web in', 'action': 'ALLOW', 'enabled': True, 'sourceZones': z('OUT'),
         'destinationZones': z('IN'), 'sourceNetworks': {'objects': [{'type': 'NetworkGroup', 'id': 'o-7', 'name': 'GRP.partners'}]},
         'destinationNetworks': {'objects': [{'type': 'Host', 'id': 'o-1', 'name': 'SRV.web'}]},
         'destinationPorts': {'objects': [{'type': 'PortObjectGroup', 'id': 'o-9', 'name': 'GRP.web'}],
                              'literals': [{'type': 'PortLiteral', 'protocol': '6', 'port': '443'}]},
         'metadata': {'section': 'Mandatory'}},
        {'id': '000-000268435457', 'name': 'block far', 'action': 'BLOCK_RESET', 'enabled': True, 'sourceZones': z('IN'),
         'destinationNetworks': {'objects': [{'type': 'Network', 'id': 'o-6', 'name': 'NET.far'}]}},
        {'id': '000-000268435458', 'name': 'app rule', 'action': 'BLOCK', 'enabled': True,
         'applications': {'applications': [{'name': 'X'}], 'objects': [{'name': 'X'}]}},
        {'id': '000-000268435459', 'name': 'watch', 'action': 'MONITOR', 'enabled': True},
        {'id': '000-000268435460', 'name': 'out', 'action': 'TRUST', 'enabled': False, 'sourceZones': z('IN'),
         'destinationZones': z('OUT'), 'sourceNetworks': {'objects': [{'type': 'Network', 'id': 'o-5', 'name': 'NET.inside'}]}},
    ]
    n = nat if nat is not None else [
        {'id': 'n1', 'natType': 'STATIC', 'enabled': True, 'sourceInterface': {'name': 'IN'},
         'destinationInterface': {'name': 'OUT'}, 'originalSource': {'type': 'Host', 'id': 'o-1', 'name': 'SRV.web'},
         'translatedSource': {'type': 'Host', 'id': 'o-2', 'name': 'PUB.web'}, 'metadata': {'section': 'BEFORE_AUTO', 'index': 1}},
        {'id': 'n2', 'natType': 'DYNAMIC', 'enabled': True, 'interfaceInTranslatedSource': True, 'unidirectional': True,
         'sourceInterface': {'name': 'IN'}, 'destinationInterface': {'name': 'OUT'},
         'originalSource': {'type': 'Network', 'id': 'o-5', 'name': 'NET.inside'},
         'metadata': {'section': 'AFTER_AUTO', 'index': 2}},
    ]
    rt = routes if routes is not None else [
        {'id': 'r1', 'interfaceName': 'OUTSIDE', 'metricValue': 1,
         'selectedNetworks': [{'type': 'Network', 'id': 'o-6', 'name': 'NET.far'}],
         'gateway': {'object': {'type': 'Host', 'id': 'o-3', 'name': 'GW.out'}}}]
    return {'fwsync_fmc_snapshot': 1, 'fmc': 'fmc.example', 'user': 'ro', 'taken': 'now',
            'device': {'id': 'dev-' + name, 'name': name, 'version': '7.7.0'} if device else None,
            'interfaces': [{'name': 'Gi0/0', 'ifname': 'OUTSIDE', 'zone': 'OUT', 'ip': '192.0.2.2', 'mask': '24'},
                           {'name': 'Gi0/1', 'ifname': 'INSIDE', 'zone': 'IN', 'ip': '10.1.1.1', 'mask': '24'}] if device else [],
            'routes': rt if device else [], 'bgp': [],
            'access_policy': {'id': 'acp-' + name, 'name': 'ACP-' + name, 'default_action': default, 'rules': r},
            'nat_policy': {'id': 'nat-' + name, 'name': 'NAT-' + name, 'manual': n, 'auto': []},
            'zones': {'z-OUT': 'OUT', 'z-IN': 'IN'}, 'objects': objs, 'warnings': []}


def test_render_real_actions_and_rule_ids():
    text, warns = fmc.render(snap())
    assert 'access-list CSM_FW_ACL_ advanced permit tcp ifc OUTSIDE object-group GRP.partners ifc INSIDE object SRV.web eq 8443 rule-id 268435456' in text
    assert 'eq 443 rule-id 268435456' in text
    assert 'advanced deny ip ifc INSIDE any object NET.far rule-id 268435457' in text
    assert 'advanced trust ip ifc INSIDE object NET.inside ifc OUTSIDE any rule-id 268435460 inactive' in text
    assert 'advanced deny ip any any rule-id 268434434' in text
    assert any('app rule' in w and 'left out' in w for w in warns)
    assert any('watch' in w and 'Monitor' in w for w in warns)
    assert 'nat (INSIDE,OUTSIDE) source static SRV.web PUB.web' in text
    assert 'nat (INSIDE,OUTSIDE) after-auto source dynamic NET.inside interface' in text and 'interface unidirectional' not in text
    assert 'route OUTSIDE 10.9.0.0 255.255.0.0 192.0.2.1 1' in text


def test_adapter_reads_snapshot_as_config():
    cfg = load(json.dumps(snap()), 'a.json')
    assert cfg.vendor == 'fmc'
    names = {r.rule_name for r in cfg.rules}
    assert {'web in', 'block far', 'out', 'DEFAULT ACTION RULE'} <= names and 'app rule' not in names
    web = [r for r in cfg.rules if r.rule_name == 'web in']
    assert all(r.action == 'permit' and r.src_ifc == 'OUTSIDE' for r in web)
    assert [r.action for r in cfg.rules if r.rule_name == 'block far'] == ['deny']
    assert any(n.kind == 'static' for n in cfg.nats) and any(n.pat for n in cfg.nats)
    assert cfg.interfaces['OUTSIDE'].ip == '192.0.2.2'


def test_compare_two_snapshots_has_gaps():
    a = snap('FW-A')
    b = snap('FW-B', rules=[], nat=[], routes=[])
    res, A, B, prof = run([(json.dumps(a), 'a.json')], (json.dumps(b), 'b.json'))
    assert res['gaps_area'] == 'fmc'
    assert res['known_gaps'][0]['rank'] == 1 and len(res['known_gaps']) >= 8
    assert any(r['status'] in ('missing', 'denied') for r in res['rules'])


def test_policy_only_snapshot_uses_zone_names():
    text, warns = fmc.render(snap(device=False))
    assert 'ifc OUT object-group GRP.partners ifc IN object SRV.web' in text
    assert any('zone names stand in' in w for w in warns)


class FakeSession:
    def __init__(self, store=None):
        self.headers, self.calls, self.verify = {}, [], False
        self.store = store or {}
        self.n = 0

    def post(self, url, auth=None, timeout=None):
        return Resp(204, '', {'X-auth-access-token': 't', 'DOMAIN_UUID': 'd'})

    def request(self, method, url, json=None, params=None, timeout=None):
        self.calls.append((method, url.split('/domain/d')[-1], json))
        path = url.split('/domain/d')[-1].split('?')[0]
        if method == 'GET':
            items = self.store.get(path, [])
            return Resp(200, __import__('json').dumps({'items': items, 'paging': {'count': len(items)}}))
        if method == 'POST':
            self.n += 1
            return Resp(201, __import__('json').dumps(dict(json, id='new-%d' % self.n)))
        return Resp(200, '{}')


class Resp:
    def __init__(self, code, text, headers=None):
        self.status_code, self.text, self.headers = code, text, headers or {}

    def json(self):
        return json.loads(self.text)


def client(write=False, store=None):
    return fmc.Client('https://fmc.example', 'u', 'p', write=write, session=FakeSession(store))


def test_reader_is_read_only_and_never_deploys():
    c = client()
    with pytest.raises(fmc.Refused):
        c.api('POST', '/object/hosts', {})
    w = client(write=True)
    with pytest.raises(fmc.Refused):
        w.api('POST', '/deployment/deploymentrequests', {})
    assert w.api('GET', '/deployment/deployabledevices') is not None


def test_plan_order_disabled_and_category():
    a = snap('FW-A')
    b = snap('FW-B', rules=[], nat=[], routes=[], objects={'hosts': [obj(3, 'Host', 'GW.out', value='192.0.2.1')]})
    plan, skips = fmc.plan_copy(a, b)
    steps = [o['step'] for o in plan]
    assert steps == sorted(steps, key=['object', 'route', 'nat', 'category', 'rule'].index)
    rules = [o for o in plan if o['step'] == 'rule']
    assert rules and all(o['payload']['enabled'] is False and 'category=fwsync-staged' in o['path'] for o in rules)
    assert all(o['payload']['enabled'] is False for o in plan if o['step'] == 'nat')
    names = [o['name'] for o in plan if o['step'] == 'object']
    assert names.index('PARTNER.1') < names.index('GRP.partners') and 'GW.out' not in names
    assert any(s[1] == 'GW.out' and 'same value' in s[2] for s in skips)


def test_apply_needs_allow_push_and_allowlist(tmp_path):
    a, b = snap('FW-A'), snap('FW-B', rules=[], nat=[], routes=[])
    plan, _ = fmc.plan_copy(a, b)
    w = client(write=True)
    with pytest.raises(fmc.Refused):
        fmc.apply_copy(w, plan, b, str(tmp_path / 'u.json'), dry_run=False, allow_push=False,
                       allowlist=str(tmp_path / 'none'))
    al = tmp_path / 'allow'
    al.write_text('other.example\n')
    with pytest.raises(fmc.Refused):
        fmc.apply_copy(w, plan, b, str(tmp_path / 'u.json'), dry_run=False, allow_push=True, allowlist=str(al))
    res, undo = fmc.apply_copy(w, plan, b, str(tmp_path / 'u.json'), dry_run=True)
    assert all(r[1].startswith('would') for r in res) and not undo['ops']
    assert not [c for c in w.s.calls if c[0] != 'GET']


def test_apply_writes_undo_and_undo_deletes_in_reverse(tmp_path):
    a, b = snap('FW-A'), snap('FW-B', rules=[], nat=[], routes=[], objects={'hosts': []})
    plan, _ = fmc.plan_copy(a, b, parts=('rules',), only_rules={'block far'})
    al = tmp_path / 'allow'
    al.write_text('fmc.example\n')
    store = {'/object/networks': [{'id': 'new-1', 'type': 'Network', 'name': 'NET.far'}],
             '/object/securityzones': [{'id': 'z1', 'type': 'SecurityZone', 'name': 'IN'}]}
    w = client(write=True, store=store)
    up = tmp_path / 'undo.json'
    res, undo = fmc.apply_copy(w, plan, b, str(up), dry_run=False, allow_push=True, allowlist=str(al))
    doc = json.loads(up.read_text())
    assert is_protected(up)
    assert [o['step'] for o in doc['ops']] == ['object', 'category', 'rule']
    posted = [c for c in w.s.calls if c[0] == 'POST']
    rule = posted[-1][2]
    assert rule['enabled'] is False and rule['destinationNetworks']['objects'][0]['id'] == 'new-1'
    assert not any('/deployment' in c[1] for c in w.s.calls)
    out = fmc.undo(w, doc, dry_run=False, allow_push=True, allowlist=str(al))
    assert [o[2] for o in out] == ['block far', 'fwsync-staged', 'NET.far']
    dels = [c[1] for c in w.s.calls if c[0] == 'DELETE']
    assert len(dels) == 3 and dels[0].endswith('/new-3')


def test_undo_refuses_other_fmc(tmp_path):
    al = tmp_path / 'allow'
    al.write_text('fmc.example\n')
    with pytest.raises(fmc.Refused):
        fmc.undo(client(write=True), {'fmc': 'https://other.example', 'ops': [{'n': 1, 'name': 'x', 'path': '/x/1'}]},
                 dry_run=False, allow_push=True, allowlist=str(al))


def test_gaps_ranked_everywhere():
    g = gaps.ranked('fmc')
    assert [x['rank'] for x in g] == sorted(x['rank'] for x in g)
    assert 'Known gaps' in gaps.markdown('lina') and 'Known gaps' in gaps.html('fmc')


def test_object_payloads_are_not_treated_as_references(tmp_path):
    a = snap('FW-A', nat=[], routes=[])
    b = snap('FW-B', rules=[], nat=[], routes=[], objects={'hosts': []})
    plan, _ = fmc.plan_copy(a, b, parts=('rules',), only_rules={'web in'})
    al = tmp_path / 'allow'
    al.write_text('fmc.example\n')
    w = client(write=True, store={'/object/securityzones': [{'id': 'z1', 'type': 'SecurityZone', 'name': 'OUT'},
                                                            {'id': 'z2', 'type': 'SecurityZone', 'name': 'IN'}]})
    res, undo = fmc.apply_copy(w, plan, b, str(tmp_path / 'u.json'), dry_run=False, allow_push=True, allowlist=str(al))
    assert not undo.get('stopped_at'), undo.get('stopped_at')
    port = [c[2] for c in w.s.calls if c[0] == 'POST' and c[1].startswith('/object/protocolportobjects')][0]
    assert port['port'] == '8443' and port['name'] == 'tcp_8443'
    grp = [c[2] for c in w.s.calls if c[0] == 'POST' and c[1].startswith('/object/portobjectgroups')][0]
    assert grp['objects'][0]['id'].startswith('new-')


def group_snap():
    rule = {'id': 'r1', 'name': 'web in', 'action': 'ALLOW', 'enabled': True,
            'sourceZones': {'objects': [{'id': 'z-OUT', 'type': 'SecurityZone', 'name': 'OUT'}]},
            'destinationZones': {'objects': [{'id': 'g-1', 'type': 'InterfaceGroup', 'name': 'GRP.shared'}]},
            'destinationNetworks': {'objects': [{'type': 'Host', 'id': 'o-1', 'name': 'SRV.web'}]}}
    nat = {'natType': 'STATIC', 'originalSource': {'type': 'Host', 'id': 'o-1', 'name': 'SRV.web'},
           'translatedSource': {'type': 'Host', 'id': 'o-2', 'name': 'PUB.web'},
           'sourceInterface': {'id': 'g-1', 'type': 'InterfaceGroup', 'name': 'GRP.shared'},
           'destinationInterface': {'id': 'z-OUT', 'type': 'SecurityZone', 'name': 'OUT'}, 'metadata': {'index': 1}}
    s = snap(rules=[rule], nat=[nat])
    s['interfaces'].append({'name': 'Gi0/2', 'ifname': 'SHARED', 'zone': '', 'ip': '10.2.2.1', 'mask': '24'})
    s['zones']['g-1'] = 'GRP.shared'
    s['iface_groups'] = {'GRP.shared': ['INSIDE', 'SHARED']}
    return s


def test_interface_group_expands_to_its_members_in_nat_and_rules():
    text, _ = fmc.render(group_snap())
    assert 'nat (INSIDE,OUTSIDE) source static SRV.web PUB.web' in text
    assert 'nat (SHARED,OUTSIDE) source static SRV.web PUB.web' in text
    assert 'GRP.shared,' not in text
    assert 'ifc OUTSIDE any ifc INSIDE object SRV.web' in text and 'ifc OUTSIDE any ifc SHARED object SRV.web' in text


def test_group_members_keep_only_this_device():
    ifs = [{'id': 'i1', 'ifname': 'INSIDE'}, {'id': 'i2', 'ifname': 'SHARED'}]
    g = [{'name': 'G', 'interfaces': [{'id': 'i1', 'name': 'x'}, {'id': 'other', 'name': 'SHARED'}, {'name': 'SHARED'}]}]
    assert fmc._group_members(g, ifs) == {'G': ['INSIDE', 'SHARED']}


def test_snapshot_reads_interface_groups_and_a_refused_read_warns():
    class C:
        def all(self, path, expanded=True):
            if path == '/object/interfacegroups':
                return [{'id': 'g', 'name': 'G', 'interfaces': []}]
            return []
    s = {'zones': {}, 'warnings': []}
    assert fmc._interface_groups(C(), s)[0]['name'] == 'G' and s['zones'] == {'g': 'G'}

    class D:
        def all(self, path, expanded=True):
            raise RuntimeError('403')
    s = {'zones': {}, 'warnings': []}
    assert fmc._interface_groups(D(), s) == [] and 'Interface groups' in s['warnings'][0]
