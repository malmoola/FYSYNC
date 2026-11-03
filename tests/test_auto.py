"""0.2.0: auto-detect, 1:1 without a profile, 2:1 chain (intersection) and B -> A over-permit."""
import os

from fwsync.adapters import load
from fwsync.compare import effective_rules, eval_slice
from fwsync.netset import IPSet, Service, PortSet
from fwsync.pipeline import read, run
from samples import A, B

HERE = os.path.dirname(__file__)
CHAIN = [os.path.join(HERE, '..', 'samples', 'chain', f) for f in ('edge.txt', 'inner.txt', 'target.txt')]


def by(rows, **kw):
    return [r for r in rows if all(r.get(k) == v for k, v in kw.items())]


def chain():
    e, i, t = [read(p) for p in CHAIN]
    return run([e, i], t)


def test_detect_1to1_no_profile():
    res, a, b, prof = run([(A, 'a')], (B, 'b'))
    d = res['detected']
    assert d['roles_a']['outside'][0] == 'outside' and d['roles_a']['inside'][0] == 'inside'
    assert prof.interface_map == {'outside': 'OUTSIDE', 'inside': 'INSIDE'}
    assert '10.20.0.0/24' in prof.scope and '10.10.0.0/24' in prof.scope
    assert d['public_b']['ranges'] == ['203.0.113.0/24'] and prof.type == 'standard'
    assert by(res['rules'], rule='Web2-In')[0]['status'] == 'missing'
    assert by(res['nat'], real_ref='WEB1')[0]['status'] == 'match'


def test_site_type_shared_when_public_overlaps():
    res, a, b, prof = run([(A, 'a')], (B.replace('203.0.113.', '198.51.100.'), 'b'))
    assert prof.type == 'shared-edge'


def test_chain_order_and_path():
    e, i, t = [read(p) for p in CHAIN]
    res, star, b, prof = run([i, e], t)                 # given the wrong way round: edge found by its public NAT
    c = res['detected']['chain']
    assert c['edge'] == 'edge.txt' and c['note'].startswith('swapped')
    assert c['a1_toward_a2'] == 'inside' and c['a2_uplink'] == 'DC-OUT'
    assert c['regions']['I chained (both)'] == '10.50.0.0/16'
    assert prof.interface_map['A1:outside'] == 'OUTSIDE' and prof.interface_map['A2:DC-IN'] == 'INSIDE'


def test_chain_intersection():
    res, star, b, prof = chain()
    rules = effective_rules(star)
    web = IPSet.host('10.50.1.10')
    inet = IPSet.host('192.0.2.77')
    tcp = lambda p: Service([('tcp', PortSet([(p, p)]), None)])
    assert eval_slice(rules, False, False, inet, web, tcp(443))[0] == 'covered'      # both allow 443
    assert eval_slice(rules, False, False, inet, web, tcp(80))[0] != 'covered'       # only the edge allows 80
    assert eval_slice(rules, False, False, inet, IPSet.host('10.50.1.20'), tcp(22))[0] != 'covered'   # edge only
    assert eval_slice(rules, False, False, inet, IPSet.host('10.50.1.30'), tcp(25))[0] != 'covered'   # inner only
    w = by(res['rules'], path='A2∩A1', rule='A2:Web-443')[0]
    assert w['status'] == 'covered' and 'A1:Web-In' in w['intersected_with']
    app = by(res['rules'], path='A2∩A1', rule='A2:App40')[0]
    assert app['status'] == 'missing' and app['dst'] == 'APP40'
    assert by(res['rules'], path='A2', rule='A2:Campus-RDP')[0]['status'] == 'missing'


def test_fmc_inline_is_literal():
    cfg = load(read(CHAIN[0])[0], 'edge')
    r = [x for x in cfg.rules if x.rule_name == 'Apps-In'][0]
    assert r.dst_ref == '10.50.1.40/31'
    res, star, b, prof = chain()
    assert not [o for o in res['objects'] if o['name'].startswith('FMC_INLINE_')]


def test_over_permitted_b_to_a():
    res, star, b, prof = chain()
    st = {r['rule']: r['status'] for r in res['b_rules']}
    assert st['Web-443'] == 'also on A' and st['DC-Out'] == 'also on A'
    assert st['Web-80'] == 'over-permitted' and st['Jump-SSH'] == 'over-permitted'


def test_routing_readiness():
    res, star, b, prof = chain()
    st = {r['subnet']: r['status'] for r in res['routing']}
    assert st['10.50.0.0/16'] == 'ok' and st['10.60.0.0/16'] == 'wrong way'


def test_nat_from_edge_and_summary():
    res, star, b, prof = chain()
    assert by(res['nat'], real_ref='WEB')[0]['status'] == 'match'
    assert by(res['nat'], real_ref='CAMPUS-NET')[0]['status'] == 'missing'
    row = [s for s in res['summary'] if s['subnet'] == '10.50.0.0/16'][0]
    assert row['rules'].get('covered', 0) >= 2 and 'routing' in row


IDNAT = """: Saved
hostname idn
interface G0/0
 nameif outside
 ip address 198.51.100.2 255.255.255.0
interface G0/1
 nameif inside
 ip address 10.1.0.1 255.255.255.0
object network LAN
 subnet 10.1.0.0 255.255.255.0
object network VPN
 subnet 10.99.0.0 255.255.255.0
object network SRV
 host 10.1.0.5
object network SRV_PUB
 host 198.51.100.5
object network SRV_ALT
 host 198.51.100.6
nat (inside,outside) source static LAN LAN destination static VPN VPN no-proxy-arp route-lookup
nat (inside,outside) source static SRV SRV_PUB destination static VPN VPN
route outside 0.0.0.0 0.0.0.0 198.51.100.1 1
"""


def test_identity_and_twice_nat():
    b = IDNAT.replace('hostname idn', 'hostname idn-b').replace('static SRV SRV_PUB', 'static SRV SRV_ALT')
    res, a, bb, prof = run([(IDNAT, 'a')], (b, 'b'))
    k = {r['real_ref']: (r['kind'], r['status']) for r in res['nat']}
    assert k['LAN'] == ('identity twice', 'match')
    assert k['SRV'] == ('static twice', 'differs')


def test_ignore_interface():
    vpn = A.replace('interface Port-channel2\n', 'interface Port-channel3\n nameif vpn\n ip address 10.70.0.1 255.255.255.0\n'
                    'interface Port-channel2\n').replace(
        'access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9',
        'access-list CSM_FW_ACL_ remark rule-id 110: RULE: Vpn-In\n'
        'access-list CSM_FW_ACL_ advanced permit ip ifc vpn any ifc inside object LAN20 rule-id 110\n'
        'access-list CSM_FW_ACL_ remark rule-id 111: RULE: Any-To-Lan\n'
        'access-list CSM_FW_ACL_ advanced permit tcp any object LAN20 eq 22 rule-id 111\n'
        'access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9') + 'nat (vpn,outside) source static LAN20 LAN20\n'
    res, a, b, prof = run([(vpn, 'a')], (B, 'b'))
    row = [m for m in res['detected']['interface_map'] if m['a'] == 'vpn'][0]
    assert row['b'] == 'ignore' and 'VPN' in row['a_reason'] and row['suggest'] == 'ignore'   # suggested by name
    assert not by(res['rules'], rule='Vpn-In')
    res, a, b, prof = run([(vpn, 'a')], (B, 'b'), {'interface_map': {'vpn': 'INSIDE'}})       # override
    assert by(res['rules'], rule='Vpn-In')
    res, a, b, prof = run([(vpn, 'a')], (B, 'b'), {'interface_map': {'vpn': 'ignore'}})
    assert not by(res['rules'], rule='Vpn-In')
    assert not [n for n in a.nats if 'vpn' in (n.real_ifc, n.mapped_ifc)]
    r = [x for x in a.rules if x.rule_name == 'Any-To-Lan'][0]
    assert not r.src.overlaps(IPSet.parse('10.70.0.0/24'))           # addresses behind the ignored interface removed
    assert '10.70.0.0/24' not in prof.scope and prof.interface_map['inside'] == 'INSIDE'
    assert [m for m in res['detected']['interface_map'] if m['a'] == 'vpn'][0]['b'] == 'ignore'


def test_ignore_interface_2to1():
    e, i, t = [read(p) for p in CHAIN]
    res, star, b, prof = run([e, i], t, {'interface_map': {'A2:DC-IN': 'ignore'}})
    assert not [r for r in res['rules'] if r['path'] in ('A2', 'A2∩A1')]


def test_ignore_keeps_any_rules_out_of_inbound():
    vpn = A.replace('interface Port-channel2\n', 'interface Port-channel3\n nameif vpn\n ip address 10.70.0.1 255.255.255.0\n'
                    'interface Port-channel2\n').replace(
        'access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9',
        'access-list CSM_FW_ACL_ remark rule-id 112: RULE: Out-Any\n'
        'access-list CSM_FW_ACL_ advanced permit udp ifc outside any any eq 53 rule-id 112\n'
        'access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9')
    res, a, b, prof = run([(vpn, 'a')], (B, 'b'), {'interface_map': {'vpn': 'ignore'}})
    assert all('Out-Any' not in i['a_rules'] for i in res['inbound'])
