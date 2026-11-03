"""0.4.1: inbound rules keep A's sources and names, PAT only for A's translated sources (interface PAT by default),
public IP math (a)/(b)/(c), rule findings per FMC rule name with server-only rules folded, ACP placement, DNS."""
from fwsync.pipeline import run
from fwsync.findings import plan_markdown

A = """hostname EDGE-A
interface Ethernet1/1
 nameif outside
 ip address 198.51.100.2 255.255.255.0
interface Ethernet1/2
 nameif inside
 ip address 10.1.0.1 255.255.255.0
object network SRV1
 host 10.20.0.10
object network PUB1
 host 198.51.100.10
object network SRV2
 host 10.20.0.11
object network PUB2
 host 198.51.100.11
object network PARTNER1
 host 192.0.2.5
object network PARTNER2
 host 192.0.2.6
object network NET20
 subnet 10.20.0.0 255.255.255.0
object network ADMIN-NET
 subnet 10.20.0.128 255.255.255.128
object-group network any
 network-object 0.0.0.0 0.0.0.0
object network PATIP
 host 198.51.100.50
object-group network PAT-HOSTS
 network-object host 10.20.0.50
 network-object host 10.20.0.51
object-group network FMC_INLINE_src_rule_201
 network-object object PARTNER1
 network-object object PARTNER2
object-group service PORTS tcp
 port-object eq 8080
 port-object eq 8081
access-list CSM_FW_ACL_ remark rule-id 200: ACCESS POLICY: EDGE - Mandatory
access-list CSM_FW_ACL_ remark rule-id 201: RULE: Partner-To-SRV1
access-list CSM_FW_ACL_ advanced permit tcp ifc outside object-group FMC_INLINE_src_rule_201 ifc inside object SRV1 eq 443 rule-id 201
access-list CSM_FW_ACL_ advanced permit tcp ifc outside object-group FMC_INLINE_src_rule_201 ifc inside object SRV1 eq 8443 rule-id 201
access-list CSM_FW_ACL_ remark rule-id 202: RULE: Any-To-SRV1
access-list CSM_FW_ACL_ advanced permit tcp ifc outside any ifc inside object SRV1 object-group PORTS rule-id 202
access-list CSM_FW_ACL_ remark rule-id 203: RULE: Admin-To-Mgmt
access-list CSM_FW_ACL_ advanced permit tcp ifc outside object PARTNER1 ifc inside object ADMIN-NET eq 22 rule-id 203
access-list CSM_FW_ACL_ advanced permit tcp ifc outside object PARTNER1 ifc inside object ADMIN-NET eq 3389 rule-id 203
access-list CSM_FW_ACL_ remark rule-id 9: L4 RULE: DEFAULT ACTION RULE
access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9
access-group CSM_FW_ACL_ global
route outside 0.0.0.0 0.0.0.0 198.51.100.1 1
route inside 10.20.0.0 255.255.255.0 10.1.0.2 1
nat (inside,outside) source static SRV1 PUB1
nat (inside,outside) source static SRV2 PUB2
nat (inside,outside) after-auto source dynamic PAT-HOSTS PATIP
"""

B = """hostname FW-B
interface Ethernet1/1
 nameif OUTSIDE
 ip address 203.0.113.2 255.255.255.248
interface Ethernet1/2
 nameif INSIDE
 ip address 10.9.0.1 255.255.255.0
object network NET77
 subnet 10.77.0.0 255.255.0.0
access-list CSM_FW_ACL_ remark rule-id 301: ACCESS POLICY: Site - Default
access-list CSM_FW_ACL_ remark rule-id 301: L4 RULE: Site-Default-Out
access-list CSM_FW_ACL_ advanced permit ip ifc INSIDE any ifc OUTSIDE any rule-id 301
access-list CSM_FW_ACL_ remark rule-id 9: L4 RULE: DEFAULT ACTION RULE
access-list CSM_FW_ACL_ advanced deny ip any any rule-id 9
access-group CSM_FW_ACL_ global
route OUTSIDE 0.0.0.0 0.0.0.0 203.0.113.1 1
route INSIDE 10.77.0.0 255.255.0.0 10.9.0.2 1
nat (INSIDE,OUTSIDE) after-auto source dynamic NET77 interface
"""

PROF = {'scope': ['10.20.0.0/24'], 'scope_names': {'10.20.0.0/24': 'VLAN 20'},
        'names': {'A': 'Edge (E)', 'B': 'DR (D)'}, 'public_pool_b': ['203.0.113.5-203.0.113.6']}


def go(**kw):
    p = dict(PROF)
    p.update(kw)
    return run([(A, 'a.txt')], (B, 'b.txt'), p)[0]


def find(res, cat, text=''):
    return [f for f in res['findings'] if f['category'] == cat and text in f['what']]


def test_inbound_keeps_source_group_name_and_ports():
    res = go()
    f = find(res, 'inbound', '10.20.0.10')[0]
    specs = {s['name']: s for s in f['acp_specs']}
    assert set(specs) == {'Partner-To-SRV1', 'Any-To-SRV1'}
    assert specs['Partner-To-SRV1']['src'] == ['PARTNER1', 'PARTNER2']
    assert specs['Partner-To-SRV1']['ports'] == ['TCP 443', 'TCP 8443']
    assert specs['Any-To-SRV1']['src'] == ['any'] and specs['Any-To-SRV1']['ports'] == ['PORTS']
    cli = '\n'.join(f['fix']['cli'])
    assert 'ifc OUTSIDE object PARTNER1 ifc INSIDE object SRV1 eq 443' in cli
    assert 'ifc OUTSIDE any ifc INSIDE object SRV1 eq 8080' in cli
    names = {o['name'] for o in f['fix']['objects']}
    assert {'PARTNER1', 'PARTNER2', 'PORTS'} <= names and 'any' not in names
    assert any('Name "Partner-To-SRV1"' in x for x in f['fix']['fmc'])


def test_server_only_rules_folded_and_rules_grouped_by_name():
    res = go()
    rules = find(res, 'rules')
    names = [f['rule'] for f in rules]
    assert 'Partner-To-SRV1' not in names and 'Any-To-SRV1' not in names
    assert set(res['folded_rules']) == {'Partner-To-SRV1', 'Any-To-SRV1'}
    net = [f for f in rules if f['rule'] == 'Admin-To-Mgmt']
    assert len(net) == 1 and net[0]['lines'] == 2


def test_pat_only_a_sources_interface_by_default():
    res = go()
    f = find(res, 'pat')[0]
    assert f['pat_sources'] == ['PAT-HOSTS'] and f['pat_pool'] == 0
    assert f['fix']['cli'] == ['nat (INSIDE,OUTSIDE) after-auto source dynamic PAT-HOSTS interface']
    d = [x for x in res['decisions'] if x['kind'] == 'PAT address'][0]
    assert not d['open'] and d['choice'].endswith('(default)')
    res2 = go(decision_state={d['id']: {'choice': "match A's address"}})
    f2 = find(res2, 'pat')[0]
    assert f2['pat_pool'] == 1 and 'interface' not in f2['fix']['cli'][0]


def test_public_ip_math():
    res = go()
    pool = [d for d in res['decisions'] if d['kind'] == 'public pool'][0]
    assert pool['per_scope']['10.20.0.0/24'] == {'a': 1, 'b': 0, 'b_total': 1, 'b_nats': 1, 'b_kept': False, 'c': 0,
                                                 'total': 1}
    assert any(m.startswith('(a) published servers') and m.endswith('= 1') for m in pool['math'])
    ident = [d for d in res['decisions'] if d['kind'] == 'outbound identity'][0]
    assert ident['open'] and 'SRV2' in ident['text']
    card = res['readiness'][0]
    pub = [l for l in card['lines'] if l['name'] == 'Public IPs'][0]
    assert pub['note'] == '1 new needed: (a) 1 published servers, (b) 0 outbound identity (1 NAT, 1 address, not kept), (c) 0 PAT'
    res2 = go(decision_state={ident['id']: {'choice': 'keep on DR'}})
    pool2 = [d for d in res2['decisions'] if d['kind'] == 'public pool'][0]
    assert pool2['needed'] == 2


def test_acp_placement_and_order_in_plan():
    res = go(fix_all=True) if False else go()
    keys = {f['key']: {'state': 'fix'} for f in res['findings']}
    res = go(finding_state=keys)
    md = plan_markdown(res)
    assert 'Mandatory section, so above Site-Default-Out (it is in the Default section), new rule 1 of 3' in md
    acp = [g for g in res['plan']['groups'] if g['name'] == 'Access Control'][0]
    assert [i['rule'] for i in acp['items'] if i.get('rule')] == ['Partner-To-SRV1', 'Any-To-SRV1', 'Admin-To-Mgmt']


def test_routing_verify_show_route_only():
    b = B.replace('route INSIDE 10.77.0.0 255.255.0.0 10.9.0.2 1\n', '')
    res = run([(A, 'a.txt')], (b, 'b.txt'), PROF)[0]
    f = find(res, 'routing')[0]
    assert f['verify'] == ['show route 10.20.0.1']


def test_dns_pending_public_ip():
    a = A.replace('access-list CSM_FW_ACL_ remark rule-id 9:', 'access-list CSM_FW_ACL_ remark rule-id 204: RULE: Any-To-SRV2\n'
                  'access-list CSM_FW_ACL_ advanced permit tcp ifc outside any ifc inside object SRV2 eq 443 rule-id 204\n'
                  'access-list CSM_FW_ACL_ remark rule-id 9:')
    p = dict(PROF, public_pool_b=['203.0.113.5-203.0.113.5'])
    res = run([(a, 'a.txt')], (B, 'b.txt'), p)[0]
    p['finding_state'] = {f['key']: {'state': 'fix'} for f in res['findings']}
    res = run([(a, 'a.txt')], (B, 'b.txt'), p)[0]
    dns = [g for g in res['plan']['groups'] if g['name'] == 'DNS'][0]
    assert dns['count'] == 2
    assert sorted('pending public IP' in i['fmc'] for i in dns['items']) == [False, True]
