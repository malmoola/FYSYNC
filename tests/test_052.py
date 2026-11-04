from fwsync.adapters import load
from fwsync.detect import roles, route_table
from fwsync.natorder import best_effective
from fwsync.netset import IPSet
from fwsync.pipeline import run

A = """hostname A
interface e1
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
interface e2
 nameif outside2
 security-level 0
 ip address 198.51.100.1 255.255.255.0
interface e3
 nameif inside
 security-level 100
 ip address 10.0.1.1 255.255.255.0
interface e4
 nameif pub
 security-level 50
 ip address 192.0.2.1 255.255.255.0
interface e5
 nameif oobnet
 security-level 50
 ip address 10.5.1.1 255.255.255.0
object network WEB
 host 10.0.1.5
 nat (inside,outside) static 203.0.113.9
object network M
 subnet 10.5.1.0 255.255.255.0
 nat (oobnet,outside) dynamic interface
route outside2 0.0.0.0 0.0.0.0 198.51.100.2 1
route outside 0.0.0.0 0.0.0.0 203.0.113.2 250
access-list CSM_FW_ACL_ advanced deny ip ifc outside host 1.2.3.4 any rule-id 1
access-list CSM_FW_ACL_ advanced permit ip ifc inside any any rule-id 2
access-group CSM_FW_ACL_ global
"""
B = """hostname B
interface e1
 nameif outside
 security-level 0
 ip address 203.0.114.1 255.255.255.0
interface e2
 nameif inside
 security-level 100
 ip address 10.9.1.1 255.255.255.0
interface e3
 nameif dmz2
 security-level 50
 ip address 192.0.2.1 255.255.255.0
interface e4
 nameif oobnet
 security-level 50
 ip address 10.5.2.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 203.0.114.2 1
route inside 0.0.0.0 0.0.0.0 10.9.1.9 tunneled
route inside 10.0.0.0 255.0.0.0 10.9.1.9 1
nat (oobnet,outside) after-auto source dynamic any interface
access-list CSM_FW_ACL_ advanced permit ip ifc inside any any rule-id 3
access-list CSM_FW_ACL_ advanced permit tcp ifc dmz2 host 10.0.1.5 any eq 25 rule-id 4
access-group CSM_FW_ACL_ global
"""


def go(**k):
    return run([(A, 'a')], (B, 'b'), k or None)


def test_same_subnet_wins_and_name_flagged():
    res = go()[0]
    m = {r['a']: r for r in res['detected']['interface_map']}
    assert m['pub']['b'] == 'dmz2' and m['pub']['how'] == 'same subnet'
    assert 'different subnet' in m['oobnet']['flag']


def test_tunneled_is_not_default():
    cfg = load(B, 'b')
    assert roles(cfg)['inside'][0] == 'inside'
    assert not [r for r in route_table(cfg) if r['plen'] == 0 and r['ifc'] == 'inside']


def test_pat_any_exit_and_any_source():
    a = load(A, 'a')
    eff, out = best_effective(a, IPSet.parse('10.5.1.0/24'), 'oobnet', ['outside', 'outside2'])
    assert out == 'outside' and eff[0][1] is not None
    res = go(scope=['10.5.1.0/24'])[0]
    assert {x['side']: x['status'] for x in res['pat']} == {'A': 'covered', 'B': 'covered'}


def test_site_subnet_is_translated_not_routed():
    res = go(scope=['10.5.1.0/24'])[0]
    assert res['scope'] == ['10.5.2.0/24'] and ('10.5.1.0/24', '10.5.2.0/24') in res['detected']['net_pairs']
    assert not [x for x in res['findings'] if x['category'] == 'routing']


def test_default_scope_is_every_subnet_and_ledger_is_complete():
    res = go()[0]
    assert {'10.9.1.0/24', '10.5.2.0/24', '192.0.2.0/24'} <= set(res['scope'])
    total = sum(x['a_lines'] for x in res['coverage'])
    assert total == len([x for x in A.splitlines() if x.strip()])
    assert 'verdict' in res and res['takeover'][-1]['severity'] == 'verify'


def test_broad_l7_block_does_not_hide_gaps():
    cfg = B.replace('access-list CSM_FW_ACL_ advanced permit ip ifc inside any any rule-id 3',
                    'access-list CSM_FW_ACL_ remark rule-id 3: L7 RULE: Blocked Countries\n'
                    'access-list CSM_FW_ACL_ advanced permit ip any any rule-id 3')
    res = run([(A, 'a')], (cfg, 'b'), {'scope': ['10.0.1.0/24']})[0]
    assert [r for r in res['rules'] if r['status'] != 'covered']


def test_shut_interface_is_a_blocker():
    cfg = B.replace(' nameif dmz2\n', ' shutdown\n nameif dmz2\n')
    t = run([(A, 'a')], (cfg, 'b'))[0]['takeover']
    assert t[0]['severity'] == 'blocker' and 'dmz2' in t[0]['title']


def test_identical_permit_not_over_permitted():
    res = go(scope=['10.0.1.0/24'])[0]
    assert all(r['status'] == 'also on A' for r in res['b_rules'] if r['src_ifc'] == 'inside')


def test_firewide():
    rows = go(scope=['10.5.1.0/24'])[0]['firewide']
    kinds = {r['check']: r for r in rows}
    assert 'A block missing on B' in kinds
    assert kinds['published on A, no NAT on B']['item'] == '203.0.113.9/32'
    assert 'B rule source not behind its interface' in kinds
