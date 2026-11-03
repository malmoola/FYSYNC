"""0.3.0 controls: routing readiness (backup-site case), L7 action overrides, interfaces (ignore / role / new on B /
chain link), scope checks and expand data, what-if on B, row states."""
import os

from fwsync.generate import generate
from fwsync.pipeline import read, run

HERE = os.path.dirname(__file__)
CHAIN = [os.path.join(HERE, '..', 'samples', 'chain', f) for f in ('edge.txt', 'inner.txt', 'target.txt')]

# Backup-site B: default to OUTSIDE, 10.0.0.0/8 to INSIDE. A private subnet inside 10/8 must be ok; a public range
# and a 172.16/12 subnet go out the default route (wrong way).
SITE_A = """: Saved
hostname site-a
interface Port-channel1
 nameif outside
 ip address 198.51.100.2 255.255.255.0
interface Port-channel2
 nameif inside
 ip address 10.9.0.1 255.255.255.248
route outside 0.0.0.0 0.0.0.0 198.51.100.1 1
route inside 10.200.100.0 255.255.252.0 10.9.0.2 1
route inside 192.0.2.0 255.255.255.0 10.9.0.2 1
route inside 172.31.10.0 255.255.255.192 10.9.0.2 1
"""
SITE_B = """: Saved
hostname site-b
interface GigabitEthernet0/0
 nameif OUTSIDE
 ip address 203.0.113.2 255.255.255.252
interface GigabitEthernet0/1
 nameif INSIDE
 ip address 10.77.0.18 255.255.255.248
route OUTSIDE 0.0.0.0 0.0.0.0 203.0.113.1 1
route INSIDE 10.0.0.0 255.0.0.0 10.77.0.17 1
"""
SCOPE = ['10.200.100.0/22', '192.0.2.0/24', '172.31.10.0/26']


def st(res, k='routing'):
    return {r['subnet']: r['status'] for r in res[k]}


def test_routing_dr_case():
    res, a, b, prof = run([(SITE_A, 'a')], (SITE_B, 'b'), {'scope': SCOPE})
    assert st(res) == {'10.200.100.0/22': 'ok', '192.0.2.0/24': 'wrong way', '172.31.10.0/26': 'wrong way'}
    nh = {r['subnet']: r['b_next_hop'] for r in res['routing']}
    assert nh['10.200.100.0/22'] == '10.0.0.0/8 10.77.0.17' and nh['192.0.2.0/24'] == '0.0.0.0/0 203.0.113.1'


def test_whatif_routes_fix_routing_and_are_listed():
    w = {'routes': [{'prefix': '192.0.2.0/24', 'ifc': 'INSIDE', 'nexthop': '10.77.0.17'},
                    {'prefix': '172.31.10.0/26', 'ifc': 'INSIDE', 'nexthop': '10.77.0.17'}]}
    res, a, b, prof = run([(SITE_A, 'a')], (SITE_B, 'b'), {'scope': SCOPE, 'whatif': w})
    assert set(st(res).values()) == {'ok'}
    assert [p['kind'] for p in res['planned']] == ['route', 'route']
    g = generate(res, [], prof, b)
    assert any(c.startswith('PLANNED') and '192.0.2.0' in c for c in g['changes'])
    assert 'route INSIDE 192.0.2.0 255.255.255.0 10.77.0.17' in g['cli']


def test_whatif_public_and_nat_pool():
    e, i, t = [read(p) for p in CHAIN]
    base, *_ = run([e, i], t)
    avail = [x for x in base['public'] if x['id'] == 'PUB-TOTAL'][0]['b_public_available']
    res, *_ = run([e, i], t, {'whatif': {'public': ['192.0.2.0/24'],
                                         'nat_pools': [{'real': '10.60.0.0/16', 'mapped': 'interface',
                                                        'in_ifc': 'INSIDE', 'out_ifc': 'OUTSIDE'}]}})
    assert [x for x in res['public'] if x['id'] == 'PUB-TOTAL'][0]['b_public_available'] >= avail + 250
    assert {(p['side'], p['subnet']): p['status'] for p in res['pat']}[('B', '10.60.0.0/16')] == 'covered'


L7EDGE = open(CHAIN[0]).read().replace('rule-id 104: RULE: Jump-In', 'rule-id 104: L7 RULE: Geo Block Jump')


def test_l7_suspect_name_is_unknown_until_confirmed():
    e, i, t = [read(p) for p in CHAIN]
    res, star, b, prof = run([(L7EDGE, 'edge.txt'), i], t)
    held = [r for r in res['held_rules'] if r['status'] == 'action unknown (L7)']
    assert [r['rule'] for r in held] == ['A1:Geo Block Jump']
    assert res['counts']['held_rules'].get('action unknown (L7)') == 1
    assert not [r for r in res['rules'] if r['rule'] == 'A1:Geo Block Jump']
    res, *_ = run([(L7EDGE, 'edge.txt'), i], t, {'rule_actions': {'A1:Geo Block Jump': 'permit'}})
    assert not res['held_rules']
    res, star, b, prof = run([(L7EDGE, 'edge.txt'), i], t, {'rule_actions': {'Geo Block Jump': 'block'}})
    assert [r['status'] for r in res['held_rules'] if r['rule'] == 'A1:Geo Block Jump'] == ['blocked (L7)']
    g = generate(res, [r['id'] for r in res['held_rules']] + [r['id'] for r in res['rules']], prof, b)
    assert not [c for c in g['changes'] if 'Geo' in c]


def test_every_l7_rule_flagged_until_set():
    e, i, t = [read(p) for p in CHAIN]
    res, *_ = run([e, i], t)
    web = [r for r in res['rules'] if r['path'] == 'A2∩A1' and r['rule'] == 'A2:Web-443'][0]
    assert web['action_check'] == 'action unknown (L7)'          # edge Web-In is an L7 RULE
    assert res['counts']['l7_actions'].get('action unknown (L7)', 0) >= 1
    res, *_ = run([e, i], t, {'rule_actions': {'A1:Web-In': 'permit', 'A2:Web-443': 'permit'}})
    web = [r for r in res['rules'] if r['path'] == 'A2∩A1' and r['rule'] == 'A2:Web-443'][0]
    assert web['action_check'] != 'action unknown (L7)'


def test_rule_action_block_on_l4_rule_is_a_deny():
    e, i, t = [read(p) for p in CHAIN]
    res, *_ = run([e, i], t, {'rule_actions': {'A1:Web-In': 'block'}})
    assert not [r for r in res['rules'] if r['path'] == 'A2∩A1' and r['rule'] == 'A2:Web-443']


def test_interfaces_role_new_on_b_and_include():
    e, i, t = [read(p) for p in CHAIN]
    res, star, b, prof = run([e, i], t, {'interface_map': {'A2:DC-IN': 'DC-NEW'}})
    links = [m for m in res['detected']['interface_map'] if m['a_role'] == 'chain link']
    assert {m['a'] for m in links} == {'A1:inside', 'A2:DC-OUT'}
    assert {'kind': 'interface', 'item': 'DC-NEW', 'detail': 'create interface DC-NEW (inside) on B'} in res['planned']
    assert any('DC-NEW' in r['b_dst_ifc'] for r in res['rules'] if r['path'] == 'A2∩A1')
    res, star, b, prof = run([e, i], t, {'roles_a': {'A1:inside': 'outside'}})
    assert 'A1:inside' in prof.outside_a
    res, star, b, prof = run([e, i], t, {'roles_a': {'A2:DC-IN': 'ignore'}})
    assert not [r for r in res['rules'] if r['path'] in ('A2', 'A2∩A1')]


def test_chain_link_override():
    e, i, t = [read(p) for p in CHAIN]
    res, *_ = run([e, i], t, {'roles_a': {'A2:DC-OUT': 'chain link', 'A1:inside': 'chain link'}})
    c = res['detected']['chain']
    assert c['a1_toward_a2'] == 'inside' and c['a2_uplink'] == 'DC-OUT'


def test_scope_check_and_expand_data():
    e, i, t = [read(p) for p in CHAIN]
    res, *_ = run([e, i], t, {'scope': ['10.50.0.0/16'], 'scope_names': {'10.50.0.0/16': 'DC'}})
    w = res['detected']['scope_warnings']
    assert any(x['suggest'] == '10.50.0.0/24' and 'connected' in x['where'] for x in w)
    kids = [p['prefix'] for p in res['detected']['prefixes'] if p['prefix'].startswith('10.50.0.') and p['prefix'] != '10.50.0.0/16']
    assert '10.50.0.0/24' in kids
    assert res['summary'][0]['scope'] == 'DC'


def test_row_state_exclude_and_not_needed():
    e, i, t = [read(p) for p in CHAIN]
    res, *_ = run([e, i], t)
    r = [x for x in res['rules'] if x['status'] == 'missing'][0]
    n = res['counts']['rules']['missing']
    res2, *_ = run([e, i], t, {'row_state': {r['key']: {'state': 'not needed', 'reason': 'decommissioned'}}})
    r2 = [x for x in res2['rules'] if x['key'] == r['key']][0]
    assert r2['row_state'] == 'not needed' and r2['row_reason'] == 'decommissioned'
    assert res2['counts']['rules']['missing'] == n - 1


def test_cli_flags(tmp_path):
    import json
    from fwsync.cli import main
    e, i, t = CHAIN
    out = tmp_path / 'r'
    main(['compare', e, i, t, '--out', str(out), '--prefix', 'x', '--save-profile', str(tmp_path / 'p.json'),
          '--map', 'A2:DC-IN=DC-NEW', '--role', 'A1:inside=inside', '--scope-add', '10.50.1.0/24=DC servers',
          '--whatif-route', '10.60.0.0/16=INSIDE@10.9.0.2', '--whatif-public', '192.0.2.0/24',
          '--whatif-nat', '10.60.0.0/16=interface@INSIDE,OUTSIDE', '--rule-action', 'A1:Web-In=permit',
          '--not-needed', 'routing|10.0.0.0/29=transit'])
    p = json.load(open(tmp_path / 'p.json'))
    assert p['interface_map']['A2:DC-IN'] == 'DC-NEW' and p['scope_names']['10.50.1.0/24'] == 'DC servers'
    assert p['whatif']['routes'][0] == {'prefix': '10.60.0.0/16', 'ifc': 'INSIDE', 'nexthop': '10.9.0.2'}
    assert p['rule_actions'] == {'A1:Web-In': 'permit'} and p['row_state']['routing|10.0.0.0/29']['state'] == 'not needed'
    r = json.load(open(out / 'x.json'))
    assert [x['row_state'] for x in r['routing'] if x['subnet'] == '10.0.0.0/29'] == ['not needed']
    assert {x['kind'] for x in r['planned']} == {'route', 'interface', 'public range', 'nat pool'}
    p2 = tmp_path / 'p.json'
    main(['compare', e, i, t, '--out', str(out), '--prefix', 'y', '--profile', str(p2)])
    assert json.load(open(out / 'y.json'))['profile_used']['interface_map']['A2:DC-IN'] == 'DC-NEW'


def test_summary_counts_specific_rules_per_subnet():
    e, i, t = [read(p) for p in CHAIN]
    res, *_ = run([e, i], t, {'scope': ['10.50.0.0/16', '10.60.0.0/16']})
    rows = {r['subnet']: r for r in res['summary']}
    assert rows['10.50.0.0/16'].get('rules') != rows['10.60.0.0/16'].get('rules')
    camp_out = [r for r in res['rules'] if r['rule'] == 'A1:Campus-Out'][0]
    assert camp_out['scopes'] == ['10.60.0.0/16'] and '10.50.0.0/16' not in camp_out['scopes']
    web = [r for r in res['rules'] if r['path'] == 'A2∩A1' and r['rule'] == 'A2:Web-443'][0]
    assert web['scopes'] == ['10.50.0.0/16'] and web['scopes_any'] == []
