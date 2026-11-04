"""0.4.0 findings: plain language, evidence with line numbers, fix / verify, readiness, decisions, plan."""
import os

from fwsync.pipeline import read, run
from fwsync.findings import plan_markdown

HERE = os.path.dirname(__file__)
CHAIN = [os.path.join(HERE, '..', 'samples', 'chain', f) for f in ('edge.txt', 'inner.txt', 'target.txt')]
NAMES = {'names': {'A1': 'Edge (E1)', 'A2': 'DC firewall (D1)', 'B': 'DR firewall (T1)'}}


def chain(extra=None):
    e, i, t = [read(p) for p in CHAIN]
    prof = dict(NAMES)
    prof.update(extra or {})
    return run([e, i], t, prof)[0]


def test_routing_finding_plain_language_and_fix():
    res = chain()
    f = [x for x in res['findings'] if x['category'] == 'routing' and '10.60.0.0/16' in x['what']][0]
    assert f['what'].startswith('10.60.0.0/16 (CAMPUS-NET): DR firewall (T1) would send it to the internet') and 'not inside' in f['what']
    assert any(e['device'] == 'DR firewall (T1)' and e['line'] > 0 and e['text'].startswith('route OUTSIDE 0.0.0.0')
               for e in f['evidence'])
    assert f['fix']['cli'] == ['route INSIDE 10.60.0.0 255.255.0.0 10.9.0.2 1']
    assert f['verify'][0].startswith('show route 10.60.')
    assert f['order'] == 0 and res['findings'][0]['category'] == 'routing'


def test_order_of_work():
    res = chain()
    orders = [f['order'] for f in res['findings']]
    assert orders == sorted(orders)


def test_inbound_finding_and_verify():
    e, i, t = [read(p) for p in CHAIN]
    tt = (t[0].replace('nat (INSIDE,OUTSIDE) source static WEB-SERVER PUB_WEB\n', ''), t[1])
    res = run([e, i], tt, dict(NAMES, public_pool_b=['203.0.113.50-203.0.113.60']))[0]
    f = [x for x in res['findings'] if x['category'] == 'inbound'][0]
    assert f['host'] == 'WEB' and f['what'] == ('10.50.1.10/32 (WEB) is published at Edge + DC firewall on 198.51.100.10 '
                                                'tcp 443. DR firewall has no NAT; the access rule is in place.')
    assert f['why'].startswith('During an Edge + DC firewall internet outage')
    assert f['verify'][0] == 'packet-tracer input OUTSIDE tcp 8.8.8.8 40000 203.0.113.50 443'
    assert any(x.startswith('DNS: failover record for WEB: 198.51.100.10 -> 203.0.113.50') for x in f['fix']['fmc'])
    assert f['dns_change']


def test_readiness_cards_and_states():
    res = chain()
    c = {x['subnet']: x for x in res['readiness']}
    dc = c['10.50.0.0/16']
    assert [l['name'] for l in dc['lines']] == ['Routing', 'Outbound internet (PAT)', 'Published servers (inbound)',
                                               'Access rules', 'DNS changes', 'Public IPs']
    assert dc['lines'][0]['state'] == 'Ready' and dc['verdict'] == '10.50.0.0/16 (DC-NET) - Not ready: 5 things to fix'
    camp = c['10.60.0.0/16']
    assert camp['lines'][0]['state'] == 'Action needed' and not camp['ready']


def test_not_needed_and_plan():
    res = chain()
    f = [x for x in res['findings'] if x['category'] == 'routing' and '10.60.0.0/16' in x['what']][0]
    pat = [x for x in res['findings'] if x['category'] == 'pat'][0]
    res2 = chain({'finding_state': {f['key']: {'state': 'not needed', 'reason': 'campus not on DR'},
                                    pat['key']: {'state': 'fix', 'reason': ''}}})
    g = {x['name']: x for x in res2['plan']['groups']}
    assert g['NAT']['count'] == 1 and g['Objects']['count'] >= 1 and g['Routing']['count'] == 0
    c = {x['subnet']: x for x in res2['readiness']}
    assert c['10.60.0.0/16']['lines'][0]['state'] == 'Ready'
    md = plan_markdown(res2)
    assert '## NAT (1)' in md and 'after-auto source dynamic' in md and 'Verify:' in md


def test_decisions_held_rule_and_test_server():
    e, i, t = [read(p) for p in CHAIN]
    edge = (e[0].replace('rule-id 104: RULE: Jump-In', 'rule-id 104: L7 RULE: Geo Block Jump')
            .replace('object network JUMP\n', 'object network test-jump.example.com\n')
            .replace('object JUMP eq ssh', 'object test-jump.example.com eq ssh'), e[1])
    res = run([edge, i], t, NAMES)[0]
    kinds = {d['kind'] for d in res['decisions']}
    assert 'L7 action' in kinds and 'public pool' not in kinds
    held = [d for d in res['decisions'] if d['kind'] == 'L7 action'][0]
    assert held['options'] == ['block', 'permit']
    res2 = run([edge, i], t, dict(NAMES, decision_state={held['id']: {'choice': 'permit', 'rule': held['rule']}}))[0]
    assert not [d for d in res2['decisions'] if d['kind'] == 'L7 action']


def test_public_ip_conflict_on_b():
    e, i, t = [read(p) for p in CHAIN]
    tt = (t[0] + 'object network OTHER\n host 10.50.1.99\nnat (INSIDE,OUTSIDE) source static OTHER PUB_WEB inactive\n', t[1])
    res = run([e, i], tt, NAMES)[0]
    c = [d for d in res['decisions'] if d['kind'] == 'public IP conflict']
    assert c and '203.0.113.10' in c[0]['text'] and len(c[0]['evidence']) == 2


def test_vpn_interface_suggested_ignore():
    e, i, t = [read(p) for p in CHAIN]
    edge = (e[0].replace('interface Port-channel2\n', 'interface Port-channel9\n nameif s2s-vpn\n ip address 10.99.0.1 '
                         '255.255.255.252\ninterface Port-channel2\n'), e[1])
    res = run([edge, i], t, NAMES)[0]
    row = [m for m in res['detected']['interface_map'] if m['a'] == 'A1:s2s-vpn'][0]
    assert row['b'] == 'ignore' and row['suggest'] == 'ignore' and 'VPN' in row['a_reason']
