"""0.5.3 report wording and takeover runbook. Made-up names, documentation addresses only."""
from fwsync.pipeline import run

A = """hostname fw-alpha
interface e1
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.192
interface e2
 nameif inside
 security-level 100
 ip address 192.0.2.1 255.255.255.192
interface e3
 nameif dmz
 security-level 50
 ip address 198.51.100.65 255.255.255.224
object network obj-NO_NAT-192.0.2.128
 subnet 192.0.2.128 255.255.255.192
object-group network GRP-SERVERS
 network-object host 192.0.2.10
 network-object host 192.0.2.11
route outside 0.0.0.0 0.0.0.0 198.51.100.2 1
route inside 192.0.2.128 255.255.255.192 192.0.2.2 1
route inside 192.0.2.200 255.255.255.255 192.0.2.3 1
route inside 192.0.2.224 255.255.255.240 192.0.2.2 1
nat (inside,outside) after-auto source dynamic any interface
access-list CSM_FW_ACL_ advanced permit tcp ifc inside object-group GRP-SERVERS ifc outside any eq 443 rule-id 1
access-list CSM_FW_ACL_ remark rule-id 5: L4 RULE: Pool-Out
access-list CSM_FW_ACL_ advanced permit ip ifc inside 192.0.2.224 255.255.255.240 ifc outside any rule-id 5
access-group CSM_FW_ACL_ global
"""
B = """hostname fw-bravo
interface e1
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.192
interface e2
 nameif inside
 security-level 100
 ip address 192.0.2.1 255.255.255.192
object-group network GRP-SERVERS
 network-object host 192.0.2.10
 network-object host 192.0.2.11
 network-object host 192.0.2.12
ip local pool VPN-USERS 192.0.2.224-192.0.2.239 mask 255.255.255.240
route outside 0.0.0.0 0.0.0.0 203.0.113.2 1
route inside 192.0.2.240 255.255.255.240 192.0.2.62 250
route inside 192.0.2.64 255.255.255.192 192.0.2.61 1
nat (inside,outside) after-auto source dynamic any interface
access-list CSM_FW_ACL_ advanced permit tcp ifc inside object-group GRP-SERVERS ifc outside any eq 443 rule-id 1
access-group CSM_FW_ACL_ global
"""
OSPF = 'router ospf 1\n network 192.0.2.0 255.255.255.192 area 0\n'


def go(b=B, **k):
    return run([(A, 'fw-alpha.txt')], (b, 'fw-bravo.txt'), k or None)[0]


def routing(res, p):
    return [f for f in res['findings'] if f['category'] == 'routing' and f['scopes'] == [p]][0]


def card(res, p):
    return [c for c in res['readiness'] if c['subnet'] == p][0]


def test_floating_route_is_not_the_next_hop():
    f = routing(go(scope=['192.0.2.128/26']), '192.0.2.128/26')
    assert f['fix']['cli'] == ['route inside 192.0.2.128 255.255.255.192 192.0.2.61 1']
    assert '192.0.2.62' not in ' '.join(f['fix']['fmc'])


def test_only_floating_route_gives_placeholder():
    b = B.replace('route inside 192.0.2.64 255.255.255.192 192.0.2.61 1\n', '')
    f = routing(go(b, scope=['192.0.2.128/26']), '192.0.2.128/26')
    assert f['fix']['cli'] == ['route inside 192.0.2.128 255.255.255.192 <next hop on inside> 1']


def test_ospf_makes_check_first_not_action():
    res = go(B + OSPF, scope=['192.0.2.128/26', '192.0.2.224/28'])
    f = routing(res, '192.0.2.128/26')
    assert f['level'] == 'check' and f['fix']['cli'][0] == 'show route 192.0.2.129'
    assert 'If it points to inside, no change is needed. If it points elsewhere, add this route' in f['fix']['fmc'][0]
    c = card(res, '192.0.2.128/26')
    assert c['state'] == 'check' and c['actions'] == 0 and c['checks'] == 1
    assert c['verdict'] == '192.0.2.128/26 - Check on firewall: 1 thing to verify'
    assert c['lines'][0]['state'] == 'Check first' and c['lines'][0]['label'] == 'Check on firewall'
    assert res['verdict']['counts']['check'] == 1 and res['verdict']['counts']['before'] == 0
    assert 'fw-bravo can take over from fw-alpha: 0 things to fix before failover' in res['verdict']['text']
    assert '1 to check on the firewall' in res['verdict']['text']


def test_singular_thing_to_fix_and_reason():
    c = card(go(scope=['192.0.2.128/26']), '192.0.2.128/26')
    assert c['verdict'] == '192.0.2.128/26 - Not ready: 1 thing to fix'
    assert c['reason'] == 'No static route on fw-bravo; it would use the default route to the internet'


def test_superset_group_is_a_note_not_an_action():
    res = go(scope=['192.0.2.0/26'])
    o = [x for x in res['objects'] if x['name'] == 'GRP-SERVERS'][0]
    assert o['status'] == 'B has extra entries' and o['b_extra'] == '192.0.2.12/32'
    f = [x for x in res['findings'] if x['category'] == 'objects'][0]
    assert f['level'] == 'review'
    c = card(res, '192.0.2.0/26')
    assert [l for l in c['lines'] if l['name'] == 'Access rules'][0]['actions'] == 0 and c['state'] == 'ready'
    assert not [i for i in res['runbook'][0]['items'] if 'GRP-SERVERS' in i['what']]


def test_missing_group_member_is_an_action():
    b = B.replace(' network-object host 192.0.2.11\n network-object host 192.0.2.12\n', '')
    res = go(b, scope=['192.0.2.0/26'])
    f = [x for x in res['findings'] if x['category'] == 'objects'][0]
    assert f['level'] == 'fix' and '192.0.2.11/32 is missing on fw-bravo' in f['what']
    assert ' network-object host 192.0.2.11' in f['fix']['cli']


def test_b_owned_network_is_not_counted():
    res = go(scope=['192.0.2.224/28'])
    assert res['b_owned'] == {'192.0.2.224/28': 'VPN pool'}
    c = card(res, '192.0.2.224/28')
    assert c['state'] == 'own' and c['ready'] and c['actions'] == 0
    assert c['verdict'] == "192.0.2.224/28 - fw-bravo's own network, not part of takeover"
    f = [x for x in res['findings'] if x['category'] == 'rules' and x['rule'] == 'Pool-Out'][0]
    assert f['level'] == 'review' and f['b_own']
    assert res['verdict']['counts']['before'] == 0


def test_vlan_network_host_wording():
    res = go(scope=['192.0.2.128/26', '192.0.2.200/32', '198.51.100.64/27'])
    why = {p: routing(res, p)['why'] for p in ('192.0.2.128/26', '192.0.2.200/32', '198.51.100.64/27')}
    assert 'this network' in why['192.0.2.128/26'] and 'VLAN' not in why['192.0.2.128/26']
    assert 'this host' in why['192.0.2.200/32'] and 'VLAN' not in why['192.0.2.200/32']
    assert 'this VLAN' in routing(res, '198.51.100.64/27')['what']


def test_finding_leads_with_subnet_not_labels():
    res = go(scope=['192.0.2.128/26'])
    f = routing(res, '192.0.2.128/26')
    assert f['what'].startswith('192.0.2.128/26: fw-bravo would send it to the internet')
    text = ' '.join([f['what'], f['why'], f['short'], card(res, '192.0.2.128/26')['verdict']])
    assert 'via inside' not in text and 'obj-NO_NAT' not in text


def test_cards_sorted_not_ready_check_ready_own():
    res = go(B + OSPF)
    order = [c['state'] for c in res['readiness']]
    rank = {'not ready': 0, 'check': 1, 'ready': 2, 'own': 3}
    assert order == sorted(order, key=rank.get) and 'own' in order and 'check' in order


def test_runbook_groups_and_four_parts():
    b = B.replace('interface e2\n', 'interface e3\n shutdown\n nameif dmz\n security-level 50\n'
                  ' ip address 198.51.100.65 255.255.255.224\ninterface e2\n')
    res = go(b)
    rb = {g['key']: g for g in res['runbook']}
    assert [g['title'] for g in res['runbook']] == ['Fix before failover', 'Do during failover', 'Check on the firewall',
                                                    'Review later', "Can't be proven from this config"]
    assert [i['subject'] for i in rb['during']['items']] == ['dmz']
    assert rb['during']['items'][0]['cli'] == ['interface e3', ' no shutdown']
    assert '1 to do during failover' in res['verdict']['text']
    for g in res['runbook']:
        for i in g['items']:
            assert i['subject'] and i['reason'] and i['what'] and i['why'] and i['fmc'] and i['cli'] and i['verify'], i
    for f in res['findings']:
        assert f['what'] and f['why'] and f['fix']['fmc'] and (f['fix']['cli'] or f['fix']['objects']) and f['verify'], f


def test_report_has_names_howto_and_runbook(tmp_path):
    from fwsync.report import write_html
    res = go(B + OSPF)
    p = tmp_path / 'r.html'
    write_html(res, p)
    h = p.read_text(encoding='utf-8')
    assert 'A = fw-alpha</b>' in h and 'B = fw-bravo</b>' in h and 'How to read this report' in h
    assert h.index('Fix before failover') < h.index('Do during failover') < h.index('Check on the firewall') < \
        h.index('Review later') < h.index("Can&#x27;t be proven from this config")
    assert "What's wrong" in h and 'Why it matters' in h and 'What to do' in h and 'How to verify' in h
    details = h.index('Details (advanced)')
    assert h.index('Every fw-alpha object') > details and h.index('Coverage: where every config line') > details
    body = h[h.index('</style>'):details]
    for jargon in ('over-permitted', 'wrong way', 'covered', 'shadowed', 'Decision needed'):
        assert jargon not in body, jargon
