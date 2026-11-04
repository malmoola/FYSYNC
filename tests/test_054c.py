"""0.5.4 gap list: first-match NAT walk, rule gaps per A rule name, other checks and the gaps-only report. One test
(or more) per numbered behaviour. Made-up names, documentation and private addresses only."""
import re

from fwsync import gaplist, safety
from fwsync.pipeline import run

A = """hostname fw-alpha
interface e1
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.192
interface e2
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
interface e3
 nameif dmz
 security-level 50
 ip address 10.2.0.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 198.51.100.62 1
access-group CSM_FW_ACL_ global
object network IN-NET
 subnet 10.1.0.0 255.255.255.0
object network DMZ-NET
 subnet 10.2.0.0 255.255.255.0
object network REMOTE
 subnet 10.200.0.0 255.255.0.0
"""
B = """hostname fw-bravo
interface e1
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.192
interface e2
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
interface e3
 nameif dmz
 security-level 50
 ip address 10.2.0.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 203.0.113.62 1
access-group CSM_FW_ACL_ global
object network IN-NET
 subnet 10.1.0.0 255.255.255.0
object network DMZ-NET
 subnet 10.2.0.0 255.255.255.0
object network REMOTE
 subnet 10.200.0.0 255.255.0.0
"""


def rule(n, name, line, l7=False):
    return ('access-list CSM_FW_ACL_ remark rule-id %d: %s: %s\n' % (n, 'L7 RULE' if l7 else 'L4 RULE', name) +
            'access-list CSM_FW_ACL_ advanced %s rule-id %d\n' % (line, n))


def go(a='', b='', a_base=A, b_base=B, **prof):
    res, A_, B_, p = run([(a_base + a, 'fw-alpha.txt')], (b_base + b, 'fw-bravo.txt'), prof or None)
    res['_B'] = B_
    return res


def gl(res):
    return res['gaplist']


def rows(res, gap=None, when=None):
    return [r for r in gl(res)['rows'] if (gap is None or r['gap'] == gap) and (when is None or r['when'] == when)]


def nref(res, text):
    return next(r for r in gl(res)['nat_ref'] if text in r['text'])


def rref(res, name):
    return next(r for r in gl(res)['rule_ref'] if r['rule'] == name)


def cfg(r):
    return ' | '.join(r['config'])


def safe(res):
    assert gaplist.unsafe(gl(res), res['_B']) == []


PAT_IN = 'nat (inside,outside) after-auto source dynamic IN-NET interface\n'
PAT_DMZ = 'nat (dmz,outside) after-auto source dynamic DMZ-NET interface\n'


# 1 where the real subnet lives on B
def test_01a_subnet_on_a_shut_b_interface_still_counts():
    b = B.replace(' nameif dmz\n', ' nameif dmz\n shutdown\n')
    res = go(PAT_DMZ, PAT_DMZ, b_base=b)
    assert nref(res, 'DMZ-NET')['result'].startswith('OK'), nref(res, 'DMZ-NET')
    assert not rows(res, 'Missing PAT')
    safe(res)


def test_01b_no_connected_subnet_uses_static_route_then_map():
    a = 'route dmz 10.5.0.0 255.255.255.0 10.2.0.254 1\nobject network FAR\n subnet 10.5.0.0 255.255.255.0\n' \
        'nat (dmz,outside) after-auto source dynamic FAR interface\n'
    res = go(a, 'object network FAR\n subnet 10.5.0.0 255.255.255.0\nnat (dmz,outside) after-auto source dynamic FAR interface\n')
    assert nref(res, 'FAR')['result'].startswith('OK')
    res = go(a, 'object network FAR\n subnet 10.5.0.0 255.255.255.0\nnat (inside,outside) after-auto source dynamic FAR interface\n')
    assert nref(res, 'FAR')['result'] == 'Wrong source interface'


# 2 B's NAT in real order, interfaces and destination limits honoured
def test_02a_auto_static_before_dynamic_and_longest_prefix():
    a = 'object network WEB\n host 10.1.0.10\nobject network WEB-PUB\n host 198.51.100.10\n' \
        'nat (inside,outside) source static WEB WEB-PUB\n'
    b = 'object network WEB\n host 10.1.0.10\n nat (inside,outside) static 203.0.113.10\n' \
        'object network IN-NET\n nat (inside,outside) dynamic interface\n'
    res = go(a + rule(1, 'Web-In', 'permit tcp ifc outside any ifc inside object WEB eq 443'), b)
    assert nref(res, 'WEB-PUB')['result'] == 'OK, fw-bravo public IP'
    assert '203.0.113.10' in nref(res, 'WEB-PUB')['b_match'] or 'static' in nref(res, 'WEB-PUB')['b_match']


def test_02b_destination_limited_rule_does_not_take_general_traffic():
    b = 'nat (inside,outside) source static IN-NET IN-NET destination static REMOTE REMOTE\n' + PAT_IN
    res = go(PAT_IN, b)
    assert nref(res, 'IN-NET interface')['result'].startswith('OK')


def test_02c_any_interface_catch_all_on_b():
    res = go(PAT_IN + PAT_DMZ, 'nat (any,outside) after-auto source dynamic any interface\n')
    assert nref(res, 'IN-NET')['result'].startswith('OK') and nref(res, 'DMZ-NET')['result'].startswith('OK')


# 3 classification
def test_03a_same_public_ip_through_dynamic_pat():
    a = 'object network PAT-A\n host 198.51.100.20\nnat (inside,outside) after-auto source dynamic IN-NET PAT-A\n'
    b = 'object network PAT-A\n host 198.51.100.20\nnat (inside,outside) after-auto source dynamic IN-NET PAT-A\n'
    assert nref(go(a, b), 'IN-NET PAT-A')['result'] == 'OK, same IP'


def test_03b_other_b_public_ip_is_never_a_gap():
    a = 'object network PAT-A\n host 198.51.100.20\nnat (inside,outside) after-auto source dynamic IN-NET PAT-A\n'
    res = go(a, PAT_IN)
    assert nref(res, 'IN-NET PAT-A')['result'] == 'OK, fw-bravo public IP'
    assert not gl(res)['rows'] or not [r for r in gl(res)['rows'] if r['kind'] == 'nat']


def test_03c_missing_pat_static_vpn_internal_exemption():
    a = (PAT_DMZ + 'object network APP\n host 10.1.0.20\nobject network APP-PUB\n host 198.51.100.21\n'
         'nat (inside,outside) source static APP APP-PUB\n' +
         rule(1, 'App-In', 'permit tcp ifc outside any ifc inside object APP eq 443') +
         'ip local pool VPN-A 10.30.0.1-10.30.0.254 mask 255.255.255.0\nobject network VPN-NET\n subnet 10.30.0.0 255.255.255.0\n'
         'nat (outside,outside) after-auto source dynamic VPN-NET interface\n'
         'object network INT-HOST\n host 10.1.0.30\nobject network INT-MAP\n host 10.2.0.30\n'
         'nat (inside,dmz) source static INT-HOST INT-MAP\n'
         'nat (inside,outside) source static IN-NET IN-NET destination static REMOTE REMOTE no-proxy-arp\n')
    b = 'ip local pool VPN-B 10.31.0.1-10.31.0.254 mask 255.255.255.0\n' + PAT_IN
    res = go(a, b)
    gaps = {r['gap'] for r in gl(res)['rows']}
    assert {'Missing PAT', 'Missing VPN NAT', 'Missing internal NAT', 'Missing NAT exemption'} <= gaps, gaps
    assert 'Missing static NAT' in gaps or 'Static NAT (optional)' in gaps
    assert nref(res, 'APP APP-PUB')['result'] == 'Missing static NAT'
    safe(res)


def test_03d_site_device_twin():
    a = 'object network SITE-DC\n host 10.1.0.5\nobject network SITE-DC-PUB\n host 198.51.100.5\n' \
        'nat (inside,outside) source static SITE-DC SITE-DC-PUB\n'
    b = 'object network SITE-DC\n host 10.1.0.6\nobject network SITE-DC-PUB\n host 203.0.113.5\n' \
        'nat (inside,outside) source static SITE-DC SITE-DC-PUB\n' + PAT_IN
    res = go(a, b)
    assert nref(res, 'SITE-DC')['result'] == 'OK, site device', nref(res, 'SITE-DC')


def test_03e_a_line_a_itself_never_hits_is_not_a_gap():
    a = 'nat (inside,outside) source dynamic IN-NET interface\n' \
        'nat (inside,outside) after-auto source static IN-NET IN-NET destination static REMOTE REMOTE\n'
    res = go(a, PAT_IN)
    assert not rows(res, 'Missing NAT exemption')
    assert nref(res, 'destination static REMOTE')['result'].startswith('OK, not hit on fw-alpha (line ')


def test_03f_static_whose_outbound_a_takes_first_still_needs_its_inbound_on_b():
    a = PAT_IN.replace('after-auto ', '') + 'object network WEB\n host 10.1.0.10\nobject network WEB-PUB\n host 198.51.100.10\n' \
        'nat (inside,outside) after-auto source static WEB WEB-PUB\n' + \
        rule(1, 'Web-In', 'permit tcp ifc outside any ifc inside object WEB eq 443')
    b = PAT_IN + 'object network WEB\n host 10.1.0.10\n nat (inside,outside) static 203.0.113.10\n'
    assert nref(go(a, b), 'WEB WEB-PUB')['result'].startswith('OK')
    assert nref(go(a, PAT_IN), 'WEB WEB-PUB')['result'] == 'Missing static NAT'


def test_03g_healthy_pair_static_behind_an_earlier_pat_is_ok():
    x = ('nat (inside,outside) source dynamic IN-NET interface\nobject network WEB\n host 10.1.0.10\n'
         'object network WEB-PUB\n host 198.51.100.10\nnat (inside,outside) after-auto source static WEB WEB-PUB\n' +
         rule(1, 'Web-In', 'permit tcp ifc outside any ifc inside object WEB eq 443'))
    res = go(x, x)
    assert not [r for r in gl(res)['rows'] if r['kind'] == 'nat' and not r['gap'].startswith('Public block')]
    assert nref(res, 'WEB WEB-PUB')['result'].startswith('OK, same IP')


def test_03h_addresses_a_routes_elsewhere_are_not_hit_by_the_a_line():
    x = 'route dmz 10.1.0.128 255.255.255.128 10.2.0.254 1\n' + PAT_IN
    res = go(x, x)
    assert gl(res)['rows'] == []
    assert 'routed to another interface' in nref(res, 'IN-NET interface')['result'] or \
        nref(res, 'IN-NET interface')['result'].startswith('OK')


# 4 a catch-all PAT covers only its own interface
def test_04_catch_all_on_inside_does_not_cover_dmz():
    res = go(PAT_DMZ, 'nat (inside,outside) after-auto source dynamic any interface\n')
    r = rows(res, 'Missing PAT')
    assert len(r) == 1 and r[0]['address'] == '10.2.0.0/24' and 'nat (dmz,outside)' in cfg(r[0])


# 5 an exemption is a gap only where B translates, per CIDR; destination-limited identity on B covers it
def test_05a_exemption_checked_per_cidr():
    a = 'object-group network BOTH\n network-object 10.1.0.0 255.255.255.0\n network-object 10.2.0.0 255.255.255.0\n' \
        'nat (any,outside) source static BOTH BOTH destination static REMOTE REMOTE\n'
    res = go(a, PAT_IN)
    r = rows(res, 'Missing NAT exemption')
    assert [x['address'] for x in r] == ['10.1.0.0/24'], r


def test_05b_destination_limited_identity_on_b_covers_it():
    a = 'nat (inside,outside) source static IN-NET IN-NET destination static REMOTE REMOTE\n'
    b = 'nat (inside,outside) source static IN-NET IN-NET destination static REMOTE REMOTE\n' + PAT_IN
    res = go(a, b)
    assert not rows(res, 'Missing NAT exemption')
    assert nref(res, 'destination static REMOTE')['result'] == 'OK, same exemption'


# 6 second pass with the fixes applied
def test_06_exemption_needed_because_of_a_new_pat():
    a = PAT_DMZ + 'nat (dmz,outside) source static DMZ-NET DMZ-NET destination static REMOTE REMOTE\n'
    res = go(a, '')
    r = rows(res, 'Missing NAT exemption')
    assert len(r) == 1 and 'Needed because of the fix' in r[0]['required'] and r[0]['note'] == 'second pass'


# 7 destination translation is real translation
def test_07_destination_translation_is_not_called_no_nat():
    a = 'object network DNS-PUB\n host 198.51.100.53\nobject network DNS-IN\n host 10.2.0.53\n' \
        'nat (inside,outside) source static IN-NET IN-NET destination static DNS-PUB DNS-IN\n'
    res = go(a, PAT_IN)
    r = nref(res, 'DNS-PUB')
    assert r['kind'] != 'exempt' and r['result'] == 'Missing static NAT'
    assert not [x for x in gl(res)['rows'] if 'no NAT' in x['required'] or 'exemption' in x['gap'].lower()]


# 8 change at outage
SHUT_DMZ = B.replace(' nameif dmz\n', ' nameif dmz\n shutdown\n') + 'route inside 10.2.0.0 255.255.255.0 10.1.0.254 1\n'


def test_08a_rule_right_today_through_inside_changes_at_outage():
    res = go(PAT_DMZ, 'nat (inside,outside) after-auto source dynamic DMZ-NET interface\n', b_base=SHUT_DMZ)
    r = rows(res, 'Change at outage')
    assert len(r) == 1 and r[0]['when'] == 'At outage' and not rows(res, 'Wrong source interface')
    assert 'Failback' in cfg(r[0])
    safe(res)


def test_08b_identity_above_static_nats_is_an_outage_step():
    b = SHUT_DMZ.replace('route inside 10.2.0.0 255.255.255.0 10.1.0.254 1\n', '') + \
        'interface e4\n nameif dci\n security-level 50\n ip address 10.9.0.1 255.255.255.0\n' \
        'route dci 10.2.0.0 255.255.255.0 10.9.0.2 1\n' \
        'nat (dci,outside) source static DMZ-NET DMZ-NET\nobject network SRV\n host 10.2.0.10\n' \
        ' nat (dmz,outside) static 203.0.113.10\n'
    a = 'object network SRV\n host 10.2.0.10\n nat (dmz,outside) static 198.51.100.10\n'
    res = go(a, b_base=b)
    r = rows(res, 'Change at outage')
    assert r and all(x['when'] == 'At outage' for x in r)
    assert not [c for x in r for c in x['config'] if c.startswith('no nat')]


# 9 static NAT with no inbound rule and a working PAT on B
def test_09_static_without_inbound_rule_is_only_if_allow_listed():
    a = 'object network HOST\n host 10.1.0.40\nobject network HOST-PUB\n host 198.51.100.40\n' \
        'nat (inside,outside) source static HOST HOST-PUB\n'
    res = go(a, PAT_IN)
    r = rows(res, 'Static NAT (optional)')
    assert len(r) == 1 and r[0]['when'] == 'Only if allow-listed' and 'allow-lists' in r[0]['required']
    assert not rows(res, when='Now') and not rows(res, when='Now disabled')


def test_09b_static_without_inbound_rule_is_optional_when_the_proposed_pat_covers_it():
    a = PAT_IN + 'object network HOST\n host 10.1.0.40\nobject network HOST-PUB\n host 198.51.100.40\n' \
        'nat (inside,outside) source static HOST HOST-PUB\n'
    res = go(a, '')
    assert len(rows(res, 'Missing PAT')) == 1 and not rows(res, 'Missing static NAT')
    assert [r['when'] for r in rows(res, 'Static NAT (optional)')] == ['Only if allow-listed']


# 10 wrong interface: edit the rule
def test_10_wrong_interface_is_one_edit():
    res = go(PAT_DMZ, 'nat (inside,outside) after-auto source dynamic DMZ-NET interface\n')
    r = rows(res, 'Wrong source interface')
    assert len(r) == 1 and 'edit line' in cfg(r[0]) and not rows(res, 'Missing PAT')
    assert not [c for c in r[0]['config'] if c.startswith(('nat ', 'no nat'))]


# 11 sibling PAT address
def test_11_reuses_the_pat_address_of_sibling_subnets():
    a = 'route inside 10.1.5.0 255.255.255.0 10.1.0.254 1\nobject network FLOOR5\n subnet 10.1.5.0 255.255.255.0\n' \
        'nat (inside,outside) after-auto source dynamic FLOOR5 interface\n'
    b = 'route inside 10.1.5.0 255.255.255.0 10.1.0.254 1\nobject network PAT-B\n host 203.0.113.20\n' \
        'nat (inside,outside) after-auto source dynamic IN-NET PAT-B\n'
    r = rows(go(a, b), 'Missing PAT')
    assert len(r) == 1 and r[0]['config'][-1].endswith('FLOOR5 PAT-B')


# 12 public IP: reuse A's when B has NATs in that block, else a decision; never a placeholder
PUB = ('object network WEB2\n host 10.1.0.11\nobject network WEB2-PUB\n host 198.51.100.11\n'
       'nat (inside,outside) source static WEB2 WEB2-PUB\n' +
       rule(1, 'Web2-In', 'permit tcp ifc outside any ifc inside object WEB2 eq 443'))


def test_12a_reuse_a_public_ip_when_b_has_nats_in_the_block():
    b = 'object network WEB1\n host 10.1.0.10\nobject network WEB1-PUB\n host 198.51.100.10\n' \
        'nat (inside,outside) source static WEB1 WEB1-PUB\n'
    r = rows(go(PUB, b), 'Missing static NAT')
    assert len(r) == 1 and r[0]['when'] == 'Now disabled'
    assert 'WEB2-PUB' in cfg(r[0]) and r[0]['config'][-1].endswith(' inactive')


def test_12b_otherwise_a_decision_without_placeholder():
    res = go(PUB, '')
    r = rows(res, 'Missing static NAT')
    assert len(r) == 1 and r[0]['when'] == 'Decision'
    assert not [c for c in r[0]['config'] if c.startswith('nat ')]
    safe(res)


# 13 never "no nat" on a live rule (the guard also strips it from older outputs)
def test_13_no_nat_on_a_live_rule_is_stripped_everywhere():
    b = 'nat (inside,outside) after-auto source dynamic DMZ-NET interface\n'
    res = go(PAT_DMZ, b, b_base=SHUT_DMZ)
    live = safety.live_nats(res['_B'])
    assert 'nat (inside,outside) after-auto source dynamic DMZ-NET interface' in live
    txt = [c for f in res['findings'] for c in f['fix']['cli']] + [c for t in res['takeover'] for c in t.get('cli', [])]
    assert not [c for c in txt if c.startswith('no nat') and c[3:] in live]
    safe(res)


# 14 NAT that could answer ARP is added disabled
def test_14_internal_nat_on_an_up_subnet_is_added_disabled():
    a = 'object network INT-HOST\n host 10.1.0.30\nobject network INT-MAP\n host 10.2.0.30\n' \
        'nat (inside,dmz) source static INT-HOST INT-MAP\n'
    r = rows(go(a, ''), 'Missing internal NAT')
    assert len(r) == 1 and r[0]['when'] == 'Now disabled' and r[0]['config'][-1].endswith(' inactive')


# 15 hairpin
def test_15_hairpin_pat_is_confirm_use():
    r = rows(go('nat (inside,inside) source dynamic any interface\n', ''), 'Hairpin PAT')
    assert len(r) == 1 and r[0]['when'] == 'Confirm use'


# 16 L7 rules are never replaced by broad rules
def test_16_l7_rule_is_compare_in_fmc_with_no_access_list():
    a = rule(1, 'Web-Apps', 'permit tcp ifc inside object IN-NET ifc outside any eq 443', l7=True)
    res = go(a, '')
    r = [x for x in gl(res)['rows'] if x['object'] == 'Web-Apps']
    assert len(r) == 1 and r[0]['when'] == 'Compare in FMC'
    assert not [c for c in r[0]['config'] if 'access-list' in c or 'Action Allow' in c]


def test_16b_specific_l7_rule_is_copied_in_fmc_with_its_conditions():
    a = rule(1, 'Erp-Apps', 'permit tcp ifc inside object IN-NET ifc dmz object DMZ-NET eq 443', l7=True)
    r = [x for x in gl(go(a, ''))['rows'] if x['object'] == 'Erp-Apps']
    assert len(r) == 1 and r[0]['gap'] == 'Missing allow' and 'copy its Applications' in cfg(r[0])
    assert not [c for c in r[0]['config'] if c.startswith('access-list')]


# 17 Block* rule shown as permit is an L7 block
def test_17a_block_rule_is_missing_block_placed_after_matching_allow():
    a = (rule(1, 'Allow-Updates', 'permit tcp ifc inside object IN-NET ifc outside any eq 443') +
         rule(2, 'Block_Social', 'permit ip ifc inside object IN-NET ifc outside any', l7=True))
    b = rule(5, 'Allow-Updates', 'permit tcp ifc inside object IN-NET ifc outside any eq 443')
    res = go(a, b)
    r = rows(res, 'Missing block')
    assert len(r) == 1 and r[0]['object'] == 'Block_Social'
    assert 'below rule "Allow-Updates"' in r[0]['required'] and 'Action Block' in cfg(r[0])
    assert 'Action Allow' not in cfg(r[0]) and 'permit' not in cfg(r[0])
    assert rref(res, 'Block_Social')['result'] == 'Missing block'
    safe(res)


def test_17b_block_rule_with_equal_block_on_b_is_ok():
    a = rule(2, 'Block_Social', 'permit ip ifc inside object IN-NET ifc outside any', l7=True)
    b = rule(7, 'Block_Social', 'permit ip ifc inside object IN-NET ifc outside any', l7=True)
    res = go(a, b)
    assert not rows(res, 'Missing block')
    assert 'covered' not in rref(res, 'Block_Social')['result'] and 'shadow' not in rref(res, 'Block_Social')['result']


# 18 every A rule name
def test_18_every_rule_name_is_accounted_for():
    a = (rule(1, 'Live', 'permit tcp ifc inside object IN-NET ifc outside any eq 443') +
         'access-list CSM_FW_ACL_ remark rule-id 2: L4 RULE: Old-Off\n'
         'access-list CSM_FW_ACL_ advanced permit tcp ifc inside object IN-NET ifc outside any eq 22 rule-id 2 inactive\n'
         'access-list CSM_FW_ACL_ remark rule-id 3: L4 RULE: Empty-Rule\n')
    res = go(a, rule(1, 'Live', 'permit tcp ifc inside object IN-NET ifc outside any eq 443'))
    assert rref(res, 'Live')['result'] == 'OK'
    assert rref(res, 'Old-Off')['result'] == 'No active lines (inactive)'
    assert rref(res, 'Empty-Rule')['result'].startswith('No lines in this config')


# 19 wrong zone: add the zone to the existing rule
def test_19_wrong_zone_edits_the_existing_rule():
    a = rule(1, 'Db-Access', 'permit tcp ifc dmz object DMZ-NET ifc inside object IN-NET eq 1433')
    b = rule(1, 'Db-Access', 'permit tcp ifc outside object DMZ-NET ifc inside object IN-NET eq 1433')
    r = rows(go(a, b), 'Wrong zone')
    assert len(r) == 1 and 'Add that zone to the existing rule' in r[0]['required']
    assert not [c for c in r[0]['config'] if 'Add Rule' in c]


# 20 FQDN allow that a B block would stop
FQ = 'object network UPDATES\n fqdn updates.example.com\n'


def test_20a_fqdn_allow_blocked_by_b_rule():
    a = FQ + rule(1, 'Updates', 'permit tcp ifc inside object IN-NET ifc outside object UPDATES eq 443')
    b = FQ + rule(1, 'Block-Web', 'deny tcp ifc inside object IN-NET ifc outside any eq 443')
    r = [x for x in gl(go(a, b))['rows'] if x['gap'].startswith('FQDN allow blocked')]
    assert len(r) == 1 and 'above that block' in r[0]['required'] and 'Block-Web' in r[0]['required']


def test_20c_fqdn_allow_blocked_by_b_l7_block_rule():
    a = FQ + rule(1, 'Updates', 'permit tcp ifc inside object IN-NET ifc outside object UPDATES eq 443')
    b = FQ + rule(1, 'Block_Web_Apps', 'permit tcp ifc inside object IN-NET ifc outside any eq 443', l7=True)
    r = [x for x in gl(go(a, b))['rows'] if x['gap'].startswith('FQDN allow blocked')]
    assert len(r) == 1 and 'Block_Web_Apps' in r[0]['required']


def test_20b_b_rule_naming_the_fqdn_is_ok():
    a = FQ + rule(1, 'Updates', 'permit tcp ifc inside object IN-NET ifc outside object UPDATES eq 443')
    b = FQ + rule(1, 'Updates', 'permit tcp ifc inside object IN-NET ifc outside object UPDATES eq 443') + \
        rule(2, 'Block-Web', 'deny tcp ifc inside object IN-NET ifc outside any eq 443')
    assert not [x for x in gl(go(a, b))['rows'] if x['gap'].startswith('FQDN')]


# 21 missing blocks have fix steps, objects and a position
def test_21_missing_l4_block_has_steps_objects_and_position():
    a = 'object network MAILHOST\n host 10.1.0.25\n' + \
        rule(1, 'Mail-Out', 'permit tcp ifc inside object MAILHOST ifc outside any eq 25') + \
        rule(2, 'No-Smtp', 'deny tcp ifc inside object IN-NET ifc outside any eq 25')
    b = 'object network MAILHOST\n host 10.1.0.25\n' + \
        rule(1, 'Mail-Out', 'permit tcp ifc inside object MAILHOST ifc outside any eq 25')
    r = rows(go(a, b), 'Missing block')
    assert len(r) == 1 and 'below rule "Mail-Out"' in r[0]['required']
    assert [c for c in r[0]['config'] if c.startswith('access-list CSM_FW_ACL_ advanced deny tcp ifc inside')]


# 22 B allows more is a review item only
def test_22_b_allows_more_is_review_only():
    b = rule(1, 'Wide', 'permit tcp ifc inside object IN-NET ifc outside any eq 8080')
    res = go('', b)
    assert gl(res)['review'] and not [r for r in gl(res)['rows'] if 'more' in r['gap'] or 'Wide' == r['object']]


# 23 site equivalents
def test_23_site_twin_interface_rule_is_not_a_gap():
    a = A + 'interface e5\n nameif site-a-lan\n security-level 80\n ip address 10.50.0.1 255.255.255.0\n'
    b = B + 'interface e5\n nameif site-b-lan\n security-level 80\n ip address 10.60.0.1 255.255.255.0\n'
    ra = rule(1, 'Site-Lan-Out', 'permit tcp ifc site-a-lan 10.50.0.0 255.255.255.0 ifc outside any eq 443')
    rb = rule(1, 'Site-Lan-Out', 'permit tcp ifc site-b-lan 10.60.0.0 255.255.255.0 ifc outside any eq 443')
    res = go(ra, rb, a_base=a, b_base=b, interface_map={'outside': 'outside', 'inside': 'inside', 'dmz': 'dmz',
                                                        'site-a-lan': 'site-b-lan'})
    assert not [r for r in gl(res)['rows'] if r['object'] == 'Site-Lan-Out']
    assert rref(res, 'Site-Lan-Out')['result'] == 'OK'


# 28 If route needed
def test_28_missing_route_uses_a_next_hop_on_b_subnet():
    r = [x for x in gl(go('route dmz 10.5.0.0 255.255.255.0 10.2.0.254 1\n', ''))['rows'] if x['gap'].startswith('Route on')]
    assert len(r) == 1 and r[0]['when'] == 'If route needed'
    assert 'route dmz 10.5.0.0 255.255.255.0 10.2.0.254 1' in r[0]['config'] and '<' not in cfg(r[0])


def test_28b_healthy_pair_with_an_ignored_tunnel_has_no_route_gap():
    tun = ('interface e4\n nameif vpn-tunnel\n security-level 50\n ip address 10.9.9.1 255.255.255.252\n'
           'route inside 10.40.0.0 255.255.0.0 10.1.0.254 1\nroute vpn-tunnel 10.40.7.0 255.255.255.0 10.9.9.2 1\n')
    res = go(tun + PAT_IN, tun + PAT_IN, scope=['10.40.0.0/16'])
    assert not [r for r in gl(res)['rows'] if r['kind'] == 'route']
    assert [r['status'] for r in res['routing'] if r['subnet'] == '10.40.0.0/16'] == ['ok']


# 24 OSPF default-information originate always
def test_24_ospf_default_always_is_a_takeover_item():
    a = 'router ospf 1\n network 10.1.0.0 255.255.255.0 area 0\n default-information originate always\n'
    r = [x for x in gl(go(a, ''))['rows'] if x['gap'].startswith('Default route always')]
    assert len(r) == 1 and r[0]['when'] == 'At outage' and 'internet down' in r[0]['required']
    assert re.match(r'fw-alpha \d+: default-information originate always', r[0]['a_line'])


# 25 both outage cases
def test_25_both_outage_cases():
    cases = gl(go(PAT_IN, PAT_IN))['outage']
    assert [c['case'] for c in cases] == ['fw-alpha internet down, firewalls up', 'fw-alpha firewalls lost']
    assert cases[0]['steps'][0].startswith("Shut fw-alpha's shared interfaces first")
    assert not any('Shut' in s for s in cases[1]['steps'])


# 26 one dependency item for a public block routed to A's ISP
def test_26_shared_public_block_is_one_dependency_item():
    b = ''.join('object network S%d\n host 10.1.0.%d\n nat (inside,outside) static 198.51.100.%d\n' % (i, 50 + i, 50 + i)
                for i in range(3))
    res = go('', b)
    r = [x for x in gl(res)['rows'] if x['gap'].startswith('Public block routed')]
    assert len(r) == 1 and '3 fw-bravo NAT lines' in r[0]['b_line'] and 'packet-tracer cannot prove' in r[0]['required']


# 27-29 columns, When values, sort order
def test_27_29_columns_when_values_and_sort():
    a = PAT_DMZ + PUB + 'nat (inside,inside) source dynamic any interface\n'
    g = gl(go(a, ''))
    assert [c[1] for c in g['cols']] == ['Gap', 'When', 'Address', 'Object', 'A (line)', 'B today (line)',
                                         'Required on B', 'Config']
    assert all(r['when'] in gaplist.WHEN for r in g['rows'])
    keys = [(gaplist.WHEN.index(r['when']), r['gap']) for r in g['rows']]
    assert keys == sorted(keys)


# 30 reference views: every A NAT line and every A rule
def test_30_reference_views_cover_every_nat_line_and_rule():
    a = PAT_DMZ + PAT_IN + 'nat (inside,outside) source dynamic IN-NET interface inactive\n' + \
        rule(1, 'Live', 'permit tcp ifc inside object IN-NET ifc outside any eq 443')
    res = go(a, PAT_IN)
    assert len(gl(res)['nat_ref']) == 3
    assert {'Live'} <= {r['rule'] for r in gl(res)['rule_ref']}
    assert all(r['b_match'] for r in gl(res)['nat_ref'] if not r['result'].startswith(('Inactive', 'Not checked')))


# 31 missing objects: needed versus not needed
def test_31_missing_objects_needed_and_not_needed():
    a = 'object network UNUSED-HOST\n host 10.1.0.99\n' + PAT_DMZ.replace('DMZ-NET', 'DMZ-ONLY') + \
        'object network DMZ-ONLY\n subnet 10.2.0.0 255.255.255.128\n' + \
        rule(1, 'Unused', 'permit tcp ifc inside object UNUSED-HOST ifc outside any eq 22')
    b = rule(1, 'Unused', 'permit tcp ifc inside host 10.1.0.99 ifc outside any eq 22')
    objs = {o['name']: o['status'] for o in gl(go(a, b))['objects']}
    assert objs.get('DMZ-ONLY') == 'needed'
    assert objs.get('UNUSED-HOST', '').startswith('not needed')


# 32 verdict counts equal the rows shown
def test_32_verdict_counts_equal_rows():
    g = gl(go(PAT_DMZ + PUB, ''))
    assert sum(g['counts'].values()) == len(g['rows']) == g['total']
    assert g['verdict']['text'].startswith('%d gaps' % len(g['rows']))
    for w, n in g['counts'].items():
        assert '%d %s' % (n, w) in g['verdict']['text']


# 33 real config line numbers
def test_33_real_line_numbers():
    a = PAT_DMZ
    res = go(a, '')
    r = rows(res, 'Missing PAT')[0]
    no = (A + a).split('\n').index(PAT_DMZ.strip()) + 1
    assert r['a_line'].startswith('fw-alpha %d: ' % no)


# safety: the guard test
def test_safety_checker_catches_every_unsafe_kind():
    bad = {'rows': [
        {'object': 'X', 'config': ['access-list CSM_FW_ACL_ advanced permit ip ifc inside any ifc outside any']},
        {'object': 'Block-Ads', 'config': ['Policies > Access Control > Add Rule: Name "Block-Ads", Action Allow']},
        {'object': 'Y', 'config': ['nat (inside,outside) source static Y <B public IP object>']},
        {'object': 'Z', 'config': ['no nat (inside,outside) after-auto source dynamic IN-NET interface']}]}
    kinds = {k for k, c in gaplist.unsafe(bad)}
    assert kinds == {'any-to-any', 'block as allow', 'placeholder', 'no nat on a live rule'}


def test_safety_no_fix_in_any_scenario_is_unsafe():
    scen = [(PAT_DMZ, ''), (PUB, ''), (PAT_DMZ, 'nat (inside,outside) after-auto source dynamic DMZ-NET interface\n'),
            (rule(1, 'Block_Ads', 'permit ip ifc inside any ifc outside any', l7=True), ''),
            (rule(1, 'Any-Any', 'permit ip any any'), ''),
            (rule(1, 'Web', 'permit ip ifc inside any ifc outside any', l7=True), '')]
    for a, b in scen:
        res = go(a, b)
        safe(res)
        assert not [c for r in gl(res)['rows'] for c in r['config'] if safety.bad(c)]
