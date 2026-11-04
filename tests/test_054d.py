"""0.5.4 takeover compare, root causes A-R found on a real pair: one synthetic test (or more) per root cause.
Made-up names, documentation and private addresses only."""
import json

from fwsync import gaplist, report
from fwsync.adapters import load
from fwsync.pipeline import run
from test_054c import A, B, PAT_DMZ, SHUT_DMZ, cfg, gl, go, nref, rows, rref, rule, safe

OSPF = 'router ospf 1\n network 10.1.0.0 255.255.255.0 area 0\n'
WEB = 'object network WEB\n host 10.2.0.10\nobject network WEB-PUB\n host 198.51.100.10\n'
WEB_IN = rule(9, 'Web-In', 'permit tcp ifc outside any ifc dmz object WEB eq 443')


def nat_rows(res):
    return [r for r in gl(res)['rows'] if r['kind'] == 'nat']


# A shared interfaces: the same address and subnet, B's copy shut; the same addresses up on both are site networks
def test_a_outage_shuts_only_interfaces_b_holds_shut():
    steps = gl(go('', '', b_base=SHUT_DMZ))['outage'][0]['steps']
    assert 'dmz' in steps[0] and 'inside' not in steps[0]
    assert 'interface e3 / shutdown (on fw-alpha)' in steps and not [s for s in steps if s.startswith('interface e2 ')]
    assert 'interface e3 / no shutdown (on fw-bravo)' in steps


def test_a_no_shared_interface_when_b_has_every_copy_up():
    steps = gl(go('', ''))['outage'][0]['steps']
    assert 'none found' in steps[0] and not [s for s in steps if s.startswith('interface ')]


# B an A line is not cleared as "not hit" by routing when A learns routes dynamically
REMOTE_PAT = 'nat (inside,outside) after-auto source dynamic REMOTE interface\n'


def test_b_not_hit_by_routing_only_without_dynamic_routing():
    plain = go(REMOTE_PAT, '')
    assert 'not hit' in nref(plain, 'REMOTE')['result'] and gl(plain)['stats']['not_hit_on_a'] == 1
    dyn = go(REMOTE_PAT, '', a_base=A + OSPF)
    assert nref(dyn, 'REMOTE')['result'] == 'Missing PAT' and gl(dyn)['stats']['not_hit_on_a'] == 0


def test_b_connected_subnets_still_count_with_dynamic_routing():
    res = go('nat (inside,outside) after-auto source dynamic DMZ-NET interface\n', '', a_base=A + OSPF)
    assert 'not hit' in nref(res, 'DMZ-NET')['result'] and not nat_rows(res)


# C a wrong-interface PAT is one row on the PAT line; statics with inbound rules stay their own rows
def test_c_wrong_interface_pat_is_one_row_and_statics_keep_theirs():
    a = PAT_DMZ + WEB + 'object network WEB2\n host 10.2.0.11\nobject network WEB2-PUB\n host 198.51.100.11\n' \
        'nat (dmz,outside) source static WEB WEB-PUB\nnat (dmz,outside) source static WEB2 WEB2-PUB\n' + WEB_IN
    res = go(a, 'nat (inside,outside) after-auto source dynamic DMZ-NET interface\n')
    wrong = rows(res, 'Wrong source interface')
    assert len(wrong) == 1 and 'DMZ-NET' in wrong[0]['a_line']
    st = rows(res, 'Missing static NAT')
    assert len(st) == 1 and '198.51.100.10' in cfg(st[0]) + st[0]['required']
    opt = rows(res, 'Static NAT (optional)')
    assert len(opt) == 1 and opt[0]['when'] == 'Only if allow-listed' and 'WEB2' in opt[0]['a_line']
    safe(res)


# D the same host and public IP on another interface of B: edit that rule at outage, never a duplicate
def test_d_same_host_and_public_ip_elsewhere_is_change_at_outage():
    a = WEB + 'nat (dmz,outside) source static WEB WEB-PUB\n' + WEB_IN
    b = WEB + 'nat (inside,outside) source static WEB WEB-PUB\n' + PAT_DMZ
    res = go(a, b, b_base=SHUT_DMZ)
    r = [x for x in rows(res, 'Change at outage') if 'WEB' in x['a_line']]
    assert len(r) == 1 and r[0]['when'] == 'At outage'
    assert 'edit line' in cfg(r[0]) and 'Add Rule' not in cfg(r[0]) and not rows(res, 'Missing static NAT')
    safe(res)


# E an identity NAT moves only when it catches traffic to a static's public IP
PUBNET = 'interface e4\n nameif pub\n security-level 50\n ip address 192.0.2.1 255.255.255.0\n shutdown\n' \
         'object network PUBNET\n subnet 192.0.2.0 255.255.255.0\nobject network ANY4\n subnet 0.0.0.0 0.0.0.0\n' \
         'object network SRV\n host 10.1.0.50\nobject network SRV-PUB\n host 192.0.2.50\n'


def test_e_identity_with_any_destination_above_a_static_moves_at_outage():
    b = PUBNET + 'nat (inside,outside) source static PUBNET PUBNET destination static ANY4 ANY4\n' \
        'nat (inside,outside) source static SRV SRV-PUB\n'
    r = [x for x in rows(go('', b), 'Change at outage') if 'PUBNET' in x['b_line']]
    assert len(r) == 1 and r[0]['when'] == 'At outage'
    assert 'pub' in cfg(r[0]) and 'After Auto' in cfg(r[0]) + r[0]['required']


def test_e_identity_with_a_specific_destination_does_not_move():
    b = PUBNET + 'object-group network ALL-NETS\n network-object 10.1.0.0 255.255.255.0\n' \
        ' network-object 192.0.2.0 255.255.255.0\nobject network PUBSRV\n host 192.0.2.60\n' \
        'nat (inside,pub) source static ALL-NETS ALL-NETS destination static PUBNET PUBNET\n' \
        'nat (pub,outside) source static PUBSRV SRV-PUB\n'
    assert not [x for x in gl(go('', b))['rows'] if x['when'] == 'At outage' and 'ALL-NETS' in x['b_line']]


# F source any: the traffic entering that real interface, never other subnets A routes there
def test_f_source_any_is_the_traffic_entering_the_interface():
    any_pat = 'nat (inside,outside) after-auto source dynamic any interface\n'
    res = go(any_pat, any_pat, a_base=A + 'route inside 203.0.113.0 255.255.255.192 10.1.0.254 1\n')
    assert not rows(res, 'Missing PAT') and nref(res, 'source dynamic any')['result'].startswith('OK')


# G coverage ignores rule names; a rule only B has never produces Wrong zone
def test_g_coverage_by_another_name_on_the_mapped_zones():
    a = rule(1, 'To-Remote', 'permit tcp ifc inside object IN-NET ifc dmz object REMOTE eq 443')
    b = rule(1, 'Other-Name', 'permit ip ifc inside object IN-NET ifc dmz object REMOTE')
    vti = 'interface t1\n nameif cloud-vti\n ip address 10.9.9.1 255.255.255.252\n' \
          'route cloud-vti 10.200.0.0 255.255.0.0 10.9.9.2 1\n'
    res = go(a, b, a_base=A + 'route dmz 10.200.0.0 255.255.0.0 10.2.0.254 1\n', b_base=B + vti)
    assert not [r for r in gl(res)['rows'] if r['kind'] == 'rule']


def test_g_b_only_rule_never_gives_wrong_zone():
    res = go('', rule(1, 'B-Only', 'permit tcp ifc inside object DMZ-NET ifc outside any eq 22'))
    res['firewide'] = [{'id': 'FW-R-B-Only', 'status': 'add zone', 'item': 'B-Only', 'src_ifc': 'inside',
                        'add_zone': ['dmz'], 'detail': 'moves at takeover'}]
    g = gaplist.Gaps(res, _prof(res), *_cfgs(res))
    g.zone_moves()
    assert not [r for r in g.rows if r['gap'] == 'Wrong zone']


def _prof(res):
    from fwsync.profile import Profile
    d = res['profile_used']
    return Profile(**{k: v for k, v in d.items() if k in Profile.__dataclass_fields__})


def _cfgs(res):
    return load(A, 'fw-alpha.txt'), res['_B'], res['detected']


# H FQDN allow lines are linked to their rule and compared; a B block above gives one Missing allow above it
def test_h_fqdn_object_with_id_and_its_lines_survive_an_ignored_interface():
    a = A + 'interface t1\n nameif lab-vti\n ip address 10.9.9.1 255.255.255.252\n' \
            'route lab-vti 10.77.0.0 255.255.0.0 10.9.9.2 1\nobject network FILES\n fqdn v4 files.example.com id 99\n'
    cfg_a = load(a, 'fw-alpha.txt')
    assert cfg_a.objects['FILES'].value == 'files.example.com'
    lines = rule(1, 'To-Files', 'permit tcp ifc inside object IN-NET ifc outside object FILES eq 22') + \
        rule(1, 'To-Files', 'permit tcp ifc inside object IN-NET ifc outside object FILES eq 990')
    b = 'object network FILES\n fqdn files.example.com\n' + \
        rule(2, 'No-Ftp', 'deny tcp ifc inside any ifc outside any range 20 990')
    res = go(lines, b, a_base=a, interface_map={'lab-vti': 'ignore'})
    assert rref(res, 'To-Files')['lines'].count(',') == 1
    r = rows(res, 'Missing allow')
    assert len(r) == 1 and r[0]['object'] == 'To-Files' and 'above rule "No-Ftp"' in r[0]['required']


def test_h_any_to_any_l7_block_does_not_stop_an_fqdn_allow():
    a = 'object network FILES\n fqdn files.example.com\n' + \
        rule(1, 'To-Files', 'permit tcp ifc inside object IN-NET ifc outside object FILES eq 22')
    b = 'object network FILES\n fqdn files.example.com\n' + \
        rule(2, 'Block-Web-Categories', 'permit ip any ifc outside any', l7=True)
    assert not rows(go(a, b), 'Missing allow')


# I an L7 Block* rule matches only a block on the same mapped zone; any to any is compared in FMC
TOOLS = 'object network TOOLS\n subnet 192.0.2.0 255.255.255.0\n'


def test_i_l7_block_needs_a_block_on_the_same_zone():
    a = TOOLS + rule(1, 'Block_Dmz_To_Tools', 'permit ip ifc dmz any ifc outside object TOOLS', l7=True)
    other_zone = TOOLS + rule(1, 'Block_In_To_Tools', 'permit ip ifc inside any ifc outside object TOOLS', l7=True)
    r = rows(go(a, other_zone), 'Missing block')
    assert len(r) == 1 and r[0]['object'] == 'Block_Dmz_To_Tools'
    same_zone = TOOLS + rule(1, 'Block_Dmz_Tools', 'permit ip ifc dmz any ifc outside object TOOLS', l7=True)
    assert not rows(go(a, same_zone), 'Missing block')


def test_i_any_to_any_l7_block_is_compared_in_fmc_unless_identical():
    a = rule(1, 'Geo-Block-Inbound', 'permit ip ifc outside any any', l7=True)
    r = [x for x in gl(go(a, rule(1, 'Geo-Block-Inbound', 'permit ip any any', l7=True)))['rows'] if x['object'] == 'Geo-Block-Inbound']
    assert len(r) == 1 and r[0]['when'] == 'Compare in FMC'
    assert not [x for x in gl(go(a, a))['rows'] if x['object'] == 'Geo-Block-Inbound']


# J blocks go above B's broad allow (never below it), below narrower allows A has above the block
def test_j_block_above_the_broad_allow_and_no_allow_first():
    a = rule(1, 'Mail-Out', 'permit tcp ifc inside host 10.1.0.25 ifc outside any eq 25') + \
        rule(2, 'No-Smtp', 'deny tcp ifc inside any ifc outside any eq 25') + \
        rule(3, 'Allow-All-In', 'permit ip ifc inside any ifc outside any')
    b = rule(1, 'Mail-Out', 'permit tcp ifc inside host 10.1.0.25 ifc outside any eq 25') + \
        rule(3, 'Allow-All-In', 'permit ip ifc inside any ifc outside any')
    r = rows(go(a, b), 'Missing block')
    assert len(r) == 1
    req = r[0]['required']
    assert 'below rule "Mail-Out"' in req and 'above rule "Allow-All-In"' in req
    assert 'below rule "Allow-All-In"' not in req and 'First add the allows' not in req


# K a new NAT brings the A exemptions above it; a NAT that could change traffic today is added disabled
def test_k_internal_nat_on_a_shut_interface_brings_its_exemption_disabled():
    a = WEB + 'nat (dmz,inside) source static WEB WEB destination static IN-NET IN-NET\n' \
              'nat (dmz,inside) source static WEB WEB-PUB\n'
    res = go(a, '', b_base=SHUT_DMZ)
    it = rows(res, 'Missing internal NAT')
    assert len(it) == 1 and it[0]['when'] == 'Now disabled' and it[0]['config'][-1].endswith(' inactive')
    ex = rows(res, 'Missing NAT exemption')
    assert len(ex) == 1 and ex[0]['when'] == 'Now disabled' and 'because of the fix' in ex[0]['required']
    assert 'the proposed rule' in ex[0]['required'] and 'line 0' not in json.dumps(ex[0])
    safe(res)


# L one A line that splits into CIDRs and B lines is one row
def test_l_one_row_per_a_line():
    a = 'object network ODD\n range 10.1.0.3 10.1.0.20\n' \
        'nat (inside,outside) source static ODD ODD destination static REMOTE REMOTE\n'
    b = 'object network H5\n host 10.1.0.5\nobject network H5-PUB\n host 203.0.113.5\n' \
        'object network H9\n host 10.1.0.9\nobject network H9-PUB\n host 203.0.113.9\n' \
        'nat (inside,outside) source static H5 H5-PUB\nnat (inside,outside) source static H9 H9-PUB\n' \
        'nat (inside,outside) after-auto source dynamic IN-NET interface\n'
    r = rows(go(a, b), 'Missing NAT exemption')
    assert len(r) == 1 and r[0]['b_line'].count('fw-bravo') >= 2


# M one isolated B line in A's block does not show that the block moves: a decision, no NAT command
def test_m_isolated_b_line_is_a_decision():
    a = WEB + 'nat (dmz,outside) source static WEB WEB-PUB\n' + WEB_IN
    b = 'object network ONE\n host 10.1.0.50\nobject network ONE-PUB\n host 198.51.100.50\n' \
        'nat (inside,outside) source static ONE ONE-PUB\n'
    r = rows(go(a, b), 'Missing static NAT')
    assert len(r) == 1 and r[0]['when'] == 'Decision' and 'public IP' in r[0]['required']
    assert not [c for c in r[0]['config'] if c.startswith('nat (') or 'Add Rule' in c]


# N site devices: edge or gateway monitoring, a public IP in B's own block, a twin host with its own public NAT
def test_n_gateway_monitoring_is_a_site_device():
    a = 'object network MON\n host 10.1.0.60\nobject network MON-PUB\n host 198.51.100.60\n' \
        'object network GW\n host 198.51.100.62\n' \
        'nat (inside,outside) source static MON MON-PUB\n' + \
        rule(1, 'Edge-To-Mon', 'permit udp ifc outside host 198.51.100.62 ifc inside object MON eq 161') + \
        'nat (inside,outside) source static IN-NET IN-NET destination static GW GW\n'
    res = go(a, '')
    assert not nat_rows(res) and not rows(res, 'Partial allow') and not rows(res, 'Missing allow')
    assert nref(res, 'MON MON-PUB')['result'].startswith('OK, site device')


def test_n_public_ip_in_b_own_block_and_twin_host():
    a = 'object network SITE\n host 10.1.0.70\nobject network SITE-PUB\n host 203.0.113.30\n' \
        'nat (inside,outside) source static SITE SITE-PUB\n' + \
        'object network VGW-A\n host 10.1.0.41\nobject network VGW-A-PUB\n host 198.51.100.41\n' \
        'nat (inside,outside) source static VGW-A VGW-A-PUB\n' + \
        rule(1, 'Voice-In', 'permit tcp ifc outside any ifc inside object-group VOICE-GWS eq 5061')
    grp = 'object-group network VOICE-GWS\n network-object host 10.1.0.41\n network-object host 10.1.0.42\n'
    b = 'object network VGW-B\n host 10.1.0.42\nobject network VGW-B-PUB\n host 203.0.113.41\n' \
        'nat (inside,outside) source static VGW-B VGW-B-PUB\n' + \
        rule(1, 'Voice-In', 'permit tcp ifc outside any ifc inside object-group VOICE-GWS eq 5061')
    res = go(a, b, a_base=A + grp, b_base=B + grp)
    assert not rows(res, 'Missing static NAT')
    assert 'own block' in nref(res, 'SITE SITE-PUB')['result'] and 'own public NAT' in nref(res, 'VGW-A VGW-A-PUB')['result']


# O a destination-any NAT on A is covered by a B NAT limited to the group of all inside networks
def test_o_destination_any_covered_by_inside_networks_group():
    a = WEB + 'object network ANY4\n subnet 0.0.0.0 0.0.0.0\n' \
              'nat (dmz,inside) source static WEB WEB-PUB destination static ANY4 ANY4\n'
    b = WEB + 'object-group network INSIDE-ALL\n network-object 10.0.0.0 255.0.0.0\n' \
              'nat (dmz,inside) source static WEB WEB-PUB destination static INSIDE-ALL INSIDE-ALL\n'
    res = go(a, b)
    assert not rows(res, 'Missing internal NAT') and nref(res, 'WEB WEB-PUB')['result'].startswith('OK')


# P an L7 row for a rule B has on fewer zones says which zone to add
def test_p_l7_rule_names_the_zone_to_add():
    a = rule(1, 'Allow_Scanner', 'permit ip ifc inside host 10.1.0.99 ifc dmz any', l7=True) + \
        rule(1, 'Allow_Scanner', 'permit ip ifc inside host 10.1.0.99 any', l7=True)
    b = rule(1, 'Allow_Scanner', 'permit ip ifc inside host 10.1.0.99 ifc outside any', l7=True)
    r = [x for x in gl(go(a, b))['rows'] if x['object'] == 'Allow_Scanner']
    assert len(r) == 1 and 'add dmz' in r[0]['required'] and 'dmz' in cfg(r[0])


# Q real line numbers on CRLF configs and for object NAT pairs; no "line 0"
def test_q_crlf_and_object_nat_line_numbers():
    a = A + 'object network OBJ-PAT\n subnet 10.1.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\n'
    want = a.split('\n').index(' nat (inside,outside) dynamic interface') + 1
    res, A_, B_, p = run([(a.replace('\n', '\r\n'), 'fw-alpha.txt')], (B.replace('\n', '\r\n'), 'fw-bravo.txt'))
    r = rows(res, 'Missing PAT')
    assert len(r) == 1 and r[0]['a_line'].startswith('fw-alpha %d: object network OBJ-PAT / nat' % want)
    assert 'line 0' not in json.dumps(gl(res)) and ' 0: ' not in json.dumps(gl(res))


# R the top verdict is the gap list's
def test_r_top_verdict_matches_the_gap_list():
    res = go(PAT_DMZ, '')
    g = gl(res)
    assert res['verdict']['ready'] == g['verdict']['ready'] and res['verdict']['text'].startswith(g['verdict']['text'])
    assert res['verdict']['runbook_text']
    html = '\n'.join(report.gaplist_html(res))
    assert g['verdict']['text'] in html
