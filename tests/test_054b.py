"""0.5.4 regressions found on real configs: L7 coverage, block names, the any-to-any safeguard, backhaul identity NAT,
NAT precedence, live rule removal, VPN pools, sibling NATs, FQDN rules, duplicate PAT findings, add-zone edits and
small corrections. Made-up names, documentation addresses only."""
import re

from fwsync import sitemap
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
 ip address 192.0.2.65 255.255.255.224
route outside 0.0.0.0 0.0.0.0 198.51.100.2 1
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
interface e3
 nameif dmz
 security-level 50
 ip address 192.0.2.65 255.255.255.224
route outside 0.0.0.0 0.0.0.0 203.0.113.2 1
access-group CSM_FW_ACL_ global
"""
APP = 'object network APP-HOST\n host 192.0.2.10\nobject network WEB-HOST\n host 192.0.2.70\n'
ANY_ANY = re.compile(r'\bpermit\s+(?:object-group\s+\S+|object\s+\S+|\S+)\s+(?:ifc\s+\S+\s+)?any4?\s+'
                     r'(?:(?:eq|lt|gt|neq)\s+\S+\s+|range\s+\S+\s+\S+\s+)?(?:ifc\s+\S+\s+)?any4?(?:\s|$)')


def rule(n, name, line, l7=False):
    return ('access-list CSM_FW_ACL_ remark rule-id %d: %s: %s\n' % (n, 'L7 RULE' if l7 else 'L4 RULE', name) +
            'access-list CSM_FW_ACL_ advanced %s rule-id %d\n' % (line, n))


def go(a='', b='', a_base=A, b_base=B, **prof):
    return run([(a_base + a, 'fw-alpha.txt')], (b_base + b, 'fw-bravo.txt'), prof or None)[0]


def cat(res, c):
    return [f for f in res['findings'] if f['category'] == c]


def named(res, name):
    return [f for f in res['findings'] if f.get('rule') == name]


def items(res):
    return [i for g in res['runbook'] for i in g['items']]


def take(res, check):
    return [t for t in res['takeover'] if t['id'].startswith('T-%s-' % check)]


def all_cli(res):
    out = [c for f in res['findings'] for c in f['fix']['cli']]
    out += [c for t in res['takeover'] for c in t.get('cli', [])]
    out += [c for i in items(res) + res['failback'] for c in i['cli'] + ((i.get('undo') or {}).get('cli') or [])]
    return out


def all_text(res):
    return ' '.join(all_cli(res) + [x for f in res['findings'] for x in f['fix']['fmc']] +
                    [x for i in items(res) for x in i['fmc']] + [d.get('text', '') for d in res.get('decisions', [])])


def pairs(monkeypatch, *p):
    monkeypatch.setattr(sitemap, 'net_pairs', lambda A, B, imap: list(p))


# ---------------------------------------------------------------- 1. L7 coverage

FINAL = rule(90, 'Allow-Inside-Out', 'permit ip ifc inside any ifc outside any', l7=True)


def test_1a_l7_allow_all_from_a_zone_covers_and_says_confirm_in_fmc():
    res = go(APP + rule(3, 'App-Out', 'permit tcp ifc inside object APP-HOST ifc outside any eq 443'), FINAL)
    row = [r for r in res['rules'] if r['rule'] == 'App-Out'][0]
    assert row['status'] == 'covered', row['status']
    assert 'confirm in FMC' in row['detail'] and 'Allow-Inside-Out' in row['detail']
    assert not named(res, 'App-Out')
    for b in (rule(90, 'Allow-Everything', 'permit ip any any', l7=True),
              rule(90, 'Block_Inside_Out', 'permit ip ifc inside any ifc outside any', l7=True)):
        res = go(APP + rule(3, 'App-Out', 'permit tcp ifc inside object APP-HOST ifc outside any eq 443'), b)
        assert [r for r in res['rules'] if r['rule'] == 'App-Out'][0]['status'] == 'missing'


# ---------------------------------------------------------------- 2. block names

def test_2a_underscore_and_dash_are_separators():
    res = go(APP + rule(6, 'Block_X_to_Y', 'permit tcp ifc inside object APP-HOST ifc outside any eq 443', l7=True))
    assert [h for h in res['held_rules'] if h['rule'] == 'Block_X_to_Y']
    assert not [r for r in res['rules'] if r['rule'] == 'Block_X_to_Y']
    from fwsync.compare import block_name
    for n in ('Block_X_to_Y', 'Deny-Social', 'drop_all', 'X_Blocked', 'Unwanted-Apps'):
        assert block_name(n), n
    for n in ('Allow_Inside', 'Blockchain-App', 'Dropbox_Sync', 'Web-In'):
        assert not block_name(n), n


def test_2b_l4_permit_with_block_name_gives_confirm_in_fmc_and_no_cli():
    res = go(APP + rule(4, 'Block_App_to_Web', 'permit tcp ifc inside object APP-HOST ifc outside any eq 443'))
    f = named(res, 'Block_App_to_Web')[0]
    assert f['fix']['cli'] == [] and not f.get('acp_rules')
    assert f['fix']['fmc'][0].startswith('Confirm the action in FMC')
    assert 'Action Allow' not in ' '.join(f['fix']['fmc'])


# ---------------------------------------------------------------- 3. any-to-any safeguard

TUN = ('interface e4\n nameif vpn-tunnel\n security-level 50\n ip address 192.0.2.97 255.255.255.252\n'
       'route vpn-tunnel 192.0.2.128 255.255.255.224 192.0.2.98 1\n')


def test_3a_l7_rule_narrowed_by_an_ignored_interface_is_still_compare_in_fmc():
    res = go(TUN + rule(7, 'Web-Apps', 'permit ip ifc inside any ifc outside any', l7=True))
    f = named(res, 'Web-Apps')[0]
    assert f['status'] == 'compare in FMC' and f['fix']['cli'] == []
    assert not [c for c in all_cli(res) if ANY_ANY.search(c)]


def test_3b_l4_any_to_any_permit_is_never_output():
    res = go(rule(8, 'Open-Out', 'permit tcp ifc inside any ifc outside any eq 443'))
    f = named(res, 'Open-Out')[0]
    assert f['fix']['cli'] == [] and f['fix']['fmc'][0].startswith('Compare in FMC')
    assert not [c for c in all_cli(res) if ANY_ANY.search(c)]
    assert 'Source any, Destination any' not in all_text(res)


def test_3c_global_check_strips_any_to_any_from_every_path_and_counts_it():
    from fwsync import safety
    res = {'findings': [{'level': 'fix', 'group': 'before', 'acp_rules': ['X'],
                         'fix': {'cli': ['access-list CSM_FW_ACL_ advanced permit ip ifc inside any ifc dmz any rule-id 5'],
                                 'fmc': ['Add Rule: Name "X", Action Allow, Zones: Source inside -> Destination dmz, '
                                         'Networks: Source any, Destination any, Ports: any.'], 'objects': []}}],
           'takeover': [{'cli': ['access-list CSM_FW_ACL_ extended permit tcp any4 any4 eq 443'], 'fmc': [],
                         'undo': {'cli': ['access-list A extended permit object-group SVC any any'], 'fmc': []}}]}
    out = safety.enforce(res)
    f = res['findings'][0]
    assert out['stripped'] == 4
    assert f['fix']['cli'] == [] and f['level'] == 'check' and 'acp_rules' not in f
    assert f['fix']['fmc'][0].startswith('Compare in FMC')
    assert res['takeover'][0]['cli'] == [] and res['takeover'][0]['undo']['cli'] == []
    clean = go(rule(8, 'Open-Out', 'permit tcp ifc inside any ifc outside any eq 443'))
    assert clean['safety']['stripped'] == 0


# ---------------------------------------------------------------- 4. backhaul identity NAT

SITE_A = """hostname fw-alpha
interface e1
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.192
interface e2
 nameif apps
 security-level 50
 ip address 192.0.2.1 255.255.255.192
interface e3
 nameif web
 security-level 50
 ip address 192.0.2.65 255.255.255.192
route outside 0.0.0.0 0.0.0.0 198.51.100.2 1
access-group CSM_FW_ACL_ global
object network SRV-APP
 host 192.0.2.10
object network SRV-APP-PUB
 host 198.51.100.10
nat (apps,outside) source static SRV-APP SRV-APP-PUB
access-list CSM_FW_ACL_ remark rule-id 10: L4 RULE: App-In
access-list CSM_FW_ACL_ advanced permit tcp ifc outside any ifc apps object SRV-APP eq 443 rule-id 10
"""
SITE_B = """hostname fw-bravo
interface e1
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.192
interface e2
 nameif apps
 shutdown
 security-level 50
 ip address 192.0.2.1 255.255.255.192
interface e3
 nameif web
 shutdown
 security-level 50
 ip address 192.0.2.65 255.255.255.192
interface e4
 nameif dci
 security-level 50
 ip address 203.0.113.65 255.255.255.224
route outside 0.0.0.0 0.0.0.0 203.0.113.2 1
route dci 192.0.2.0 255.255.255.0 203.0.113.66 1
access-group CSM_FW_ACL_ global
object network SITE-NETS
 subnet 192.0.2.0 255.255.255.192
object network SRV-DB
 host 192.0.2.20
object network SRV-DB-PUB
 host 203.0.113.20
nat (dci,outside) source static SITE-NETS SITE-NETS
nat (apps,outside) source static SRV-DB SRV-DB-PUB
object network SRV-APP
 host 192.0.2.10
 nat (apps,outside) static 203.0.113.10
access-list CSM_FW_ACL_ remark rule-id 10: L4 RULE: App-In
access-list CSM_FW_ACL_ advanced permit tcp ifc outside any ifc apps object SRV-APP eq 443 rule-id 10
"""
IDENT = 'nat (dci,outside) source static SITE-NETS SITE-NETS'
BACK = re.compile(r'^nat \(dci,outside\) 1 source static SITE-NETS SITE-NETS$')


def site(b=SITE_B, **prof):
    return run([(SITE_A, 'fw-alpha.txt')], (b, 'fw-bravo.txt'), prof or None)[0]


def test_4a_backhaul_identity_nat_is_a_during_failover_edit_to_after_auto():
    res = site()
    t = [x for x in res['takeover'] if IDENT in ' '.join(x['cli'])]
    assert len(t) == 1, [x['title'] for x in res['takeover']]
    t = t[0]
    assert t['group'] == 'during'
    assert 'nat (apps,outside) after-auto source static SITE-NETS SITE-NETS' in t['cli']
    assert 'After Auto NAT' in ' '.join(t['fmc'])
    assert "doesn't match" not in t['detail'] and 'does not match' not in t['detail']
    assert t['undo'] and [c for c in t['undo']['cli'] if BACK.match(c)]


def test_4b_never_says_it_does_not_match_today_when_routed_another_way():
    b = SITE_B.replace('route dci 192.0.2.0 255.255.255.0 203.0.113.66 1',
                       'route outside 192.0.2.0 255.255.255.0 203.0.113.3 1')
    res = site(b)
    t = [x for x in res['takeover'] if IDENT in ' '.join(x['cli'])]
    assert t and all(x['group'] == 'during' for x in t)
    assert not [x for x in res['takeover'] if 'does not match this traffic today' in x['detail']]


def test_4c_override_notes_name_every_published_server_below():
    res = site()
    t = [x for x in res['takeover'] if IDENT in ' '.join(x['cli'])][0]
    assert 'SRV-APP' in t['detail'] and 'auto NAT' in t['detail']
    assert 'SRV-DB' in t['detail'] and 'manual NAT' in t['detail']


# ---------------------------------------------------------------- 5. NAT precedence: broader means contains

FARM_A = ('object network FARM\n subnet 192.0.2.68 255.255.255.252\nobject network FARM-PUB\n'
          ' subnet 198.51.100.8 255.255.255.252\nnat (dmz,outside) source static FARM FARM-PUB\n' +
          rule(11, 'Farm-In', 'permit tcp ifc outside any ifc dmz object FARM eq 443'))
FARM_B = ('object network ONE\n host 192.0.2.69\nobject network ONE-PUB\n host 203.0.113.69\n'
          'nat (dmz,outside) source static ONE ONE-PUB\n'
          'object network FARM\n subnet 192.0.2.68 255.255.255.252\nobject network FARM-PUB-B\n'
          ' subnet 203.0.113.8 255.255.255.252\nnat (dmz,outside) source static FARM FARM-PUB-B\n' +
          rule(11, 'Farm-In', 'permit tcp ifc outside any ifc dmz object FARM eq 443'))


def test_5_a_host_inside_a_group_is_a_partial_overlap_not_an_override():
    res = go(FARM_A, FARM_B, scope=['192.0.2.64/27'])
    assert not take(res, 'NATORDER')
    t = take(res, 'NATOVERLAP')
    assert len(t) == 1 and t[0]['group'] == 'later'
    assert all(c.startswith('show ') for c in t[0]['cli'])


# ---------------------------------------------------------------- 6. live rule removal / VPN pool

def test_6a_vpn_pool_nat_on_the_vpn_interface_is_review_only():
    b = ('ip local pool BRAVO-VPN 192.0.2.200-192.0.2.220 mask 255.255.255.224\n'
         'route inside 192.0.2.0 255.255.255.0 192.0.2.2 1\n'
         'object network VPN-NET\n subnet 192.0.2.192 255.255.255.224\nobject network IN-NET\n'
         ' subnet 192.0.2.0 255.255.255.192\n'
         'nat (outside,inside) source static VPN-NET VPN-NET destination static IN-NET IN-NET\n')
    res = go('', b)
    t = [x for x in res['takeover'] if 'VPN-NET' in x['title'] or 'VPN-NET' in x['detail']]
    assert t and all(x['group'] == 'later' for x in t)
    assert not [c for c in all_cli(res) if c.startswith('no nat')]
    assert any('show nat detail' in c for x in t for c in x['cli'])


def test_6b_nat_check_item_never_removes_a_rule():
    b = ('object network DMZ-NET\n subnet 192.0.2.64 255.255.255.224\n'
         'nat (inside,outside) after-auto source dynamic DMZ-NET interface\n')
    res = go('', b)
    t = take(res, 'NATIFC')
    assert t and t[0]['group'] == 'check'
    assert not [c for c in t[0]['cli'] if c.startswith(('no ', 'nat '))]


# ---------------------------------------------------------------- 7. VPN pool mapping

VPN_A = ('ip local pool ALPHA-VPN 192.0.2.200-192.0.2.220 mask 255.255.255.224\n'
         'object network ALPHA-VPN-NET\n subnet 192.0.2.192 255.255.255.224\n' + APP +
         rule(5, 'Vpn-To-App', 'permit tcp ifc outside object ALPHA-VPN-NET ifc inside object APP-HOST eq 443'))
VPN_B = 'ip local pool BRAVO-VPN 198.51.100.200-198.51.100.220 mask 255.255.255.224\n'


def test_7a_new_rule_uses_bs_pool_object():
    b = VPN_B + 'object network BRAVO-VPN-NET\n subnet 198.51.100.192 255.255.255.224\n'
    res = go(VPN_A, b, scope=['192.0.2.0/26'])
    f = named(res, 'Vpn-To-App')[0]
    cli = ' '.join(f['fix']['cli'])
    assert 'object BRAVO-VPN-NET' in cli, cli
    assert 'ALPHA-VPN' not in cli and '192.0.2.192' not in cli
    assert not [o for o in f['fix']['objects'] if 'ALPHA' in o['name'] or '192.0.2.192' in o['value']]


def test_7b_without_a_b_object_the_new_one_has_bs_pool_value():
    res = go(VPN_A, VPN_B, scope=['192.0.2.0/26'])
    f = named(res, 'Vpn-To-App')[0]
    assert 'ALPHA-VPN' not in ' '.join(f['fix']['cli'])
    assert [o for o in f['fix']['objects'] if '198.51.100.192' in o['value']], f['fix']['objects']


def test_7c_b_rule_for_its_own_pool_covers():
    b = VPN_B + 'object network BRAVO-VPN-NET\n subnet 198.51.100.192 255.255.255.224\n' + \
        rule(5, 'Vpn-To-App', 'permit tcp ifc outside object BRAVO-VPN-NET ifc inside host 192.0.2.10 eq 443')
    res = go(VPN_A, b, scope=['192.0.2.0/26'])
    assert [r for r in res['rules'] if r['rule'] == 'Vpn-To-App'][0]['status'] == 'covered'


# ---------------------------------------------------------------- 8. sibling NATs

def test_8a_unrelated_sibling_is_not_reported():
    b = ('interface e5\n nameif oob\n security-level 50\n ip address 192.0.2.97 255.255.255.224\n'
         'object network OOB-NET\n subnet 192.0.2.96 255.255.255.224\n'
         'nat (oob,outside) source static OOB-NET OOB-NET\n')
    res = go('', b, scope=['192.0.2.64/27'])
    assert not take(res, 'NATSIB')


def test_8b_site_twin_with_its_own_rule_on_b_is_not_reported():
    a = ('interface e4\n nameif users\n security-level 80\n ip address 192.0.2.129 255.255.255.224\n'
         'ip local pool ALPHA-VPN 192.0.2.200-192.0.2.220 mask 255.255.255.224\n'
         'object network A-USERS\n subnet 192.0.2.128 255.255.255.224\nobject network A-POOL\n'
         ' range 192.0.2.200 192.0.2.220\n'
         'nat (users,outside) source static A-USERS A-USERS destination static A-POOL A-POOL\n')
    b = ('interface e4\n nameif users\n security-level 80\n ip address 198.51.100.129 255.255.255.224\n'
         'interface e5\n nameif dci\n security-level 50\n ip address 203.0.113.65 255.255.255.224\n'
         'route dci 192.0.2.128 255.255.255.224 203.0.113.66 1\n'
         'ip local pool BRAVO-VPN 198.51.100.200-198.51.100.220 mask 255.255.255.224\n'
         'object network B-USERS\n subnet 198.51.100.128 255.255.255.224\nobject network B-POOL\n'
         ' range 198.51.100.200 198.51.100.220\n'
         'nat (users,outside) source static B-USERS B-USERS destination static B-POOL B-POOL\n')
    res = go(a, b, scope=['192.0.2.128/27'])
    assert not take(res, 'NATSIB'), [t['title'] for t in take(res, 'NATSIB')]


# ---------------------------------------------------------------- 9. FQDN rules

FQ = ('object network UPDATES\n fqdn updates.example.com\nobject network IN-NET\n subnet 192.0.2.0 255.255.255.192\n' +
      rule(20, 'Allow-Updates', 'permit tcp ifc inside object IN-NET ifc outside object UPDATES eq 443') +
      rule(21, 'Block_Web_Out', 'permit tcp ifc inside object IN-NET ifc outside any eq 443', l7=True))


def test_9a_fqdn_rule_above_an_a_block_is_a_real_gap():
    res = go(FQ, scope=['192.0.2.0/26'])
    row = [r for r in res['rules'] if r['rule'] == 'Allow-Updates'][0]
    assert row['status'] == 'missing', row
    assert 'Block_Web_Out' in row['detail']
    f = named(res, 'Allow-Updates')[0]
    assert 'UPDATES' in ' '.join(f['fix']['cli'])
    b = ('object network UPDATES\n fqdn updates.example.com\nobject network IN-NET\n subnet 192.0.2.0 255.255.255.192\n' +
         rule(20, 'Updates', 'permit tcp ifc inside object IN-NET ifc outside object UPDATES eq 443'))
    res = go(FQ, b, scope=['192.0.2.0/26'])
    assert [r for r in res['rules'] if r['rule'] == 'Allow-Updates'][0]['status'] == 'covered'


# ---------------------------------------------------------------- 10. one finding for a PAT on the wrong interface

def test_10_pat_on_wrong_interface_is_one_edit_that_keeps_bs_address():
    a = ('object network USERS\n subnet 192.0.2.0 255.255.255.192\n'
         'nat (inside,outside) after-auto source dynamic USERS interface\n')
    b = ('object network USERS-B\n subnet 192.0.2.0 255.255.255.192\nobject network PAT-B\n host 203.0.113.5\n'
         'nat (dmz,outside) after-auto source dynamic USERS-B PAT-B\n')
    res = go(a, b, scope=['192.0.2.0/26'])
    p = cat(res, 'pat')
    assert len(p) == 1
    fmc, cli = ' '.join(p[0]['fix']['fmc']), p[0]['fix']['cli']
    assert 'Add Rule' not in fmc and 'edit' in fmc
    assert 'nat (inside,outside) after-auto source dynamic USERS-B PAT-B' in cli
    assert not [c for c in cli if c.endswith(' interface')]
    assert not [t for t in res['takeover'] if 'USERS-B' in t['title']]


# ---------------------------------------------------------------- 11. add the zone, keep the live one

def test_11_rule_on_b_with_another_live_zone_gets_add_zone_in_rule_findings():
    a = (APP + 'object network CLIENTS\n subnet 192.0.2.128 255.255.255.224\n'
         'interface e4\n nameif users\n security-level 80\n ip address 192.0.2.129 255.255.255.224\n' +
         rule(30, 'Clients-To-App', 'permit tcp ifc users object CLIENTS ifc inside object APP-HOST eq 443') +
         rule(31, 'Clients-To-App', 'permit tcp ifc users object CLIENTS ifc inside object WEB-HOST eq 443'))
    b = (APP + 'object network CLIENTS\n subnet 192.0.2.128 255.255.255.224\n'
         'interface e4\n nameif users\n shutdown\n security-level 80\n ip address 192.0.2.129 255.255.255.224\n'
         'interface e5\n nameif dci\n security-level 50\n ip address 203.0.113.65 255.255.255.224\n'
         'route inside 192.0.2.128 255.255.255.128 192.0.2.2 1\n' +
         rule(30, 'Clients-To-App', 'permit tcp ifc dci object CLIENTS ifc inside object APP-HOST eq 443'))
    res = go(a, b, scope=['192.0.2.0/26'])
    f = named(res, 'Clients-To-App')
    assert len(f) == 1
    fmc = ' '.join(f[0]['fix']['fmc'])
    assert 'add users and keep dci' in fmc, fmc
    assert 'Add Rule' not in fmc
    assert not [c for c in f[0]['fix']['cli'] if c.startswith('no ')]


# ---------------------------------------------------------------- 12. small corrections

SRV = ('object network SRV-WEB\n host 192.0.2.70\nobject network SRV-WEB-PUB\n host 198.51.100.10\n'
       'nat (dmz,outside) source static SRV-WEB SRV-WEB-PUB dns\n' +
       rule(10, 'Web-In', 'permit tcp ifc outside any ifc dmz object SRV-WEB eq 443'))


def test_12a_new_public_object_reuses_as_name_and_keeps_dns():
    res = go(SRV, scope=['192.0.2.64/27'], public_b=['203.0.113.32/28'])
    f = cat(res, 'inbound')[0]
    assert [o for o in f['fix']['objects'] if o['name'] == 'SRV-WEB-PUB' and '203.0.113.' in o['value']]
    line = [c for c in f['fix']['cli'] if c.startswith('nat (dmz,outside)')][0]
    assert line.split()[-1] == 'dns' or line.split()[-2] == 'dns', line


def test_12b_standby_fix_uses_as_standby_address():
    a = A.replace('ip address 192.0.2.65 255.255.255.224', 'ip address 192.0.2.65 255.255.255.224 standby 192.0.2.66')
    res = go(a_base=a, b_base=B.replace(' nameif dmz\n', ' shutdown\n nameif dmz\n'))
    t = [x for x in res['takeover'] if x['title'].startswith('No standby IP on dmz')][0]
    assert ' ip address 192.0.2.65 255.255.255.224 standby 192.0.2.66' in t['cli']
    assert not [c for c in t['cli'] if '<' in c]


def test_12c_published_no_nat_says_plainly_what_to_confirm():
    a = ('object network SRV-OLD\n host 192.0.2.75\nobject network SRV-OLD-PUB\n host 198.51.100.20\n'
         'nat (dmz,outside) source static SRV-OLD SRV-OLD-PUB\n')
    res = go(a)
    i = [x for x in items(res) if x['subject'] == '198.51.100.20/32']
    assert len(i) == 1
    assert i[0]['fmc'][0].startswith('Confirm: must SRV-OLD (192.0.2.75) be reachable from the internet at '
                                     '198.51.100.20 after failover?')
    assert not [c for c in i[0]['cli'] + i[0]['verify'] if '<' in c]


# ---------------------------------------------------------------- 13. end to end

def test_e2e_final_allow_from_inside_covers_narrower_rules():
    a = APP + (rule(3, 'App-Out', 'permit tcp ifc inside object APP-HOST ifc outside any eq 443') +
               rule(4, 'Dns-Out', 'permit udp ifc inside object APP-HOST ifc outside any eq 53') +
               rule(5, 'Ping-Out', 'permit icmp ifc inside any ifc outside any') + FINAL)
    res = go(a, FINAL)
    assert not cat(res, 'rules'), [f['short'] for f in cat(res, 'rules')]


def test_e2e_block_rule_is_never_proposed_as_allow():
    a = (APP + rule(6, 'Block_App_Games', 'permit tcp ifc inside object APP-HOST ifc outside any eq 443', l7=True) +
         rule(7, 'Block_X', 'permit udp ifc inside object APP-HOST ifc outside any eq 3074'))
    res = go(a)
    text = all_text(res)
    assert not re.search(r'Name "Block_[^"]*", Action Allow', text)
    assert not [c for c in all_cli(res) if 'permit' in c and ('3074' in c or 'Block' in c)]
    assert 'Confirm the action in FMC' in text


def test_e2e_l7_url_exceptions_rule_gives_no_cli():
    res = go(TUN + rule(9, 'URL-Exceptions', 'permit tcp ifc inside any ifc outside any eq 443', l7=True))
    f = named(res, 'URL-Exceptions')
    assert f and all(x['fix']['cli'] == [] for x in f)
    assert not [i for i in items(res) if 'URL-Exceptions' in i['reason'] and i['cli'] and
                not all(c.startswith('show ') for c in i['cli'])]


def test_e2e_two_sites_backhaul_identity_one_during_fix_one_failback_and_overrides():
    res = site()
    during = [i for i in items(res) if i['group'] == 'during' and IDENT in ' '.join(i['cli'])]
    assert len(during) == 1
    back = [i for i in res['failback'] if i['ref'] == during[0]['ref'] + '-back']
    assert len(back) == 1 and [c for c in back[0]['cli'] if BACK.match(c)]
    assert 'SRV-APP' in during[0]['what'] and 'SRV-DB' in during[0]['what']
    assert not [c for c in all_cli(res) if ANY_ANY.search(c)]


HEALTHY = A + TUN + APP + (
    'object network SRV-WEB-PUB\n host 198.51.100.10\nnat (dmz,outside) source static WEB-HOST SRV-WEB-PUB\n'
    'object network SOME-USERS\n range 192.0.2.10 192.0.2.20\n'
    'nat (inside,outside) after-auto source dynamic SOME-USERS interface\n'
    'object network DMZ-NET\n subnet 192.0.2.64 255.255.255.224\n'
    'nat (inside,outside) after-auto source dynamic DMZ-NET interface\n' +
    rule(1, 'Block-Bad', 'deny tcp ifc outside host 198.51.100.50 any eq 22') +
    rule(2, 'Web-In', 'permit tcp ifc outside any ifc dmz object WEB-HOST eq 443') +
    rule(3, 'Any-To-Web', 'permit tcp any ifc dmz object WEB-HOST eq 22') +
    rule(4, 'App-Out', 'permit tcp ifc inside object APP-HOST ifc outside any eq 443') +
    rule(5, 'Odd-Src', 'permit tcp ifc dmz object APP-HOST ifc outside any eq 25'))


def test_e2e_healthy_pair_against_itself_gives_no_fixes():
    res = run([(HEALTHY, 'fw-alpha.txt')], (HEALTHY.replace('fw-alpha', 'fw-bravo'), 'fw-bravo.txt'))[0]
    assert not [f['short'] for f in res['findings'] if f['category'] in ('rules', 'inbound', 'pat')], \
        [f['short'] for f in res['findings']]
    assert not [t['title'] for t in res['takeover'] if t['id'].split('-')[1] in ('NATIFC', 'NATORDER', 'NATSIB')]
    assert all(r['status'] == 'covered' for r in res['rules'])
