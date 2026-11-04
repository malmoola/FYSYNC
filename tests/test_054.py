"""0.5.4 remediation accuracy: every fix is safe to follow, or says what to check and gives no command. Made-up names,
documentation addresses only. Site translation is tested by giving the site pairs directly (documentation ranges
count as public, so the tool would not pair them on its own)."""
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
SRV = ('object network SRV-WEB\n host 192.0.2.70\n'
       'object network SRV-WEB-PUB\n host 198.51.100.10\n'
       'nat (dmz,outside) source static SRV-WEB SRV-WEB-PUB\n'
       'access-list CSM_FW_ACL_ remark rule-id 10: L4 RULE: Web-In\n'
       'access-list CSM_FW_ACL_ advanced permit tcp ifc outside any ifc dmz object SRV-WEB eq 443 rule-id 10\n')
DCI = 'interface e4\n nameif dci\n security-level 50\n ip address 192.0.2.97 255.255.255.224\n'


def rule(n, name, line, l7=False):
    return ('access-list CSM_FW_ACL_ remark rule-id %d: %s: %s\n' % (n, 'L7 RULE' if l7 else 'L4 RULE', name) +
            'access-list CSM_FW_ACL_ advanced %s rule-id %d\n' % (line, n))


def go(a='', b='', a_base=A, b_base=B, **prof):
    return run([(a_base + a, 'fw-alpha.txt')], (b_base + b, 'fw-bravo.txt'), prof or None)[0]


def cat(res, c):
    return [f for f in res['findings'] if f['category'] == c]


def rb(res):
    return {g['key']: g['items'] for g in res['runbook']}


def items(res):
    return [(g['key'], i) for g in res['runbook'] for i in g['items']]


def pairs(monkeypatch, *p):
    monkeypatch.setattr(sitemap, 'net_pairs', lambda A, B, imap: list(p))


# ---------------------------------------------------------------- A. wrong fixes

def test_1_nat_uses_the_servers_interface_not_the_generic_inside():
    lab = 'interface e5\n nameif lab\n security-level 50\n ip address 192.0.2.129 255.255.255.224\n'
    res = go(lab + SRV, scope=['192.0.2.64/27'],
             interface_map={'outside': 'outside', 'inside': 'inside', 'lab': 'inside', 'dmz': 'dmz'})
    f = cat(res, 'inbound')[0]
    assert 'nat (dmz,outside) source static SRV-WEB' in ' '.join(f['fix']['cli'])
    assert not [c for c in f['fix']['cli'] if c.startswith('nat (inside,')]
    assert any('Source dmz, Destination outside' in x for x in f['fix']['fmc'])
    assert any('ifc dmz object SRV-WEB eq 443' in c for c in f['fix']['cli'])


def test_2_l7_any_to_any_rule_is_compared_in_fmc_never_copied():
    res = go(rule(7, 'Web-Apps', 'permit ip ifc inside any ifc outside any', l7=True))
    f = [x for x in cat(res, 'rules') if x['rule'] == 'Web-Apps'][0]
    assert f['fix']['cli'] == [] and f['fix']['objects'] == [] and not f.get('acp_rules')
    assert f['fix']['fmc'][0].startswith('Compare in FMC: URL, application or geo conditions are not visible')
    assert 'copying it without its conditions would allow all traffic' in f['why']
    assert f['level'] == 'check'
    plan = [i for g in res['plan']['groups'] for i in g['items']]
    assert not [i for i in plan if 'Web-Apps' in i['fmc']]


def test_3a_object_on_b_by_value_is_reused():
    a = ('object network APP-HOST\n host 192.0.2.10\n' +
         rule(3, 'App-Out', 'permit tcp ifc inside object APP-HOST ifc outside any eq 443'))
    res = go(a, 'object network B-APP\n host 192.0.2.10\n')
    f = [x for x in cat(res, 'rules') if x['rule'] == 'App-Out'][0]
    assert any('object B-APP' in c for c in f['fix']['cli']), f['fix']['cli']
    assert not [o for o in f['fix']['objects'] if o['name'] == 'APP-HOST']
    assert not any('APP-HOST' in c for c in f['fix']['cli'])


def test_3b_name_on_b_with_another_value_is_never_redefined():
    a = ('object network PARTNER\n host 198.51.100.50\n' +
         rule(3, 'To-Partner', 'permit tcp ifc inside any ifc outside object PARTNER eq 443'))
    res = go(a, 'object network PARTNER\n host 203.0.113.50\n')
    f = [x for x in cat(res, 'rules') if x['rule'] == 'To-Partner'][0]
    assert not [o for o in f['fix']['objects'] if o['name'] == 'PARTNER']
    assert 'object network PARTNER' not in f['fix']['cli']
    assert any('already exists on fw-bravo with another value' in x and 'not redefined' in x for x in f['fix']['fmc'])


def test_3c_translated_address_uses_b_object(monkeypatch):
    pairs(monkeypatch, ('192.0.2.0/26', '198.51.100.128/26'))
    b = B.replace('ip address 192.0.2.1 255.255.255.192', 'ip address 198.51.100.129 255.255.255.192')
    a = ('object network ALPHA-APP\n host 192.0.2.10\n' +
         rule(3, 'App-Out', 'permit tcp ifc inside object ALPHA-APP ifc outside any eq 443'))
    res = go(a, 'object network BRAVO-APP\n host 198.51.100.138\n', b_base=b)
    f = [x for x in cat(res, 'rules') if x['rule'] == 'App-Out'][0]
    assert any('object BRAVO-APP' in c for c in f['fix']['cli']), f['fix']['cli']
    assert not [o for o in f['fix']['objects'] if o['name'] == 'ALPHA-APP']


def test_4a_nat_on_wrong_interface_is_edited_not_added():
    b = ('object network SRV-WEB\n host 192.0.2.70\nobject network SRV-B-PUB\n host 203.0.113.10\n'
         'nat (inside,outside) source static SRV-WEB SRV-B-PUB\n' +
         rule(20, 'Web-In', 'permit tcp ifc outside any ifc dmz object SRV-WEB eq 443'))
    res = go(SRV, b, scope=['192.0.2.64/27'])
    f = cat(res, 'inbound')[0]
    assert f['nat_status'] == 'wrong interface'
    fmc = ' '.join(f['fix']['fmc'])
    assert 'it already exists on fw-bravo, do not add a new one' in fmc and 'Option: Source any' in fmc
    assert 'Add Rule: NAT Rule Manual' not in fmc
    assert 'no nat (inside,outside) source static SRV-WEB SRV-B-PUB' in f['fix']['cli']
    assert 'nat (dmz,outside) source static SRV-WEB SRV-B-PUB' in f['fix']['cli']


def test_4b_rule_on_other_zone_is_edited_not_added():
    a = 'object network APP\n host 192.0.2.70\n' + rule(3, 'App-Out', 'permit tcp ifc dmz object APP ifc outside any eq 443')
    b = 'object network APP\n host 192.0.2.70\n' + rule(30, 'App-Out', 'permit tcp ifc inside object APP ifc outside any eq 443')
    res = go(a, b)
    f = [x for x in cat(res, 'rules') if x['rule'] == 'App-Out'][0]
    fmc = ' '.join(f['fix']['fmc'])
    assert 'edit rule "App-Out"' in fmc and 'Source Zones: replace inside with dmz' in fmc
    assert 'Add Rule' not in fmc


def test_5_zone_that_serves_the_other_site_is_kept():
    b = B.replace(' nameif dmz\n', ' shutdown\n nameif dmz\n') + DCI + \
        'route dci 192.0.2.64 255.255.255.224 192.0.2.98 1\n'
    a = 'object network APP\n host 192.0.2.70\n' + rule(3, 'App-Out', 'permit tcp ifc dmz object APP ifc outside any eq 443')
    res = go(a, 'object network APP\n host 192.0.2.70\n' +
             rule(30, 'App-Out', 'permit tcp ifc dci object APP ifc outside any eq 443'), b_base=b)
    f = [x for x in cat(res, 'rules') if x['rule'] == 'App-Out'][0]
    assert 'Source Zones: add dmz and keep dci' in ' '.join(f['fix']['fmc'])
    keep = [i for i in rb(res)['before'] if i['subject'] == 'App-Out']
    assert keep and 'add zone dmz, keep dci' in keep[0]['reason']
    assert not [i for k, i in items(res) if 'can never match' in i['reason'] and i['subject'] == 'App-Out']


# ---------------------------------------------------------------- B. false positives

def test_6_inbound_rule_status_uses_the_real_source():
    a = SRV.replace('ifc outside any ifc dmz', 'ifc outside host 198.51.100.50 ifc dmz')
    b = ('object network SRV-WEB\n host 192.0.2.70\nobject network SRV-B-PUB\n host 203.0.113.10\n'
         'nat (dmz,outside) source static SRV-WEB SRV-B-PUB\n' +
         rule(20, 'Web-In', 'permit tcp ifc outside host 198.51.100.50 ifc dmz object SRV-WEB eq 443'))
    res = go(a, b, scope=['192.0.2.64/27'])
    assert res['inbound'][0]['rule_status'] == 'covered'
    assert not cat(res, 'inbound')


def test_7a_same_block_above_the_permit_on_both_is_same():
    lines = (rule(1, 'Block-SMTP', 'deny tcp ifc inside any ifc outside any eq 25') +
             rule(2, 'Lan-Out', 'permit ip ifc inside 192.0.2.0 255.255.255.192 ifc outside any'))
    res = go(lines, lines)
    r = [x for x in res['rules'] if x['rule'] == 'Lan-Out'][0]
    assert r['status'] == 'covered'
    assert not [f for f in cat(res, 'rules') if f['rule'] == 'Lan-Out']


def test_7b_tunnel_default_rules_are_skipped():
    lan = rule(2, 'Lan-Out', 'permit ip ifc inside 192.0.2.0 255.255.255.192 ifc outside any')
    tun = ('access-list CSM_FW_ACL_ remark rule-id 9998: PREFILTER POLICY: Default Tunnel and Priority Policy\n'
           'access-list CSM_FW_ACL_ remark rule-id 9998: RULE: DEFAULT TUNNEL ACTION RULE\n'
           'access-list CSM_FW_ACL_ advanced permit ipinip any any rule-id 9998\n'
           'access-list CSM_FW_ACL_ advanced permit 41 any any rule-id 9998\n'
           'access-list CSM_FW_ACL_ advanced permit gre any any rule-id 9998\n')
    res = go(lan, tun + lan)
    assert not [f for f in res['findings'] if 'TUNNEL' in f['what'].upper()]
    assert not [r for r in res['b_rules'] if 'TUNNEL' in (r['rule'] or '').upper()]


def test_7c_l7_any_to_any_on_b_is_not_coverage():
    lan = rule(2, 'Lan-Out', 'permit ip ifc inside 192.0.2.0 255.255.255.192 ifc outside any')
    res = go(lan, rule(40, 'Apps', 'permit ip ifc inside any ifc outside any', l7=True))
    r = [x for x in res['rules'] if x['rule'] == 'Lan-Out'][0]
    assert r['status'] == 'missing'


def test_8_pbr_to_the_isp_b_already_uses_needs_no_action():
    a = A.replace(' ip address 192.0.2.1 255.255.255.192\n', ' ip address 192.0.2.1 255.255.255.192\n'
                  ' policy-route route-map RM-OUT\n') + \
        'access-list PBR-LAN extended permit ip 192.0.2.0 255.255.255.192 any\n' \
        'route-map RM-OUT permit 10\n match ip address PBR-LAN\n set ip next-hop 198.51.100.2\n'
    res = go(a_base=a)
    pbr = [t for t in res['takeover'] if t['area'] == 'Policy routing']
    assert pbr and pbr[0]['group'] == 'later' and 'needs no change' in pbr[0]['title']
    assert pbr[0]['action'].startswith('No action')
    assert not [i for i in rb(res)['before'] if 'Source-based routing' in i['reason']]


def test_9_reusing_as_own_public_ip_in_a_shared_range_is_not_a_conflict():
    b = ('object network SRV-WEB\n host 192.0.2.70\nobject network SRV-WEB-PUB\n host 198.51.100.10\n'
         'nat (dmz,outside) source static SRV-WEB SRV-WEB-PUB\n'
         'object network SRV-WEB-2\n host 192.0.2.70\n nat (dmz,outside) static 198.51.100.10\n' +
         rule(20, 'Web-In', 'permit tcp ifc outside any ifc dmz object SRV-WEB eq 443'))
    res = go(SRV, b, scope=['192.0.2.64/27'], type='shared-edge')
    n = [x for x in res['nat'] if x['real'] == '192.0.2.70/32'][0]
    assert n['status'] == 'match', n
    assert not [d for d in res['decisions'] if d['kind'] == 'public IP conflict']


def test_10_site_twins_each_site_has_its_own(monkeypatch):
    pairs(monkeypatch, ('192.0.2.64/27', '203.0.113.64/27'))
    b = B.replace('ip address 192.0.2.65 255.255.255.224', 'ip address 203.0.113.65 255.255.255.224')
    twin = ('object network SRV-BRAVO\n host 203.0.113.70\nobject network PUB-BRAVO\n host 203.0.113.10\n'
            'nat (dmz,outside) source static SRV-BRAVO PUB-BRAVO\n' +
            rule(20, 'Web-In', 'permit tcp ifc outside any ifc dmz object SRV-BRAVO eq 443'))
    res = go(SRV, twin, b_base=b, scope=['192.0.2.64/27'])
    assert res['inbound'][0]['status'] == 'ready: each site has its own'
    assert not cat(res, 'inbound')
    assert not [d for d in res['decisions'] if d['kind'] == 'public IP conflict']
    assert not [f for f in res['findings'] for o in f['fix']['objects'] if o['name'] == 'SRV-WEB']


def test_11_rule_that_cannot_match_is_optional_cleanup_when_carried():
    b = ('object network APP\n host 192.0.2.70\n' +
         rule(30, 'Old-App', 'permit tcp ifc inside object APP ifc outside any eq 443') +
         rule(31, 'App-Out', 'permit tcp ifc dmz object APP ifc outside any eq 443'))
    res = go('', b)
    later = [i for i in rb(res)['later'] if i['subject'] == 'Old-App']
    assert later and later[0]['reason'].startswith('Optional cleanup')
    assert 'carries this traffic' in later[0]['why']


def test_11b_source_only_at_the_failed_site_is_optional_cleanup():
    a = A + 'route inside 192.0.2.160 255.255.255.224 192.0.2.2 1\n'
    b = 'object network ALPHA-LAB\n subnet 192.0.2.160 255.255.255.224\n' + \
        rule(30, 'Lab-Out', 'permit ip ifc inside object ALPHA-LAB ifc outside any')
    res = go('', b, a_base=a)
    row = [r for r in res['firewide'] if r['item'] == 'Lab-Out'][0]
    assert row['status'] == 'optional cleanup' and row.get('failed_site_only')


def test_12_no_duplicate_findings_and_no_empty_action():
    a = SRV + 'object network SRV-WEB-OBJ\n host 192.0.2.70\n nat (dmz,outside) static SRV-WEB-PUB\n'
    res = go(a, scope=['192.0.2.64/27'])
    whats = [f['what'] for f in res['findings']]
    assert len(whats) == len(set(whats))
    assert len(cat(res, 'inbound')) == 1
    for k, i in items(res):
        assert i['fmc'] or i['cli'], i


def test_13_group_that_names_as_own_address_is_not_different(monkeypatch):
    pairs(monkeypatch, ('192.0.2.0/26', '198.51.100.128/26'))
    b = B.replace('ip address 192.0.2.1 255.255.255.192', 'ip address 198.51.100.129 255.255.255.192')
    grp = 'object-group network GRP-APP\n network-object host 192.0.2.10\n network-object host 192.0.2.11\n'
    a = grp + rule(3, 'App-Out', 'permit tcp ifc inside object-group GRP-APP ifc outside any eq 443')
    res = go(a, grp, b_base=b)
    o = [x for x in res['objects'] if x['name'] == 'GRP-APP'][0]
    assert o['status'] == 'same', o
    assert not cat(res, 'objects')
    t = [x for x in res['objects_all'] if x['name'] == 'GRP-APP'][0]
    assert t['status'] == 'same'


# ---------------------------------------------------------------- C. missed gaps

APPS = 'interface e5\n nameif apps\n security-level 50\n ip address 192.0.2.97 255.255.255.224\n'


def test_14_broader_nat_that_overrides_a_published_server():
    b = APPS + ('object network ALL-SRV\n subnet 192.0.2.64 255.255.255.192\n'
                'nat (any,outside) source static ALL-SRV ALL-SRV\n'
                'object network SRV-WEB\n host 192.0.2.70\n nat (dmz,outside) static 203.0.113.10\n' +
                rule(20, 'Web-In', 'permit tcp ifc outside any ifc dmz object SRV-WEB eq 443'))
    res = go(SRV, b, scope=['192.0.2.64/27'])
    t = [x for x in res['takeover'] if x['title'].startswith('NAT line') and 'overrides' in x['title']]
    assert t and t[0]['group'] == 'during'
    assert 'Source apps' in t[0]['fmc'][0] and 'Manual NAT Rules > Before Auto NAT, above line' in t[0]['fmc'][0]
    assert t[0]['undo']['cli'] == ['nat (any,outside) source static ALL-SRV ALL-SRV']


def test_15_nat_whose_real_addresses_are_not_behind_its_interface():
    b = 'object network DMZ-HOSTS\n subnet 192.0.2.64 255.255.255.224\n nat (inside,outside) dynamic interface\n'
    res = go('', b)
    t = [x for x in res['takeover'] if x['area'] == 'NAT' and 'its addresses are behind dmz' in x['title']]
    assert t and t[0]['group'] == 'check'
    assert t[0]['cli'] == ['object network DMZ-HOSTS', ' nat (dmz,outside) dynamic interface']


def test_16_pat_on_each_isp():
    two = 'interface e6\n nameif outside2\n security-level 0\n ip address %s 255.255.255.192\n'
    a = two % '198.51.100.65' + 'route outside2 0.0.0.0 0.0.0.0 198.51.100.66 5\n' + \
        'object network LAN\n subnet 192.0.2.0 255.255.255.192\n' \
        'nat (inside,outside) after-auto source dynamic LAN interface\n' \
        'nat (inside,outside2) after-auto source dynamic LAN interface\n'
    b = two % '203.0.113.65' + 'route outside2 0.0.0.0 0.0.0.0 203.0.113.66 5\n' + \
        'object network LAN\n subnet 192.0.2.0 255.255.255.192\nobject network B-PAT2\n host 203.0.113.70\n' \
        'object network DMZ\n subnet 192.0.2.64 255.255.255.224\n' \
        'nat (inside,outside) after-auto source dynamic LAN interface\n' \
        'nat (dmz,outside2) after-auto source dynamic DMZ B-PAT2\n'
    res = go(a, b, scope=['192.0.2.0/26'], outside_a=['outside', 'outside2'], outside_b=['outside', 'outside2'])
    t = [x for x in res['takeover'] if 'outbound PAT on outside only, not on outside2' in x['title']]
    assert t and t[0]['cli'] == ['nat (inside,outside2) after-auto source dynamic LAN B-PAT2']


POOL = 'ip local pool VPN-POOL 192.0.2.200-192.0.2.210 mask 255.255.255.240\n' \
       'object network VPN-NET\n range 192.0.2.200 192.0.2.210\n'


def test_17a_nat_a_has_for_a_shared_network():
    a = POOL + 'object network DMZ-NET\n subnet 192.0.2.64 255.255.255.224\n' \
               'nat (dmz,outside) source static DMZ-NET DMZ-NET destination static VPN-NET VPN-NET\n'
    res = go(a, POOL + 'object network DMZ-NET\n subnet 192.0.2.64 255.255.255.224\n', scope=['192.0.2.64/27'])
    t = [x for x in res['takeover'] if x['title'] == '192.0.2.64/27: fw-bravo has no VPN pool to the network; fw-alpha has one']
    assert t, [x['title'] for x in res['takeover']]
    assert 'nat (dmz,outside) source static DMZ-NET DMZ-NET destination static VPN-NET VPN-NET' in t[0]['cli'][-1]


def test_17b_nat_a_sibling_has_is_a_check_without_a_command():
    b = POOL + 'object network IN-NET\n subnet 192.0.2.0 255.255.255.192\n' \
               'nat (inside,outside) source static IN-NET IN-NET destination static VPN-NET VPN-NET\n'
    res = go('', b, scope=['192.0.2.64/27'])
    t = [x for x in res['takeover'] if 'no VPN pool to the network on fw-bravo; sibling 192.0.2.0/26 has one' in x['title']]
    assert t and t[0]['group'] == 'check'
    assert not [c for c in t[0]['cli'] if c.startswith('nat ')]


def test_18_fqdn_rules_matched_by_object_name_and_port():
    fq = 'object network UPD\n fqdn updates.example.com\nobject network LAN\n subnet 192.0.2.0 255.255.255.192\n'
    allow = rule(4, 'Allow-Updates', 'permit tcp ifc inside object LAN ifc outside object UPD eq 443')
    block = rule(5, 'Block-Web', 'deny tcp ifc inside object LAN ifc outside any eq 443')
    same = go(fq + allow + block, fq + allow + block)
    assert not [f for f in cat(same, 'rules') if f['rule'] == 'Allow-Updates']
    gap = go(fq + allow + block, fq + block)
    f = [x for x in cat(gap, 'rules') if x['rule'] == 'Allow-Updates']
    assert f and 'has no rule for UPD' in f[0]['what']
    quiet = go(fq + allow, fq)
    assert not [x for x in cat(quiet, 'rules') if x['rule'] == 'Allow-Updates']


def test_19_copying_a_block_lists_the_allows_above_it_first():
    a = (rule(1, 'Mail-Relay', 'permit tcp ifc inside host 192.0.2.10 ifc outside any eq 25') +
         rule(2, 'Block-SMTP', 'deny tcp ifc inside any ifc outside any eq 25'))
    res = go(a)
    row = [r for r in res['firewide'] if r['item'] == 'Block-SMTP'][0]
    assert [d['rule'] for d in row['deps']] == ['Mail-Relay']
    it = [i for i in rb(res)['later'] if i['subject'] == 'Block-SMTP'][0]
    assert it['fmc'][0].startswith('First add the fw-bravo allows') and 'Mail-Relay' in it['fmc'][0]
    assert 'Warning: copying the block alone would cut off hosts' in it['what']
    assert 'untick Enabled' in it['fmc'][1]


def test_20_block_in_another_place_among_the_allows():
    deny = rule(1, 'Block-Telnet', 'deny tcp ifc inside any ifc outside any eq 23')
    allow = rule(2, 'Lan-Out', 'permit ip ifc inside 192.0.2.0 255.255.255.192 ifc outside any')
    res = go(deny + allow, allow.replace('rule-id 2', 'rule-id 12') + deny.replace('rule-id 1', 'rule-id 11'))
    row = [r for r in res['firewide'] if r['check'] == 'Rule position differs']
    assert row and row[0]['item'] == 'Block-Telnet' and 'sits below allow rule "Lan-Out"' in row[0]['detail']
    rev = go(allow + deny, deny + allow)
    f = [x for x in cat(rev, 'rules') if x['rule'] == 'Lan-Out'][0]
    assert 'On fw-alpha, the same block "Block-Telnet" sits below this rule' in f['what']


def test_21_vpn_interfaces_are_mapped_and_headends_described():
    b = B.replace('nameif outside', 'nameif internet').replace('route outside', 'route internet')
    imap = {'outside': 'internet', 'inside': 'inside', 'dmz': 'dmz'}
    same = go('webvpn\n enable outside\n', 'webvpn\n enable internet\n', b_base=b, interface_map=imap,
              outside_a=['outside'], outside_b=['internet'])
    assert not [t for t in same['takeover'] if 'enabled on different interfaces' in t['title']]
    miss = go('webvpn\n enable outside\n', '', b_base=b, interface_map=imap, outside_a=['outside'],
              outside_b=['internet'])
    t = [t for t in miss['takeover'] if 'enabled on different interfaces' in t['title']][0]
    assert 'fw-alpha headend: outside (198.51.100.1)' in t['detail'] and 'Missing on fw-bravo: internet' in t['detail']


def test_22_fmc_reach_and_server_start_are_listed_with_a_go_no_go():
    res = go()
    un = [i['reason'] for i in rb(res)['unprovable']]
    assert any(x.startswith("Go/no-go: FMC can reach and deploy to fw-bravo with fw-alpha's site down") for x in un)
    assert 'How the servers on shared networks start at fw-bravo' in un
    assert 'Go/no-go:' in res['verdict']['text']


def test_23_advertised_route_with_a_next_hop_on_no_b_subnet():
    b = 'route outside 203.0.113.64 255.255.255.224 192.0.2.250 1\n' \
        'object network LAN\n subnet 192.0.2.0 255.255.255.192\nobject network B-PAT\n host 203.0.113.70\n' \
        'nat (inside,outside) after-auto source dynamic LAN B-PAT\n'
    res = go('', b)
    t = [x for x in res['takeover'] if x['title'].startswith('Next hop 192.0.2.250')]
    assert t and 'does not advertise the public range' in t[0]['detail']
    assert 'LAN -> B-PAT' in t[0]['detail']


# ---------------------------------------------------------------- D. timing and safety

def test_24_route_that_moves_live_traffic_is_during_failover():
    a = A + 'route inside 192.0.2.128 255.255.255.224 192.0.2.2 1\n'
    b = B + DCI + 'route dci 192.0.2.128 255.255.255.128 192.0.2.98 1\n'
    res = go(a_base=a, b_base=b, scope=['192.0.2.128/27'])
    f = cat(res, 'routing')[0]
    assert f['group'] == 'during' and f['fix']['fmc'][0].startswith('During failover, not before')
    assert [i['subject'] for i in rb(res)['during']] == ['192.0.2.128/27']
    plain = go(a_base=a, scope=['192.0.2.128/27'])
    assert cat(plain, 'routing')[0]['group'] == 'before'


def test_25_nat_that_changes_live_traffic_is_created_disabled():
    a = ('object network SRV-APP\n host 192.0.2.10\nobject network SRV-APP-PUB\n host 198.51.100.11\n'
         'nat (inside,outside) source static SRV-APP SRV-APP-PUB\n' +
         rule(11, 'App-In', 'permit tcp ifc outside any ifc inside object SRV-APP eq 443'))
    res = go(a, scope=['192.0.2.0/26'], public_pool_b=['203.0.113.20-203.0.113.21'])
    f = cat(res, 'inbound')[0]
    nat = [c for c in f['fix']['cli'] if c.startswith('nat ')]
    assert nat == ['nat (inside,outside) source static SRV-APP SRV-APP-PUB_fw-bravo inactive'] or \
        (len(nat) == 1 and nat[0].endswith(' inactive')), nat
    assert any('untick Enable: create it disabled' in x for x in f['fix']['fmc'])
    on = [i for i in rb(res)['during'] if i['reason'].startswith('Enable the NAT rule for')]
    assert on and not on[0]['cli'][0].endswith('inactive')


def test_26_route_lists_the_nat_exemption_it_depends_on():
    a = A + 'route inside 192.0.2.128 255.255.255.224 192.0.2.2 1\n' + \
        'object network LAN\n subnet 192.0.2.0 255.255.255.192\nobject network REMOTE\n subnet 192.0.2.128 255.255.255.224\n' \
        'nat (inside,outside) source static LAN LAN destination static REMOTE REMOTE\n'
    res = go(a_base=a, scope=['192.0.2.128/27'])
    f = cat(res, 'routing')[0]
    assert any('depends on the NAT exemption fw-alpha has' in x for x in f['fix']['fmc'])
    assert 'nat (inside,outside) source static LAN LAN destination static REMOTE REMOTE' in f['fix']['cli']


def test_27_failback_reverses_every_during_failover_step():
    a = A + 'route inside 192.0.2.128 255.255.255.224 192.0.2.2 1\n'
    b = B.replace(' nameif dmz\n', ' shutdown\n nameif dmz\n') + DCI + \
        'route dci 192.0.2.128 255.255.255.128 192.0.2.98 1\n'
    res = go(a_base=a, b_base=b)
    during = [i['subject'] for i in rb(res)['during']]
    assert len(during) >= 2
    assert [i['subject'] for i in res['failback']] == list(reversed(during))
    back = {i['subject']: i for i in res['failback']}
    assert back['dmz']['cli'] == ['interface e3', ' shutdown']
    assert back['192.0.2.128/27']['cli'] == ['no route inside 192.0.2.128 255.255.255.224 <next hop on inside> 1']


def test_28_test_host_is_one_the_claimed_nat_matches():
    a = ('object network LAN\n subnet 192.0.2.0 255.255.255.192\n'
         'object network PRINTER\n host 192.0.2.1\nobject network PRINTER-PUB\n host 198.51.100.20\n'
         'nat (inside,outside) source static PRINTER PRINTER-PUB\n'
         'nat (inside,outside) after-auto source dynamic LAN interface\n')
    res = go(a, scope=['192.0.2.0/26'])
    f = cat(res, 'pat')[0]
    assert f['verify'][0] == 'packet-tracer input inside tcp 192.0.2.2 40000 8.8.8.8 443', f['verify']
    assert any(x.startswith('Expected: 192.0.2.2 is translated to the outside interface address') for x in f['verify'])
    shut = go(a, b_base=B.replace(' nameif inside\n', ' shutdown\n nameif inside\n'), scope=['192.0.2.0/26'])
    g = cat(shut, 'pat')[0]
    assert any(x.startswith('Not testable yet: inside is shut down') for x in g['verify'])
