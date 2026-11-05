"""0.5.4 takeover compare, second round on a real pair: VPN NAT copied as A's rule, PAT on any, NAT options,
sibling exemptions, L7 blocks on site interfaces, true position text. Made-up names, documentation and private
addresses only."""
from test_054c import A, B, SHUT_DMZ, cfg, gl, go, nref, rows, rref, rule

POOLS_A = 'ip local pool A-POOL 192.168.50.10-192.168.50.200 mask 255.255.255.0\n' \
          'object network A-VPN\n subnet 192.168.50.0 255.255.255.0\n'
POOLS_B = 'ip local pool OLD-POOL 192.168.70.10-192.168.70.200 mask 255.255.255.0\n' \
          'ip local pool B-POOL 192.168.177.10-192.168.177.200 mask 255.255.255.0\n' \
          'object network OLD-VPN\n subnet 192.168.70.0 255.255.255.0\n' \
          'object network B-VPN\n subnet 192.168.177.0 255.255.255.0\n' \
          'tunnel-group RA general-attributes\n address-pool B-POOL\n'
WEB = 'object network WEB\n host 10.2.0.10\nobject network WEB-PUB\n host 198.51.100.10\n'


def vpn(res):
    return rows(res, 'Missing VPN NAT')


# 1 a VPN NAT with destination translation is A's rule with B's active pool
def test_1_vpn_nat_with_destination_is_copied_as_a_rule():
    a = POOLS_A + WEB + 'nat (outside,dmz) source static A-VPN A-VPN destination static WEB-PUB WEB no-proxy-arp\n'
    res = go(a, WEB, a_base=A, b_base=B + POOLS_B)
    r = vpn(res)
    assert len(r) == 1 and r[0]['when'] == 'Now disabled'
    assert 'nat (outside,dmz) source static B-VPN B-VPN destination static WEB-PUB WEB no-proxy-arp inactive' in r[0]['config']
    assert 'A-VPN' not in cfg(r[0]) and 'after-auto' not in cfg(r[0]) and 'route-lookup' not in cfg(r[0])
    assert 'OLD-VPN' not in cfg(r[0]) and 'Before Auto NAT' in cfg(r[0])


# 2 a PAT with source interface any stays any, with B's pool as one object; another path than B's main one: confirm
OUT2_A = 'interface e7\n nameif outside2\n security-level 0\n ip address 198.51.100.129 255.255.255.192\n' \
         'route outside2 0.0.0.0 0.0.0.0 198.51.100.190 250\n'
OUT2_B = 'interface e7\n nameif outside2\n security-level 0\n ip address 203.0.113.129 255.255.255.192\n' \
         'route outside2 0.0.0.0 0.0.0.0 203.0.113.190 250\n'


def test_2a_pat_on_any_stays_any_with_the_pool_as_one_object():
    a = POOLS_A + 'object network A-VPN\n nat (any,outside) dynamic interface\n'
    r = vpn(go(a, '', b_base=B + POOLS_B))
    assert len(r) == 1 and r[0]['when'] == 'Now disabled'
    assert 'nat (any,outside) after-auto source dynamic B-VPN interface inactive' in r[0]['config']
    assert r[0]['address'] == '192.168.177.0/24'


def test_2b_pat_on_another_path_than_b_main_is_confirm_use():
    a = POOLS_A + 'object network A-VPN\n nat (any,outside2) dynamic interface\n'
    r = vpn(go(a, '', a_base=A + OUT2_A, b_base=B + OUT2_B + POOLS_B))
    assert len(r) == 1 and r[0]['when'] == 'Confirm use' and "main path is outside" in r[0]['required']
    assert 'nat (any,outside2) after-auto source dynamic B-VPN interface inactive' in r[0]['config']


# 3 A's NAT options are copied, nothing is added
def test_3a_dns_is_copied():
    a = WEB + 'nat (dmz,outside) source static WEB WEB-PUB dns\n' + \
        rule(9, 'Web-In', 'permit tcp ifc outside any ifc dmz object WEB eq 443')
    b = 'object network H1\n host 10.1.0.21\nobject network H1-PUB\n host 198.51.100.21\n' \
        'object network H2\n host 10.1.0.22\nobject network H2-PUB\n host 198.51.100.22\n' \
        'nat (inside,outside) source static H1 H1-PUB\nnat (inside,outside) source static H2 H2-PUB\n'
    r = rows(go(a, b), 'Missing static NAT')
    assert len(r) == 1
    nat = [c for c in r[0]['config'] if c.startswith('nat (')]
    assert nat and nat[0].endswith(' dns inactive') and 'Translate DNS replies' in cfg(r[0])
    assert 'no-proxy-arp' not in nat[0] and 'route-lookup' not in nat[0]


def test_3b_exemption_gets_no_options_a_does_not_have():
    a = 'nat (inside,outside) source static IN-NET IN-NET destination static REMOTE REMOTE\n'
    b = 'nat (inside,outside) after-auto source dynamic IN-NET interface\n'
    r = rows(go(a, b, a_base=A + 'route outside 10.200.0.0 255.255.0.0 198.51.100.62 1\n'), 'Missing NAT exemption')
    assert len(r) == 1
    assert 'route-lookup' not in cfg(r[0]) and 'no-proxy-arp' not in cfg(r[0])
    assert 'nat (inside,outside) source static IN-NET IN-NET destination static REMOTE REMOTE' in cfg(r[0])


# 4 a B static on any/any is not B's own choice when B exempts the same traffic toward its other shared interfaces
APP_A = 'interface e5\n nameif app\n security-level 50\n ip address 10.3.0.1 255.255.255.0\n' \
        'object network APP-NET\n subnet 10.3.0.0 255.255.255.0\n'
APP_B = 'interface e5\n nameif app\n security-level 50\n ip address 10.3.0.1 255.255.255.0\n shutdown\n' \
        'object network APP-NET\n subnet 10.3.0.0 255.255.255.0\n' \
        'object-group network INSIDE-ALL\n network-object 10.1.0.0 255.255.255.0\n' \
        'object network H33\n host 10.1.0.33\nobject network H33-PUB\n host 203.0.113.33\n' \
        'object network H33\n nat (any,any) static H33-PUB\n'
SIB = 'nat (inside,dmz) source static INSIDE-ALL INSIDE-ALL destination static DMZ-NET DMZ-NET\n'


def test_4a_missing_exemption_for_the_shared_interface_that_lacks_it():
    a = 'nat (inside,app) source static IN-NET IN-NET destination static APP-NET APP-NET\n'
    res = go(a, SIB, a_base=A + APP_A, b_base=SHUT_DMZ + APP_B)
    r = rows(res, 'Missing NAT exemption')
    assert len(r) == 1 and 'INSIDE-ALL' in cfg(r[0]) and 'nat (inside,app) source static INSIDE-ALL INSIDE-ALL' in cfg(r[0])


def test_4b_without_sibling_exemptions_it_stays_b_own_device():
    a = 'nat (inside,app) source static IN-NET IN-NET destination static APP-NET APP-NET\n'
    res = go(a, '', a_base=A + APP_A, b_base=SHUT_DMZ + APP_B)
    assert not rows(res, 'Missing NAT exemption') and 'own static NAT' in nref(res, 'APP-NET')['result']


# 5 an L7 block on a site interface is equal to B's block for the mapped interface, named the same way
SITE_A = 'interface e6\n nameif site1\n security-level 50\n ip address 10.4.0.1 255.255.255.0\n'
SITE_B = 'interface e6\n nameif site9\n security-level 50\n ip address 10.4.0.1 255.255.255.0\n'


def test_5_l7_block_on_a_site_interface_with_b_mapped_block():
    a = rule(1, 'Block_Site1_to_Tools', 'permit ip ifc site1 any ifc outside any', l7=True)
    b = rule(1, 'Block_SITE9_to_Tools', 'permit ip ifc site9 any ifc outside any', l7=True)
    res = go(a, b, a_base=A + SITE_A, b_base=B + SITE_B, interface_map={'site1': 'site9'})
    assert not [r for r in gl(res)['rows'] if r['object'] == 'Block_Site1_to_Tools']
    assert 'equal block' in rref(res, 'Block_Site1_to_Tools')['result']
    other = go(a, rule(1, 'Block_Other', 'permit ip ifc site9 any ifc outside any', l7=True), a_base=A + SITE_A,
               b_base=B + SITE_B, interface_map={'site1': 'site9'})
    assert [r for r in gl(other)['rows'] if r['object'] == 'Block_Site1_to_Tools' and r['when'] == 'Compare in FMC']


# 6 position text only claims a carried A allow when that allow is above the block and takes some of its traffic
def test_6_no_false_carrier_claim_and_block_above_the_first_allow():
    a = rule(1, 'Web-Out', 'permit tcp ifc inside host 10.1.0.25 ifc outside any eq 443') + \
        rule(2, 'No-Smtp', 'deny tcp ifc inside any ifc outside any eq 25') + \
        rule(3, 'Allow-All-In', 'permit ip ifc inside any ifc outside any')
    b = rule(1, 'Host-Any', 'permit ip ifc inside host 10.1.0.25 ifc outside any') + \
        rule(3, 'Allow-All-In', 'permit ip ifc inside any ifc outside any')
    r = rows(go(a, b), 'Missing block')
    assert len(r) == 1
    req = r[0]['required']
    assert 'carries' not in req and 'above rule "Host-Any"' in req and 'also above rule "Allow-All-In"' in req


def test_6b_true_carrier_is_named_with_its_a_line():
    a = rule(1, 'Mail-Out', 'permit tcp ifc inside host 10.1.0.25 ifc outside any eq 25') + \
        rule(2, 'No-Smtp', 'deny tcp ifc inside any ifc outside any eq 25')
    b = rule(1, 'Mail-Out', 'permit tcp ifc inside host 10.1.0.25 ifc outside any eq 25')
    req = rows(go(a, b), 'Missing block')[0]['required']
    assert 'below rule "Mail-Out"' in req and 'carries fw-alpha\'s allow "Mail-Out"' in req


# route rows carry routes only; the NAT a route depends on is judged by the NAT walk
def test_route_rows_have_no_nat_lines():
    res = go('route dmz 10.70.0.0 255.255.0.0 10.2.0.254 1\n', '')
    for r in rows(res):
        if r['kind'] == 'route':
            assert not [c for c in r['config'] if c.startswith('nat ')]


# a copied "destination static" keeps B's object of the same name (also for any), else B's object of the same value,
# else adds the object
ALL = 'object network obj_all\n subnet 0.0.0.0 0.0.0.0\n'
EXEMPT_ALL = 'nat (inside,outside) source static IN-NET IN-NET destination static obj_all obj_all\n'
PAT_IN_B = 'nat (inside,outside) after-auto source dynamic IN-NET interface\n'


def _exempt_cfg(b_extra):
    r = rows(go(ALL + EXEMPT_ALL, PAT_IN_B, b_base=B + b_extra), 'Missing NAT exemption')
    assert len(r) == 1
    return r[0]['config']


def test_destination_object_of_the_same_name_is_kept():
    c = _exempt_cfg(ALL)
    assert [x for x in c if 'destination static obj_all obj_all' in x]
    assert not [x for x in c if 'destination static any any' in x] and 'object network obj_all' not in c


def test_destination_object_reuses_b_object_of_the_same_value():
    c = _exempt_cfg('object network every-net\n subnet 0.0.0.0 0.0.0.0\n')
    assert [x for x in c if 'destination static every-net every-net' in x] and 'object network obj_all' not in c


def test_destination_object_is_added_when_b_has_none():
    c = _exempt_cfg('')
    assert [x for x in c if 'destination static obj_all obj_all' in x]
    assert 'object network obj_all' in c and ' subnet 0.0.0.0 0.0.0.0' in c
