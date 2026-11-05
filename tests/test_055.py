"""0.5.5: FMC adds -NNN to a copied rule's name, and a NAT exemption stays one row for one network on A.
Made-up names, documentation and private addresses only."""
from test_054c import go, rows, rule
from fwsync.compare import base_rule_name, same_rule_name


def test_base_name_strips_only_the_copy_suffix_and_spaces():
    assert base_rule_name('Allow_Web-207') == 'Allow_Web' and base_rule_name('Allow_Web -207') == 'Allow_Web'
    assert base_rule_name(' Allow_Web ') == 'Allow_Web' and base_rule_name('rule_#16-195') == 'rule_#16'
    assert same_rule_name('Allow_Web-207', 'Allow_Web') and not same_rule_name('Allow_Web', 'Allow_Db')


def test_l7_any_rule_copied_by_fmc_with_a_suffix_is_the_same_rule():
    line = 'permit tcp ifc dmz any any eq https'
    assert not [r for r in go(rule(1, 'Allow_Agent', line, l7=True), rule(1, 'Allow_Agent-207', line, l7=True))['gaplist']['rows']
                if r['when'] == 'Compare in FMC' and r['object'] == 'Allow_Agent']


def test_l7_any_rule_with_another_name_is_still_compared_in_fmc():
    line = 'permit tcp ifc dmz any any eq https'
    assert [r for r in go(rule(1, 'Allow_Agent', line, l7=True), rule(1, 'Other_Rule', line, l7=True))['gaplist']['rows']
            if r['when'] == 'Compare in FMC' and r['object'] == 'Allow_Agent']


def test_l7_block_copied_by_fmc_with_a_suffix_is_not_missing():
    line = 'permit ip ifc dmz any ifc outside any'
    res = go(rule(1, 'Block_Dmz_to_Vendor', line, l7=True), rule(1, 'Block_Dmz_to_Vendor-210', line, l7=True))
    assert not rows(res, 'Missing block') and not [
        r for r in res['gaplist']['rows'] if r['object'] == 'Block_Dmz_to_Vendor']


def test_l7_block_on_another_zone_with_a_suffix_is_still_flagged():
    a = rule(1, 'Block_Dmz_to_Vendor', 'permit ip ifc dmz any ifc outside any', l7=True)
    b = rule(1, 'Block_Dmz_to_Vendor-210', 'permit ip ifc inside any ifc outside any', l7=True)
    assert [r for r in go(a, b)['gaplist']['rows'] if r['object'] == 'Block_Dmz_to_Vendor']


GROUP_B = 'object network SRV\n host 10.2.0.10\nobject network SRV-PUB\n host 198.51.100.10\n' \
          'nat (inside,outside) source static SRV SRV-PUB dns\nnat (web2,outside) source static SRV SRV-PUB dns\n' \
          'nat (dmz,outside) source static SRV SRV-PUB dns\n'
WEB2 = 'interface e8\n nameif web2\n security-level 50\n ip address 10.9.0.1 255.255.255.0\n'


def test_nat_on_an_interface_group_is_judged_as_one_rule():
    from test_054c import A, B
    a = 'object network SRV\n host 10.2.0.10\nobject network SRV-PUB\n host 198.51.100.10\n' \
        'nat (dmz,outside) source static SRV SRV-PUB dns\n'
    res = go(a, GROUP_B, a_base=A, b_base=B + WEB2)
    n = next(x for x in res['nat'] if x['real_ref'] == 'SRV')
    assert n['status'] != 'wrong interface' and 'dmz' in n['detail'] and 'inside' in n['detail']
    assert not [t for t in res['takeover'] if t['id'].startswith('T-NATIFC') and 'SRV' in t['title']]
    assert not [r for r in res['gaplist']['rows'] if r['object'] == 'SRV']
    ref = next(x for x in res['gaplist']['nat_ref'] if 'SRV' in x['text'])
    assert ref['result'].startswith('OK') and 'one rule on dmz, inside, web2' in ref['b_match']


def test_nat_on_another_interface_only_is_still_wrong_interface():
    from test_054c import A, B
    a = 'object network SRV\n host 10.2.0.10\nobject network SRV-PUB\n host 198.51.100.10\n' \
        'nat (dmz,outside) source static SRV SRV-PUB\n'
    b = 'object network SRV\n host 10.2.0.10\nobject network SRV-PUB\n host 198.51.100.10\n' \
        'nat (inside,outside) source static SRV SRV-PUB\n'
    n = next(x for x in go(a, b, a_base=A, b_base=B)['nat'] if x['real_ref'] == 'SRV')
    assert n['status'] == 'wrong interface'
