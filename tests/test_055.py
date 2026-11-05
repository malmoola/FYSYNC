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
