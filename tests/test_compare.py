from fwsync.adapters import load
from fwsync.compare import compare
from fwsync.profile import Profile
from samples import A, B, PROFILE


def run(**kw):
    p = Profile(**dict(PROFILE, **kw))
    return compare(load(A, 'a'), load(B, 'b'), p)


def by(rows, key, val):
    return [r for r in rows if r[key] == val][0]


def test_rule_statuses():
    res = run()
    assert by(res['rules'], 'rule', 'Lan-Out')['status'] == 'shadowed'   # B denies tcp 8000-8010 first
    assert by(res['rules'], 'rule', 'Web-In')['status'] == 'partial'      # only WEB1:80 on B
    assert by(res['rules'], 'rule', 'Mixed')['status'] in ('shadowed', 'partial')
    assert by(res['rules'], 'rule', 'Web2-In')['status'] == 'missing'


def test_nat_statuses():
    res = run()
    assert by(res['nat'], 'real_ref', 'WEB1')['status'] == 'match'
    w2 = by(res['nat'], 'real_ref', 'WEB2')
    assert w2['status'] == 'inactive on B'
    pat = {(p['side'], p['subnet']): p['status'] for p in res['pat']}
    assert pat[('A', '10.20.0.0/24')] == 'covered' and pat[('B', '10.20.0.0/24')] == 'missing'


def test_missing_static_gets_pool_ip():
    p = dict(PROFILE)
    res = compare(load(A, 'a'), load(B.replace('nat (INSIDE,OUTSIDE) source static WEB-ONE-RENAMED B_PUB_WEB2 inactive', ''), 'b'), Profile(**p))
    w2 = by(res['nat'], 'real_ref', 'WEB2')
    assert w2['status'] == 'missing' and w2['proposed_b_mapped'] == '203.0.113.50'


def test_shared_edge_requires_same_mapped():
    res = run(type='shared-edge')
    assert by(res['nat'], 'real_ref', 'WEB1')['status'] == 'mapped conflict'


def test_inbound_and_dns():
    res = run()
    i = {x['object']: x for x in res['inbound']}
    assert i['WEB1']['status'] == 'nat ok, rule partial'     # B permits 80, A permits 80+443
    assert i['WEB2']['status'].startswith('nat inactive on B')
    d = {x['host']: x for x in res['dns']}
    assert d['WEB1']['a_public_ip'] == '198.51.100.10' and d['WEB1']['b_public_ip'] == '203.0.113.10'


def test_objects():
    res = run()
    o = {x['name']: x['status'] for x in res['objects']}
    assert o['WEB1'] == 'same'
    assert o['WEB2'] == 'same value, different name'
    assert o['LAN20'] == 'same name, different value'
    assert o['RANGE1'] == 'missing on B'


def test_reverse_direction():
    p = Profile(**PROFILE).reversed()
    res = compare(load(B, 'b'), load(A, 'a'), p)
    assert by(res['rules'], 'rule', 'Web-In')['status'] == 'covered'


def test_public_budget_and_pat_detail():
    res = run()
    pub = [r for r in res['public'] if r['scope'] == 'VLAN 20'][0]
    assert pub['b_missing'] == 0 and pub['b_inactive'] == 1 and pub['b_public_needed'] == 1
    used = [r for r in res['public'] if r['scope'] == 'B used'][0]
    assert '203.0.113.10' in used['status'] and '203.0.113.11' in used['status']
    a = [d for d in res['pat_detail'] if d['side'] == 'A']
    assert any(d['status'] == 'translated' and d['object'] == 'RANGE1' and d['count'] == 11 for d in a)
    assert not any(d['status'] == 'not translated' for d in a)
    assert [d for d in res['pat_detail'] if d['side'] == 'B' and d['status'] == 'not translated']


def test_yaml_profile_and_samples(tmp_path):
    import os
    from fwsync.cli import main
    here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'samples')
    p = Profile.load(os.path.join(here, 'profile.yaml'))
    assert p.scope == ['10.20.0.0/24'] and p.interface_map['inside'] == 'INSIDE'
    main(['compare', os.path.join(here, 'edge-a.txt'), os.path.join(here, 'edge-b.txt'), '--profile',
          os.path.join(here, 'profile.yaml'), '--out', str(tmp_path), '--prefix', 't'])
    assert (tmp_path / 't.html').exists() and (tmp_path / 't_nat.csv').exists()
