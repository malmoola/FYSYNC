from fwsync.adapters import load
from fwsync.netset import IPSet
from samples import A


def test_objects_groups():
    c = load(A, 'a')
    assert c.hostname == 'edge-a'
    assert c.interfaces['inside'].vlan == 10 and c.interfaces['inside'].standby == '10.10.0.2'
    assert c.objects['RANGE1'].addrs.size() == 11
    assert c.objects['NAME1'].kind == 'fqdn'
    from fwsync.adapters.lina import LinaAdapter
    la = LinaAdapter()
    la.cfg = c
    assert la.resolve('OUTER') == IPSet.parse('10.20.0.10,10.20.0.12,10.30.0.0/16')
    assert not c.warnings


def test_rules_and_names():
    c = load(A, 'a')
    r = {x.rule_name: x for x in c.rules}
    assert r['Web-In'].policy == 'EDGE-ACP - Mandatory'
    assert r['Web-In'].src_ifc == 'outside' and r['Web-In'].dst_ifc == 'inside'
    assert r['Web-In'].dst == IPSet.parse('10.20.0.10,10.20.0.12')
    assert repr(r['Web-In'].svc) == 'tcp/80 tcp/443'
    assert repr(r['Mixed'].svc) == 'tcp/8000-8010 udp/53'
    assert r['Web2-In'].dst == IPSet.host('10.20.0.11')
    assert r['DEFAULT ACTION RULE'].action == 'deny'          # 'L4 RULE:' / 'L7 RULE:' remarks


def test_nat_kinds():
    c = load(A, 'a')
    kinds = [(n.section, n.kind, n.pat, n.real_ref) for n in c.nats]
    assert kinds[0][:3] == ('manual-before', 'static', False)
    assert ('auto', 'dynamic', True, 'RANGE1') in kinds
    assert kinds[-1][:3] == ('manual-after', 'dynamic', True)
    web2 = [n for n in c.nats if n.real_ref == 'WEB2'][0]
    assert web2.description == 'web two' and web2.mapped == IPSet.host('198.51.100.11')
