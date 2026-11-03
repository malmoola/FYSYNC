from fwsync.netset import IPSet, PortSet, Service


def test_set_ops():
    a = IPSet.parse('10.0.0.0/24')
    b = IPSet.parse('10.0.0.128/25')
    assert b.issubset(a) and not a.issubset(b)
    assert (a - b).cidrs() == ['10.0.0.0/25']
    assert (a | IPSet.parse('10.0.1.0/24')).cidrs() == ['10.0.0.0/23']
    assert IPSet.range('10.0.0.1', '10.0.0.3').size() == 3
    assert IPSet.any().is_any()


def test_service_cover():
    web = Service([('tcp', PortSet([(80, 80)]), None), ('tcp', PortSet([(443, 443)]), None)])
    assert Service([('tcp', PortSet([(443, 443)]), None)]).covered_by(web)
    assert not Service([('tcp', PortSet([(80, 443)]), None)]).covered_by(web)
    assert web.covered_by(Service.any())
    assert not Service.any().covered_by(web)
    assert Service([('udp', PortSet([(53, 53)]), None)]).overlaps(Service.any())
