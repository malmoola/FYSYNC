"""0.4.2: NAT first-match order (section 1, auto NAT, after-auto; interface pairs incl. any), effective translation,
never-hit rules, PAT finding from the effective translation, public IPs = size of the mapped object."""
from fwsync.pipeline import run
from fwsync.adapters import load
from fwsync import natorder
from fwsync.netset import IPSet

A = """hostname EDGE-N
interface Ethernet1/1
 nameif outside
 ip address 198.51.100.2 255.255.255.0
interface Ethernet1/2
 nameif inside
 ip address 10.1.0.1 255.255.255.0
object network MGMT-NET
 subnet 10.30.0.0 255.255.255.192
object network MGMT-PUB
 host 198.51.100.83
object network APP-GRP
 range 10.30.0.10 10.30.0.13
object network APP-PUB
 host 198.51.100.97
object network ANYHOST
 host 10.40.0.5
object network ANYHOST-PUB
 host 198.51.100.40
object network OBJ-AUTO-BIG
 subnet 10.50.0.0 255.255.255.0
 nat (inside,outside) dynamic interface
object network OBJ-AUTO-HOST
 host 10.50.0.9
 nat (inside,outside) static 198.51.100.59
route outside 0.0.0.0 0.0.0.0 198.51.100.1 1
route inside 10.0.0.0 255.0.0.0 10.1.0.2 1
nat (any,any) source static ANYHOST ANYHOST-PUB
nat (inside,outside) source static MGMT-NET MGMT-PUB
nat (inside,outside) source dynamic APP-GRP APP-PUB
nat (inside,outside) source dynamic ANYHOST interface
"""

B = """hostname FW-N
interface Ethernet1/1
 nameif OUTSIDE
 ip address 203.0.113.2 255.255.255.248
interface Ethernet1/2
 nameif INSIDE
 ip address 10.9.0.1 255.255.255.0
route OUTSIDE 0.0.0.0 0.0.0.0 203.0.113.1 1
route INSIDE 10.0.0.0 255.0.0.0 10.9.0.2 1
"""


def cfg():
    return load(A, 'a.txt')


def by_ref(c, ref):
    return [n for n in c.nats if n.real_ref == ref]


def test_order_sections_and_auto_static_first():
    c = cfg()
    refs = [n.real_ref for n in natorder.ordered(c)]
    assert refs[:4] == ['ANYHOST', 'MGMT-NET', 'APP-GRP', 'ANYHOST']
    assert refs[4:] == ['OBJ-AUTO-HOST', 'OBJ-AUTO-BIG']


def test_effective_first_match_and_shadow():
    c = cfg()
    eff = natorder.effective(c, IPSet.parse('10.30.0.0/26'), 'inside', 'outside')
    assert len(eff) == 1 and eff[0][1].real_ref == 'MGMT-NET'
    sh = natorder.shadowed(c)
    app = by_ref(c, 'APP-GRP')[0]
    assert sh[id(app)][1].startswith('never hit: covered by line')
    dyn_any = [n for n in by_ref(c, 'ANYHOST') if n.kind == 'dynamic'][0]
    assert id(dyn_any) in sh
    assert id(by_ref(c, 'OBJ-AUTO-HOST')[0]) not in sh


def test_any_any_pair_matches_any_interfaces():
    c = cfg()
    eff = natorder.effective(c, IPSet.parse('10.40.0.5/32'), 'inside', 'outside')
    assert eff[0][1].real_ifc == 'any' and eff[0][1].kind == 'static'


def test_pat_finding_uses_effective_source_and_public_size():
    prof = {'scope': ['10.30.0.0/26'], 'names': {'A': 'Edge (E)', 'B': 'DR (D)'},
            'public_pool_b': ['203.0.113.5-203.0.113.6']}
    res = run([(A, 'a.txt')], (B, 'b.txt'), prof)[0]
    f = [x for x in res['findings'] if x['category'] == 'pat'][0]
    assert f['pat_sources'] == ['NET_10.30.0.0_26']
    assert f['fix']['cli'] == ['nat (INSIDE,OUTSIDE) after-auto source dynamic NET_10.30.0.0_26 interface']
    assert any('never hit' in e['text'] and 'APP-GRP' in e['text'] for e in f['evidence'])
    pub = [x for x in res['public'] if x['id'] == 'PUB-10.30.0.0/26'][0]
    assert pub['pub_b'] == 1 and pub['pub_b_nats'] == 1
