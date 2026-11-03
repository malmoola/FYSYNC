import pytest
from fwsync.adapters import load
from fwsync.compare import compare
from fwsync.generate import generate
from fwsync.profile import Profile
from fwsync import push
from samples import A, B, PROFILE


def test_generate_order_and_views():
    p = Profile(**PROFILE)
    Bc = load(B, 'b')
    res = compare(load(A, 'a'), Bc, p)
    ids = [r['id'] for r in res['rules'] if r['status'] == 'missing'] + [x['id'] for x in res['nat']] + \
          [x['id'] for x in res['pat'] if x['side'] == 'B'] + [x['id'] for x in res['objects'] if x['status'] == 'missing on B']
    g = generate(res, ids, p, Bc)
    steps = [o['step'] for o in g['plan']]
    assert steps == sorted(steps, key=['object', 'group', 'nat', 'access-rule'].index)
    assert any('after-auto source dynamic' in l for l in g['cli'])
    assert any(o['path'].startswith('/policy/accesspolicies/{ACP-B}') for o in g['plan'])
    assert any('Z_OUT' in str(o['payload']) for o in g['plan'])
    assert g['changes']


def test_push_guard(tmp_path):
    with pytest.raises(PermissionError):
        push.run([], 'https://192.0.2.10', 'admin', 'x', allow_push=False)
    al = tmp_path / 'allow.txt'
    al.write_text('192.0.2.10\n')
    assert push.allowed('https://192.0.2.10', str(al))
    assert not push.allowed('https://192.0.2.1', str(al))
