"""Web API smoke test: 2:1 upload, rerun with edits from the auto-detected panel, generate."""
import json
import os

import pytest

fastapi = pytest.importorskip('fastapi')
from fastapi.testclient import TestClient  # noqa: E402
from fwsync.web import app  # noqa: E402

HERE = os.path.join(os.path.dirname(__file__), '..', 'samples', 'chain')


def test_web_2to1_and_rerun():
    c = TestClient(app)
    files = {k: (f, open(os.path.join(HERE, f), 'rb')) for k, f in (('a1', 'edge.txt'), ('a2', 'inner.txt'), ('b', 'target.txt'))}
    r = c.post('/api/compare', data={'mode': '2:1'}, files=files)
    assert r.status_code == 200
    j = r.json()
    assert j['mode'] == '2:1' and j['detected']['chain']['a1_toward_a2'] == 'inside'
    sid = j['session']
    r = c.post('/api/compare', data={'mode': '2:1', 'session': sid,
                                     'overrides': json.dumps({'scope': ['10.50.0.0/16'], 'type': 'standard'})})
    j2 = r.json()
    assert r.status_code == 200 and j2['scope'] == ['10.50.0.0/16'] and j2['session'] == sid
    ids = [x['id'] for x in j2['rules'] if x['status'] != 'covered']
    g = c.post('/api/generate', json={'session': sid, 'ids': ids}).json()
    assert g['changes'] and g['cli']
    assert c.get('/api/report/%s.html' % sid).status_code == 200
    assert 'What-if on B' in c.get('/').text


def test_native_app_server_starts():
    import importlib.util
    import os
    p = os.path.join(os.path.dirname(__file__), '..', 'packaging', 'macos', 'fwsync_app.py')
    spec = importlib.util.spec_from_file_location('fwsync_app', p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    server, t, url = m.start_server()
    import urllib.request
    try:
        assert urllib.request.urlopen(url, timeout=10).status == 200
    finally:
        server.should_exit = True
        t.join(timeout=5)
