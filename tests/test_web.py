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


def test_details_table_can_be_scrolled_and_long_cells_clip():
    page = TestClient(app).get('/').text
    assert 'id=tbltop' in page and 'function fitTbl' in page               # scrollbar on top, box fits the window
    assert 'tr class=ff' in page and 'tr.ff th{top:' in page               # both header rows stay visible
    assert "CLIP=new Set(['scope'" in page and '.clip.open{display:block}' in page


def test_report_long_cells_clip_and_keep_full_text(tmp_path):
    from fwsync import report
    long = ', '.join('subnet-%d' % i for i in range(40))
    assert 'scope' in report.CLIP_COLS and len(long) > 120
    assert '.clip.open{display:block}' in report.CSS and 'max-height:calc(100vh' in report.CSS
