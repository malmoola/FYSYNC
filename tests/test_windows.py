"""0.5.1 Windows support: paths, config input encodings / line endings, owner-only files (icacls mocked off Windows,
real on Windows), local port selection, web bind address, FMC TLS settings. Synthetic data only."""
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from fwsync import osutil
from fwsync.pipeline import read

CFG = ': Saved\nhostname fw-é\ninterface Ethernet1/1\n nameif inside\n ip address 10.9.0.1 255.255.255.0\n'
WIN = sys.platform == 'win32'


@pytest.mark.parametrize('data', [
    CFG.encode('utf-8'),
    CFG.replace('\n', '\r\n').encode('utf-8'),
    b'\xef\xbb\xbf' + CFG.replace('\n', '\r\n').encode('utf-8'),
    CFG.replace('\n', '\r\n').encode('cp1252'),
    CFG.replace('\n', '\r').encode('utf-8'),
], ids=['utf8-lf', 'utf8-crlf', 'utf8-bom-crlf', 'cp1252-crlf', 'cr-only'])
def test_read_any_encoding_and_line_ending(tmp_path, data):
    p = tmp_path / 'fw.txt'
    p.write_bytes(data)
    text, name = read(str(p))
    assert text == CFG and name == 'fw.txt'
    assert '\r' not in text and not text.startswith('\ufeff')


def test_parse_crlf_bom_same_as_lf(tmp_path):
    from fwsync.adapters import load
    a, b = tmp_path / 'lf.txt', tmp_path / 'crlf.txt'
    a.write_bytes(CFG.encode())
    b.write_bytes(b'\xef\xbb\xbf' + CFG.replace('\n', '\r\n').encode('cp1252', errors='strict'))
    ca, cb = load(*read(str(a))), load(*read(str(b)))
    assert [i.nameif for i in ca.interfaces.values()] == [i.nameif for i in cb.interfaces.values()] == ['inside']


def test_config_dir_is_home_dot_fwsync(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    assert osutil.config_dir() == tmp_path / '.fwsync'


def test_allowlist_default_under_config_dir():
    from fwsync import push
    if not os.environ.get('FWSYNC_ALLOWLIST'):
        assert Path(push.ALLOWLIST_FILE) == Path.home() / '.fwsync' / 'fmc_allowlist.txt'


def test_allowlist_crlf(tmp_path):
    from fwsync.push import allowed
    p = tmp_path / 'allow.txt'
    p.write_bytes(b'\xef\xbb\xbf# lab\r\nfmc.example\r\n')
    assert allowed('https://fmc.example/', str(p)) and not allowed('https://other.example/', str(p))


def test_no_hardcoded_posix_paths_or_bash():
    src = Path(__file__).resolve().parent.parent / 'fwsync'
    for f in src.rglob('*.py'):
        t = f.read_text(encoding='utf-8')
        assert "expanduser('~')" not in t and 'os.chmod(' not in t.replace('os.chmod(p, 0o600)', ''), f
        assert 'shell=True' not in t and "'bash'" not in t and '/bin/sh' not in t, f


def test_written_text_is_utf8_lf(tmp_path):
    p = osutil.write_text(tmp_path / 'r.md', 'é line1\nline2\n')
    assert p.read_bytes() == 'é line1\nline2\n'.encode('utf-8')


# ------------------------------------------------------------------ file protection
class Run:
    def __init__(self, rc=0, out='', sid='S-1-5-21-1-2-3-1001'):
        self.calls, self.rc, self.out, self.sid = [], rc, out, sid

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd[0] == 'whoami':
            return subprocess.CompletedProcess(cmd, 0, '"host\\\\me","%s"\n' % self.sid, '')
        return subprocess.CompletedProcess(cmd, self.rc, self.out, 'Access is denied.' if self.rc else '')


@pytest.fixture
def as_windows(monkeypatch):
    monkeypatch.setattr(osutil, 'is_windows', lambda: True)
    monkeypatch.setitem(os.environ, 'USERNAME', 'me')
    osutil._SID.clear()
    yield
    osutil._SID.clear()


def test_protect_icacls_call(as_windows, tmp_path):
    r = Run()
    assert osutil.protect(tmp_path / 'r.html', run=r)
    assert r.calls[-1] == ['icacls', str(tmp_path / 'r.html'), '/inheritance:r', '/grant:r', '*S-1-5-21-1-2-3-1001:F']


def test_protect_icacls_falls_back_to_username(as_windows, tmp_path):
    r = Run(sid='')
    assert osutil.protect(tmp_path / 'r.html', run=r)
    assert r.calls[-1][-1] == 'me:F'


def test_protect_icacls_failure_warns(as_windows, tmp_path):
    with pytest.warns(UserWarning, match='could not restrict'):
        assert osutil.protect(tmp_path / 'r.html', run=Run(rc=5)) is False


def test_protect_missing_icacls_warns(as_windows, tmp_path):
    def boom(cmd, **kw):
        if cmd[0] == 'whoami':
            return subprocess.CompletedProcess(cmd, 0, '"h\\\\me","S-1-5-21-9"', '')
        raise FileNotFoundError('icacls')
    with pytest.warns(UserWarning):
        assert osutil.protect(tmp_path / 'x', run=boom) is False


def test_is_protected_parses_icacls(as_windows):
    p = r'C:\Users\me\fwsync-reports\r (1).html'
    one = '%s HOST\\me:(F)\n\nSuccessfully processed 1 files; Failed processing 0 files\n' % p
    two = '%s HOST\\me:(F)\n    BUILTIN\\Users:(RX)\n\nSuccessfully processed 1 files; Failed processing 0 files\n' % p
    assert osutil.is_protected(p, run=lambda c, **k: subprocess.CompletedProcess(c, 0, one, ''))
    assert not osutil.is_protected(p, run=lambda c, **k: subprocess.CompletedProcess(c, 0, two, ''))


@pytest.mark.skipif(WIN, reason='POSIX mode bits')
def test_protect_posix_mode_600(tmp_path):
    p = tmp_path / 'r.json'
    p.write_text('{}')
    os.chmod(p, 0o644)
    assert osutil.protect(p) and (os.stat(p).st_mode & 0o777) == 0o600 and osutil.is_protected(p)


@pytest.mark.skipif(not WIN, reason='real icacls only on Windows')
def test_protect_real_icacls(tmp_path):
    p = tmp_path / 'r.json'
    p.write_text('{}')
    assert osutil.protect(p) and osutil.is_protected(p)


def test_reports_are_protected(tmp_path):
    from fwsync.pipeline import run
    from fwsync.profile import Profile
    from fwsync.report import write_all
    here = Path(__file__).resolve().parent.parent / 'samples'
    res, *_ = run([read(str(here / 'edge-a.txt'))], read(str(here / 'edge-b.txt')), Profile())
    for p in write_all(res, tmp_path / 'out', 't'):
        assert osutil.is_protected(p), p


# ------------------------------------------------------------------ ports and web
def test_free_port_skips_busy():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    s.listen(1)
    busy = s.getsockname()[1]
    try:
        assert not osutil.port_free(busy)
        assert osutil.free_port(busy, tries=20) != busy
    finally:
        s.close()


def test_free_port_none_left(monkeypatch):
    monkeypatch.setattr(osutil, 'port_free', lambda p, host='127.0.0.1': False)
    with pytest.raises(OSError, match='no free port'):
        osutil.free_port(8765, tries=3)


def test_serve_binds_loopback_first_free_port(monkeypatch):
    from fwsync import web
    seen = {}
    import uvicorn
    monkeypatch.setattr(uvicorn, 'run', lambda app, **kw: seen.update(kw))
    monkeypatch.setattr(web, 'free_port', lambda start: start + 2)
    opened = []
    monkeypatch.setattr(web.threading, 'Timer', lambda t, f, a: type('T', (), {'start': lambda s: opened.append(a)})())
    web.serve(None, browser=True)
    assert seen['host'] == '127.0.0.1' and seen['port'] == 8767 and seen['reload'] is False and seen['workers'] == 1
    assert opened == [('http://127.0.0.1:8767/',)]


def test_serve_port_in_use_message(monkeypatch):
    from fwsync import web
    monkeypatch.setattr(web, 'port_free', lambda p: False)
    with pytest.raises(SystemExit, match='in use'):
        web.serve(8765, browser=False)


def test_serve_ctrl_c_is_clean(monkeypatch, capsys):
    from fwsync import web
    import uvicorn

    def stop(app, **kw):
        raise KeyboardInterrupt
    monkeypatch.setattr(uvicorn, 'run', stop)
    web.serve(None, browser=False)
    assert 'stopped' in capsys.readouterr().out


# ------------------------------------------------------------------ FMC TLS / proxy
def test_tls_verify_on_by_default():
    from fwsync.fmc import new_session
    s = new_session()
    assert s.verify is True and s.trust_env is True


def test_tls_ca_bundle(tmp_path):
    from fwsync.fmc import new_session
    ca = tmp_path / 'corp-ca.pem'
    ca.write_text('-----BEGIN CERTIFICATE-----\n')
    assert new_session(str(ca)).verify == str(ca)
    with pytest.raises(FileNotFoundError):
        new_session(str(tmp_path / 'missing.pem'))


def test_tls_insecure_warns():
    from fwsync.fmc import new_session
    with pytest.warns(UserWarning, match='OFF'):
        assert new_session(False).verify is False


def test_cli_verify_order(tmp_path, monkeypatch):
    import argparse
    from fwsync.cli import _verify
    prof = tmp_path / 'p.json'
    prof.write_text('{"fmc": {"ca_bundle": "%s"}}' % (tmp_path / 'p.pem').as_posix())
    monkeypatch.setenv('FWSYNC_CA_BUNDLE', str(tmp_path / 'env.pem'))
    ns = lambda **k: argparse.Namespace(**{'insecure': False, 'ca_bundle': None, 'profile': None, **k})
    assert _verify(ns(insecure=True, ca_bundle='x')) is False
    assert Path(_verify(ns(ca_bundle=str(tmp_path / 'c.pem'), profile=str(prof)))).name == 'c.pem'
    assert Path(_verify(ns(profile=str(prof)))).name == 'p.pem'
    assert Path(_verify(ns())).name == 'env.pem'
    monkeypatch.delenv('FWSYNC_CA_BUNDLE')
    assert _verify(ns()) is True


def test_proxy_env_respected(monkeypatch):
    from fwsync.fmc import new_session
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.example:3128')
    monkeypatch.setenv('NO_PROXY', 'fmc.internal.example')
    s = new_session()
    env = s.merge_environment_settings('https://fmc.example/api', {}, None, None, None)
    assert env['proxies'].get('https') == 'http://proxy.example:3128'
    env = s.merge_environment_settings('https://fmc.internal.example/api', {}, None, None, None)
    assert 'https' not in env['proxies'] or not env['proxies']['https']
