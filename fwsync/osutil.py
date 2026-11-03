"""OS helpers shared by the CLI, the web UI and the FMC client: config directory, tolerant text input, owner-only
file protection (chmod 600 on macOS/Linux, icacls on Windows) and local port selection."""
import getpass
import os
import re
import socket
import subprocess
import sys
import warnings
from pathlib import Path

ENCODINGS = ('utf-8', 'utf-8-sig', 'cp1252')
WEB_HOST = '127.0.0.1'
WEB_PORT = 8765


def is_windows():
    return os.name == 'nt'


def config_dir():
    """~/.fwsync (%USERPROFILE%\\.fwsync on Windows)"""
    return Path.home() / '.fwsync'


def decode(data):
    """bytes -> str: utf-8, then utf-8 with BOM, then cp1252; any line ending becomes \\n"""
    for enc in ENCODINGS:
        try:
            text = data.decode(enc)
        except UnicodeDecodeError:
            continue
        if enc == 'utf-8' and text.startswith('﻿'):
            text = text[1:]
        break
    else:
        text = data.decode('utf-8', errors='replace')
    return text.replace('\r\n', '\n').replace('\r', '\n')


def read_text(path):
    return decode(Path(path).expanduser().read_bytes())


def write_text(path, text):
    """UTF-8 with \\n line endings on every OS, then owner-only"""
    p = Path(path)
    with open(p, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(text)
    protect(p)
    return p


_SID = {}


def _windows_user():
    return os.environ.get('USERNAME') or getpass.getuser()


def _windows_sid(run=subprocess.run):
    """the current user's SID (whoami /user), so the grant also works for domain and Entra ID accounts"""
    if 'sid' not in _SID:
        try:
            out = run(['whoami', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True).stdout.strip()
            _SID['sid'] = out.rsplit(',', 1)[-1].strip().strip('"') if out.startswith('"') else ''
        except OSError:
            _SID['sid'] = ''
    return _SID['sid']


def protect(path, run=subprocess.run):
    """make a report, profile or credential file readable by the current user only. Returns True on success; on
    failure warns (never silent) and returns False."""
    p = str(path)
    if is_windows():
        sid = _windows_sid(run)
        who = '*%s' % sid if sid.startswith('S-1-') else _windows_user()
        cmd = ['icacls', p, '/inheritance:r', '/grant:r', '%s:F' % who]
        try:
            r = run(cmd, capture_output=True, text=True)
            ok, why = r.returncode == 0, (r.stderr or r.stdout or '').strip()
            if ok and run is subprocess.run and sid.startswith('S-1-'):
                ok, why = _strip_other_entries(p, sid)
        except OSError as e:
            ok, why = False, str(e)
        if not ok:
            warnings.warn('could not restrict %s to the current user (icacls: %s); protect it by hand' % (p, why),
                          stacklevel=2)
        return ok
    try:
        os.chmod(p, 0o600)
        return True
    except OSError as e:
        warnings.warn('could not chmod 600 %s: %s' % (p, e), stacklevel=2)
        return False


def _sddl_dacl(path):
    """the file's DACL as SDDL (Win32 API through ctypes: no shell-out, no localized tool output)"""
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    k32 = ctypes.WinDLL('kernel32')
    adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    sd, text = ctypes.c_void_p(), wintypes.LPWSTR()
    rc = adv.GetNamedSecurityInfoW(str(path), 1, 4, None, None, None, None, ctypes.byref(sd))
    if rc:
        raise OSError(rc, 'GetNamedSecurityInfoW failed', str(path))
    try:
        if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 4, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return text.value
    finally:
        k32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        k32.LocalFree(sd)


def _full_sid(text):
    """SDDL SID or alias (LA, SY, BA, OW ...) -> 'S-1-...' (Win32 ConvertStringSidToSid / ConvertSidToStringSid)"""
    if text.upper().startswith('S-1-'):
        return text.upper()
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL('advapi32', use_last_error=True)
    k32 = ctypes.WinDLL('kernel32')
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    psid, out = ctypes.c_void_p(), wintypes.LPWSTR()
    if not adv.ConvertStringSidToSidW(text, ctypes.byref(psid)):
        return text.upper()
    try:
        if not adv.ConvertSidToStringSidW(psid, ctypes.byref(out)):
            return text.upper()
        v = out.value.upper()
        k32.LocalFree(ctypes.cast(out, ctypes.c_void_p))
        return v
    finally:
        k32.LocalFree(psid)


def dacl_entries(sddl, resolve=_full_sid):
    """'D:PAI(A;;FA;;;LA)(A;;FA;;;SY)' -> (protected, [(type, rights, 'S-1-...'), ...])"""
    m = re.match(r'^D:([A-Z]*)((?:\([^)]*\))*)$', sddl or '')
    if not m:
        return False, None
    aces = []
    for ace in re.findall(r'\(([^)]*)\)', m.group(2)):
        f = ace.split(';')
        if len(f) >= 6:
            aces.append((f[0], f[2], resolve(f[5])))
    return 'P' in m.group(1), aces


def owner_only_dacl(sddl, sid, resolve=_full_sid):
    """protected DACL (no inherited entries) with one allow entry: full control for this SID"""
    protected, aces = dacl_entries(sddl, resolve)
    return bool(protected and aces and len(aces) == 1 and aces[0][0] == 'A' and aces[0][1] in ('FA', '0x1f01ff')
                and aces[0][2] == sid.upper())


def _strip_other_entries(path, sid):
    """icacls /grant:r keeps explicit entries of other accounts (for example SYSTEM / Administrators / OWNER RIGHTS
    copied from a folder created with mode 0o700): remove them with icacls /remove:g, then check again"""
    protected, aces = dacl_entries(_sddl_dacl(path))
    others = sorted({a[2] for a in aces or [] if a[2] != sid.upper()})
    if others:
        r = subprocess.run(['icacls', str(path), '/remove:g'] + ['*' + o for o in others], capture_output=True,
                           text=True)
        if r.returncode:
            return False, (r.stderr or r.stdout).strip()
    if owner_only_dacl(_sddl_dacl(path), sid):
        return True, ''
    return False, 'other accounts still have access: %s' % _sddl_dacl(path)


def is_protected(path):
    """True if only the current user has access (mode 600, or on Windows a protected DACL with one full-control entry
    for the current user's SID)"""
    if not is_windows():
        return (os.stat(path).st_mode & 0o777) == 0o600
    return owner_only_dacl(_sddl_dacl(path), _windows_sid())


def port_free(port, host=WEB_HOST):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if not is_windows():
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def free_port(start=WEB_PORT, tries=100, host=WEB_HOST):
    for p in range(start, start + tries):
        if port_free(p, host):
            return p
    raise OSError('no free port in %d-%d on %s' % (start, start + tries - 1, host))


def console_utf8():
    """Windows consoles default to cp437/cp1252: keep printing report paths and names from failing"""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors='replace')
        except (AttributeError, ValueError):
            pass
