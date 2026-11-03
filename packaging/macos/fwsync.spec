# PyInstaller spec: fwsync.app (macOS, onedir bundle) or fwsync.exe (Windows, one file). Build from the repo root:
#   pyinstaller packaging/macos/fwsync.spec --noconfirm
import os
import re
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, '..', '..'))
VERSION = re.search(r"__version__ = '([^']+)'", open(os.path.join(ROOT, 'fwsync', '__init__.py')).read()).group(1)
ICON_PNG = os.path.join(SPECPATH, 'icon.png')
ICON_ICNS = os.path.join(SPECPATH, 'icon.icns')
ICON_ICO = os.path.join(SPECPATH, 'icon.ico')

hidden = (collect_submodules('uvicorn') + collect_submodules('fwsync') + collect_submodules('webview')
          + ['yaml', 'multipart', 'python_multipart'])

a = Analysis([os.path.join(SPECPATH, 'fwsync_app.py')], pathex=[ROOT], hiddenimports=hidden, datas=[],
             excludes=['tkinter', 'pytest', 'requests'], noarchive=False)
pyz = PYZ(a.pure)

if sys.platform == 'darwin':
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='fwsync', console=False, upx=False,
              target_arch=os.environ.get('FWSYNC_ARCH') or None,
              codesign_identity=os.environ.get('FWSYNC_CODESIGN_IDENTITY') or None,
              entitlements_file=os.path.join(SPECPATH, 'entitlements.plist'))
    coll = COLLECT(exe, a.binaries, a.datas, name='fwsync', upx=False)
    app = BUNDLE(coll, name='fwsync.app', bundle_identifier='org.fwsync.app',
                 icon=ICON_ICNS if os.path.exists(ICON_ICNS) else ICON_PNG, version=VERSION,
                 info_plist={'CFBundleShortVersionString': VERSION, 'CFBundleVersion': VERSION,
                             'NSHighResolutionCapable': True, 'LSMinimumSystemVersion': '12.0'})
else:
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name='fwsync', console=False, upx=False,
              icon=ICON_ICO if os.path.exists(ICON_ICO) else ICON_PNG, version=None)
