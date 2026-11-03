"""Native window for fwsync (PyInstaller entry point, macOS and Windows).
The web UI runs in-process on 127.0.0.1 on a random free port and is shown in a pywebview window (WebKit on macOS,
Edge WebView2 on Windows). Closing the window stops the server and quits.
  python fwsync_app.py              native window
  python fwsync_app.py --no-window  start, check the UI answers, stop (used by the build test)"""
import socket
import sys
import threading
import time
import urllib.request

import uvicorn

from fwsync import __version__
from fwsync.web import app


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server():
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port, log_level='warning'))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    return server, t, 'http://127.0.0.1:%d/' % port


def main():
    server, t, url = start_server()
    try:
        if '--no-window' in sys.argv:
            with urllib.request.urlopen(url, timeout=10) as r:
                print('fwsync %s answered %d at %s' % (__version__, r.status, url))
            return
        import webview
        webview.settings['ALLOW_DOWNLOADS'] = True
        webview.create_window('fwsync %s' % __version__, url, width=1440, height=920, min_size=(900, 600))
        webview.start()
    finally:
        server.should_exit = True
        t.join(timeout=5)


if __name__ == '__main__':
    main()
