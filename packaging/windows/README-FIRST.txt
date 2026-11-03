fwsync for Windows
==================

1. Before extracting: right-click the downloaded zip > Properties > tick "Unblock" > OK.
   (Otherwise Windows marks every file as "from the internet" and may warn on each one.)
2. Right-click the zip > Extract All. Do not run fwsync from inside the zip.
3. Double-click fwsync.cmd in the extracted folder.
   If Windows shows "Windows protected your PC": click "More info", then "Run anyway".
   The zip is not code-signed; the bundled python\python.exe is the official, signed python.org build.
4. The first run installs fwsync offline into python\ (about a minute, no admin rights, no network).
   Then your browser opens fwsync at http://127.0.0.1:8765/ (or the next free port).
   Keep the black window open while you work; close it (or Ctrl-C) to stop fwsync.

selftest.cmd checks the installation and writes selftest-result.txt.
Reports are written so that only your Windows user can read them. Keep them out of shared folders.
More: WINDOWS.md and README.md.
