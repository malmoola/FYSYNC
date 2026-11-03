# fwsync on Windows

Two ways to run it: **native** with the bundled Python (the main path, no admin rights, nothing to install), or
**WSL** as a fallback. There is no .exe and the zip is not code-signed.

## Native (bundled Python)

`fwsync-<ver>-windows.zip` contains:

| Path | What |
|---|---|
| `fwsync.cmd` | double-click launcher: first run installs offline, then starts the web UI and opens your browser |
| `selftest.cmd` | checks the installation, writes `selftest-result.txt` |
| `README-FIRST.txt` | the four steps below |
| `python\` | the official Python 3.12 embeddable package (win_amd64) from python.org, set up so `site-packages` works |
| `vendor\wheels\` | every dependency as a wheel (win_amd64 and pure Python), installed offline |
| `fwsync\`, `tests\`, `samples\`, `scripts\` | the tool, its tests, synthetic sample configs and helper scripts |

### Steps

1. **Unblock before extracting.** Right-click the downloaded zip > Properties > tick **Unblock** > OK.
   Otherwise every extracted file keeps the "downloaded from the internet" mark and Windows may warn for each one.
   (The launcher detects the mark and offers to unblock the extracted folder for you.)
2. **Extract All** (right-click the zip). Do not run `fwsync.cmd` from inside the zip view: Windows would extract only
   that one file, and the launcher would tell you that files are missing.
3. Double-click **`fwsync.cmd`**. If you see **"Windows protected your PC"** (SmartScreen): click **More info**, then
   **Run anyway**. `python\python.exe` itself is signed by the Python Software Foundation.
4. First run only: "installing offline into python\" (about a minute). Then the browser opens fwsync at
   `http://127.0.0.1:8765/`, or the next free port if 8765 is taken (another fwsync window, another program).
5. Keep the console window open while you work. To stop: close the window, or press **Ctrl-C** (Windows then asks
   "Terminate batch job (Y/N)?": answer Y).

### Messages from the launcher

| Message | Meaning / fix |
|---|---|
| files are missing next to fwsync.cmd | the zip was not fully extracted, or the launcher was opened from inside the zip: Extract All, run it from the extracted folder |
| This folder is still marked as downloaded from the internet | answer Y to unblock it, or unblock the zip (step 1) and extract again |
| the offline install failed | `vendor\wheels` is incomplete (extract again) or the folder is read-only (extract it to a folder you own, e.g. Documents) |
| port ... is in use | only when you give `--port N`: close the other program or start without `--port` |
| the python\ folder is missing and no Python 3.12 is installed | you have the Mac/Linux zip: use `fwsync-<ver>-windows.zip`, or install Python 3.12 |

### Without the bundled Python

If `python\` is missing, the launchers use an installed Python: `py -3.12` first, then `python` (3.10 or newer), with
a venv in `%LOCALAPPDATA%\fwsync\venv`, installed offline from `vendor\wheels`.

### Command line

Open a Command Prompt in the extracted folder:
```
python\python.exe -m fwsync compare A.txt B.txt --out %USERPROFILE%\fwsync-reports --prefix a-to-b
python\python.exe -m fwsync compare EDGE.txt INNER.txt B.txt --out %USERPROFILE%\fwsync-reports --prefix chain
python\python.exe -m fwsync web --no-browser
python\python.exe -m fwsync fmc-read --fmc https://fmc.example --cred %USERPROFILE%\.fwsync\ro.json --device NAME --out snap.json --ca-bundle corp-ca.pem
```
(Run `fwsync.cmd` or `selftest.cmd` once first so fwsync is installed into `python\`.)

### Files and protection

- Settings: `%USERPROFILE%\.fwsync\` (for example `fmc_allowlist.txt` for the FMC copy commands, credential files).
- Config backups may be UTF-8 (with or without BOM) or Windows-1252, with CRLF or LF line endings.
- Reports, profiles, snapshots and undo files are UTF-8. Each one is restricted to your user with
  `icacls <file> /inheritance:r /grant:r <you>:F` (your SID, so domain and Entra ID accounts work); fwsync then reads
  the ACL back and removes any other account still listed (`icacls /remove:g`). If that fails, fwsync prints a
  warning naming the file; protect it by hand. Write reports to a folder only you use, not a share.
- TLS: FMC certificates are verified. If your FMC uses an internal or corporate CA, export that CA as PEM and pass
  `--ca-bundle corp-ca.pem` (or set `fmc.ca_bundle` in a profile, or `FWSYNC_CA_BUNDLE`). A proxy from `HTTPS_PROXY`
  is used unless the FMC is in `NO_PROXY`.

### Selftest

`selftest.cmd` installs offline (including the test extra), runs the test suite, a synthetic compare 1:1 and 2:1,
starts the web UI for 10 s and checks that it answers on 127.0.0.1 and stops cleanly on Ctrl-Break, checks that a
report is readable by your user only, and writes `selftest-result.txt` next to it. Send that file when you report a
problem; it holds no network data.

## WSL fallback

Use this if the native path is blocked (for example by an application control policy that stops `python.exe` from a
user folder).

1. PowerShell as administrator, once: `wsl --install -d Ubuntu`, reboot, open **Ubuntu** and create your Linux user.
2. In Ubuntu:
   ```
   sudo apt update && sudo apt install -y python3.12 python3.12-venv unzip
   cp /mnt/c/Users/<you>/Downloads/fwsync-<ver>.zip ~ && cd ~ && unzip fwsync-<ver>.zip && cd fwsync-<ver>
   python3.12 -m venv .venv
   .venv/bin/pip install --no-index --find-links vendor/wheels "fwsync[web,yaml,fmc]"
   .venv/bin/fwsync web --no-browser
   ```
   (Ubuntu 22.04 has no `python3.12` package: use `python3` (3.10) there, it is supported. Use the Mac/Linux zip
   `fwsync-<ver>.zip`; it has the Linux wheels.)
3. Open the printed address, e.g. `http://localhost:8765/`, in your Windows browser (WSL forwards localhost).
4. Windows files from WSL are under `/mnt/c/Users/<you>/...`, e.g.
   `.venv/bin/fwsync compare /mnt/c/Users/<you>/Documents/A.txt /mnt/c/Users/<you>/Documents/B.txt --out ~/fwsync-reports`.
   Keep reports in your WSL home (`~/fwsync-reports`): files on `/mnt/c` do not keep Linux permissions, so mode 600 is
   not enforced there.
