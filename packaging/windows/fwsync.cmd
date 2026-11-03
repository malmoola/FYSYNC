@echo off
rem fwsync for Windows: double-click. First run installs offline into python\ (no admin rights, no network);
rem every run starts the web UI on 127.0.0.1 (first free port from 8765) and opens your browser.
setlocal EnableExtensions
title fwsync
set "HERE=%~dp0"
set "ROOT=%HERE%"
if not exist "%ROOT%fwsync\__init__.py" for %%I in ("%HERE%..\..") do set "ROOT=%%~fI\"
if not exist "%ROOT%packaging\windows\setup.cmd" goto :missing
call "%ROOT%packaging\windows\setup.cmd" "web,yaml,fmc"
if errorlevel 1 goto :end
echo.
echo  fwsync is starting; your browser opens in a moment.
echo  Keep this window open while you use fwsync. Press Ctrl-C (then Y) or close the window to stop it.
echo.
"%PY%" -m fwsync web %*
if not errorlevel 1 goto :end
echo.
echo  fwsync stopped with an error. If the port was in use, close the other fwsync window and start again.
goto :end
:missing
echo.
echo  fwsync: files are missing next to fwsync.cmd.
echo  Did you open it from inside the zip? Right-click the zip ^> Extract All, then run fwsync.cmd from the
echo  extracted folder.
:end
if not defined CI pause
endlocal
