@echo off
rem fwsync selftest for Windows: offline install, test suite, synthetic compare 1:1 and 2:1, web UI for 10 s on
rem 127.0.0.1, owner-only protection of a report. Writes selftest-result.txt next to this file.
setlocal EnableExtensions
title fwsync selftest
set "HERE=%~dp0"
set "ROOT=%HERE%"
if not exist "%ROOT%fwsync\__init__.py" for %%I in ("%HERE%..\..") do set "ROOT=%%~fI\"
if not exist "%ROOT%packaging\windows\setup.cmd" (
  echo fwsync: files are missing. Extract the whole zip first, then run selftest.cmd from the extracted folder.
  set "RC=2"
  goto :end
)
call "%ROOT%packaging\windows\setup.cmd" web,yaml,fmc,test
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo fwsync selftest FAILED: offline install> "%ROOT%selftest-result.txt"
  echo offline install            FAIL  %INSTALL_STATUS%>> "%ROOT%selftest-result.txt"
  goto :end
)
"%PY%" "%ROOT%scripts\selftest.py" --root "%ROOT:~0,-1%" --kind %KIND% --install-status "%INSTALL_STATUS%"
set "RC=%ERRORLEVEL%"
:end
echo.
if exist "%ROOT%selftest-result.txt" echo Result: %ROOT%selftest-result.txt
if not defined CI pause
exit /b %RC%
