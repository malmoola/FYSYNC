@echo off
rem fwsync setup, called by fwsync.cmd and selftest.cmd with ROOT set (ends with \) and the extras as %1.
rem Sets PY (a Python with fwsync installed), KIND (bundled | installed) and INSTALL_STATUS. Offline only.
set "WHEELS=%ROOT%vendor\wheels"
set "EXTRAS=%~1"
set "INSTALL_STATUS=ok (already installed)"
set "WHL="
set "WANT="
if not exist "%WHEELS%\" goto :missing
for %%W in ("%WHEELS%\fwsync-*-py3-none-any.whl") do set "WHL=%%~nxW"
if not defined WHL goto :missing
for /f "tokens=2 delims=-" %%V in ("%WHL%") do set "WANT=%%V"
if exist "%ROOT%python\python.exe" goto :bundled

rem ---- no python\ folder: fall back to an installed Python (3.12 preferred)
set "KIND=installed"
set "BASE="
py -3.12 -c "import sys" >nul 2>&1
if not errorlevel 1 set "BASE=py -3.12"
if defined BASE goto :have_base
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if not errorlevel 1 set "BASE=python"
if defined BASE goto :have_base
echo.
echo  fwsync: the python\ folder is missing and no Python 3.12 is installed.
echo  Use the fwsync-%WANT%-windows.zip download (it includes python\), or install Python 3.12 from python.org.
exit /b 2
:have_base
set "VENV=%LOCALAPPDATA%\fwsync\venv"
set "PY=%VENV%\Scripts\python.exe"
if not exist "%PY%" goto :mkvenv
"%PY%" -c "import fwsync, sys; sys.exit(0 if fwsync.__version__ == '%WANT%' else 1)" >nul 2>&1
if errorlevel 1 goto :mkvenv
if "%EXTRAS%"=="web,yaml,fmc" exit /b 0
goto :pipinstall
:mkvenv
echo fwsync: setting up %VENV% with %BASE% (one time, offline) ...
if exist "%VENV%\" rmdir /s /q "%VENV%"
%BASE% -m venv "%VENV%"
if errorlevel 1 goto :installfail
goto :pipinstall

rem ---- bundled python\ (official embeddable package, no admin rights)
:bundled
set "KIND=bundled"
set "PY=%ROOT%python\python.exe"
call :motw
"%PY%" -c "import fwsync, sys; sys.exit(0 if fwsync.__version__ == '%WANT%' else 1)" >nul 2>&1
if not errorlevel 1 if "%EXTRAS%"=="web,yaml,fmc" exit /b 0
echo fwsync: installing offline into python\ (first run only, about a minute) ...

:pipinstall
"%PY%" -m pip install -q --disable-pip-version-check --no-index --find-links "%WHEELS%" --no-warn-script-location "fwsync[%EXTRAS%]"
if errorlevel 1 goto :installfail
"%PY%" -c "import fwsync, sys; sys.exit(0 if fwsync.__version__ == '%WANT%' else 1)" >nul 2>&1
if errorlevel 1 goto :installfail
set "INSTALL_STATUS=ok (offline from vendor\wheels, %KIND% Python)"
exit /b 0

:installfail
set "INSTALL_STATUS=failed"
echo.
echo  fwsync: the offline install failed (see the messages above).
echo  Make sure the whole zip was extracted (vendor\wheels must be complete), then run it again.
exit /b 3

:missing
echo.
echo  fwsync: files are missing next to this launcher (vendor\wheels\fwsync-*.whl).
echo  Did you open it from inside the zip? Right-click the zip ^> Extract All, then run fwsync.cmd from the
echo  extracted folder. Keep the folder together (fwsync.cmd, python\, vendor\, fwsync\).
exit /b 2

:motw
rem Files from an internet download carry a Zone.Identifier stream ("blocked"); SmartScreen then warns.
powershell -NoProfile -ExecutionPolicy Bypass -Command "if (Get-Item -LiteralPath '%PY%' -Stream Zone.Identifier -ErrorAction SilentlyContinue) { exit 3 }" >nul 2>&1
if not errorlevel 3 exit /b 0
echo.
echo  This folder is still marked as downloaded from the internet, so Windows may warn
echo  "Windows protected your PC" (More info ^> Run anyway) for its files.
echo  Better: right-click the downloaded zip ^> Properties ^> tick Unblock ^> OK, then Extract All again.
if defined CI exit /b 0
choice /c YN /m "Unblock this extracted folder now"
if errorlevel 2 exit /b 0
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%ROOT:~0,-1%' -Recurse | Unblock-File"
echo  Unblocked.
exit /b 0
