@echo off
REM Install Cerberus Agent service. Must run as Administrator.
setlocal
set SVC=CerberusAgent
set BIN=%~dp0Cerberus.Agent.exe

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [ERROR] Please run this script as Administrator.
  pause
  exit /b 1
)

if not exist "%BIN%" (
  echo [ERROR] Not found: %BIN%
  pause
  exit /b 1
)

sc.exe query %SVC% >nul 2>&1
if %errorlevel%==0 (
  echo Service exists. Stopping and removing old version...
  sc.exe stop %SVC% >nul 2>&1
  sc.exe delete %SVC% >nul 2>&1
  timeout /t 2 /nobreak >nul
)

echo Creating service...
sc.exe create %SVC% binPath= "\"%BIN%\"" start= auto DisplayName= "Cerberus Endpoint Guard" obj= "NT AUTHORITY\SYSTEM"
if %errorlevel% neq 0 ( echo [ERROR] Failed to create service. & pause & exit /b 1 )

sc.exe description %SVC% "Endpoint guard that blocks and monitors unauthorized remote-access tools."
sc.exe failure %SVC% reset= 86400 actions= restart/1000/restart/1000/restart/5000
sc.exe failureflag %SVC% 1

echo Starting service...
sc.exe start %SVC%

set TRAY=%~dp0Cerberus.Tray.exe
if exist "%TRAY%" (
  echo Stopping any existing Tray...
  taskkill /im Cerberus.Tray.exe /f >nul 2>&1
  echo Registering Tray autostart...
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v CerberusTray /t REG_SZ /d "\"%TRAY%\"" /f >nul
  echo Starting Tray...
  start "" "%TRAY%"
)

echo.
echo Done. Config: %ProgramData%\Cerberus\cerberus.json
echo Mode defaults to Audit (alert only). Switch to Enforce after validation.
echo A shield icon should appear in the system tray.
pause
endlocal