@echo off
REM Remove Cerberus Agent service. Must run as Administrator.
setlocal
set SVC=CerberusAgent

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo [ERROR] Please run this script as Administrator.
  pause
  exit /b 1
)

sc.exe stop %SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
sc.exe delete %SVC%

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v CerberusTray /f >nul 2>&1
taskkill /im Cerberus.Tray.exe /f >nul 2>&1

echo Service removed. Config and alert queue remain under %ProgramData%\Cerberus (delete manually if needed).
pause
endlocal