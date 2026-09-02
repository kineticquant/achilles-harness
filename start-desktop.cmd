@echo off
setlocal
cd /d "%~dp0"

where bash >nul 2>&1
if %errorlevel%==0 (
  bash "%~dp0start-desktop.sh" %*
  exit /b %errorlevel%
)

echo This launcher needs Git Bash.
echo Install Git for Windows from https://git-scm.com/download/win
echo Then either:
echo   1. Double-click start-desktop.cmd again, or
echo   2. Open Git Bash in this folder and run:  ./start-desktop.sh
pause
exit /b 1
