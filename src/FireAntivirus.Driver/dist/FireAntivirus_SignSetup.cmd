@echo off
title FireAntivirus Driver Signing Setup (run ONCE, then reboot)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Please right-click this file and choose "Run as administrator".
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0FireAntivirus_SignSetup.ps1"

echo.
echo ================= window stays open - press any key ================
pause