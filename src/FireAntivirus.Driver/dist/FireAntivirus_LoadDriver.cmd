@echo off
title FireAntivirus Kernel Driver Loader
echo ============================================================
echo  FireAntivirus Kernel Driver Loader
echo  (right-click - Run as administrator)
echo ============================================================
echo.
echo [1/3] Creating service...
sc create FireAntivirusKrn type= kernel start= demand binPath= "%~dp0FireAntivirusKrn.sys"
echo.
echo [2/3] Test-signing status:
bcdedit /enum {current} | findstr /i "testsigning"
if %errorlevel% neq 0 (
    echo.
    echo [!] Test signing seems OFF. For unsigned driver on x64:
    echo     run as admin: bcdedit /set testsigning on
    echo     then REBOOT the computer.
    echo.
)
echo [3/3] Starting driver...
sc start FireAntivirusKrn
echo.
echo ============================================================
echo  "STATE : 4 RUNNING" = driver loaded successfully.
echo  error 577 = signature problem (see step 2 + reboot)
echo  error 5   = not running as administrator
echo ============================================================
pause