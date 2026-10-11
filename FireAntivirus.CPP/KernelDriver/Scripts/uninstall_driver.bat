@echo off
REM 卸载驱动
setlocal
net session >nul 2>&1
if errorlevel 1 ( echo 请以管理员运行 & exit /b 1 )
sc stop FireAntivirusKernel 2>nul
sc delete FireAntivirusKernel 2>nul
bcdedit /set testsigning off
echo 已卸载。重启后生效。
pause
