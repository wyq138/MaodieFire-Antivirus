@echo off
REM ============================================================
REM FireAntivirus Kernel Driver - 自签名(黑签名)安装脚本
REM 
REM 用法: 以管理员身份运行此脚本
REM   1. 启用 Windows 测试签名模式 (需要重启)
REM   2. 生成自签名证书 (FireAntivirusTestCert.cer)
REM   3. 将证书导入受信任根证书存储
REM   4. 用 signtool 给 FireAntivirusDriver.sys / INF 签名
REM   5. 安装驱动
REM ============================================================

setlocal enabledelayedexpansion

echo [1/6] 检查管理员权限...
net session >nul 2>&1
if errorlevel 1 (
    echo !!!! 请以管理员身份运行此脚本 !!!!
    pause
    exit /b 1
)

echo [2/6] 启用测试签名模式 (TESTSIGNING)...
bcdedit /set testsigning on
if errorlevel 1 (
    echo [WARN] bcdedit 失败,请检查驱动是否已启用测试签名
) else (
    echo [INFO] 测试签名模式已启用,安装驱动前需要重启一次系统
    echo [INFO] 如果是首次安装,请重启后重新运行本脚本继续
)

echo [3/6] 生成自签名证书...
powershell -NoProfile -Command ^
    "$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=FireAntivirus Test Signer' -CertStoreLocation Cert:\CurrentUser\My; " ^
    "Export-Certificate -Cert $cert -FilePath '%~dp0FireAntivirusTestCert.cer'; " ^
    "Export-PfxCertificate -Cert $cert -FilePath '%~dp0FireAntivirusTestCert.pfx' -Password (ConvertTo-SecureString -String 'FireAntivirus123!' -Force -AsPlainText); " ^
    "Write-Host 'Certificate thumbprint:' $cert.Thumbprint"
if errorlevel 1 (
    echo [ERROR] 证书生成失败
    pause
    exit /b 1
)

echo [4/6] 导入证书到受信任根...
certutil -user -addstore Root "%~dp0FireAntivirusTestCert.cer" >nul
certutil -user -addstore TrustedPublisher "%~dp0FireAntivirusTestCert.cer" >nul
echo [OK] 证书已导入

echo [5/6] 定位并签名驱动...
set DRIVER_FILE=
for %%f in ("%~dp0..\..\build\FireAntivirusDriver.sys"
            "%~dp0..\..\build\x64\Release\FireAntivirusDriver.sys"
            "%~dp0Driver\FireAntivirusDriver.sys") do (
    if exist %%f set DRIVER_FILE=%%f
)
if "%DRIVER_FILE%"=="" (
    echo [WARN] 未找到编译好的 FireAntivirusDriver.sys
    echo [INFO] 请先使用 WDK 编译驱动,或将 .sys 文件放到 Driver\ 目录下
    echo [INFO] 如果暂时不想使用驱动,可以跳过此步(引擎会降级到用户模式保护)
) else (
    echo [INFO] 找到驱动: %DRIVER_FILE%
    where signtool >nul 2>&1
    if errorlevel 1 (
        echo [WARN] signtool 未找到,请安装 Windows SDK SignTool
        echo        或直接双击证书文件 -> 安装 -> 放入 受信任的根证书颁发机构
    ) else (
        echo [INFO] 使用 signtool 签名...
        signtool sign /fd sha256 /a "%DRIVER_FILE%"
        echo [OK] 签名完成
    )
)

echo [6/6] 完成
echo ============================================
echo 首次启用测试签名需要重启电脑
echo 重启后可通过 devcon install 或 sc create 安装驱动
echo 详细说明请查看 README.txt
echo ============================================
pause
