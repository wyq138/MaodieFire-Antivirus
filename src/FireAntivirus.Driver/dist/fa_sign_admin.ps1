param(
    [string]$SignPassword = $env:FA_SIGN_PASSWORD
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Path "D:\fa-build" -Force | Out-Null

# 签名密码参数化: 环境变量 FA_SIGN_PASSWORD > dist\sign_password.txt（首次随机生成）
$pwdFile = Join-Path $PSScriptRoot "sign_password.txt"
if (-not $SignPassword -and (Test-Path $pwdFile)) {
    $SignPassword = (Get-Content $pwdFile -Raw).Trim()
}
if (-not $SignPassword) {
    $SignPassword = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
    Set-Content -Path $pwdFile -Value $SignPassword -Encoding ASCII
}

$out = "D:\fa-build\fa_sign_admin_result.txt"
$log = @()
$dist = $PSScriptRoot
$sys = Join-Path $dist "FireAntivirusKrn.sys"
$certName = "FireAntivirus Driver"

$signtool = @(
    "E:\Program Files\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $signtool) {
    $signtool = Get-ChildItem "D:\Windows Kits\10\bin" -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $signtool) {
    $signtool = Get-ChildItem "G:\Windows Kits\10\bin" -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $signtool) {
    $log += "FATAL: signtool not found (checked E:/D:/G: Windows Kits)"
    $log | Out-File $out -Encoding UTF8
    exit 1
}
$log += "signtool: $signtool"

$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
if ($c) { $log += "existing cert: " + $c.Thumbprint } else { $log += "no existing cert" }

$pw = ConvertTo-SecureString -String $SignPassword -Force -AsPlainText
$pfx = Join-Path D:\fa-build "fav_sign.pfx"
Remove-Item $pfx -Force -ErrorAction SilentlyContinue

if ($c) {
    try {
        Export-PfxCertificate -Cert $c -FilePath $pfx -Password $pw -ErrorAction Stop | Out-Null
        $log += "export OK from existing cert"
    } catch {
        $log += "export FAILED: " + $_.Exception.Message
        $c = $null
    }
}

if (-not $c) {
    $log += "recreating code signing certificate"
    $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$certName" -KeyUsage DigitalSignature -KeyExportPolicy Exportable -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10)
    if (-not $c) { $log += "FATAL: cert creation failed"; $log | Out-File $out -Encoding UTF8; exit 1 }
    $log += "new cert: " + $c.Thumbprint
    Export-PfxCertificate -Cert $c -FilePath $pfx -Password $pw | Out-Null
    if (-not (Test-Path $pfx)) { $log += "FATAL: export failed again"; $log | Out-File $out -Encoding UTF8; exit 1 }
    Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\LocalMachine\Root -Password $pw | Out-Null
    Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -Password $pw | Out-Null
    $log += "installed into Root + TrustedPublisher"
}

& $signtool sign /fd SHA256 /f $pfx /p fav $sys 2>&1 | ForEach-Object { $log += "sign: $_" }
$log += "sign exit: $LASTEXITCODE"

$v = Get-AuthenticodeSignature $sys
$log += "verify dist sys: " + $v.Status

Copy-Item $sys "C:\ProgramData\FireAntivirus\FireAntivirusKrn.sys" -Force
$v2 = Get-AuthenticodeSignature "C:\ProgramData\FireAntivirus\FireAntivirusKrn.sys"
$log += "verify deployed sys: " + $v2.Status

Remove-Item $pfx -Force -ErrorAction SilentlyContinue
$log | Out-File -FilePath $out -Encoding UTF8