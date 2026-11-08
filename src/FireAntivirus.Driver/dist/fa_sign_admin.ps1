$ErrorActionPreference = "Continue"
$out = "$env:TEMP\fa_sign_admin_result.txt"
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

$pw = ConvertTo-SecureString -String "fav" -Force -AsPlainText
$pfx = Join-Path $env:TEMP "fav_sign.pfx"
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