$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Path "D:\fa-build" -Force | Out-Null
$sys = Join-Path $PSScriptRoot "FireAntivirusKrn.sys"
$certName = "FireAntivirus Driver"

if (-not (Test-Path $sys)) { Write-Host "[ERROR] FireAntivirusKrn.sys not found next to this script"; exit 1 }

Write-Host "=== [1/4] self-signed code signing certificate ==="
$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
if (-not $c) {
    $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$certName" -KeyUsage DigitalSignature -KeyExportPolicy Exportable -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10)
    Write-Host ("  created: " + $c.Thumbprint)
    if (-not $c) { Write-Host "[ERROR] certificate creation failed (must run as administrator)"; exit 1 }
} else {
    Write-Host ("  already exists: " + $c.Thumbprint)
}

$pfx = Join-Path D:\fa-build "fav_sign.pfx"
$pw = ConvertTo-SecureString -String "fav" -Force -AsPlainText
Export-PfxCertificate -Cert $c -FilePath $pfx -Password $pw | Out-Null
Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\LocalMachine\Root -Password $pw | Out-Null
Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -Password $pw | Out-Null
Remove-Item $pfx -Force
Write-Host "  installed into Trusted Root + Trusted Publisher"

Write-Host "=== [2/4] locating signtool (EWDK mounted) ==="
$signtool = $null
foreach ($v in (Get-Volume | Where-Object { $_.DriveLetter })) {
    $binRoot = "$($v.DriveLetter):\Program Files (x86)\Windows Kits\10\bin"
    if (Test-Path $binRoot) {
        $signtool = Get-ChildItem $binRoot -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "x64" } | Select-Object -First 1 -ExpandProperty FullName
        if ($signtool) { break }
    }
}

if ($signtool) {
    Write-Host ("  signtool: " + $signtool)
    Write-Host "=== [3/4] signing FireAntivirusKrn.sys ==="
    & $signtool sign /fd SHA256 /n "CN=$certName" $sys
    if ($LASTEXITCODE -ne 0) { Write-Host "  [WARN] sign failed - test-signing mode still allows unsigned drivers" }
} else {
    Write-Host "  [WARN] signtool not found - skipping sign (test-signing mode allows unsigned drivers)"
}

Write-Host "=== [4/4] enabling test signing mode ==="
bcdedit /set testsigning on
if ($LASTEXITCODE -ne 0) { Write-Host "  [ERROR] bcdedit failed (must run as administrator)"; exit 1 }

Write-Host ""
Write-Host "============================================================"
Write-Host "  DONE. Now REBOOT the computer."
Write-Host "  After reboot: run FireAntivirus_LoadDriver.cmd as admin"
Write-Host "  (future rebuilt drivers need NO signing steps anymore)"
Write-Host "============================================================"