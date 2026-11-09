param(
    [string]$SignPassword = $env:FA_SIGN_PASSWORD
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Path "D:\fa-build" -Force | Out-Null

# 签名密码参数化: 与 fa_sign_admin.ps1 共用 dist\sign_password.txt
$pwdFile = Join-Path $PSScriptRoot "sign_password.txt"
if (-not $SignPassword -and (Test-Path $pwdFile)) {
    $SignPassword = (Get-Content $pwdFile -Raw).Trim()
}
if (-not $SignPassword) {
    $SignPassword = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
    Set-Content -Path $pwdFile -Value $SignPassword -Encoding ASCII
}

$out = "D:\fa-build\fa_pnp_sign_result.txt"
$log = @()
$cat = "C:\ProgramData\FireAntivirus\pnp\FireAntivirusKrn.cat"
$inf = "C:\ProgramData\FireAntivirus\pnp\fa_pnp.inf"

$signtool = @(
    "E:\Program Files\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $signtool) {
    $signtool = Get-ChildItem "D:\Windows Kits\10\bin" -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $signtool) { $log += "FATAL: signtool not found"; $log | Out-File $out -Encoding UTF8; exit 1 }
$log += "signtool: $signtool"

$stage = Join-Path D:\fa-build "fapnp"
if (Test-Path (Join-Path $stage "fa_pnp.inf")) {
    Copy-Item (Join-Path $stage "FireAntivirusKrn.cat") $cat -Force
    Copy-Item (Join-Path $stage "FireAntivirusKrn.sys") "C:\ProgramData\FireAntivirus\pnp\FireAntivirusKrn.sys" -Force
    Copy-Item (Join-Path $stage "fa_pnp.inf") $inf -Force
    $log += "staged files synced to pnp dir"
} else {
    $log += "WARN: stage dir missing, using existing pnp files"
}

$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=FireAntivirus Driver" } | Select-Object -First 1
if (-not $c) { $log += "FATAL: cert not found"; $log | Out-File $out -Encoding UTF8; exit 1 }
$log += "cert: " + $c.Thumbprint

$pw = ConvertTo-SecureString -String $SignPassword -Force -AsPlainText
$pfx = Join-Path D:\fa-build "fav_sign.pfx"
Remove-Item $pfx -Force -ErrorAction SilentlyContinue
Export-PfxCertificate -Cert $c -FilePath $pfx -Password $pw | Out-Null
if (-not (Test-Path $pfx)) { $log += "FATAL: pfx export failed"; $log | Out-File $out -Encoding UTF8; exit 1 }
$log += "pfx exported"

& $signtool sign /fd SHA256 /f $pfx /p fav $cat 2>&1 | ForEach-Object { $log += "sign: $_" }
$log += "sign exit: $LASTEXITCODE"

$v = Get-AuthenticodeSignature $cat
$log += "verify cat: " + $v.Status

$log += "pnputil add-driver:"
& pnputil.exe /add-driver $inf /install 2>&1 | ForEach-Object { $log += "  $_" }
$log += "sc query:"
& sc.exe query FireAntivirusKrn 2>&1 | ForEach-Object { $log += "  $_" }

Remove-Item $pfx -Force -ErrorAction SilentlyContinue
$log | Out-File -FilePath $out -Encoding UTF8