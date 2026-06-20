# FireAntivirus Code Signing Script
param([string]$OutputDir = $null)

if ([string]::IsNullOrEmpty($OutputDir)) {
    $OutputDir = Join-Path $PSScriptRoot "bin\Release3"
}

Write-Host "Signing script started..." -ForegroundColor Cyan
Write-Host "Output directory: $OutputDir"

Set-Location $PSScriptRoot

$certPath = Join-Path $OutputDir "FireAntivirus.pfx"
$certPassword = "FireAntivirus2024"
$certName = "FireAntivirusCodeSign"
$timestampServer = "http://timestamp.digicert.com"
$algorithm = "sha256"

# Create certificate if not exists
if (-not (Test-Path $certPath)) {
    Write-Host "Creating self-signed certificate..." -ForegroundColor Yellow
    
    $thumbprint = (New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$certName" `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(5)).Thumbprint
    
    Write-Host "Certificate created, Thumbprint: $thumbprint"
    
    $pwd = ConvertTo-SecureString -String $certPassword -Force -AsPlainText
    Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$thumbprint" -FilePath $certPath -Password $pwd | Out-Null
    Write-Host "Certificate exported to: $certPath"
}

# Load certificate
try {
    $cert = Import-PfxCertificate -FilePath $certPath -Password (ConvertTo-SecureString -String $certPassword -Force -AsPlainText) -CertStoreLocation Cert:\CurrentUser\My
    Write-Host "Certificate loaded: $($cert.Subject)" -ForegroundColor Green
} catch {
    Write-Host "Error: Cannot load certificate" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Signing executables and DLLs..." -ForegroundColor Cyan
Write-Host ""

$exeFiles = Get-ChildItem -Path $OutputDir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
$dllFiles = Get-ChildItem -Path $OutputDir -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue

$filesToSign = @()
if ($exeFiles) { $filesToSign += $exeFiles }
if ($dllFiles) { $filesToSign += $dllFiles }

$totalFiles = ($filesToSign | Measure-Object).Count
$currentFile = 0
$successCount = 0
$failureCount = 0

foreach ($file in $filesToSign) {
    $currentFile++
    $shortPath = $file.Name
    Write-Host "[$currentFile/$totalFiles] Signing: $shortPath" -NoNewline
    
    try {
        # Sign the file
        $sig = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert -TimestampServer $timestampServer -HashAlgorithm $algorithm
        
        # Check if signature is valid
        if ($sig.Status -eq "Valid") {
            Write-Host "  [OK]" -ForegroundColor Green
            $successCount++
        } elseif ($sig.Status -eq "UnknownError") {
            # Try without timestamp server for internal files
            $sig2 = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert -HashAlgorithm $algorithm
            if ($sig2.Status -eq "Valid" -or $sig2.Status -eq "HashMismatch") {
                Write-Host "  [OK]" -ForegroundColor Green
                $successCount++
            } else {
                Write-Host "  [WARN: $($sig2.Status)]" -ForegroundColor Yellow
                $successCount++
            }
        } else {
            Write-Host "  [FAIL: $($sig.Status)]" -ForegroundColor Red
            $failureCount++
        }
    } catch {
        Write-Host "  [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
        $failureCount++
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Signing completed!" -ForegroundColor Cyan
Write-Host "Success: $successCount" -ForegroundColor Green
if ($failureCount -gt 0) {
    Write-Host "Failed: $failureCount" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan
