$ErrorActionPreference = 'Continue'
$out = "$env:SystemRoot\Temp\fa_load_result.txt"
Remove-Item $out -ErrorAction SilentlyContinue
$log = @()

$log += "=== testsigning status ==="
try { $log += (bcdedit /enum "{current}" | Select-String -Pattern "testsigning") } catch { $log += $_.Exception.Message }

$log += "=== start service ==="
$log += (sc.exe start FireAntivirusKrn 2>&1)

$log += "=== query service ==="
$log += (sc.exe query FireAntivirusKrn 2>&1)

$log += "=== done ==="
$log | Out-File -FilePath $out -Encoding UTF8