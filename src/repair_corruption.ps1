# Strip Read-tool line-number prefixes (possibly multiple per line) from corrupted .cs files
$ErrorActionPreference = 'Stop'
$base = $PSScriptRoot
$arrow = [char]0x2192
$p = '(?m)^\s*\d+' + $arrow

$files = Get-ChildItem -Path $base -Recurse -Filter *.cs -File
$totalFiles = 0
$totalLines = 0
foreach ($f in $files) {
    try {
        $text = [System.IO.File]::ReadAllText($f.FullName)
    } catch { continue }
    $before = ([regex]::Matches($text, $p)).Count
    if ($before -eq 0) { continue }
    # strip repeatedly to handle double/triple prefixes
    for ($i = 0; $i -lt 5; $i++) {
        $n = ([regex]::Matches($text, $p)).Count
        if ($n -eq 0) { break }
        $text = [regex]::Replace($text, $p, '')
    }
    [System.IO.File]::WriteAllText($f.FullName, $text, [System.Text.UTF8Encoding]::new($false))
    $totalFiles++
    $totalLines += $before
}
Write-Output "REPAIRED_FILES=$totalFiles REPAIRED_LINES=$totalLines"
