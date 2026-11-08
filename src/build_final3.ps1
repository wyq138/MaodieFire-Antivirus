param([switch]$ProbeOnly)
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Path "D:\fa-build" -Force | Out-Null

# One-click driver build using the mounted EWDK ISO (CD-ROM with LaunchBuildEnv.cmd).
# Builds ONLY FireAntivirusKrn.sys. Quoting: space-bearing /p: switches go through an
# ASCII response file (PowerShell 5.1 eats closing quotes for native args ending with '\').

$drive = $null
foreach ($v in (Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'CD-ROM' })) {
    if ($v.DriveLetter -and (Test-Path ("{0}:\LaunchBuildEnv.cmd" -f $v.DriveLetter))) {
        $drive = [string]$v.DriveLetter
        break
    }
}
if (-not $drive) { Write-Output "FATAL: no mounted EWDK (CD-ROM containing LaunchBuildEnv.cmd)"; exit 1 }
$bt   = "${drive}:\Program Files\Microsoft Visual Studio\18\BuildTools"
$kits = "${drive}:\Program Files\Windows Kits\10"
Write-Output "[iso] ${drive}:"

$msbuild = @("$bt\MSBuild\Current\Bin\amd64\MSBuild.exe", "$bt\MSBuild\Current\Bin\MSBuild.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1

$vcTargets = @('v180','v170','v160') |
    ForEach-Object { Join-Path $bt "MSBuild\Microsoft\VC\$_" } |
    Where-Object { Test-Path (Join-Path $_ 'Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0') } |
    Select-Object -First 1

$msvc = Get-ChildItem (Join-Path $bt 'VC\Tools\MSVC') -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1

$wdkVer = @('10.0.28000.0','10.0.26100.0','10.0.22621.0') |
    Where-Object { Test-Path (Join-Path $kits "Include\$_\km\fltkernel.h") } | Select-Object -First 1

if ($ProbeOnly) {
    Write-Output "msbuild   = $msbuild"
    Write-Output "vcTargets = $vcTargets"
    Write-Output "vctools   = $($msvc.Name)"
    Write-Output "wdkver    = $wdkVer"
    Write-Output "fltmgr    = $(Test-Path (Join-Path $kits "Lib\$wdkVer\km\x64\FltMgr.lib"))"
    exit 0
}

if (-not $msbuild)   { Write-Output "FATAL: MSBuild.exe not found under $bt"; exit 1 }
if (-not $vcTargets) { Write-Output "FATAL: WindowsKernelModeDriver10.0 toolset not found under $bt"; exit 1 }
if (-not $msvc)      { Write-Output "FATAL: no MSVC toolset under $bt"; exit 1 }
if (-not $wdkVer)    { Write-Output "FATAL: no kernel-mode WDK headers under $kits"; exit 1 }

$projDir   = Join-Path $PSScriptRoot 'FireAntivirus.Driver\bld'
$proj      = Join-Path $projDir 'FireAntivirusKrn.vcxproj'
$srcDriver = Join-Path $PSScriptRoot 'FireAntivirus.Driver'
if (-not (Test-Path $proj)) { Write-Output "FATAL: project missing at $proj"; exit 1 }

$stage  = Join-Path 'D:\fa-build' 'fabuild'
$outDir = (Join-Path $stage 'out') + '\'
$intDir = (Join-Path $stage 'int') + '\'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
New-Item -ItemType Directory -Path $intDir -Force | Out-Null

$rsp = Join-Path $stage 'fa_build.rsp'
$rspLines = @(
    ('"/p:VCTargetsPath=' + $vcTargets + '\\"'),
    ('"/p:WDKContentRoot=' + $kits + '\\"'),
    ('"/p:WindowsSdkDir=' + $kits + '\\"'),
    ('"/p:WindowsSDKVersion=' + $wdkVer + '\\"'),
    ('"/p:VCToolsInstallDir=' + $msvc.FullName + '\\"'),
    ('"/p:VCToolsVersion=' + $msvc.Name + '"'),
    ('/p:WDKBuildFolder=' + $wdkVer),
    '/p:TargetVersion=Windows10',
    ('/p:TargetPlatformVersion=' + $wdkVer),
    ('/p:WindowsTargetPlatformVersion=' + $wdkVer),
    '/p:Inf2Cat=false',
    '/p:SignMode=Off',
    '/p:SpectreMitigation=false',
    '/m',
    '/v:m',
    '/nologo'
)
Set-Content -LiteralPath $rsp -Value $rspLines -Encoding Ascii

Write-Output "[msbuild] $msbuild"
Write-Output "[vctargets] $vcTargets"
Write-Output "[vctools] $($msvc.Name)"
Write-Output "[wdk] $kits ($wdkVer)"
Write-Output "[stage] $stage"

& $msbuild $proj ("@" + $rsp) 2>&1 | Select-Object -Last 45

if ($LASTEXITCODE -ne 0) {
    Write-Output ('[FAILED] msbuild exit code ' + $LASTEXITCODE + ' - see errors above')
    exit 1
}

$sys = Get-ChildItem (Join-Path $stage 'out') -Filter 'FireAntivirusKrn.sys' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sys) {
    $sys = Get-ChildItem $projDir -Recurse -Filter 'FireAntivirusKrn.sys' -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $sys) { Write-Output '[FAILED] msbuild ok but no FireAntivirusKrn.sys produced'; exit 1 }

$dist = Join-Path $srcDriver 'dist'
New-Item -ItemType Directory -Path $dist -Force | Out-Null
$distSys = Join-Path $dist 'FireAntivirusKrn.sys'
if ((Test-Path $distSys) -and ((Get-Item $distSys).LastWriteTime -gt $sys.LastWriteTime)) {
    Write-Output '[skip] dist\FireAntivirusKrn.sys is newer (already signed) - not overwriting'
} else {
    Copy-Item $sys.FullName $distSys -Force
    Write-Output ('[copy] fresh sys -> dist (' + [math]::Round($sys.Length/1KB,1) + ' KB)')
}
$size = [math]::Round((Get-Item $distSys).Length / 1KB, 1)
Write-Output '==================================================='
Write-Output "[SUCCESS] dist\FireAntivirusKrn.sys ($size KB) packaged!"
Write-Output '==================================================='