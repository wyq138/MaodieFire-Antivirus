$ErrorActionPreference = "Stop"
$src = "d:\桌面\All-files\Item file\耄耋安全软件\src\FireAntivirus.Host.WPF\bin\Release\selfcontained\win-x64"
$base = "d:\桌面\All-files\Item file\耄耋安全软件\msix"
$payload = "$base\payload_sc"

if (Test-Path $payload) { Remove-Item $payload -Recurse -Force }
New-Item -ItemType Directory -Force $payload | Out-Null

robocopy $src $payload /E /XF *.pdb *.lk *.locked *.log /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null

New-Item -ItemType Directory -Force "$payload\Assets" | Out-Null
$logos = @("StoreLogo","Square150x150Logo","Square71x71Logo","Square310x310Logo","Wide310x150Logo","SplashScreen")
foreach ($n in $logos) { Copy-Item "$payload\Resources\cat_logo.png" "$payload\Assets\$n.png" -Force }
Copy-Item "$payload\Resources\cat_icon.png" "$payload\Assets\Square44x44Logo.png" -Force
Copy-Item "$base\payload\AppxManifest.xml" "$payload\AppxManifest.xml" -Force

Write-Host ("manifest=" + (Test-Path "$payload\AppxManifest.xml"))
Write-Host ("exe=" + (Test-Path "$payload\FireAntivirus.exe"))
Write-Host ("assetsCount=" + (Get-ChildItem "$payload\Assets" -File).Count)
Write-Host ("files=" + (Get-ChildItem $payload -Recurse -File).Count)