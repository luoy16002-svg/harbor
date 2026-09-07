param([string]$EnginePath,[string]$ResultDirectory)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if(!$EnginePath){$EnginePath=Join-Path $projectRoot 'target/release/harbor-engine.exe'}
if(!$ResultDirectory){$ResultDirectory=Join-Path $projectRoot '.cache/native-tun'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'This isolated Wintun validation requires Windows administrator rights.'}
New-Item -ItemType Directory -Path $ResultDirectory -Force | Out-Null
$exitCode=1
try {
    $output=& $EnginePath --validate-tun 2>&1
    $exitCode=$LASTEXITCODE
    [IO.File]::WriteAllText((Join-Path $ResultDirectory 'output.txt'),($output -join "`n"),[Text.UTF8Encoding]::new($false))
    @{passed=($exitCode -eq 0);exitCode=$exitCode;test='isolated Wintun DNS packet and adapter removal';defaultRoutesModified=$false;systemProxyModified=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $ResultDirectory 'result.json') -Encoding utf8
} catch { @{passed=$false;error=$_.Exception.Message}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $ResultDirectory 'result.json') -Encoding utf8 }
exit $exitCode
