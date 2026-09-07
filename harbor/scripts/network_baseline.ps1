param([Parameter(Mandatory=$true)][ValidateSet('before','after')][string]$Stage)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$directory=Join-Path $projectRoot '.cache/network-baseline'
New-Item -ItemType Directory -Path $directory -Force | Out-Null
function Digest([object]$Value) {
    if($Value -is [byte[]]){$bytes=$Value}else{$bytes=[Text.Encoding]::UTF8.GetBytes([string]$Value)}
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$bytes))
}
$settings=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$connections=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$state=[ordered]@{
    proxy=[ordered]@{enabled=$settings.ProxyEnable;server=Digest $settings.ProxyServer;bypass=Digest $settings.ProxyOverride;pac=Digest $settings.AutoConfigURL;connection=Digest $connections.DefaultConnectionSettings}
    routes=@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0','::/1','8000::/1')} | Sort-Object AddressFamily,DestinationPrefix,InterfaceIndex,NextHop | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
    dns=@(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
}
$json=$state|ConvertTo-Json -Depth 8
[IO.File]::WriteAllText((Join-Path $directory ($Stage+'.json')),$json,[Text.UTF8Encoding]::new($false))
if($Stage -eq 'after') {
    $original=[IO.File]::ReadAllText((Join-Path $directory 'before.json'))|ConvertFrom-Json
    $differences=@('proxy','routes','dns' | Where-Object {($original.$_|ConvertTo-Json -Depth 8 -Compress) -ne ($state.$_|ConvertTo-Json -Depth 8 -Compress)})
    $report=@{checkedAt=[DateTimeOffset]::UtcNow;unchanged=($differences.Count -eq 0);changedSections=$differences;test='Read-only comparison of Windows proxy, default/capture routes and DNS';mutationsPerformed=$false}
    $releaseEngine=Join-Path $projectRoot 'target/release/harbor-engine.exe'
    if(!(Test-Path -LiteralPath $releaseEngine)){
        [xml]$desktopProject=Get-Content -LiteralPath (Join-Path $projectRoot 'desktop/Harbor.csproj') -Raw
        $releaseEngine=Join-Path $projectRoot ('dist/Harbor-'+[string]$desktopProject.Project.PropertyGroup.Version+'-win-x64/harbor-engine.exe')
    }
    if(Test-Path -LiteralPath $releaseEngine){$report.engineSha256=(Get-FileHash -LiteralPath $releaseEngine -Algorithm SHA256).Hash.ToLowerInvariant()}
    $report|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $directory 'result.json') -Encoding utf8
    $report|ConvertTo-Json
    if($differences.Count -gt 0){throw 'Network state changed; inspect the local baseline before continuing.'}
} else { 'Read-only network baseline captured. Proxy and PAC values stored as hashes.' }
