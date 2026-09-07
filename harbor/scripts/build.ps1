param([switch]$Interop,[switch]$Visual)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$previousCargoHome=$env:CARGO_HOME
Push-Location -LiteralPath $projectRoot
try {
    $env:CARGO_HOME=Join-Path $projectRoot '.cache/cargo'
    & (Join-Path $PSScriptRoot 'prepare-wintun.ps1')
    cargo fmt -p harbor-engine --check
    if($LASTEXITCODE -ne 0){throw 'Rust formatting failed'}
    cargo clippy --all-targets -- -D warnings
    if($LASTEXITCODE -ne 0){throw 'Rust checks failed'}
    $rustLog=@(cargo test --tests 2>&1);$rustExit=$LASTEXITCODE;$rustLog | ForEach-Object {"$_"}
    if($rustExit -ne 0){throw 'Rust tests failed'}
    $desktopLog=@(dotnet run --project tests/DesktopChecks/DesktopChecks.csproj 2>&1);$desktopExit=$LASTEXITCODE;$desktopLog | ForEach-Object {"$_"}
    if($desktopExit -ne 0){throw 'Desktop checks failed'}
    python scripts/check_advisories.py
    if($LASTEXITCODE -ne 0){throw 'Dependency advisory check failed'}
    python scripts/check_nuget.py
    if($LASTEXITCODE -ne 0){throw 'NuGet advisory check failed'}
    cargo build --release
    if($LASTEXITCODE -ne 0){throw 'Release engine build failed'}
    [xml]$desktopProject=Get-Content -LiteralPath 'desktop/Harbor.csproj' -Raw
    $version=[string]$desktopProject.Project.PropertyGroup.Version
    $package=Join-Path $projectRoot ('dist/Harbor-'+$version+'-win-x64')
    dotnet publish desktop/Harbor.csproj -c Release -r win-x64 --self-contained true -p:RuntimeFrameworkVersion=9.0.19 -p:PublishSingleFile=false -p:DebugType=None -o $package
    if($LASTEXITCODE -ne 0){throw 'Desktop publish failed'}
    Copy-Item -LiteralPath 'target/release/harbor-engine.exe' -Destination $package
    Copy-Item -LiteralPath 'desktop/Harbor-Local.cmd' -Destination $package
    Copy-Item -LiteralPath 'vendor/wintun/bin/amd64/wintun.dll' -Destination $package
    $signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $package 'wintun.dll')
    if($signature.Status -ne 'Valid'){throw 'Wintun signature verification failed'}
    Copy-Item -LiteralPath 'README.md','LICENSE','THIRD-PARTY.md' -Destination $package
    Copy-Item -LiteralPath 'docs' -Destination $package -Recurse -Force
    $licenses=Join-Path $package 'licenses';New-Item -ItemType Directory -Path $licenses -Force | Out-Null
    Copy-Item -LiteralPath 'vendor/wintun/LICENSE.txt' -Destination (Join-Path $licenses 'Wintun.txt')
    python scripts/collect_licenses.py $package
    if($LASTEXITCODE -ne 0){throw 'License collection failed'}
    if($Interop){$previousTestEngine=$env:HARBOR_TEST_ENGINE;try{$env:HARBOR_TEST_ENGINE=Join-Path $package 'harbor-engine.exe';python tests/interop.py;if($LASTEXITCODE -ne 0){throw 'Protocol interop failed'}}finally{$env:HARBOR_TEST_ENGINE=$previousTestEngine}}
    $previousTestEngine=$env:HARBOR_TEST_ENGINE
    try{$env:HARBOR_TEST_ENGINE=Join-Path $package 'harbor-engine.exe';python tests/control_plane.py;if($LASTEXITCODE -ne 0){throw 'Control-plane checks failed'}}finally{$env:HARBOR_TEST_ENGINE=$previousTestEngine}
    if($Visual){
        $visualDirectory=Join-Path $projectRoot '.cache/visual-final'
        $visualProcess=Start-Process -FilePath (Join-Path $package 'Harbor.exe') -ArgumentList @('--visual-check',('"'+$visualDirectory+'"')) -WindowStyle Hidden -PassThru
        if(-not $visualProcess.WaitForExit(55000)){throw 'Isolated desktop validation did not finish in time'}
        if($visualProcess.ExitCode -ne 0){throw 'Desktop validation failed'}
        $visualReport=Get-Content -LiteralPath (Join-Path $visualDirectory 'visual-check.json') -Raw -Encoding UTF8|ConvertFrom-Json
        if(-not $visualReport.passed -or $visualReport.applicationSha256 -ne (Get-FileHash -LiteralPath (Join-Path $package 'Harbor.dll') -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'Desktop validation evidence does not match the package'}
    }
    $rustCount=([regex]::Matches(($rustLog -join "`n"),'test result: ok\. (\d+) passed')|ForEach-Object {[int]$_.Groups[1].Value}|Measure-Object -Sum).Sum
    $desktopCount=[int][regex]::Match(($desktopLog -join "`n"),'(\d+) checks passed').Groups[1].Value
    if($rustCount -lt 1 -or $desktopCount -lt 1){throw 'Unable to count completed checks'}
    $checkReport=@{checkedAt=[DateTimeOffset]::UtcNow;passed=$true;rustTests=$rustCount;desktopChecks=$desktopCount;strictClippy=$true;engineSha256=(Get-FileHash -LiteralPath (Join-Path $package 'harbor-engine.exe') -Algorithm SHA256).Hash.ToLowerInvariant();applicationSha256=(Get-FileHash -LiteralPath (Join-Path $package 'Harbor.dll') -Algorithm SHA256).Hash.ToLowerInvariant();cargoLockSha256=(Get-FileHash -LiteralPath 'Cargo.lock' -Algorithm SHA256).Hash.ToLowerInvariant()}
    $checkReport|ConvertTo-Json|Set-Content -LiteralPath '.cache/test-suite.json' -Encoding utf8
    python scripts/collect_evidence.py $package
    if($LASTEXITCODE -ne 0){throw 'Evidence collection failed'}
    python scripts/package.py
    if($LASTEXITCODE -ne 0){throw 'Packaging failed'}
    & (Join-Path $PSScriptRoot 'clean-releases.ps1')
} finally {Pop-Location;$env:CARGO_HOME=$previousCargoHome}
