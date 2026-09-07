# Old release files may be removed only when their source version has a Git tag.
# Running applications are retained. Current release and build caches are untouched.
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
[xml]$project = Get-Content -LiteralPath (Join-Path $projectRoot 'desktop/Harbor.csproj') -Raw
$version = [string]$project.Project.PropertyGroup.Version
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot 'dist'))
if (!(Test-Path -LiteralPath $releaseRoot)) { return }
$running = @(Get-CimInstance Win32_Process -Filter "Name = 'Harbor.exe' OR Name = 'harbor-engine.exe'")
foreach ($entry in Get-ChildItem -LiteralPath $releaseRoot) {
    if ($entry.Name -notmatch '^Harbor-(\d+\.\d+\.\d+)-preview-(win-x64|source)(\.zip)?$') { continue }
    $old = $Matches[1] + '-preview'
    if ($old -eq $version) { continue }
    & git -C $projectRoot rev-parse --verify --quiet ('refs/tags/v' + $old) | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Output "Retained $($entry.Name): source version is not tagged in Git."; continue }
    $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $entry.FullName).Path)
    if (!$resolved.StartsWith($releaseRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup path escaped the release directory.' }
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Release cleanup does not follow reparse points.' }
    if ($entry.PSIsContainer) {
        if (@(Get-ChildItem -LiteralPath $resolved -Recurse -Force -Attributes ReparsePoint).Count) { throw 'Release directory contains a reparse point.' }
        if ($running | Where-Object { !$_.ExecutablePath -or $_.ExecutablePath.StartsWith($resolved + '\', [StringComparison]::OrdinalIgnoreCase) }) { Write-Output "Retained $($entry.Name): application may still be running."; continue }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    } else { Remove-Item -LiteralPath $resolved -Force }
    Write-Output "Removed $($entry.Name); source is preserved as v$old."
}
