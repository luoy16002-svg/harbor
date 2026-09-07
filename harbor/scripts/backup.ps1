param([string]$Destination)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repository = (& git -C $projectRoot rev-parse --show-toplevel)
if ($LASTEXITCODE -ne 0) { throw 'Initialize and commit a Git repository before creating a backup.' }
if (& git -C $repository status --porcelain) { throw 'Commit the current source changes before creating a complete Git backup.' }
if (!$Destination) { $Destination = Join-Path (Split-Path $repository -Parent) ('backups/' + (Split-Path $repository -Leaf) + '.bundle') }
$Destination = [IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force | Out-Null
$temporary = $Destination + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
try {
    & git -C $repository bundle create $temporary --all
    if ($LASTEXITCODE -ne 0) { throw 'Git bundle creation failed.' }
    & git -C $repository bundle verify $temporary
    if ($LASTEXITCODE -ne 0) { throw 'Git backup verification failed; previous backup is preserved.' }
    Move-Item -LiteralPath $temporary -Destination $Destination -Force
    Get-FileHash -LiteralPath $Destination -Algorithm SHA256
} finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
