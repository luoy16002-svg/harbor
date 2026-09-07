$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$archiveHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
$dllHash = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
$downloadUri = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
$archivePath = Join-Path $projectRoot '.cache/wintun-0.14.1.zip'
$dllPath = Join-Path $projectRoot 'vendor/wintun/bin/amd64/wintun.dll'

function Assert-WintunFile([string]$Path) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $dllHash) {
        throw 'Wintun DLL does not match the pinned official distribution.'
    }
    if ((Get-AuthenticodeSignature -LiteralPath $Path).Status -ne 'Valid') {
        throw 'Wintun Authenticode signature verification failed.'
    }
}

if (Test-Path -LiteralPath $dllPath) {
    Assert-WintunFile $dllPath
    Write-Output 'Wintun 0.14.1 is present and verified.'
    return
}

if (!(Test-Path -LiteralPath $archivePath)) {
    New-Item -ItemType Directory -Path (Split-Path $archivePath -Parent) -Force | Out-Null
    $download = $archivePath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        Invoke-WebRequest -Uri $downloadUri -OutFile $download -MaximumRedirection 0 -TimeoutSec 60
        if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveHash) {
            throw 'Wintun archive checksum verification failed.'
        }
        Move-Item -LiteralPath $download -Destination $archivePath
    } finally {
        if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Force }
    }
}

if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveHash) {
    throw 'Cached Wintun archive does not match the pinned checksum.'
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
New-Item -ItemType Directory -Path (Split-Path $dllPath -Parent) -Force | Out-Null
$extracted = Join-Path (Split-Path $dllPath -Parent) ([Guid]::NewGuid().ToString('N') + '.dll')
try {
    $entry = $archive.GetEntry('wintun/bin/amd64/wintun.dll')
    if (!$entry -or $entry.Length -ne 427552) { throw 'Expected AMD64 Wintun DLL is missing or has an unexpected size.' }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $extracted)
    Assert-WintunFile $extracted
    Move-Item -LiteralPath $extracted -Destination $dllPath
} finally {
    $archive.Dispose()
    if (Test-Path -LiteralPath $extracted) { Remove-Item -LiteralPath $extracted -Force }
}
Write-Output 'Prepared and verified Wintun 0.14.1 for Windows x64.'
