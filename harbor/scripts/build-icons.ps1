# Render the editable SVG with Windows vector primitives, then embed PNG frames in ICO.
# No external image service, package, font, or image editor is required.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore,WindowsBase
$assetRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../desktop/Assets'))
[xml]$svg = Get-Content -LiteralPath (Join-Path $assetRoot 'harbor.svg') -Raw
function Brush([string]$value) { return [Windows.Media.BrushConverter]::new().ConvertFromString($value) }
function Render-Icon([int]$size, [string]$state) {
    $visual = [Windows.Media.DrawingVisual]::new()
    $draw = $visual.RenderOpen()
    $draw.PushTransform([Windows.Media.ScaleTransform]::new($size / 256.0, $size / 256.0))
    foreach ($shape in $svg.svg.ChildNodes) {
        switch ($shape.LocalName) {
            'rect' {
                $fill = if ($state -eq 'stopped') { '#586D63' } else { $shape.fill }
                $draw.DrawRoundedRectangle((Brush $fill), $null, [Windows.Rect]::new([double]$shape.x, [double]$shape.y, [double]$shape.width, [double]$shape.height), [double]$shape.rx, [double]$shape.rx)
            }
            'path' { $draw.DrawGeometry((Brush $shape.fill), $null, [Windows.Media.Geometry]::Parse($shape.d)) }
            'circle' { if ($size -ge 32) { $draw.DrawEllipse((Brush $shape.fill), $null, [Windows.Point]::new([double]$shape.cx, [double]$shape.cy), [double]$shape.r, [double]$shape.r) } }
        }
    }
    if ($state -eq 'connected') {
        $draw.DrawEllipse((Brush '#D9F2BA'), [Windows.Media.Pen]::new((Brush '#264E43'), 9), [Windows.Point]::new(205, 205), 31, 31)
    }
    $draw.Pop(); $draw.Close()
    $bitmap = [Windows.Media.Imaging.RenderTargetBitmap]::new($size, $size, 96, 96, [Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder = [Windows.Media.Imaging.PngBitmapEncoder]::new()
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream = [IO.MemoryStream]::new()
    $encoder.Save($stream)
    $bytes = $stream.ToArray(); $stream.Dispose()
    return ,$bytes
}
foreach ($state in @('brand', 'stopped', 'connected')) {
    $sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
    $frames = @($sizes | ForEach-Object { ,(Render-Icon $_ $state) })
    $name = if ($state -eq 'brand') { 'harbor' } else { "harbor-$state" }
    $stream = [IO.File]::Create((Join-Path $assetRoot "$name.ico"))
    $writer = [IO.BinaryWriter]::new($stream)
    try {
        $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Length)
        $offset = 6 + 16 * $sizes.Length
        for ($i = 0; $i -lt $sizes.Length; $i++) {
            $edge = if ($sizes[$i] -eq 256) { 0 } else { $sizes[$i] }
            $writer.Write([byte]$edge); $writer.Write([byte]$edge)
            $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([uint16]1); $writer.Write([uint16]32)
            $writer.Write([uint32]$frames[$i].Length); $writer.Write([uint32]$offset)
            $offset += $frames[$i].Length
        }
        foreach ($frame in $frames) { $writer.Write([byte[]]$frame) }
    } finally { $writer.Dispose(); $stream.Dispose() }
}
[IO.File]::WriteAllBytes((Join-Path $assetRoot 'harbor.png'), (Render-Icon 256 'brand'))
Write-Output 'Rendered Harbor app and tray icons at 16–256 px.'
