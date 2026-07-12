# Regenerates the tray/exe icons: a white Times New Roman "f" whose outline
# colour signals the tunnel state:
#   fortochka.ico      black outline  — exe icon + disconnected
#   st_connecting.ico  orange outline — connecting
#   st_connected.ico   green outline  — connected
# Windows only (System.Drawing). Run from the repo root:
#
#   pwsh ./tools/genicons.ps1
#   go run ./tools/mksyso cmd/fortochka/fortochka.ico cmd/fortochka/fortochka.syso cmd/fortochka/fortochka.manifest
#
param([string]$OutDir = "cmd/fortochka", [string]$PreviewDir = "")
Add-Type -AssemblyName System.Drawing

function New-Frame([int]$size, $outline) {
  $bmp = New-Object System.Drawing.Bitmap($size, $size)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $g.Clear([System.Drawing.Color]::Transparent)

  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $ff = New-Object System.Drawing.FontFamily('Times New Roman')
  $em = [float]($size * 1.15)
  $sf = New-Object System.Drawing.StringFormat
  $sf.Alignment = [System.Drawing.StringAlignment]::Center
  $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
  $rect = New-Object System.Drawing.RectangleF(0, 0, [float]$size, [float]$size)
  $path.AddString('f', $ff, [int][System.Drawing.FontStyle]::Regular, $em, $rect, $sf)

  $penW = [float]([Math]::Max(1.2, $size * 0.11))
  $pen = New-Object System.Drawing.Pen($outline, $penW)
  $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
  $g.DrawPath($pen, $path)
  $g.FillPath([System.Drawing.Brushes]::White, $path)

  $pen.Dispose(); $path.Dispose(); $g.Dispose()
  $ms = New-Object System.IO.MemoryStream
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
  $bmp.Dispose()
  return , $ms.ToArray()
}

function Save-Ico([string]$path, $outline) {
  $sizes = 16, 24, 32, 48
  $frames = @{}
  foreach ($s in $sizes) { $frames[$s] = (New-Frame $s $outline) }
  $out = New-Object System.IO.MemoryStream
  $bw = New-Object System.IO.BinaryWriter($out)
  $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
  $offset = 6 + 16 * $sizes.Count
  foreach ($s in $sizes) {
    $len = $frames[$s].Length
    $bw.Write([byte]$s); $bw.Write([byte]$s); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$len); $bw.Write([uint32]$offset)
    $offset += $len
  }
  foreach ($s in $sizes) { $bw.Write($frames[$s]) }
  $bw.Flush()
  [System.IO.File]::WriteAllBytes($path, $out.ToArray())
  $bw.Dispose()
  Write-Output ("{0}: {1} bytes" -f (Split-Path $path -Leaf), (Get-Item $path).Length)
}

$black = [System.Drawing.Color]::Black
$orange = [System.Drawing.Color]::FromArgb(255, 255, 165, 0)
$green = [System.Drawing.Color]::FromArgb(255, 46, 204, 64)

# white fill throughout; only the outline colour changes.
Save-Ico (Join-Path $OutDir 'fortochka.ico')     $black
Save-Ico (Join-Path $OutDir 'st_connecting.ico') $orange
Save-Ico (Join-Path $OutDir 'st_connected.ico')  $green

if ($PreviewDir) {
  foreach ($v in @(@('base', $black), @('connecting', $orange), @('connected', $green))) {
    $png = New-Frame 72 $v[1]
    [System.IO.File]::WriteAllBytes((Join-Path $PreviewDir ("prev_" + $v[0] + ".png")), $png)
  }
  Write-Output "previews written"
}
