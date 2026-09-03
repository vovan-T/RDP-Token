Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'
$OutputDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) 'assets\icons'
[System.IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null

function New-IconCanvas {
    $bitmap = [System.Drawing.Bitmap]::new(32, 32, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::Transparent)
    return @($bitmap, $graphics)
}

function Save-Icon($name, $bitmap, $graphics) {
    $graphics.Dispose()
    $path = Join-Path $OutputDirectory "$name.png"
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
}

function Draw-Circle($graphics, $color) {
    $brush = [System.Drawing.SolidBrush]::new([System.Drawing.ColorTranslator]::FromHtml($color))
    $graphics.FillEllipse($brush, 2, 2, 28, 28)
    $brush.Dispose()
}

function New-InfoIcon {
    $canvas = New-IconCanvas; $bitmap = $canvas[0]; $graphics = $canvas[1]
    Draw-Circle $graphics '#1976D2'
    $font = [System.Drawing.Font]::new('Segoe UI', 18, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $brush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
    $format = [System.Drawing.StringFormat]::new(); $format.Alignment = 'Center'; $format.LineAlignment = 'Center'
    $graphics.DrawString('i', $font, $brush, [System.Drawing.RectangleF]::new(2, 1, 28, 28), $format)
    $format.Dispose(); $brush.Dispose(); $font.Dispose()
    Save-Icon 'info' $bitmap $graphics
}

function New-RefreshIcon {
    $canvas = New-IconCanvas; $bitmap = $canvas[0]; $graphics = $canvas[1]
    Draw-Circle $graphics '#2EAD59'
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, 3)
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $graphics.DrawBezier($pen, 7, 16, 7, 9, 13, 7, 23, 10)
    $graphics.DrawBezier($pen, 25, 16, 25, 23, 19, 25, 9, 22)
    $brush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
    $graphics.FillPolygon($brush, [System.Drawing.Point[]]@(
        [System.Drawing.Point]::new(23, 7), [System.Drawing.Point]::new(27, 12),
        [System.Drawing.Point]::new(20, 13)))
    $graphics.FillPolygon($brush, [System.Drawing.Point[]]@(
        [System.Drawing.Point]::new(9, 25), [System.Drawing.Point]::new(5, 20),
        [System.Drawing.Point]::new(12, 19)))
    $brush.Dispose(); $pen.Dispose()
    Save-Icon 'refresh' $bitmap $graphics
}

function New-SettingsIcon {
    $canvas = New-IconCanvas; $bitmap = $canvas[0]; $graphics = $canvas[1]
    Draw-Circle $graphics '#F39C12'
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, 3)
    for ($angle = 0; $angle -lt 360; $angle += 45) {
        $radians = $angle * [Math]::PI / 180
        $x1 = 16 + [Math]::Cos($radians) * 7
        $y1 = 16 + [Math]::Sin($radians) * 7
        $x2 = 16 + [Math]::Cos($radians) * 11
        $y2 = 16 + [Math]::Sin($radians) * 11
        $graphics.DrawLine($pen, [single]$x1, [single]$y1, [single]$x2, [single]$y2)
    }
    $graphics.DrawEllipse($pen, 10, 10, 12, 12)
    $pen.Dispose()
    Save-Icon 'settings' $bitmap $graphics
}

function New-LoginIcon {
    $canvas = New-IconCanvas; $bitmap = $canvas[0]; $graphics = $canvas[1]
    Draw-Circle $graphics '#2EAD59'
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, 3)
    $graphics.DrawRectangle($pen, 17, 8, 7, 16)
    $graphics.DrawLine($pen, 6, 16, 19, 16)
    $graphics.DrawLine($pen, 14, 11, 19, 16)
    $graphics.DrawLine($pen, 14, 21, 19, 16)
    $pen.Dispose()
    Save-Icon 'login' $bitmap $graphics
}

function New-LogoutIcon {
    $canvas = New-IconCanvas; $bitmap = $canvas[0]; $graphics = $canvas[1]
    Draw-Circle $graphics '#1976D2'
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, 3)
    $graphics.DrawRectangle($pen, 8, 8, 7, 16)
    $graphics.DrawLine($pen, 13, 16, 26, 16)
    $graphics.DrawLine($pen, 21, 11, 26, 16)
    $graphics.DrawLine($pen, 21, 21, 26, 16)
    $pen.Dispose()
    Save-Icon 'logout' $bitmap $graphics
}

function New-EmergencyIcon {
    $canvas = New-IconCanvas; $bitmap = $canvas[0]; $graphics = $canvas[1]
    Draw-Circle $graphics '#D32F2F'
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, 4)
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $graphics.DrawLine($pen, 9, 9, 23, 23)
    $pen.Dispose()
    Save-Icon 'emergency' $bitmap $graphics
}

function New-RenameIcon {
    $canvas = New-IconCanvas; $bitmap = $canvas[0]; $graphics = $canvas[1]
    Draw-Circle $graphics '#7E57C2'
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, 4)
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $graphics.DrawLine($pen, 10, 22, 22, 10)
    $brush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
    $graphics.FillPolygon($brush, [System.Drawing.Point[]]@(
        [System.Drawing.Point]::new(8, 24), [System.Drawing.Point]::new(11, 17),
        [System.Drawing.Point]::new(15, 21)))
    $brush.Dispose(); $pen.Dispose()
    Save-Icon 'rename' $bitmap $graphics
}

New-InfoIcon
New-RefreshIcon
New-SettingsIcon
New-LoginIcon
New-LogoutIcon
New-EmergencyIcon
New-RenameIcon

Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.png' | Sort-Object Name |
    Select-Object Name, Length
