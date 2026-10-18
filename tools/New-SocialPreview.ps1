<#
.SYNOPSIS
    Renders the GitHub social preview image (1280x640 PNG) shown when the repository link is shared.
.DESCRIPTION
    Composes the title, tagline and a screenshot of the Results page with WPF, using the app's dark theme colors.
    Upload the result under the repository's Settings > General > Social preview.
.EXAMPLE
    powershell -STA -File tools\New-SocialPreview.ps1
#>
param(
    [string]$Screenshot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'docs\images\results-dark.png'),
    [string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'docs\images\social-preview.png')
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

$xaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Width="1280" Height="640" Background="#0B0F12" ClipToBounds="True">
    <!-- Soft teal glow behind the screenshot -->
    <Ellipse Width="900" Height="700" Margin="560,-40,-280,-60" Opacity="0.35">
        <Ellipse.Fill>
            <RadialGradientBrush>
                <GradientStop Color="#2014B8A6" Offset="0"/>
                <GradientStop Color="#0014B8A6" Offset="1"/>
            </RadialGradientBrush>
        </Ellipse.Fill>
    </Ellipse>

    <StackPanel Width="560" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="72,0,0,0">
        <Border Width="56" Height="6" CornerRadius="3" Background="#14B8A6" HorizontalAlignment="Left" Margin="0,0,0,22"/>
        <TextBlock Text="PowerSCAP" FontFamily="Segoe UI" FontWeight="Bold" FontSize="76" Foreground="#E3EAEE"/>
        <TextBlock Text="SCAP compliance scanner for Windows" FontFamily="Segoe UI" FontSize="27" Foreground="#2DD4BF" Margin="2,2,0,30"/>
        <StackPanel x:Name="Points" Margin="2,0,0,0"/>
        <StackPanel Orientation="Horizontal" Margin="2,30,0,0" x:Name="Chips"/>
    </StackPanel>

    <Border HorizontalAlignment="Left" VerticalAlignment="Center" Margin="668,0,0,0" CornerRadius="10"
            BorderBrush="#26343D" BorderThickness="1" Background="#121A1F" ClipToBounds="True">
        <Border.Effect>
            <DropShadowEffect BlurRadius="40" ShadowDepth="0" Opacity="0.6" Color="#000000"/>
        </Border.Effect>
        <Image x:Name="Shot" Width="700" Stretch="Uniform" RenderOptions.BitmapScalingMode="HighQuality"/>
    </Border>
</Grid>
'@
$root = [Windows.Markup.XamlReader]::Parse($xaml)

foreach ($line in @(
        'DISA STIG scans that match SCC rule for rule',
        'HTML reports, STIG Viewer .cklb, XCCDF / OVAL / ARF',
        'Desktop app or PowerShell; nothing to install',
        'Local and read-only: never changes the system')) {
    $row = New-Object Windows.Controls.StackPanel -Property @{ Orientation = 'Horizontal'; Margin = '0,0,0,12' }
    $dot = New-Object Windows.Shapes.Ellipse -Property @{ Width = 8; Height = 8; Margin = '0,0,14,0'; VerticalAlignment = 'Center' }
    $dot.Fill = [Windows.Media.BrushConverter]::new().ConvertFromString('#14B8A6')
    $text = New-Object Windows.Controls.TextBlock -Property @{ Text = $line; FontSize = 21; FontFamily = 'Segoe UI' }
    $text.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString('#C9D4DA')
    [void]$row.Children.Add($dot); [void]$row.Children.Add($text)
    [void]$root.FindName('Points').Children.Add($row)
}
foreach ($chip in 'PowerShell 5.1', 'C#', 'WPF', 'GPL-3.0') {
    $b = New-Object Windows.Controls.Border -Property @{ CornerRadius = 6; Padding = '12,5'; Margin = '0,0,10,0'; BorderThickness = 1 }
    $b.Background = [Windows.Media.BrushConverter]::new().ConvertFromString('#1A242B')
    $b.BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFromString('#26343D')
    $t = New-Object Windows.Controls.TextBlock -Property @{ Text = $chip; FontSize = 16; FontFamily = 'Segoe UI' }
    $t.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString('#8FA1AC')
    $b.Child = $t
    [void]$root.FindName('Chips').Children.Add($b)
}

# The Results page without the side rail and the "not elevated" banner of an unelevated capture.
$full = New-Object Windows.Media.Imaging.BitmapImage
$full.BeginInit(); $full.CacheOption = 'OnLoad'; $full.UriSource = [Uri](Resolve-Path $Screenshot).Path; $full.EndInit()
$crop = New-Object Windows.Int32Rect(224, 84, [Math]::Min(1040, $full.PixelWidth - 224), [Math]::Min(700, $full.PixelHeight - 84))
$root.FindName('Shot').Source = New-Object Windows.Media.Imaging.CroppedBitmap($full, $crop)

$root.Measure((New-Object Windows.Size(1280, 640)))
$root.Arrange((New-Object Windows.Rect(0, 0, 1280, 640)))
$root.UpdateLayout()
$bmp = New-Object Windows.Media.Imaging.RenderTargetBitmap(1280, 640, 96, 96, [Windows.Media.PixelFormats]::Pbgra32)
$bmp.Render($root)
$enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
$enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bmp))
$f = [IO.File]::Create($OutputPath)
try { $enc.Save($f) } finally { $f.Dispose() }
Get-Item $OutputPath
