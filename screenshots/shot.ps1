param(
    [Parameter(Mandatory)][string]$Out,
    [Parameter(Mandatory)][string]$Cmd,
    [int]$Cols = 130,
    [int]$Rows = 30,
    [int]$TimeoutSec = 240
)
# Opens a real console window, runs $Cmd in it, and saves a screenshot of that window to $Out.
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class W {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int attr, out RECT r, int size);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@
Add-Type -AssemblyName System.Drawing
[W]::SetProcessDPIAware() | Out-Null

$id = [guid]::NewGuid().ToString("N")
$flag = Join-Path $env:TEMP "shot-done-$id.flag"
$script = Join-Path $env:TEMP "shot-run-$id.ps1"
@"
`$Host.UI.RawUI.WindowTitle = 'Agent 18 - Windows PowerShell'
mode con: cols=$Cols lines=$Rows | Out-Null
`$Host.UI.RawUI.BackgroundColor = 'Black'
`$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host
Write-Host 'PS C:\Users\soham\Desktop\firewall-agent> ' -NoNewline
Write-Host '$($Cmd.Replace("'", "''"))'
$Cmd
New-Item '$flag' -ItemType File | Out-Null
"@ | Set-Content -Path $script -Encoding UTF8

$p = Start-Process conhost.exe -ArgumentList @('powershell.exe', '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', $script) -PassThru
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while (-not (Test-Path $flag) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path $flag)) { Write-Error "command did not finish in $TimeoutSec s"; Stop-Process -Id $p.Id -Force; exit 1 }
Start-Sleep -Seconds 2

$h = [IntPtr]::Zero
for ($i = 0; $i -lt 20 -and $h -eq [IntPtr]::Zero; $i++) {
    $p.Refresh(); $h = $p.MainWindowHandle
    if ($h -eq [IntPtr]::Zero) {
        $ps = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" | Where-Object Name -eq 'powershell.exe' | Select-Object -First 1
        if ($ps) { $h = (Get-Process -Id $ps.ProcessId).MainWindowHandle }
    }
    if ($h -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 300 }
}
if ($h -eq [IntPtr]::Zero) { Write-Error "no window handle"; Stop-Process -Id $p.Id -Force; exit 1 }

$r = New-Object W+RECT
[W]::GetWindowRect($h, [ref]$r) | Out-Null
[W]::MoveWindow($h, 60, 40, $r.Right - $r.Left, $r.Bottom - $r.Top, $true) | Out-Null   # fully on screen, own size
[W]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Seconds 1
$v = New-Object W+RECT
[W]::DwmGetWindowAttribute($h, 9, [ref]$v, 16) | Out-Null          # visible frame, without the invisible shadow border
$w = $v.Right - $v.Left; $ht = $v.Bottom - $v.Top
$bmp = New-Object System.Drawing.Bitmap $w, $ht
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($v.Left, $v.Top, 0, 0, $bmp.Size)
$g.Dispose()
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -eq 'Agent 18 - Windows PowerShell' } | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item $flag, $script -ErrorAction SilentlyContinue
"saved $Out ($w x $ht)"
