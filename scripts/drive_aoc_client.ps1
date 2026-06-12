param(
    [int]$DurationSeconds = 110,
    [int]$InitialDelaySeconds = 12,
    [int]$DelayMs = 250,
    [string]$LogDir = ''
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms

$sig = @'
using System;
using System.Runtime.InteropServices;

public static class AoCClientWin32 {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);

  public struct RECT {
    public int Left;
    public int Top;
    public int Right;
    public int Bottom;
  }
}
'@
Add-Type -TypeDefinition $sig

function Get-AoCWindow {
    Get-Process AOCClient-Win64-Shipping -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 } |
        Select-Object -First 1
}

function Focus-AoCWindow {
    $proc = Get-AoCWindow
    if (-not $proc) { return $null }
    [AoCClientWin32]::ShowWindow($proc.MainWindowHandle, 9) | Out-Null
    [AoCClientWin32]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
    Start-Sleep -Milliseconds $DelayMs
    return $proc
}

function Send-AoCKey([string]$Key) {
    $proc = Focus-AoCWindow
    if (-not $proc) { return }
    Write-Host ("[drive] key {0}" -f $Key)
    [System.Windows.Forms.SendKeys]::SendWait($Key)
    Start-Sleep -Milliseconds $DelayMs
}

function Click-AoCRelative([double]$XFrac, [double]$YFrac, [string]$Name) {
    $proc = Focus-AoCWindow
    if (-not $proc) { return }

    $rect = New-Object AoCClientWin32+RECT
    [AoCClientWin32]::GetWindowRect($proc.MainWindowHandle, [ref]$rect) | Out-Null
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -le 0 -or $height -le 0) { return }

    $x = [int]($rect.Left + ($width * $XFrac))
    $y = [int]($rect.Top + ($height * $YFrac))
    [AoCClientWin32]::SetCursorPos($x, $y) | Out-Null
    Start-Sleep -Milliseconds 100
    [AoCClientWin32]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 80
    [AoCClientWin32]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
    Write-Host ("[drive] click {0} {1},{2}" -f $Name, $x, $y)
    Start-Sleep -Milliseconds $DelayMs
}

function Test-LatestServerLog([string]$Pattern) {
    if (-not $LogDir) { return $false }
    if (-not (Test-Path $LogDir)) { return $false }
    $log = Get-ChildItem -Path $LogDir -Filter 'emu-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $log) { return $false }
    return [bool](Select-String -Path $log.FullName -Pattern $Pattern -Quiet -ErrorAction SilentlyContinue)
}

$deadline = (Get-Date).AddSeconds($DurationSeconds)
Start-Sleep -Seconds $InitialDelaySeconds

foreach ($i in 1..3) {
    if ((Get-Date) -gt $deadline) { exit 0 }
    Send-AoCKey '{ENTER}'
    Start-Sleep -Seconds 8
}

while ((Get-Date) -lt $deadline -and -not (Test-LatestServerLog 'GetCharacters world=')) {
    if ((Get-Date) -gt $deadline) { exit 0 }
    Click-AoCRelative 0.215 0.433 'realm-row'
    Click-AoCRelative 0.801 0.650 'select-realm'
    Start-Sleep -Seconds 3
}

Start-Sleep -Seconds 4

while ((Get-Date) -lt $deadline -and -not (Test-LatestServerLog 'Play char=')) {
    if ((Get-Date) -gt $deadline) { exit 0 }
    Click-AoCRelative 0.770 0.390 'character-row'
    Click-AoCRelative 0.500 0.955 'play'
    Start-Sleep -Seconds 4
}
