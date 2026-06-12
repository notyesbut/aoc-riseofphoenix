param(
    [string[]]$Keys = @('{ENTER}'),
    [int]$DelayMs = 300
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms

$sig = @'
[DllImport("user32.dll")]
public static extern bool SetForegroundWindow(System.IntPtr hWnd);

[DllImport("user32.dll")]
public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
'@
Add-Type -MemberDefinition $sig -Name Win32Window -Namespace Native

$proc = Get-Process AOCClient-Win64-Shipping -ErrorAction Stop |
    Where-Object { $_.MainWindowHandle -ne 0 } |
    Select-Object -First 1

if (-not $proc) {
    throw 'AOCClient-Win64-Shipping window not found'
}

[Native.Win32Window]::ShowWindow($proc.MainWindowHandle, 9) | Out-Null
[Native.Win32Window]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
Start-Sleep -Milliseconds $DelayMs

foreach ($key in $Keys) {
    Write-Host ("[sendkeys] {0}" -f $key)
    [System.Windows.Forms.SendKeys]::SendWait($key)
    Start-Sleep -Milliseconds $DelayMs
}
