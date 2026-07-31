<#
  install-connect-handlers.ps1 — teach Windows the rdp:// and ssh:// links the Connect
  buttons emit, so clicking one opens Remote Desktop / a terminal DIRECTLY. No download step.

  Run it as yourself — no admin rights needed. Everything is written under HKEY_CURRENT_USER
  and %LOCALAPPDATA%, so it affects only your account and uninstall-connect-handlers.ps1
  removes every trace.

      powershell -ExecutionPolicy Bypass -File install-connect-handlers.ps1

  FLEET DEPLOYMENT: the same keys work under HKLM for all users on a machine. Push
  connect-launch.ps1 to a fixed path (e.g. C:\ProgramData\RBZ\connect\) and write the same
  values under HKLM\Software\Classes via GPO Preferences or Intune. Nothing else changes —
  the webapp emits standard URLs and does not care how the scheme got registered.
#>
[CmdletBinding()]
param(
    # Where the launcher is installed to. Default keeps it per-user and needs no admin.
    [string] $InstallDir = (Join-Path $env:LOCALAPPDATA 'RBZ\connect')
)

$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'connect-launch.ps1'
if (-not (Test-Path $src)) { throw "connect-launch.ps1 not found next to this script ($PSScriptRoot)." }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$dest = Join-Path $InstallDir 'connect-launch.ps1'
Copy-Item $src $dest -Force
Write-Host "launcher installed -> $dest"

$pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# -WindowStyle Hidden so no console flashes up between the click and the client appearing.
$cmd = "`"$pwsh`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`" `"%1`""

foreach ($scheme in @(
    @{ name = 'rdp'; label = 'URL:Remote Desktop Protocol' },
    @{ name = 'ssh'; label = 'URL:Secure Shell Protocol' }
)) {
    $root = "HKCU:\Software\Classes\$($scheme.name)"
    New-Item -Path "$root\shell\open\command" -Force | Out-Null
    # The two values below are what make Windows treat this as a launchable URL scheme.
    Set-ItemProperty -Path $root -Name '(default)'   -Value $scheme.label
    Set-ItemProperty -Path $root -Name 'URL Protocol' -Value ''
    Set-ItemProperty -Path "$root\shell\open\command" -Name '(default)' -Value $cmd
    Write-Host "registered $($scheme.name)://"
}

Write-Host ''
Write-Host 'Done. Restart your browser, then the Connect buttons launch directly.' -ForegroundColor Green
Write-Host 'Test from Win+R:   rdp://10.0.212.3' -ForegroundColor DarkGray
Write-Host 'Undo any time:     uninstall-connect-handlers.ps1' -ForegroundColor DarkGray
