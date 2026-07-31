<#
  uninstall-connect-handlers.ps1 — remove everything install-connect-handlers.ps1 added.
  Per-user only, no admin rights needed.

      powershell -ExecutionPolicy Bypass -File uninstall-connect-handlers.ps1
#>
[CmdletBinding()]
param([string] $InstallDir = (Join-Path $env:LOCALAPPDATA 'RBZ\connect'))

$ErrorActionPreference = 'Stop'

foreach ($scheme in @('rdp', 'ssh')) {
    $root = "HKCU:\Software\Classes\$scheme"
    if (Test-Path $root) {
        Remove-Item $root -Recurse -Force
        Write-Host "removed $scheme://"
    } else {
        Write-Host "$scheme:// was not registered"
    }
}

if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "removed $InstallDir"
}
Write-Host 'Done — the buttons fall back to the .rdp download.' -ForegroundColor Green
