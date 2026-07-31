<#
  connect-launch.ps1 — the local half of the Connect feature.

  A browser cannot start a program: that is the sandbox, and no amount of web code gets
  around it. What a browser CAN do is hand a URL to a scheme that Windows has registered.
  This script is what that scheme points at — it receives rdp:// or ssh:// and launches the
  real client, so a button in the webapp becomes a genuine one-click session.

      rdp://10.0.212.3        -> mstsc.exe /v:10.0.212.3
      rdp://10.0.212.3:3389   -> mstsc.exe /v:10.0.212.3:3389
      ssh://10.100.249.244    -> Windows Terminal (or a console) running ssh

  No credential is passed through here — mstsc and ssh prompt for their own, which is the
  whole point: Windows handles the secret, not the web app and not this script.

  SECURITY: the target is validated against a strict allow-list before it reaches a command
  line. Anything the app can be tricked into linking arrives here as an argument, so a target
  like  10.0.0.1" & calc & "  must never survive. Only host/IP characters are permitted, and
  the value is passed as a separate argument (never string-concatenated into a shell line).
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true, Position = 0)][string] $Uri)

$ErrorActionPreference = 'Stop'

function Fail([string] $msg) {
    # Interactive: the user clicked something, so a silent no-op would be baffling.
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [System.Windows.Forms.MessageBox]::Show($msg, 'Connect', 'OK', 'Warning') | Out-Null
    exit 1
}

# ---- parse: scheme://[user@]host[:port][/] -------------------------------------------------
if ($Uri -notmatch '^(?<scheme>rdp|ssh)://(?<target>[^/?#]+)/?$') {
    Fail("Unrecognised connect link:`n`n$Uri")
}
$scheme = $Matches['scheme'].ToLower()
$target = $Matches['target']

# ---- validate BEFORE it can reach a command line ------------------------------------------
# user@host, host, or host:port — letters, digits, dot, dash, underscore, one @ and one colon.
if ($target -notmatch '^[A-Za-z0-9_.\-]+(@[A-Za-z0-9_.\-]+)?(:[0-9]{1,5})?$') {
    Fail("Refusing to launch: the target contains characters that are not valid in a host name.`n`n$target")
}

$user = ''
$hostport = $target
if ($target.Contains('@')) {
    $parts = $target.Split('@', 2)
    $user = $parts[0]
    $hostport = $parts[1]
}

if ($scheme -eq 'rdp') {
    $mstsc = Join-Path $env:SystemRoot 'System32\mstsc.exe'
    if (-not (Test-Path $mstsc)) { Fail('Remote Desktop (mstsc.exe) was not found on this machine.') }
    # /v: takes host or host:port. Passed as its own argument — no shell string building.
    Start-Process -FilePath $mstsc -ArgumentList "/v:$hostport"
    exit 0
}

# ---- ssh: prefer Windows Terminal, fall back to a plain console ----------------------------
$sshHost = $hostport
$sshPort = ''
if ($hostport -match '^(?<h>[^:]+):(?<p>[0-9]+)$') {
    $sshHost = $Matches['h']; $sshPort = $Matches['p']
}

$sshArgs = @()
if ($sshPort) { $sshArgs += @('-p', $sshPort) }
$sshArgs += $(if ($user) { "$user@$sshHost" } else { $sshHost })

$wt = (Get-Command wt.exe -ErrorAction SilentlyContinue).Source
if ($wt) {
    Start-Process -FilePath $wt -ArgumentList (@('ssh') + $sshArgs)
    exit 0
}
$ssh = (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source
if (-not $ssh) { Fail('No SSH client found (looked for Windows Terminal and OpenSSH ssh.exe).') }
# -NoExit so the window stays up if the connection drops or the host key needs accepting.
Start-Process -FilePath 'powershell.exe' `
    -ArgumentList (@('-NoExit', '-NoProfile', '-Command', $ssh) + $sshArgs)
exit 0
