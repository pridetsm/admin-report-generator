<#
  check_log_size_t24.ps1  -  track T24's JBoss server.log size for the windows_exporter
  textfile collector.

  WHY server.log AND NOT gc.log:
    gc.log rotates at 5x3MB (~15MB max) - self-capped, never a real disk risk. server.log
    has no stated rotation policy on this box and is the one that can grow unbounded and
    actually threaten disk space, so it's the log worth watching. If a second log later
    needs the same treatment, point another copy of this script at it with -FilePath /
    -Label / -OutFile changed - the metric schema is generic (log_file_size_bytes{file=...}),
    so a second file becomes a second row, not a new metric.

  Emits:
      log_file_size_bytes{file="<Label>"} <bytes>
      log_check_success{file="<Label>"}   1 = file found / 0 = missing
      log_check_timestamp_seconds         when this ran

  Deploy: Task Scheduler, same cadence as the backup checks (every few minutes is plenty -
  a log file's size does not need second-by-second tracking). Run as an account that can
  read the T24 install path and write this host's windows_exporter textfile dir.
    powershell -ExecutionPolicy Bypass -File check_log_size_t24.ps1
#>
[CmdletBinding()]
param(
    [string]$FilePath    = 'C:\Temenos\R23\JBoss\standalone\log\server.log',
    [string]$Label       = 'server.log',                                          # value of the file= label
    [string]$TextfileDir = 'C:\Program Files\windows_exporter\textfile_inputs',   # this host's windows_exporter textfile dir
    [string]$OutFile     = 't24_log_size.prom'
)

$ErrorActionPreference = 'Stop'
$outPath = Join-Path $TextfileDir $OutFile
$tmpPath = "$outPath.$PID.tmp"
$now     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

$checkOk = 1
$sizeBytes = 0

if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
    $sizeBytes = (Get-Item -LiteralPath $FilePath).Length
}
else {
    $checkOk = 0
}

$labelEsc = ($Label) -replace '\\', '\\' -replace '"', '\"'

$lines = @(
    '# HELP log_file_size_bytes Size of a watched log file in bytes.'
    '# TYPE log_file_size_bytes gauge'
    ('log_file_size_bytes{{file="{0}"}} {1}' -f $labelEsc, $sizeBytes)
    '# HELP log_check_success Whether the file was found (1) or missing (0).'
    '# TYPE log_check_success gauge'
    ('log_check_success{{file="{0}"}} {1}' -f $labelEsc, $checkOk)
    '# HELP log_check_timestamp_seconds Unix time when this check last ran.'
    '# TYPE log_check_timestamp_seconds gauge'
    "log_check_timestamp_seconds $now"
)

if (-not (Test-Path $TextfileDir)) { New-Item -ItemType Directory -Path $TextfileDir -Force | Out-Null }
Set-Content -Path $tmpPath -Value $lines -Encoding ascii
Move-Item -Path $tmpPath -Destination $outPath -Force   # atomic swap
if ($checkOk -eq 0) { exit 1 }
exit 0
