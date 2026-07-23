<#
  check_backup_bsa.ps1  -  track the newest BSA SQL Server backup for the
  windows_exporter textfile collector. Windows / MSSQL .BAK case.

  Fork of check_backup_smarthr.ps1. Difference: BSA writes its daily FULL backup as a
  single .bak straight into a FLAT folder (no dated sub-folders), named with an embedded
  YYYYMMDD_HHMMSS stamp, e.g.:
      E:\BACKUP\BSAV50_FULL_20260720_233003.bak
      E:\BACKUP\BSAV50_FULL_20260721_233003.bak   (next day)
  Old .bak files often accumulate in the same folder, so a file merely EXISTING proves
  nothing. We emit ONE row per FRESH .bak (each judged today/yesterday by its own mtime),
  so stale leftovers are ignored automatically. No fresh .bak at all => NO BACKUP (critical).

  WHY LastWriteTime (not CreationTime), and not the name's timestamp:
    LastWriteTime is set when SQL Server finishes writing the .bak = when the backup was
    actually produced, and it survives leaving the file in place. CreationTime resets if the
    file is copied in, so a stale copy would look "fresh". The YYYYMMDD_HHMMSS in the name is
    only the *intended* run time and can lie if a job is re-run or a name reused, so we trust
    the filesystem mtime (the same signal every other server's check uses). Use
    -TimeField CreationTime only if the .bak is COPIED in via a same-volume move that preserves it.

  Emits the shared schema (renders under the system owning this host's instance -> "BSA"):
      backup_file{file="BSAV50_FULL_20260721_233003.bak",day="today|yesterday"} 1782939900  # value = mtime
      backup_file_count                 1 = a fresh .bak exists / 0 = none within yesterday..today
      backup_check_success              1 = backup root reachable / 0 = missing
      backup_check_timestamp_seconds    when this ran

  Deploy: Task Scheduler, daily (after the BSA backup window), run as an account that
  can read E:\BACKUP, writing to this host's windows_exporter textfile dir.
    powershell -ExecutionPolicy Bypass -File check_backup_bsa.ps1
#>

[CmdletBinding()]
param(
    [string]$BackupRoot  = 'E:\BACKUP',                                    # flat folder holding the BSA .bak files
    [string]$FileName    = 'BSAV50_FULL_*.bak',                            # the daily MSSQL full backup (glob; broaden to 'BSAV50_*.bak' to include DIFF/LOG)
    [string]$TextfileDir = 'C:\metrics\',                                  # SET to this host's windows_exporter textfile dir
    [string]$OutFile     = 'backup_file.prom',
    [ValidateSet('LastWriteTime', 'CreationTime')]
    [string]$TimeField   = 'LastWriteTime',                                # generation-time signal (see header)
    [long]$MinBytes      = 1                                                # reject 0-byte / partial backups
)

$ErrorActionPreference = 'Stop'
$outPath = Join-Path $TextfileDir $OutFile
$tmpPath = "$outPath.$PID.tmp"
$now     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$todayMid     = (Get-Date).Date            # local midnight today
$yesterdayMid = $todayMid.AddDays(-1)

$checkOk = 1
$fileLines = @()

if (Test-Path -LiteralPath $BackupRoot) {
    # ONE row per FRESH .bak. The folder is flat and keeps old backups, so a file existing does
    # NOT prove a fresh one is present -> judge each on its own mtime, keep only today/yesterday.
    Get-ChildItem -LiteralPath $BackupRoot -Filter $FileName -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -ge $MinBytes } | ForEach-Object {
            $ts = $_.$TimeField
            $day = if ($ts -ge $todayMid) { 'today' } elseif ($ts -ge $yesterdayMid) { 'yesterday' } else { $null }
            if ($day) {                                        # older than yesterday -> stale, skipped
                # label: the filename (it already carries the YYYYMMDD_HHMMSS stamp, so no folder needed)
                $label = ($_.Name) -replace '\\', '\\' -replace '"', '\"'
                $epoch = ([DateTimeOffset]$ts).ToUnixTimeSeconds()   # value = file mtime (unix secs) = when generated
                $fileLines += ('backup_file{{file="{0}",day="{1}"}} {2}' -f $label, $day, $epoch)
            }
        }
}
else {
    $checkOk = 0
}

$count = $fileLines.Count

$lines = @(
    '# HELP backup_file A backup file modified yesterday or today (day label = which). Value = file mtime (unix seconds) = when it was generated.'
    '# TYPE backup_file gauge'
)
if ($fileLines.Count) { $lines += $fileLines }
$lines += @(
    '# HELP backup_file_count Number of backup files modified yesterday or today.'
    '# TYPE backup_file_count gauge'
    "backup_file_count $count"
    '# HELP backup_check_success Whether the folder scan succeeded (1) or failed (0 = folder missing).'
    '# TYPE backup_check_success gauge'
    "backup_check_success $checkOk"
    '# HELP backup_check_timestamp_seconds Unix time when the scan last ran.'
    '# TYPE backup_check_timestamp_seconds gauge'
    "backup_check_timestamp_seconds $now"
)

if (-not (Test-Path $TextfileDir)) { New-Item -ItemType Directory -Path $TextfileDir -Force | Out-Null }
Set-Content -Path $tmpPath -Value $lines -Encoding ascii
Move-Item -Path $tmpPath -Destination $outPath -Force   # atomic swap
if ($checkOk -eq 0) { exit 1 }
exit 0
