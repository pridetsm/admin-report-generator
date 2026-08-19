<#
  check_backup_edms.ps1  -  track EDMS SQL Server backups for the windows_exporter
  textfile collector. Windows / MSSQL .BAK case.

  Fork of check_backup_smarthr.ps1. Differences: EDMS backs up to SQL Server's DEFAULT
  backup directory, plus a secondary location:

      C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup
      C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backups2

  which a maintenance plan usually fills with ONE SUB-FOLDER PER DATABASE, e.g.
      ...\Backup\EDMS\EDMS_backup_2026_08_14_220000.bak
      ...\Backup\master\master_backup_2026_08_14_220000.bak
  so this fork recurses and labels each file with its path RELATIVE to the backup root.
  That keeps the database visible in the label instead of collapsing every database's
  backup onto a bare filename, and it still works if the folder turns out to be flat.

  Only .bak / .BAK is treated as a backup (matched case-insensitively). If EDMS ever
  starts writing transaction-log backups here as well, fork check_backup_ebis.ps1 instead:
  it counts fulls and logs separately, because a log job that keeps running while the
  nightly full fails will otherwise make this host look healthy.

  WHY LastWriteTime (not CreationTime, not the name)
    LastWriteTime is set when SQL Server finishes writing the .BAK = when the backup was
    actually produced, and it survives the file being left in place. CreationTime resets
    when a file is copied in, so a stale copy would look fresh. The date embedded in a
    maintenance-plan filename is only the INTENDED run time and can lie if a job is re-run.
    Use -TimeField CreationTime only if backups arrive by a same-volume move, which
    preserves it.

  Emits the shared schema (renders under the system owning this host's instance -> "EDMS"):
      backup_file{file="EDMS\EDMS_backup_2026_08_14_220000.bak",day="today"} 1786...  # value = mtime
      backup_file_count                 fresh .bak files / 0 = none within yesterday..today
      backup_check_success              1 = backup root reachable / 0 = missing
      backup_check_timestamp_seconds    when this ran

  Deploy: Task Scheduler, daily AFTER the EDMS backup window, as an account that can read
  the backup directory and write this host's windows_exporter textfile dir.
    powershell -ExecutionPolicy Bypass -File check_backup_edms.ps1
#>

[CmdletBinding()]
param(
    # Quoted because the default MSSQL backup paths contain spaces. Backups2 is a secondary
    # location EDMS also writes to.
    [string[]]$BackupRoot = @(
        'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backup',
        'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Backups2'
    ),
    [string[]]$BackupExt = @('.bak'),                   # matched case-insensitively, so .BAK too
    [string]$TextfileDir = 'C:\metrics\',               # SET to this host's windows_exporter textfile dir
    [string]$OutFile     = 'backup_file.prom',
    [ValidateSet('LastWriteTime', 'CreationTime')]
    [string]$TimeField   = 'LastWriteTime',             # generation-time signal (see header)
    [long]$MinBytes      = 1,                           # reject 0-byte / partial backups
    # A maintenance plan writes one sub-folder per database, so recursing is the norm here.
    # A flat scan against that layout finds nothing and reports NO BACKUP on a healthy host.
    [switch]$NoRecurse
)

$ErrorActionPreference = 'Stop'
$outPath = Join-Path $TextfileDir $OutFile
$tmpPath = "$outPath.$PID.tmp"
$now     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$todayMid     = (Get-Date).Date            # local midnight today
$yesterdayMid = $todayMid.AddDays(-1)

$checkOk   = 0
$fileLines = @()

foreach ($root in $BackupRoot) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $checkOk = 1

    $gci = @{ LiteralPath = $root; File = $true; ErrorAction = 'SilentlyContinue' }
    if (-not $NoRecurse) { $gci['Recurse'] = $true }

    $rootFull = (Resolve-Path -LiteralPath $root).Path.TrimEnd('\')

    # ONE row per FRESH .bak. The folder keeps old backups, so a file merely EXISTING proves
    # nothing -> judge each on its own mtime and keep only today/yesterday.
    Get-ChildItem @gci | Where-Object {
        $_.Length -ge $MinBytes -and $BackupExt -contains $_.Extension.ToLowerInvariant()
    } | ForEach-Object {
        $ts  = $_.$TimeField
        $day = if ($ts -ge $todayMid) { 'today' } elseif ($ts -ge $yesterdayMid) { 'yesterday' } else { $null }
        if (-not $day) { return }                       # older than yesterday -> stale, skipped

        $label = $_.FullName
        if ($label.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
            $label = $label.Substring($rootFull.Length).TrimStart('\')
        }
        $label = $label -replace '\\', '\\' -replace '"', '\"'
        $epoch = ([DateTimeOffset]$ts).ToUnixTimeSeconds()   # value = mtime = when generated
        $fileLines += ('backup_file{{file="{0}",day="{1}"}} {2}' -f $label, $day, $epoch)
    }
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
Move-Item -Path $tmpPath -Destination $outPath -Force   # atomic swap: never a half-written .prom
if ($checkOk -eq 0) { exit 1 }
exit 0
