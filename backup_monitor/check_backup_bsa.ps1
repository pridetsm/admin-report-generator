<#
  check_backup_bsa.ps1  -  track the newest BSA SQL Server backup for the
  windows_exporter textfile collector. Windows / MSSQL .BAK case.

  Fork of check_backup_smarthr.ps1. Difference: BSA writes its FULL backup as a
  single .bak straight into a FLAT folder (no dated sub-folders), named with an embedded
  YYYYMMDD_HHMMSS stamp, e.g.:
      E:\BACKUP\BSAV50_FULL_20260730_233003.bak
      E:\BACKUP\BSAV50_FULL_20260802_233003.bak   (next run - 3 days later, not next day)
  Old .bak files often accumulate in the same folder, so a file merely EXISTING proves
  nothing. We emit ONE row per FRESH .bak (each judged by its own mtime), so stale
  leftovers are ignored automatically. No fresh .bak at all => NO BACKUP (critical).

  WHY THIS ONE ISN'T A today/yesterday CHECK (the difference from every sibling script):
    BSA does NOT back up daily - the job runs every 3rd day (e.g. 30 Jul, then 2 Aug).
    The sibling scripts hard-code a today-or-yesterday window, which on the 2 intervening
    days finds nothing fresh and reports NO BACKUP even though the policy is being met.
    So the window is a PARAMETER here: -MaxAgeDays (default 3 = the BSA interval). A .bak
    counts as current while it is at most that many calendar days old; older => stale.
    Boundaries are calendar midnights, matching how the rest of the stack judges age.
      e.g. today = 2 Aug, MaxAgeDays 3 -> a 30 Jul .bak still counts (the 2 Aug run is
      only just due). Come 3 Aug it does not - by then the 2 Aug run must have landed.
    Set -MaxAgeDays 1 to get the plain daily today/yesterday behaviour of the siblings.
    If the interval changes, change this ONE number - nothing else in the script cares.

  WHY LastWriteTime (not CreationTime), and not the name's timestamp:
    LastWriteTime is set when SQL Server finishes writing the .bak = when the backup was
    actually produced, and it survives leaving the file in place. CreationTime resets if the
    file is copied in, so a stale copy would look "fresh". The YYYYMMDD_HHMMSS in the name is
    only the *intended* run time and can lie if a job is re-run or a name reused, so we trust
    the filesystem mtime (the same signal every other server's check uses). Use
    -TimeField CreationTime only if the .bak is COPIED in via a same-volume move that preserves it.

  Emits the shared schema, UNCHANGED from the sibling scripts - the wider window changes
  only WHICH files qualify, never the metric names, labels or label values. Nothing
  downstream sees a new or renamed series:
      backup_file{file="BSAV50_FULL_20260802_233003.bak",day="today|yesterday|<weekday>"} 1782939900  # value = mtime
      backup_file_count                 1 = a current .bak exists / 0 = none within the window
      backup_check_success              1 = backup root reachable / 0 = missing
      backup_check_timestamp_seconds    when this ran
  day= is today/yesterday as usual, and for a qualifying .bak older than that, the weekday
  it was written ("wednesday") - naming it honestly rather than mislabelling it "yesterday".
  NOTHING judges freshness from this label (every consumer re-derives that from the mtime
  value), so the extra values are safe; a consumer that only knows the first two renders it
  as PRESENT. The HELP lines are kept identical to the siblings - the textfile collector
  errors if two .prom files in the same directory describe the same metric differently.

  Deploy: Task Scheduler, DAILY (not every 3rd day) as usual - the check runs every day
  and simply stays green on the intervening days. Run as an account that can read
  E:\BACKUP, writing to this host's windows_exporter textfile dir.
    powershell -ExecutionPolicy Bypass -File check_backup_bsa.ps1

  NOTE - the dashboard and the xlsx/e-mail report do NOT read the window above; they
  re-derive freshness from the mtime with their own fixed yesterday-midnight cutoff
  (api/Services/IngestionService.cs ln 75, send_report/generate_report.py ln 803/868/1396).
  Until those learn this host's interval, BSA still shows NO BACKUP there on the off days
  even though this script reports correctly.
#>

[CmdletBinding()]
param(
    [string]$BackupRoot  = 'E:\BACKUP',                                    # flat folder holding the BSA .bak files
    [string]$FileName    = 'BSAV50_FULL_*.bak',                            # the daily MSSQL full backup (glob; broaden to 'BSAV50_*.bak' to include DIFF/LOG)
    [string]$TextfileDir = 'C:\Program Files\windows_exporter\textfile_inputs',   # this host's windows_exporter textfile dir
    [string]$OutFile     = 'backup_file.prom',
    [ValidateSet('LastWriteTime', 'CreationTime')]
    [string]$TimeField   = 'LastWriteTime',                                # generation-time signal (see header)
    [long]$MinBytes      = 1,                                               # reject 0-byte / partial backups
    [ValidateRange(1, 366)]
    [int]$MaxAgeDays     = 3                                                # BSA runs every 3rd day, not daily -> a .bak stays current
)                                                                           # this many calendar days. 1 = plain today/yesterday (see header)

$ErrorActionPreference = 'Stop'
$outPath = Join-Path $TextfileDir $OutFile
$tmpPath = "$outPath.$PID.tmp"
$now     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$todayMid = (Get-Date).Date                # local midnight today

$checkOk = 1
$fileLines = @()

if (Test-Path -LiteralPath $BackupRoot) {
    # ONE row per CURRENT .bak. The folder is flat and keeps old backups, so a file existing does
    # NOT prove a current one is present -> judge each on its own mtime against the policy window.
    Get-ChildItem -LiteralPath $BackupRoot -Filter $FileName -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -ge $MinBytes } | ForEach-Object {
            $ts = $_.$TimeField
            # whole calendar days between the file's date and today; <=0 (incl. a future mtime
            # from clock skew) counts as today, exactly as the previous $ts -ge $todayMid test did
            $ageDays = [int][math]::Floor(($todayMid - $ts.Date).TotalDays)
            if ($ageDays -le $MaxAgeDays) {                    # beyond the window -> stale, skipped
                # today/yesterday keep their usual meaning; anything older inside the window is
                # named by its weekday ("wednesday") rather than being squeezed into one of those
                # two. Calling a 3-day-old .bak "yesterday" would simply be untrue, and the window
                # here is far shorter than a week so a weekday name is never ambiguous.
                $day = switch ($ageDays) {
                    { $_ -le 0 } { 'today';     break }
                    1            { 'yesterday'; break }
                    default      { $ts.ToString('dddd', [Globalization.CultureInfo]::InvariantCulture).ToLowerInvariant() }
                }
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
