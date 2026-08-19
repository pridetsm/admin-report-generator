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

  WHY A STATE FILE (-StateFile) IS NEEDED ON TOP OF THE WINDOW:
    Housekeeping on E:\BACKUP can reclaim the previous .bak before the next one lands, so on
    an "off" day the folder can legitimately hold ZERO matching files even though the policy
    isn't actually broken yet (tomorrow may be the next due day). A window computed purely
    from files currently on disk can't tell that apart from a real miss - once the evidence is
    deleted there's nothing left to judge age from, no matter how MaxAgeDays is tuned. So the
    script also remembers the newest .bak it has ever actually seen, in a small JSON state file
    next to the .prom output, and falls back to that memory when the live scan finds nothing.
    An alert now only fires once that remembered backup is itself older than MaxAgeDays - i.e.
    a backup is genuinely overdue - not merely because housekeeping ran before this check did.

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

  NOTE - the dashboard and the xlsx/e-mail report do NOT read the window above; each
  re-derives freshness from the mtime against its OWN per-host cutoff, so -MaxAgeDays here
  must be kept in step with both:
    * send_report/generate_report.py: BACKUP_MAX_AGE_DAYS dict, keyed by instance (already
      has "10.0.206.5:9182": 3 for BSA).
    * api/Services/IngestionService.cs: BackupConfig.MaxAgeDays, set via the OPTIONAL
      max_age_days key on this host's `backups:` block in systems_config.yml. BSA is not
      currently a tracked system in systems_config.yml, so the live dashboard doesn't poll
      it at all yet - only the xlsx/e-mail report does.
#>

[CmdletBinding()]
param(
    [string]$BackupRoot  = 'E:\BACKUP',                                    # flat folder holding the BSA .bak files
    [string]$FileName    = 'BSAV50_FULL_*.bak',                            # the daily MSSQL full backup (glob; broaden to 'BSAV50_*.bak' to include DIFF/LOG)
    [string]$TextfileDir = 'C:\Program Files\windows_exporter\textfile_inputs',   # this host's windows_exporter textfile dir
    [string]$OutFile     = 'backup_file.prom',
    [string]$StateFile   = (Join-Path $TextfileDir 'bsa_last_backup_state.json'), # remembers the newest .bak ever seen (see header)
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

if (-not (Test-Path $TextfileDir)) { New-Item -ItemType Directory -Path $TextfileDir -Force | Out-Null }

# today/yesterday keep their usual meaning; anything older inside the window is named by its
# weekday ("wednesday") rather than being squeezed into one of those two. Calling a 3-day-old
# .bak "yesterday" would simply be untrue, and the window here is far shorter than a week so a
# weekday name is never ambiguous.
function Resolve-DayLabel([datetime]$ts, [datetime]$todayMid) {
    $ageDays = [int][math]::Floor(($todayMid - $ts.Date).TotalDays)
    switch ($ageDays) {
        { $_ -le 0 } { 'today';     break }
        1            { 'yesterday'; break }
        default      { $ts.ToString('dddd', [Globalization.CultureInfo]::InvariantCulture).ToLowerInvariant() }
    }
}

$checkOk = 1
$fileLines = @()
$liveNewest = $null

if (Test-Path -LiteralPath $BackupRoot) {
    # ONE row per CURRENT .bak. The folder is flat and keeps old backups, so a file existing does
    # NOT prove a current one is present -> judge each on its own mtime against the policy window.
    Get-ChildItem -LiteralPath $BackupRoot -Filter $FileName -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -ge $MinBytes } | ForEach-Object {
            if (-not $liveNewest -or $_.$TimeField -gt $liveNewest.$TimeField) { $liveNewest = $_ }

            $ts = $_.$TimeField
            # whole calendar days between the file's date and today; <=0 (incl. a future mtime
            # from clock skew) counts as today, exactly as the previous $ts -ge $todayMid test did
            $ageDays = [int][math]::Floor(($todayMid - $ts.Date).TotalDays)
            if ($ageDays -le $MaxAgeDays) {                    # beyond the window -> stale, skipped
                $day = Resolve-DayLabel $ts $todayMid
                # label: the filename (it already carries the YYYYMMDD_HHMMSS stamp, so no folder needed)
                $label = ($_.Name) -replace '\\', '\\' -replace '"', '\"'
                $epoch = ([DateTimeOffset]$ts).ToUnixTimeSeconds()   # value = file mtime (unix secs) = when generated
                $fileLines += ('backup_file{{file="{0}",day="{1}"}} {2}' -f $label, $day, $epoch)
            }
        }

    # Remember the newest .bak actually seen so housekeeping deleting it before the window
    # naturally excludes it doesn't erase the fact a backup landed (see header). Never regress
    # the memory to something older than what's already recorded.
    if ($liveNewest) {
        $prevTime = $null
        if (Test-Path -LiteralPath $StateFile) {
            try { $prevTime = [datetime](Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json).Time } catch { }
        }
        if (-not $prevTime -or $liveNewest.$TimeField -gt $prevTime) {
            @{ Name = $liveNewest.Name; Time = $liveNewest.$TimeField.ToString('o') } |
                ConvertTo-Json -Compress | Set-Content -LiteralPath $StateFile -Encoding ascii
        }
    }
    elseif ($fileLines.Count -eq 0 -and (Test-Path -LiteralPath $StateFile)) {
        # nothing matches on disk right now (housekeeping already reclaimed it) - fall back to
        # the last confirmed backup ever seen and judge freshness from THAT, instead of
        # reporting NO BACKUP purely because the evidence was cleaned up ahead of the next run
        try {
            $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
            $ts = [datetime]$state.Time
            $ageDays = [int][math]::Floor(($todayMid - $ts.Date).TotalDays)
            if ($ageDays -le $MaxAgeDays) {
                $day = Resolve-DayLabel $ts $todayMid
                $label = ($state.Name) -replace '\\', '\\' -replace '"', '\"'
                $epoch = ([DateTimeOffset]$ts).ToUnixTimeSeconds()
                $fileLines += ('backup_file{{file="{0}",day="{1}"}} {2}' -f $label, $day, $epoch)
            }
        } catch { }
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

Set-Content -Path $tmpPath -Value $lines -Encoding ascii
Move-Item -Path $tmpPath -Destination $outPath -Force   # atomic swap
if ($checkOk -eq 0) { exit 1 }
exit 0
