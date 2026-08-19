#!/usr/bin/env bash
# check_backup_eagle.sh  -  track the newest Eagle daily SQL dump for the node_exporter
# textfile collector. Dated-folder / single-file case (same shape as check_backup_snapshot.sh),
# for the Eagle database on hre-eagledb-01.
#
# Same dated-folder layout as CEPECS, one dump per day, e.g.:
#     /u01/backupset/EAGLE/2026_07_02/eagle.sql.gz    (+ eagle.log, NOT tracked)
# We track the single newest matching dump under the root and confirm it was generated today
# or, at the oldest, yesterday. Older/missing/empty => NO BACKUP (critical).
#
# CHECKS BOTH eagle.sql AND eagle.sql.gz -- the job compresses its dump now (confirmed on
# hre-eagledb-01: the .sql name was never written, only .sql.gz, so a check for .sql alone
# always found nothing and reported NO BACKUP even on nights the backup ran and succeeded).
# Both stay checked, not just .gz, so this keeps working if the job is ever run uncompressed
# again -- add a name to FILENAMES rather than replace one.
#
# Age is judged by mtime (%Y) = when the dump was written.
#
# Emits the shared schema; renders under the system owning this host's exporter instance
# (hre-eagledb-01 -> system "Eagle"):
#     backup_file{file="2026_07_02/eagle.sql.gz",day="today|yesterday"} 1782939900   # value = mtime
#     backup_file_count               1 = a fresh dump exists / 0 = none within yesterday..today
#     backup_check_success            1 = backup root reachable / 0 = missing
#     backup_check_timestamp_seconds  when this ran
#
# Deploy (cron on hre-eagledb-01, after the daily dump, before the report scrape), e.g.:
#   45 6 * * *  /opt/backup_monitor/check_backup_eagle.sh
set -u

BACKUP_ROOT="${BACKUP_ROOT:-/u01/backupset/EAGLE}"          # root holding the dated folders
FILENAMES="${FILENAMES:-eagle.sql eagle.sql.gz}"            # space-separated; any one match counts
OUT="${OUT:-backup_file.prom}"
MIN_BYTES="${MIN_BYTES:-1}"                                  # reject 0-byte / partial dumps

# node_exporter ONLY scrapes the exact --collector.textfile.directory it was started
# with, and that path differs per install. So: honor an explicit TEXTFILE_DIR, else
# read it from the running node_exporter, else fall back to a common path that exists;
# refuse to guess-and-write to a dir node_exporter isn't watching.
resolve_textfile_dir() {
    if [ -n "${TEXTFILE_DIR:-}" ]; then printf '%s\n' "$TEXTFILE_DIR"; return 0; fi
    local args dir
    args="$(ps -ww -eo args= 2>/dev/null | grep -E '(^|/)(prometheus-)?node[_-]exporter([[:space:]]|$)' | grep -v grep | head -n1)"
    dir="$(printf '%s' "$args" | grep -oE -- '--collector\.textfile\.directory(=|[[:space:]])[^[:space:]]+' | head -n1 | sed -E 's/^--collector\.textfile\.directory(=|[[:space:]])//')"
    if [ -n "$dir" ]; then printf '%s\n' "$dir"; return 0; fi
    for d in /var/lib/node_exporter/textfile_collector /var/lib/prometheus/node-exporter \
             /var/lib/prometheus/node_exporter /etc/node_exporter/textfile_collector \
             /opt/node_exporter/textfile_collector; do
        [ -d "$d" ] && { printf '%s\n' "$d"; return 0; }
    done
    return 1
}
if ! TEXTFILE_DIR="$(resolve_textfile_dir)"; then
    echo "[!] cannot determine node_exporter textfile dir (is it running with --collector.textfile.directory?); set TEXTFILE_DIR explicitly" >&2
    exit 2
fi

OUT_PATH="$TEXTFILE_DIR/$OUT"
TMP_PATH="$OUT_PATH.$$.tmp"
NOW="$(date +%s)"
mkdir -p "$TEXTFILE_DIR"

# day boundaries (local): mtime >= TODAY_MID -> today; >= YEST_MID -> yesterday; else too old
if TODAY_MID="$(date -d "$(date +%Y-%m-%d) 00:00:00" +%s 2>/dev/null)"; then
    :
else
    TODAY_MID="$(date -v0H -v0M -v0S +%s)"              # BSD/macOS fallback
fi
YEST_MID=$(( TODAY_MID - 86400 ))

# escape \ and " so odd names can't break the label syntax
esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# build the find(1) name-matching expression from FILENAMES, e.g.:
#   -name eagle.sql -o -name eagle.sql.gz
find_name_expr=()
first=1
for fn in $FILENAMES; do
    [ "$first" -eq 1 ] || find_name_expr+=( -o )
    find_name_expr+=( -name "$fn" )
    first=0
done

check_ok=1
file_line=""

if [ -d "$BACKUP_ROOT" ]; then
    # newest non-empty match (any name in FILENAMES) anywhere under the backup root (by mtime)
    newest=""; newest_mtime=0
    while IFS= read -r -d '' f; do
        m="$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || date -r "$f" +%s 2>/dev/null)"
        sz="$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f" 2>/dev/null)"
        [ -n "$m" ] && [ -n "$sz" ] && [ "$sz" -ge "$MIN_BYTES" ] || continue
        if [ "$m" -gt "$newest_mtime" ]; then newest_mtime="$m"; newest="$f"; fi
    done < <(find "$BACKUP_ROOT" -type f \( "${find_name_expr[@]}" \) -print0 2>/dev/null)

    if [ -n "$newest" ]; then
        if   [ "$newest_mtime" -ge "$TODAY_MID" ]; then day="today"
        elif [ "$newest_mtime" -ge "$YEST_MID" ];  then day="yesterday"
        else day=""; fi                                # newer copy is older than yesterday -> stale
        if [ -n "$day" ]; then
            # label = dated-folder/filename so the report shows which day's dump satisfied it
            label="$(basename "$(dirname "$newest")")/$(basename "$newest")"
            file_line="backup_file{file=\"$(esc "$label")\",day=\"$day\"} $newest_mtime"   # value = mtime = when generated
        fi
    fi
else
    check_ok=0
fi

count=$([ -n "$file_line" ] && echo 1 || echo 0)

{
    echo '# HELP backup_file A backup file modified yesterday or today (day label = which). Value = file mtime (unix seconds) = when it was generated.'
    echo '# TYPE backup_file gauge'
    [ -n "$file_line" ] && echo "$file_line"
    echo '# HELP backup_file_count Number of backup files modified yesterday or today.'
    echo '# TYPE backup_file_count gauge'
    echo "backup_file_count $count"
    echo '# HELP backup_check_success Whether the folder scan succeeded (1) or failed (0 = folder missing).'
    echo '# TYPE backup_check_success gauge'
    echo "backup_check_success $check_ok"
    echo '# HELP backup_check_timestamp_seconds Unix time when the scan last ran.'
    echo '# TYPE backup_check_timestamp_seconds gauge'
    echo "backup_check_timestamp_seconds $NOW"
} > "$TMP_PATH"

mv -f "$TMP_PATH" "$OUT_PATH"          # atomic swap; collector never reads a half-written file
[ "$check_ok" -eq 1 ] && exit 0 || exit 1
