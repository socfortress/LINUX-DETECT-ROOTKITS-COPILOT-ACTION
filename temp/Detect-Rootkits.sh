#!/bin/sh
set -eu

ScriptName="Detect-Rootkits"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)

PROC_MODULES_FILE="${1:-/proc/modules}"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"
  case "$Level" in
    ERROR) printf '\033[31m%s\033[0m\n' "$line" >&2 ;;
    WARN)  printf '\033[33m%s\033[0m\n' "$line" >&2 ;;
    DEBUG) [ "${VERBOSE:-0}" -eq 1 ] && printf '%s\n' "$line" >&2 ;;
    *)     printf '%s\n' "$line" >&2 ;;
  esac
  printf '%s\n' "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}
escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

RotateLog

if ! rm -f "$ARLog" 2>/dev/null; then
  WriteLog "Failed to clear $ARLog (might be locked)" WARN
else
  : > "$ARLog"
  WriteLog "Active response log cleared for fresh run." INFO
fi

WriteLog "=== SCRIPT START : $ScriptName ==="
WriteLog "Collecting loaded kernel modules..." INFO
process_json_list=""
proc_list=$(awk '{print $1}' "$PROC_MODULES_FILE")
lsmod_list=$(lsmod | awk '{print $1}' | tail -n +2)

for module in $proc_list; do
    path=$(modinfo -n "$module" 2>/dev/null || echo "")
    suspicious=0
    reason=""
    if ! modinfo "$module" 2>/dev/null | grep -qi 'signature'; then
        suspicious=1
        reason="Unsigned module"
    fi
    if [ -n "$path" ] && echo "$path" | grep -Eq '^(/tmp|/var/tmp|/dev/shm)'; then
        suspicious=1
        reason="Module loaded from temp directory"
    fi
    if ! echo "$lsmod_list" | grep -q "^$module$"; then
        suspicious=1
        reason="Module hidden from lsmod"
    fi

    if [ "$suspicious" -eq 1 ]; then
        escaped_module=$(escape_json "$module")
        escaped_path=$(escape_json "$path")
        escaped_reason=$(escape_json "$reason")
        item="{\"module\":\"$escaped_module\",\"path\":\"$escaped_path\",\"reason\":\"$escaped_reason\"}"
        [ -z "$process_json_list" ] && process_json_list="$item" || process_json_list="$process_json_list,$item"
    fi
done

[ -n "$process_json_list" ] && process_json_list="[$process_json_list]" || process_json_list="[]"

ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"data\":$process_json_list,\"copilot_soar\":true}"

tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

WriteLog "JSON result written to $ARLog" INFO

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
