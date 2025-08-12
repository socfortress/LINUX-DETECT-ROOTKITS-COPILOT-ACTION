#!/bin/sh
set -eu

# ==============================
# CONFIGURATION
# ==============================
ScriptName="SCRIPT_NAME_HERE"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)

# ==============================
# LOGGING FUNCTIONS
# ==============================
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

# Escape text for safe JSON
escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# ==============================
# PRE-RUN SETUP
# ==============================
RotateLog

if ! rm -f "$ARLog" 2>/dev/null; then
  WriteLog "Failed to clear $ARLog (might be locked)" WARN
else
  : > "$ARLog"
  WriteLog "Active response log cleared for fresh run." INFO
fi

WriteLog "=== SCRIPT START : $ScriptName ==="

# ==============================
# MAIN SCRIPT LOGIC
# ==============================
# REPLACE THE BLOCK BELOW WITH YOUR SPECIFIC LOGIC
# Must produce JSON payload and assign it to $final_json

# Example dummy JSON payload
payload='{"example_key":"example_value"}'

ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"data\":$payload,\"copilot_soar\":true}"

# ==============================
# WRITE JSON OUTPUT
# ==============================
tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

WriteLog "JSON result written to $ARLog" INFO

# ==============================
# SCRIPT END
# ==============================
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="