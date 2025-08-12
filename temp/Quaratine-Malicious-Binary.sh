#!/bin/sh
set -eu

ScriptName="Quarantine-Malicious-Binary"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)

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
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; print(json.dumps(sys.stdin.read())[1:-1])"
  else
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
  fi
}

RotateLog

if ! rm -f "$ARLog" 2>/dev/null; then
  WriteLog "Failed to clear $ARLog (might be locked)" WARN
else
  : > "$ARLog"
  WriteLog "Active response log cleared for fresh run." INFO
fi

WriteLog "=== SCRIPT START : $ScriptName ==="

FilePath="${ARG1:-}"

if [ -z "$FilePath" ] || [ ! -f "$FilePath" ]; then
  WriteLog "File not found or ARG1 not set: $FilePath" ERROR
  ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
  final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"status\":\"error\",\"error\":\"No file specified or not found: $FilePath\",\"copilot_soar\":true}"
  tmpfile=$(mktemp)
  printf '%s\n' "$final_json" > "$tmpfile"
  if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then mv -f "$tmpfile" "$ARLog.new"; fi
  exit 1
fi

QDir="/var/ossec/quarantine"
mkdir -p "$QDir"

BaseName=$(basename "$FilePath")
TS=$(date +%Y%m%d%H%M%S)
Quarantined="$QDir/${BaseName}.${TS}.quarantine"

if command -v sha256sum >/dev/null 2>&1; then
  OrigHash=$(sha256sum "$FilePath" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  OrigHash=$(shasum -a 256 "$FilePath" | awk '{print $1}')
else
  OrigHash="(sha256sum not available)"
fi

if mv -f "$FilePath" "$Quarantined" 2>/dev/null; then
  WriteLog "Moved $FilePath to $Quarantined" INFO
else
  WriteLog "Failed to move $FilePath to quarantine" ERROR
  ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
  final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"status\":\"error\",\"error\":\"Failed to move file to quarantine.\",\"copilot_soar\":true}"
  tmpfile=$(mktemp)
  printf '%s\n' "$final_json" > "$tmpfile"
  if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then mv -f "$tmpfile" "$ARLog.new"; fi
  exit 2
fi

chmod a-x "$Quarantined" 2>/dev/null || true
if [ -f "$Quarantined" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    QuarHash=$(sha256sum "$Quarantined" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    QuarHash=$(shasum -a 256 "$Quarantined" | awk '{print $1}')
  else
    QuarHash="(sha256sum not available)"
  fi
else
  QuarHash="(file missing)"
fi

payload="{\"original_path\":\"$(escape_json "$FilePath")\",\"quarantine_path\":\"$(escape_json "$Quarantined")\",\"sha256_before\":\"$OrigHash\",\"sha256_after\":\"$QuarHash\"}"

ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"data\":$payload,\"copilot_soar\":true}"

tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

WriteLog "JSON result written to $ARLog" INFO

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
