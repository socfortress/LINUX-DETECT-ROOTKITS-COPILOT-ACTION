#!/bin/bash
set -eu

ScriptName="Detect-SSHConfig-Risks"
LOG="/var/ossec/active-response/active-responses.log"
LogPath="/tmp/${ScriptName}.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart=$(date +%s)
TmpResults=$(mktemp)
> "$TmpResults"

WriteLog() {
  local level="$1"
  local message="$2"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$ts][$level] $message" >&2
  echo "[$ts][$level] $message" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  local size_kb
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  local i=$((LogKeep - 1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i - 1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

RotateLog

if ! rm -f "$LOG" 2>/dev/null; then
  WriteLog "WARN" "Failed to clear $LOG (might be locked)"
else
  : > "$LOG"
  WriteLog "INFO" "Active response log cleared for fresh run."
fi

WriteLog "INFO" "=== SCRIPT START : $ScriptName ==="

check_world_writable() {
  find /home/*/.ssh/ -type f \( -name "config" -o -name "authorized_keys" \) -perm -0002 2>/dev/null | while read -r file; do
    WriteLog "WARN" "World-writable SSH file: $file"
    jq -n --arg path "$file" --arg issue "world_writable" '{path: $path, issue: $issue}' >> "$TmpResults"
  done
}

check_hidden_outside_home() {
  find / -type f \( -name "config" -o -name "authorized_keys" \) -path "*/.ssh/*" ! -path "/home/*" 2>/dev/null | while read -r file; do
    WriteLog "WARN" "Hidden SSH file outside /home: $file"
    jq -n --arg path "$file" --arg issue "hidden_outside_home" '{path: $path, issue: $issue}' >> "$TmpResults"
  done
}

check_world_writable
check_hidden_outside_home

if [ -s "$TmpResults" ]; then
  json_array=$(jq -s '.' "$TmpResults")
  Status="risky"
  Reason="Risky SSH config files found"
else
  json_array="[]"
  Status="ok"
  Reason="No risky SSH config files found"
fi

Timestamp=$(date --iso-8601=seconds 2>/dev/null || date -Iseconds)

final_json=$(jq -n \
  --arg timestamp "$Timestamp" \
  --arg host "$HostName" \
  --arg action "$ScriptName" \
  --arg status "$Status" \
  --arg reason "$Reason" \
  --argjson results "$json_array" \
  --argjson copilot_soar true \
  '{
    timestamp: $timestamp,
    host: $host,
    action: $action,
    status: $status,
    reason: $reason,
    results: $results,
    copilot_soar: $copilot_soar
  }')

tmpfile=$(mktemp)
echo "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$LOG" 2>/dev/null; then
  mv -f "$tmpfile" "$LOG.new"
fi

Duration=$(( $(date +%s) - RunStart ))
WriteLog "INFO" "=== SCRIPT END : duration ${Duration}s ==="
