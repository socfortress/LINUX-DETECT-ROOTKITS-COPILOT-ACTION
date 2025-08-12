#!/bin/bash
set -eu

ScriptName="Block-IP-iptables"
LOG="/var/ossec/active-response/active-responses.log"
LogPath="/tmp/${ScriptName}.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart=$(date +%s)

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

IP="${ARG1:-}"

if [ -z "$IP" ]; then
  WriteLog "ERROR" "No IP address provided, exiting."
  Status="error"
  Reason="No IP provided"
elif ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  WriteLog "ERROR" "Invalid IPv4 address format: $IP"
  Status="error"
  Reason="Invalid IP format"
else
  if ! command -v iptables >/dev/null 2>&1; then
    WriteLog "ERROR" "iptables command not found, cannot block IP."
    Status="failed"
    Reason="iptables not installed"
  else
    # Check if IP already blocked
    if iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
      WriteLog "INFO" "IP $IP is already blocked"
      Status="already_blocked"
      Reason="IP was already blocked"
    else
      if iptables -A INPUT -s "$IP" -j DROP; then
        WriteLog "INFO" "Blocked IP $IP successfully"
        Status="blocked"
        Reason="IP blocked successfully"
      else
        WriteLog "ERROR" "Failed to block IP $IP"
        Status="failed"
        Reason="iptables command failed"
      fi
    fi
  fi
fi

Timestamp=$(date --iso-8601=seconds 2>/dev/null || date -Iseconds)
final_json=$(jq -n \
  --arg timestamp "$Timestamp" \
  --arg host "$HostName" \
  --arg action "$ScriptName" \
  --arg ip "$IP" \
  --arg status "$Status" \
  --arg reason "$Reason" \
  --argjson copilot_soar true \
  '{
    timestamp: $timestamp,
    host: $host,
    action: $action,
    ip: $ip,
    status: $status,
    reason: $reason,
    copilot_soar: $copilot_soar
  }'
)

tmpfile=$(mktemp)
echo "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$LOG" 2>/dev/null; then
  mv -f "$tmpfile" "$LOG.new"
fi

Duration=$(( $(date +%s) - RunStart ))
WriteLog "INFO" "=== SCRIPT END : duration ${Duration}s ==="
