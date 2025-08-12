#!/bin/bash
set -eu

PID="$1"
LOG="/var/ossec/active-response/active-responses.log"
HostName="$(hostname)"
LogTemp="/tmp/kill_process.log"
RunStart=$(date +%s)

if [[ -z "$PID" ]]; then
  echo "Usage: $0 <pid>"
  exit 1
fi

function Write-Log {
  local level="$1"
  local message="$2"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$ts][$level] $message"
}

Write-Log "INFO" "=== SCRIPT START : Kill-Suspicious-Process ==="
Write-Log "INFO" "Attempting to kill process PID=$PID"

ExePath=$(readlink -f "/proc/$PID/exe" 2>/dev/null || echo "unknown")

if kill -9 "$PID" 2>/dev/null; then
  Write-Log "INFO" "Process $PID killed successfully (exe: $ExePath)"
  Status="killed"
  Reason="Process killed successfully"
else
  Write-Log "ERROR" "Failed to kill process $PID (exe: $ExePath)"
  Status="failed"
  Reason="Failed to kill process"
fi

Timestamp=$(date -Iseconds)
jq -n --arg timestamp "$Timestamp" \
      --arg host "$HostName" \
      --arg action "Kill-Suspicious-Process" \
      --arg pid "$PID" \
      --arg exe "$ExePath" \
      --arg status "$Status" \
      --arg reason "$Reason" \
      --argjson copilot_soar true \
      '{
        timestamp: $timestamp,
        host: $host,
        action: $action,
        pid: $pid,
        exe: $exe,
        status: $status,
        reason: $reason,
        copilot_soar: $copilot_soar
      }' > "$LogTemp"

if mv -f "$LogTemp" "$LOG"; then
  Write-Log "INFO" "Log file replaced at $LOG"
else
  mv -f "$LogTemp" "$LOG.new"
  Write-Log "WARN" "Log file locked, wrote results to $LOG.new"
fi

Duration=$(( $(date +%s) - RunStart ))
Write-Log "INFO" "=== SCRIPT END : duration ${Duration}s ==="
