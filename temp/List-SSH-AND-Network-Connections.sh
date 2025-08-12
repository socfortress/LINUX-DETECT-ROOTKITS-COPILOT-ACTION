#!/bin/sh
set -eu

ScriptName="List-SSH-Network-Connections"
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

if ! command -v netstat >/dev/null 2>&1; then
  WriteLog "netstat not found, attempting to install..." WARN
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y net-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y net-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y net-tools
  else
    WriteLog "No supported package manager found for netstat installation." ERROR
    payload='{"error":"netstat not installed and no supported package manager found."}'
  fi
fi

if [ -z "${payload:-}" ]; then
  conns="$(netstat -tunap 2>/dev/null | grep -E 'tcp|udp' | grep -v 'Active Internet' | grep -v 'Proto' || true)"

  json_lines=""
  count=0
  while IFS= read -r line; do
    proto=$(echo "$line" | awk '{print $1}')
    recvq=$(echo "$line" | awk '{print $2}')
    sendq=$(echo "$line" | awk '{print $3}')
    local_addr=$(echo "$line" | awk '{print $4}')
    foreign_addr=$(echo "$line" | awk '{print $5}')
    state=$(echo "$line" | awk '{print $6}')
    pidprog=$(echo "$line" | awk '{print $7}')
    [ -n "$proto" ] || continue
    obj="{\"proto\":\"$(escape_json "$proto")\",\"recvq\":\"$recvq\",\"sendq\":\"$sendq\",\"local\":\"$(escape_json "$local_addr")\",\"remote\":\"$(escape_json "$foreign_addr")\",\"state\":\"$(escape_json "$state")\",\"pid_prog\":\"$(escape_json "$pidprog")\"}"
    if [ $count -eq 0 ]; then
      json_lines="$obj"
    else
      json_lines="$json_lines,$obj"
    fi
    count=$((count+1))
  done <<EOF
$conns
EOF

  conns_json="[$json_lines]"
  payload="{\"connections\":$conns_json}"
fi

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
