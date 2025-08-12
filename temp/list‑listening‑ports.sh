#!/bin/sh
set -eu

LogPath="/tmp/ListListeningPorts-script.log"
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

RotateLog

if ! rm -f "$ARLog" 2>/dev/null; then
  WriteLog "Failed to clear $ARLog (might be locked)" WARN
else
  : > "$ARLog"
  WriteLog "Active response log cleared for fresh run." INFO
fi

WriteLog "=== SCRIPT START : List Listening Ports ==="

escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

collect_ports() {
  [ -x "$(command -v lsof)" ] || { WriteLog "lsof not installed." ERROR; echo "[]"; return; }

  lsof -nP -iTCP -sTCP:LISTEN -iUDP 2>/dev/null | awk 'NR>1' |
  while read -r line; do
    cmd=$(echo "$line" | awk '{print $1}')
    pid=$(echo "$line" | awk '{print $2}')
    proto=$(echo "$line" | grep -o 'TCP\|UDP' | tr 'A-Z' 'a-z')
    port=$(echo "$line" | grep -Eo ':[0-9]+(\)|$| )' | grep -Eo '[0-9]+' | tail -n1)
    [ -z "$port" ] && port="unknown"

    [ -z "$pid" ] && pid="0"
    [ -z "$cmd" ] && cmd="unknown"
    [ -z "$proto" ] && proto="unknown"

    program_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")

    cmd=$(escape_json "$cmd")
    proto=$(escape_json "$proto")
    program_path=$(escape_json "$program_path")

    printf '{"protocol":"%s","port":"%s","pid":"%s","program":"%s","program_path":"%s"}\n' \
      "$proto" "$port" "$pid" "$cmd" "$program_path"
  done
}

ports_list=$(collect_ports | paste -sd "," -)
[ -z "$ports_list" ] && ports_list=""

ports_json="[$ports_list]"

ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"list_listening_ports\",\"ports\":$ports_json,\"copilot_soar\":true}"

tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

WriteLog "Listening ports JSON written to $ARLog" INFO
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
