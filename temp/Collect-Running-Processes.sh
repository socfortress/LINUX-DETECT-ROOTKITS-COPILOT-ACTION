#!/bin/bash
set -eu

ScriptName="Collect-Running-Processes"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName=$(hostname)
runStart=$(date +%s)

WriteLog() {
  local msg="$1"
  local level="${2:-INFO}"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  local line="[$ts][$level] $msg"
  echo "$line" >&2
  echo "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  local size_kb
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  local i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

escape_json() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

RotateLog

rm -f "$ARLog" 2>/dev/null || true
: > "$ARLog"
WriteLog "Active response log cleared for fresh run."

WriteLog "=== SCRIPT START : $ScriptName ==="

WriteLog "Collecting running processes snapshot..."

results=()
for pid_dir in /proc/[0-9]*; do
  pid=$(basename "$pid_dir")
  [ -d "/proc/$pid" ] || continue

  ppid=$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo "")
  cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/ $//')
  if [ -z "$cmdline" ]; then
    cmdline=$(cat "/proc/$pid/comm" 2>/dev/null || echo "")
  fi
  user=$(stat -c '%U' "/proc/$pid" 2>/dev/null || echo "unknown")
  exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")
  sha256=""
  if [ -n "$exe_path" ] && [ -f "$exe_path" ]; then
    sha256=$(sha256sum "$exe_path" 2>/dev/null | awk '{print $1}' || echo "")
  fi

  pid_j=$(escape_json "$pid")
  ppid_j=$(escape_json "$ppid")
  user_j=$(escape_json "$user")
  cmdline_j=$(escape_json "$cmdline")
  exe_j=$(escape_json "$exe_path")
  sha256_j=$(escape_json "$sha256")

  results+=("{\"pid\":\"$pid_j\",\"ppid\":\"$ppid_j\",\"user\":\"$user_j\",\"cmd\":\"$cmdline_j\",\"exe\":\"$exe_j\",\"sha256\":\"$sha256_j\"}")
done

if [ ${#results[@]} -eq 0 ]; then
  data="[]"
else
  data="["
  data+=$(IFS=, ; echo "${results[*]}")
  data+="]"
fi

ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"data\":$data,\"copilot_soar\":true}"

tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

WriteLog "JSON result written to $ARLog"

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
