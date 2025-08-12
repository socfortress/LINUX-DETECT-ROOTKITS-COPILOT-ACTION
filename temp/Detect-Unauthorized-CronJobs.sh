#!/bin/bash
set -eu

ScriptName="Detect-Unauthorized-CronJobs"
ARLog="/var/ossec/active-response/active-responses.log"
HostName="$(hostname)"
runStart=$(date +%s)

WriteLog() {
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts][$2] $1" >&2
}

escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

> "$ARLog"
WriteLog "Active response log cleared for fresh run." INFO
WriteLog "=== SCRIPT START : $ScriptName ===" INFO

suspicious_json=""
SUSP_DIRS="/tmp /dev/shm /home"
WriteLog "Scanning cron files..." INFO

cron_files=$(find /etc/cron* /var/spool/cron* -type f 2>/dev/null)
for file in $cron_files; do
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    for dir in $SUSP_DIRS; do
      if echo "$line" | grep -q "$dir"; then
        escaped_line=$(escape_json "$line")
        item="{\"type\":\"cron\",\"entry\":\"$escaped_line\",\"reason\":\"Non-standard path in cron\"}"
        suspicious_json="$suspicious_json,$item"
      fi
    done
  done < "$file"
done

WriteLog "Scanning systemd timers..." INFO

timers=$(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $3}' | grep '\.timer$' || true)
for timer in $timers; do
  service="${timer%.timer}.service"
  service_path=$(systemctl show -p FragmentPath "$service" 2>/dev/null | cut -d= -f2 || true)
  exec_start=$(systemctl show -p ExecStart "$service" 2>/dev/null | cut -d= -f2- || true)
  
  for dir in $SUSP_DIRS; do
    if echo "$exec_start" | grep -q "$dir"; then
      escaped_service=$(escape_json "$service")
      escaped_exec=$(escape_json "$exec_start")
      item="{\"type\":\"systemd_timer\",\"entry\":\"$escaped_service\",\"reason\":\"ExecStart in suspicious path: $escaped_exec\"}"
      suspicious_json="$suspicious_json,$item"
    fi
  done
done

suspicious_json="${suspicious_json#,}" 
[ -n "$suspicious_json" ] && suspicious_json="[$suspicious_json]" || suspicious_json="[]"

ts=$(date --iso-8601=seconds)
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"data\":$suspicious_json,\"copilot_soar\":true}"

tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
mv -f "$tmpfile" "$ARLog" 2>/dev/null || mv -f "$tmpfile" "$ARLog.new"

dur=$(( $(date +%s) - runStart ))
WriteLog "JSON result written to $ARLog" INFO
WriteLog "=== SCRIPT END : duration ${dur}s ===" INFO

