#!/bin/sh
set -eu

LogPath="/tmp/ListLinuxUsers-script.log"
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
    ERROR) printf '\033[31m%s\033[0m\n' "$line" ;;
    WARN)  printf '\033[33m%s\033[0m\n' "$line" ;;
    DEBUG) [ "${VERBOSE:-0}" -eq 1 ] && printf '%s\n' "$line" ;;
    *)     printf '%s\n' "$line" ;;
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

WriteLog "=== SCRIPT START : List Linux Users ==="

escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

shadow_status() {
  user="$1"
  entry=$(grep "^$user:" /etc/shadow 2>/dev/null || true)
  if [ -z "$entry" ]; then
    printf 'true|false|'
    return
  fi
  pw_field=$(printf '%s' "$entry" | cut -d: -f2)
  expire_days=$(printf '%s' "$entry" | cut -d: -f8)
  today=$(($(date +%s)/86400))
  required=true; expired=false
  [ "$pw_field" = "!" ] || [ "$pw_field" = "*" ] && required=false
  [ -n "$expire_days" ] && [ "$expire_days" -gt 0 ] && [ "$expire_days" -lt "$today" ] && expired=true
  printf '%s|%s|' "$required" "$expired"
}

# Build user JSON in a variable directly (no subshell)
user_json="["
first_user=1
for entry in $(getent passwd | awk -F: '$3 >= 0 {print $1":"$5":"$6}'); do
  username=$(printf '%s' "$entry" | cut -d: -f1)
  gecos=$(printf '%s' "$entry" | cut -d: -f2)
  homedir=$(printf '%s' "$entry" | cut -d: -f3)

  case "$username" in
    daemon|bin|sys|sync|games|man|lp|mail|news) continue ;; # skip obvious service accounts
  esac

  full=$(escape_json "$gecos")
  groups_list=$(id -nG "$username" 2>/dev/null | tr ' ' ',' || true)
  lastlogon=$(lastlog "$username" 2>/dev/null | head -n1 | awk '{print $4,$5,$6,$7}' || true)
  lastlogon=$(escape_json "$lastlogon")

  status_fields=$(shadow_status "$username")
  pw_required=$(printf '%s' "$status_fields" | cut -d'|' -f1)
  pw_expired=$(printf '%s' "$status_fields" | cut -d'|' -f2)

  json_user="{\"username\":\"$username\",\"fullname\":\"$full\",\"home\":\"$homedir\",\"groups\":\"$groups_list\",\"lastlogon\":\"$lastlogon\",\"password_required\":$pw_required,\"password_expired\":$pw_expired}"

  if [ $first_user -eq 1 ]; then
    user_json="$user_json$json_user"
    first_user=0
  else
    user_json="$user_json,$json_user"
  fi
done
user_json="$user_json]"

ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"list_linux_users\",\"users\":$user_json,\"copilot_soar\":true}"

tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

WriteLog "User list JSON written to $ARLog" INFO
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
