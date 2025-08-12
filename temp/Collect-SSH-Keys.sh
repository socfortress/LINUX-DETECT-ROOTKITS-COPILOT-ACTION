#!/bin/bash
set -eu

ScriptName="Collect-SSH-Keys"
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
: > "$ARLog"
WriteLog "Active response log cleared for fresh run."

WriteLog "=== SCRIPT START : $ScriptName ==="

declare -a SSH_LOCATIONS

mapfile -t USER_HOMES < <(awk -F: '$3 >= 1000 && $1 != "nobody" {print $6}' /etc/passwd)

for home in "${USER_HOMES[@]}"; do
  SSH_LOCATIONS+=("$home/.ssh")
done
SSH_LOCATIONS+=("/etc/ssh")

data_json="["

first_entry=true

for dir in "${SSH_LOCATIONS[@]}"; do
  [ -d "$dir" ] || continue

  for file in authorized_keys config ssh_config sshd_config id_rsa id_dsa id_ecdsa id_ed25519; do
    path="$dir/$file"
    [ -f "$path" ] || continue

    content=$(sed 's/"/\\"/g' "$path" | tr -d '\r')
    escaped_content=$(escape_json "$content")

    reason=""
    if [[ "$file" == "authorized_keys" ]]; then
      if grep -qE '^\s*$' "$path"; then
        reason="Contains empty lines"
      elif grep -qE 'ssh-rsa' "$path"; then
        reason="Contains ssh-rsa key (considered weak)"
      fi
    fi

    entry_json="{\"file\":\"$path\",\"content\":\"$escaped_content\""
    [ -n "$reason" ] && entry_json+=",\"flag\":\"$reason\""
    entry_json+="}"

    if $first_entry; then
      data_json+="$entry_json"
      first_entry=false
    else
      data_json+=",$entry_json"
    fi
  done
done

data_json+="]"

ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"data\":$data_json,\"copilot_soar\":true}"

tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then
  mv -f "$tmpfile" "$ARLog.new"
fi

WriteLog "JSON result written to $ARLog"

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
