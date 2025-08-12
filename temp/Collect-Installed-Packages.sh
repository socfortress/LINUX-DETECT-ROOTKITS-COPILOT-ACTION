#!/bin/sh
set -eu
ScriptName="Collect-Installed-Packages"
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
if command -v dpkg-query >/dev/null 2>&1; then
  PKG_MANAGER="apt"
  INSTALLED="$(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort)"
  UPDATES="$(apt list --upgradeable 2>/dev/null | awk 'NR>1 {print $1 " " $2}' | sort)"
  RECENT="$(grep ' install ' /var/log/dpkg.log* 2>/dev/null | awk -v d1="$(date --date='7 days ago' +%Y-%m-%d)" '$1>=d1 {print $0}' | cut -d' ' -f1,5 | sort)"
elif command -v rpm >/dev/null 2>&1; then
  PKG_MANAGER="rpm"
  INSTALLED="$(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | sort)"
  if command -v dnf >/dev/null 2>&1; then
    UPDATES="$(dnf check-update 2>/dev/null | grep -E '^[a-zA-Z0-9_\-\.\+]+ ' | awk '{print $1 " " $2}' | sort || true)"
  elif command -v yum >/dev/null 2>&1; then
    UPDATES="$(yum check-update 2>/dev/null | grep -E '^[a-zA-Z0-9_\-\.\+]+ ' | awk '{print $1 " " $2}' | sort || true)"
  else
    UPDATES=""
  fi
  RECENT="$(find /var/log/ -type f -name "*yum.log*" -exec grep 'Installed:' {} \; 2>/dev/null | awk -v d1="$(date --date='7 days ago' +%Y-%m-%d)" '$1>=d1 {print $0}' | cut -d':' -f2- | sort)"
else
  WriteLog "No supported package manager found." ERROR
  payload='{"error":"No supported package manager found."}'
fi

if [ -z "${payload:-}" ]; then
  installed_json="$(printf '%s\n' "$INSTALLED" | awk '{printf "\"%s\",\n", $0}' | sed '$s/,$//')"
  updates_json="$(printf '%s\n' "$UPDATES" | awk '{printf "\"%s\",\n", $0}' | sed '$s/,$//')"
  recent_json="$(printf '%s\n' "$RECENT" | awk '{printf "\"%s\",\n", $0}' | sed '$s/,$//')"

  payload="{\"package_manager\":\"$PKG_MANAGER\",\
\"installed_packages\":[${installed_json}],\
\"available_updates\":[${updates_json}],\
\"recent_installs_7days\":[${recent_json}]}"
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
