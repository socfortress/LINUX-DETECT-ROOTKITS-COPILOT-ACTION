#!/bin/sh
set -eu

ScriptName="Collect-Browser-Artifacts"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)
VERBOSE=1

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"
  case "$Level" in
    ERROR) printf '\033[31m%s\033[0m\n' "$line" >&2 ;;
    WARN)  printf '\033[33m%s\033[0m\n' "$line" >&2 ;;
    DEBUG) [ "$VERBOSE" -eq 1 ] && printf '\033[36m%s\033[0m\n' "$line" >&2 ;;
    *)     printf '%s\n' "$line" >&2 ;;
  esac
  printf '%s\n' "$line" >> "$LogPath" 2>/dev/null || true
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
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; print(json.dumps(sys.stdin.read())[1:-1])"
  else
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
  fi
}

RotateLog

if ! rm -f "$ARLog" 2>/dev/null; then
  WriteLog "Failed to clear $ARLog (might be locked)" WARN
else
  : > "$ARLog"
  WriteLog "Active response log cleared for fresh run." INFO
fi

WriteLog "=== SCRIPT START : $ScriptName ==="

install_sqlite3() {
  if ! command -v sqlite3 >/dev/null 2>&1; then
    WriteLog "sqlite3 not found. Attempting install..." WARN
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update && apt-get install -y sqlite3
    elif command -v yum >/dev/null 2>&1; then
      yum install -y sqlite
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y sqlite
    else
      WriteLog "No supported package manager for sqlite3 install." ERROR
      return 1
    fi
  fi
}

query_sqlite() {
  db="$1"
  sql="$2"
  [ -s "$db" ] || return 0
  tmpdb="/tmp/$(basename "$db").$$"
  cp "$db" "$tmpdb" 2>/dev/null || return 0
  result=$(timeout 10 sqlite3 -readonly -json "$tmpdb" "$sql" 2>/dev/null | sed '/^null$/d' || true)
  rm -f "$tmpdb"
  echo "$result"
}

collect_chrome_artifacts_all() {
  results=""
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user=$(basename "$home")
    for browser in "google-chrome" "chromium"; do
      profile_dir="$home/.config/$browser/Default"
      [ -d "$profile_dir" ] || continue
      WriteLog "Collecting from $user - $browser" DEBUG
      out=""
      history=$(query_sqlite "$profile_dir/History" "SELECT url,title,datetime(last_visit_time/1000000-11644473600,'unixepoch') AS last_visit FROM urls ORDER BY last_visit_time DESC;")
      [ -n "$history" ] && out="$out\"history\":$history,"
      if [ -f "$profile_dir/Bookmarks" ]; then
        bookmarks=$(tr -d '\n\r\000' < "$profile_dir/Bookmarks")
        bookmarks=$(echo "$bookmarks" | escape_json)
        [ -n "$bookmarks" ] && out="$out\"bookmarks\":\"$bookmarks\","
      fi
      downloads=$(query_sqlite "$profile_dir/History" "SELECT target_path,tab_url,datetime(start_time/1000000-11644473600,'unixepoch') as start_time FROM downloads ORDER BY start_time DESC;")
      [ -n "$downloads" ] && out="$out\"downloads\":$downloads,"
      cookies=$(query_sqlite "$profile_dir/Network/Cookies" "SELECT host_key,name,value,datetime(expires_utc/1000000-11644473600,'unixepoch') as expires FROM cookies;")
      [ -n "$cookies" ] && out="$out\"cookies\":$cookies,"
      out="${out%,}"
      [ -n "$out" ] && results="$results,\"$user-$browser\":{$out}"
    done
  done
  [ -n "$results" ] && printf '"chrome_chromium":{%s}' "${results#,}"
}

collect_edge_artifacts_all() {
  results=""
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user=$(basename "$home")
    profile_dir="$home/.config/microsoft-edge/Default"
    [ -d "$profile_dir" ] || continue
    WriteLog "Collecting from $user - edge" DEBUG
    out=""
    history=$(query_sqlite "$profile_dir/History" "SELECT url,title,datetime(last_visit_time/1000000-11644473600,'unixepoch') AS last_visit FROM urls ORDER BY last_visit_time DESC;")
    [ -n "$history" ] && out="$out\"history\":$history,"
    if [ -f "$profile_dir/Bookmarks" ]; then
      bookmarks=$(tr -d '\n\r\000' < "$profile_dir/Bookmarks")
      bookmarks=$(echo "$bookmarks" | escape_json)
      [ -n "$bookmarks" ] && out="$out\"bookmarks\":\"$bookmarks\","
    fi
    downloads=$(query_sqlite "$profile_dir/History" "SELECT target_path,tab_url,datetime(start_time/1000000-11644473600,'unixepoch') as start_time FROM downloads ORDER BY start_time DESC;")
    [ -n "$downloads" ] && out="$out\"downloads\":$downloads,"
    cookies=$(query_sqlite "$profile_dir/Network/Cookies" "SELECT host_key,name,value,datetime(expires_utc/1000000-11644473600,'unixepoch') as expires FROM cookies;")
    [ -n "$cookies" ] && out="$out\"cookies\":$cookies,"
    out="${out%,}"
    [ -n "$out" ] && results="$results,\"$user-edge\":{$out}"
  done
  [ -n "$results" ] && printf '"edge":{%s}' "${results#,}"
}

collect_firefox_artifacts_all() {
  results=""
  for home in /home/* /root; do
    [ -d "$home" ] || continue
    user=$(basename "$home")
    for base in \
      "$home/.mozilla/firefox" \
      "$home/.var/app/org.mozilla.firefox/.mozilla/firefox" \
      "$home/snap/firefox/common/.mozilla/firefox"; do

      [ -d "$base" ] || continue
      for prof in "$base"/*.default*; do
        [ -d "$prof" ] || continue
        WriteLog "Collecting from $user - firefox profile $(basename "$prof") [$base]" DEBUG
        out=""
        history=$(query_sqlite "$prof/places.sqlite" "SELECT url,title,datetime(last_visit_date/1000000,'unixepoch') as last_visit FROM moz_places ORDER BY last_visit_date DESC;")
        [ -n "$history" ] && out="$out\"history\":$history,"
        cookies=$(query_sqlite "$prof/cookies.sqlite" "SELECT host,name,value,datetime(expiry,'unixepoch') as expires FROM moz_cookies;")
        [ -n "$cookies" ] && out="$out\"cookies\":$cookies,"
        downloads=$(query_sqlite "$prof/downloads.sqlite" "SELECT name,source,datetime(endTime/1000000,'unixepoch') as end_time FROM moz_downloads;")
        [ -n "$downloads" ] && out="$out\"downloads\":$downloads,"
        out="${out%,}"
        [ -n "$out" ] && results="$results,\"$user-firefox\":{$out}"
      done
    done
  done
  [ -n "$results" ] && printf '"firefox":{%s}' "${results#,}"
}

install_sqlite3 || {
  ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
  errorMsg="sqlite3 missing and could not be installed."
  WriteLog "$errorMsg" ERROR
  final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"status\":\"error\",\"error\":\"$errorMsg\",\"copilot_soar\":true}"
  tmpfile=$(mktemp)
  printf '%s\n' "$final_json" > "$tmpfile"
  if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then mv -f "$tmpfile" "$ARLog.new"; fi
  exit 1
}

payload=""
for func in collect_chrome_artifacts_all collect_edge_artifacts_all collect_firefox_artifacts_all; do
  WriteLog "Starting collection: $func" INFO
  val=$($func 2>/dev/null || true)
  [ -n "$val" ] && payload="$payload,$val"
done
payload="{${payload#,}}"

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
