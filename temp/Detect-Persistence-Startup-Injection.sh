#!/bin/sh
set -eu
ScriptName="Detect-Persistence-Startup-Injection"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart=$(date +%s)

RECENT_DAYS="${RECENT_DAYS:-90}"
HASH_ALL="${HASH_ALL:-0}"
DO_FIX="0"
[ "${1:-}" = "--fix" ] && DO_FIX="1"
[ "${FIX:-0}" = "1" ] && DO_FIX="1"

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

escape_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

RotateLog
if ! rm -f "$ARLog" 2>/dev/null; then
  WriteLog "Failed to clear $ARLog (might be locked)" WARN
else
  : > "$ARLog"
  WriteLog "Active response log cleared for fresh run." INFO
fi
WriteLog "=== SCRIPT START : $ScriptName ==="

is_valid_shell() { case "$1" in */nologin|*/false|"") return 1 ;; *) return 0 ;; esac; }

collect_targets() {
  printf '%s\n' "/etc/profile" "/etc/bash.bashrc"
  if [ "${SKIP_ETC_PROFILED:-0}" != "1" ] && [ -d /etc/profile.d ]; then
    find /etc/profile.d -maxdepth 1 -type f -name '*.sh' 2>/dev/null
  fi
  getent passwd | awk -F: '($3>=1000 || $1=="root"){print $6":"$7}' | \
  while IFS=: read -r home shell; do
    is_valid_shell "$shell" || continue
    [ -d "$home" ] || continue
    printf '%s\n' \
      "$home/.bashrc" "$home/.profile" "$home/.bash_profile" "$home/.bash_login" \
      "$home/.zshrc" "$home/.zprofile" "$home/.zlogin" \
      "$home/.xprofile" "$home/.xsessionrc"
  done
}

is_comment_or_blank() {
  line="$1"
  printf '%s' "$line" | grep -Eq '^[[:space:]]*$' && return 0 || true
  printf '%s' "$line" | grep -Eq '^[[:space:]]*#' && return 0 || true
  return 1
}

is_benign_line() {
  echo "$1" | grep -Eiq '(PS1=|PROMPT_COMMAND=__vte_|bash_completion|XDG_DATA_DIRS|XDG_CONFIG_DIRS|debian_chroot|lesspipe|dircolors|checkwinsize|sudo hint|flatpak\.sh|vte-2\.91\.sh|cloud-init warnings|locale test|apps-bin-path|gnome-session_gnomerc|cedilla-portuguese|^return 0$)'
}

hit_category() {
  line="$1"
  echo "$line" | grep -Eiq '(curl|wget|fetch)[^|;\n]*https?://[^|;\n]*\|\s*(sh|bash|zsh|ksh)' && { echo "pipe_download"; return; }
  echo "$line" | grep -Eiq 'base64\s+-d\s*\|\s*(sh|bash)|python[^#\n]*base64[^#\n]*decode|perl[^#\n]*MIME::Base64|eval\s+["'\''`].{0,200}(base64|\\x[0-9a-f]{2}|[A-Za-z0-9+/]{200,}={0,2})' && { echo "encoded_exec"; return; }
  echo "$line" | grep -Eiq '(nc|ncat|netcat)\s+[^#\n]*( -e |/bin/sh|/bin/bash)|bash\s+-i[^#\n]*>/dev/tcp/|/dev/tcp/[0-9\.]+/[0-9]+|python\s+-c\s*["'\''`][^"'\''`]*socket[^"'\''`]*connect|openssl\s+s_client[^|]*\|\s*(sh|bash)' && { echo "revshell"; return; }
  echo "$line" | grep -Eiq 'stratum\+tcp|xmrig|minerd|cpuminer|hellminer|nbminer|t-rex|trex|lolminer|bminer|phoenixminer|teamredminer|gminer|ethminer' && { echo "miner"; return; }
  echo "$line" | grep -Eiq '(^|;|\s)export\s+PATH=.*(^|:)(\.|/tmp|/var/tmp|/dev/shm)(:|$)|(^|;|\s)(LD_PRELOAD=|export\s+LD_PRELOAD)\s*/(tmp|var/tmp|dev/shm)/' && { echo "env_hijack"; return; }
  echo "$line" | grep -Eiq 'PROMPT_COMMAND=.*(curl|wget|nc|/dev/tcp|bash\s+-i)|(^|;|\s)trap\s+['"'"'"].*['"'"'"]' && { echo "prompt_trap"; return; }
  echo ""
}

file_score_for_cat() { case "$1" in revshell) echo 50 ;; pipe_download|encoded_exec) echo 40 ;; miner) echo 35 ;; env_hijack|prompt_trap) echo 25 ;; *) echo 0 ;; esac; }

scan_file() {
  f="$1"; tmp_hits="$2"
  [ -f "$f" ] || { printf '{"path":"%s","exists":"false"}' "$(escape_json "$f")"; : > "$tmp_hits"; return 0; }
  [ -r "$f" ] || { printf '{"path":"%s","exists":"true","readable":"false"}' "$(escape_json "$f")"; : > "$tmp_hits"; return 0; }
  mtime_epoch="$(stat -c %Y "$f" 2>/dev/null || date -r "$f" +%s 2>/dev/null || echo 0)"
  mtime_iso="$(date -u -d "@$mtime_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -r "$f" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")"
  size="$(stat -c%s "$f" 2>/dev/null || wc -c <"$f" 2>/dev/null || echo 0)"
  owner="$(stat -c '%U' "$f" 2>/dev/null || echo "")"
  perm="$(stat -c '%a' "$f" 2>/dev/null || echo "")"
  ww="false"; echo "$perm" | grep -Eq '.[2367][2367]$' && ww="true"
  hits_json=""; total_score=0; count=0; ln=0; : > "$tmp_hits"
  while IFS= read -r line || [ -n "$line" ]; do
    ln=$((ln+1))
    is_comment_or_blank "$line" && continue
    is_benign_line "$line" && continue
    catg="$(hit_category "$line")"; [ -z "$catg" ] && continue
    count=$((count+1)); s="$(file_score_for_cat "$catg")"; total_score=$((total_score+s))
    esc="$(escape_json "$(printf '%s' "$line" | tr -d '\r')")"
    j="{\"line\":$ln,\"category\":\"$(escape_json "$catg")\",\"text\":\"$esc\"}"
    [ -z "$hits_json" ] && hits_json="[$j" || hits_json="$hits_json,$j"
    printf '%s\n' "$ln" >> "$tmp_hits"
    [ $count -ge 100 ] && break
  done < "$f"
  [ -z "$hits_json" ] && hits_json="[]"
  susp="false"; [ "$count" -gt 0 ] && susp="true"
  sha=""
  if [ "$HASH_ALL" = "1" ] || [ "$susp" = "true" ]; then
    command -v sha256sum >/dev/null 2>&1 && sha="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
  fi
  recent="$( [ $(( $(date +%s) - mtime_epoch )) -le $(( RECENT_DAYS*86400 )) ] && echo true || echo false )"
  printf '{"path":"%s","exists":"true","mtime":"%s","size":"%s","sha256":"%s","owner":"%s","perm":"%s","world_writable":"%s","suspicious":%s,"score":%s,"hits":%s,"recent_mod":%s}' \
    "$(escape_json "$f")" "$(escape_json "$mtime_iso")" "$(escape_json "$size")" "$(escape_json "$sha")" "$(escape_json "$owner")" "$(escape_json "$perm")" "$ww" "$susp" "$total_score" "$hits_json" "$recent"
}

targets="$(collect_targets | awk 'NF' | sort -u)"
payload_items=""; tmpdir="$(mktemp -d)"

for tgt in $targets; do
  hf="$tmpdir/$(echo "$tgt" | sed 's/[\/\.]/_/g').lines"
  rec="$(scan_file "$tgt" "$hf")"
  [ -z "$payload_items" ] && payload_items="$rec" || payload_items="$payload_items,$rec"
done

overall_sev="low"
printf '%s' "$payload_items" | grep -q '"category":"revshell"' && overall_sev="critical"
[ "$overall_sev" = "low" ] && printf '%s' "$payload_items" | grep -q '"category":"pipe_download"' && overall_sev="high"
[ "$overall_sev" = "low" ] && printf '%s' "$payload_items" | grep -q '"category":"encoded_exec"' && overall_sev="high"
[ "$overall_sev" = "low" ] && printf '%s' "$payload_items" | grep -q '"category":"miner"' && overall_sev="medium"
[ "$overall_sev" = "low" ] && printf '%s' "$payload_items" | grep -q '"category":"env_hijack"' && overall_sev="medium"
[ "$overall_sev" = "low" ] && printf '%s' "$payload_items" | grep -q '"category":"prompt_trap"' && overall_sev="medium"
[ "$overall_sev" != "low" ] && printf '%s' "$payload_items" | grep -q '"recent_mod":true' && overall_sev="critical"

remediations="[]"
FIX_MADE=0
if [ "$DO_FIX" = "1" ] && { [ "$overall_sev" = "high" ] || [ "$overall_sev" = "critical" ]; }; then
  WriteLog "Auto-remediation enabled (--fix). Applying safe comments to flagged lines." WARN
  rem_list=""
  for tgt in $targets; do
    hf="$tmpdir/$(echo "$tgt" | sed 's/[\/\.]/_/g').lines"
    [ -f "$tgt" ] || continue
    [ -s "$hf" ] || continue
    tsfix="$(date -u '+%Y%m%d%H%M%S')"
    bak="${tgt}.bak.${tsfix}"
    cp -p "$tgt" "$bak" 2>/dev/null || cp "$tgt" "$bak" 2>/dev/null || true
    lines="$(awk 'NF' "$hf" | paste -sd, -)"
    tmpf="$tmpdir/patch.$$"
    awk -v LINES="$lines" -v TS="$tsfix" '
      BEGIN{ split(LINES, a, ","); for(i in a) mark[a[i]]=1 }
      { ln++; if (ln in mark) { print "# [SOAR-" TS "] " $0 } else { print $0 } }
    ' ln=0 "$tgt" > "$tmpf"
    mv -f "$tmpf" "$tgt"
    FIX_MADE=1
    j="{\"file\":\"$(escape_json "$tgt")\",\"backup\":\"$(escape_json "$bak")\",\"commented_lines\":["
    first=1
    for l in $(awk 'NF' "$hf"); do
      if [ $first -eq 1 ]; then j="$j$l"; first=0; else j="$j,$l"; fi
    done
    j="$j]}"
    [ -z "$rem_list" ] && rem_list="$j" || rem_list="$rem_list,$j"
  done
  remediations="[$rem_list]"
fi

payload="{\"targets\":[$payload_items],\"severity\":\"$overall_sev\",\"recent_days\":\"$RECENT_DAYS\",\"hash_all\":\"$HASH_ALL\",\"fix_applied\":$([ $FIX_MADE -eq 1 ] && echo true || echo false),\"remediations\":$remediations}"
ts=$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')
final_json="{\"timestamp\":\"$ts\",\"host\":\"$HostName\",\"action\":\"$ScriptName\",\"data\":$payload,\"copilot_soar\":true}"

tmpfile=$(mktemp)
printf '%s\n' "$final_json" > "$tmpfile"
if ! mv -f "$tmpfile" "$ARLog" 2>/dev/null; then mv -f "$tmpfile" "$ARLog.new"; fi

WriteLog "JSON result written to $ARLog" INFO
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
