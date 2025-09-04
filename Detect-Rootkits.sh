#!/bin/sh
set -eu

ScriptName="Detect-Rootkits"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"

DEFAULT_PROC="/proc/modules"
HINTS_FILE="${MODULE_HINTS:-/tmp/modules.hints}"

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

iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; }
AddRecord(){
  ts="$(iso_now)"
  src="$1"; mod="$2"; path="$3"; signed="$4"; hidden="$5"; from_tmp="$6"; reason="$7"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"source":"%s","module":"%s","path":"%s","signed":%s,"hidden_from_lsmod":%s,"from_temp_dir":%s,"reason":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" \
    "$(escape_json "$src")" "$(escape_json "$mod")" "$(escape_json "$path")" \
    "$signed" "$hidden" "$from_tmp" "$(escape_json "$reason")" >> "$TMP_AR"
}
AddStatus(){
  ts="$(iso_now)"; st="${1:-info}"; msg="$(escape_json "${2:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"
}
CommitNDJSON(){
  [ -s "$TMP_AR" ] || AddStatus "no_results" "no suspicious kernel modules found"
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog"; then
    WriteLog "Wrote NDJSON to $ARLog" INFO
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new"; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

looks_like_modules_file() {
  awk '
    /^[[:space:]]*$/ {next}
    /^[[:space:]]*#/ {next}
    { if (NF >= 3 && $1 ~ /^[A-Za-z0-9_-]+$/) { print "OK"; exit } else { print "NO"; exit } }
    END { if (NR==0) print "NO" }
  ' "$1" 2>/dev/null
}

find_mock_modules() {
  for base in /tmp /var/tmp /dev/shm; do
    [ -d "$base" ] || continue
    cand=$(
      find "$base" -xdev -type f -size -5120k -printf '%T@ %p\n' 2>/dev/null \
      | sort -nr \
      | while read -r ts path; do
          [ -r "$path" ] || continue
          if [ "$(looks_like_modules_file "$path")" = "OK" ]; then
            printf '%s\n' "$path"
            break
          fi
        done
    )
    if [ -n "$cand" ]; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  return 1
}

lookup_hint_path() {
  m="$1"
  [ -r "$HINTS_FILE" ] || return 1
  awk -v mod="$m" 'NF>=2 && $1==mod {print $2; exit}' "$HINTS_FILE"
}

choose_modules_source() {
  if [ -n "${PROC_MODULES_FILE:-}" ] && [ -r "${PROC_MODULES_FILE:-}" ]; then
    printf '%s\n' "$PROC_MODULES_FILE"; return
  fi
  mock="$(find_mock_modules || true)"
  if [ -n "$mock" ]; then
    WriteLog "Using mock modules source: $mock" INFO
    printf '%s\n' "$mock"; return
  fi
  printf '%s\n' "$DEFAULT_PROC"
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="
BeginNDJSON

SRC_FILE="$(choose_modules_source)"
if [ ! -r "$SRC_FILE" ]; then
  AddStatus "error" "cannot read modules source: $SRC_FILE"
  CommitNDJSON
  dur=$(( $(date +%s) - runStart )); WriteLog "=== SCRIPT END : ${dur}s ==="
  exit 0
fi

HAVE_MODINFO=0; command -v modinfo >/dev/null 2>&1 && HAVE_MODINFO=1
HAVE_LSMOD=0;   command -v lsmod   >/dev/null 2>&1 && HAVE_LSMOD=1

proc_list=$(awk '{print $1}' "$SRC_FILE" 2>/dev/null || true)
lsmod_list=""
[ "$HAVE_LSMOD" -eq 1 ] && lsmod_list="$(lsmod 2>/dev/null | awk 'NR>1{print $1}')" || true

emitted=0
for module in $proc_list; do
  path=""
  signed=true
  hidden=false
  from_tmp=false
  reason_list=""

  if [ "$HAVE_MODINFO" -eq 1 ]; then
    path="$(modinfo -n "$module" 2>/dev/null || echo "")"
    signer="$(modinfo -F signer "$module" 2>/dev/null || echo "")"
    [ -n "$signer" ] || signed=false
  else
    signed=false
    reason_list="${reason_list:+$reason_list; }modinfo unavailable"
  fi

  [ -z "${path:-}" ] && path="$(lookup_hint_path "$module" || true)"

  if [ -n "$path" ] && printf '%s' "$path" | grep -Eq '^(/tmp|/var/tmp|/dev/shm)(/|$)'; then
    from_tmp=true
    reason_list="${reason_list:+$reason_list; }module path in temp dir"
  fi

  if [ "$HAVE_LSMOD" -eq 1 ]; then
    printf '%s\n' "$lsmod_list" | grep -qx "$module" || { hidden=true; reason_list="${reason_list:+$reason_list; }hidden from lsmod"; }
  else
    reason_list="${reason_list:+$reason_list; }lsmod unavailable"
  fi

  if [ "$from_tmp" = true ] || [ "$signed" = false ] || [ "$hidden" = true ]; then
    AddRecord "$SRC_FILE" "$module" "${path:-}" \
      "$([ "$signed" = true ] && echo true || echo false)" \
      "$([ "$hidden" = true ] && echo true || echo false)" \
      "$([ "$from_tmp" = true ] && echo true || echo false)" \
      "${reason_list:-suspicious properties}"
    emitted=$((emitted+1))
  fi
done

[ "$emitted" -gt 0 ] || AddStatus "info" "no suspicious kernel modules found (source: $SRC_FILE)"

CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
