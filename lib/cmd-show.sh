#!/usr/bin/env bash
# cmd-show.sh — print current TOTP codes with countdowns.

set -euo pipefail
source "$(dirname "$0")/common.sh"

WATCH=0
FILTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --watch|-w) WATCH=1; shift ;;
    --help|-h)  echo "usage: otp show [-w|--watch] [filter]"; exit 0 ;;
    --*) die "unknown flag: $1" ;;
    *) FILTER="$1"; shift ;;
  esac
done

require_bins oathtool
ensure_store

BAR_WIDTH=20

make_bar() {
  local filled="$1" empty="$2" out=""
  local i
  for ((i=0; i<filled; i++)); do out+='#'; done
  for ((i=0; i<empty;  i++)); do out+='.'; done
  printf '%s' "$out"
}

render() {
  local now; now=$(date +%s)
  printf '%-40s  %-10s  %-4s  %s\n' "NAME" "CODE" "LEFT" "EXPIRES"
  printf '%-40s  %-10s  %-4s  %s\n' "----" "----" "----" "-------"

  local uri raw label secret digits period algo code rem filled empty bar lshow
  while IFS= read -r uri; do
    [[ -z "$uri" ]] && continue
    [[ "$uri" == otpauth://totp/* ]] || continue

    raw="${uri#otpauth://totp/}"; raw="${raw%%\?*}"
    label="$(urldecode "$raw")"

    if [[ -n "$FILTER" ]]; then
      shopt -s nocasematch
      if [[ "$label" != *"$FILTER"* ]]; then shopt -u nocasematch; continue; fi
      shopt -u nocasematch
    fi

    secret="$(extract_secret "$uri")"
    [[ -n "$secret" ]] || continue
    digits="$(extract_param "$uri" digits)"; digits="${digits:-6}"
    period="$(extract_param "$uri" period)"; period="${period:-30}"
    algo="$(extract_param "$uri" algorithm)"; algo="${algo:-SHA1}"

    code="$(oathtool --base32 "--totp=$algo" "--digits=$digits" \
              "--time-step-size=${period}s" "$secret" 2>/dev/null || echo ERR)"

    rem=$(( period - now % period ))
    filled=$(( rem * BAR_WIDTH / period ))
    empty=$(( BAR_WIDTH - filled ))
    bar="$(make_bar "$filled" "$empty")"

    lshow="$label"
    [[ ${#lshow} -gt 40 ]] && lshow="${lshow:0:37}..."

    printf '%-40s  %-10s  %-4s  [%s]\n' "$lshow" "$code" "${rem}s" "$bar"
  done < "$OTP_STORE"
}

if [[ $WATCH -eq 1 ]]; then
  # In-place watch: print once, then move cursor back up N lines and
  # redraw over the same region every second. `\033[K` erases to end of
  # line so shrinking values don't leave trailing chars; cursor hidden
  # to stop it flickering at the bottom.
  command -v tput >/dev/null && tput civis
  trap 'command -v tput >/dev/null && tput cnorm; echo' EXIT INT TERM

  first=1
  lines=0
  while true; do
    frame="$(
      date '+%H:%M:%S  (Ctrl-C to exit)'
      echo
      render
    )"

    if [[ $first -eq 0 ]]; then
      printf '\033[%dA' "$lines"
    fi
    first=0

    lines=0
    while IFS= read -r row; do
      printf '\033[K%s\n' "$row"
      lines=$((lines+1))
    done <<< "$frame"

    sleep 1
  done
else
  render
fi
