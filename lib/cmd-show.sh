#!/usr/bin/env bash
# cmd-show.sh — print current TOTP codes with countdowns.
# In watch mode (-w), letter keys a-z copy the corresponding code to
# the clipboard without leaving watch mode.

set -euo pipefail
source "$(dirname "$0")/common.sh"

WATCH=0
FILTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --watch|-w) WATCH=1; shift ;;
    --help|-h)
      cat <<'EOF'
usage: otp show [-w|--watch] [filter]

Prints a table: key (a-z), name, code, seconds left, countdown bar.
With -w the view redraws in place every second and letter keys copy
the matching code to the clipboard (Ctrl-C to exit). Hard-capped at
26 rows; use [filter] to narrow.
EOF
      exit 0 ;;
    --*) die "unknown flag: $1" ;;
    *) FILTER="$1"; shift ;;
  esac
done

require_bins oathtool
ensure_store

BAR_WIDTH=20
LETTERS=(a b c d e f g h i j k l m n o p q r s t u v w x y z)

make_bar() {
  local filled="$1" empty="$2" out="" i
  for ((i=0; i<filled; i++)); do out+='#'; done
  for ((i=0; i<empty;  i++)); do out+='.'; done
  printf '%s' "$out"
}

# Matches filter (case-insensitive substring). Always-succeed so set -e safe.
label_matches() {
  local label="$1"
  [[ -z "$FILTER" ]] && return 0
  shopt -s nocasematch
  local hit=1
  [[ "$label" == *"$FILTER"* ]] && hit=0
  shopt -u nocasematch
  return $hit
}

render() {
  local now; now=$(date +%s)
  printf '%-4s  %-40s  %-10s  %-4s  %s\n' "KEY" "NAME" "CODE" "LEFT" "EXPIRES"
  printf '%-4s  %-40s  %-10s  %-4s  %s\n' "---" "----" "----" "----" "-------"

  local uri raw label secret digits period algo code rem filled empty bar lshow
  local idx=0 capped=0
  while IFS= read -r uri; do
    [[ -z "$uri" ]] && continue
    [[ "$uri" == otpauth://totp/* ]] || continue

    raw="${uri#otpauth://totp/}"; raw="${raw%%\?*}"
    label="$(urldecode "$raw")"
    label_matches "$label" || continue

    if [[ $idx -ge 26 ]]; then capped=1; break; fi

    secret="$(extract_secret "$uri")"
    [[ -n "$secret" ]] || continue
    digits="$(extract_param "$uri" digits)";    digits="${digits:-6}"
    period="$(extract_param "$uri" period)";    period="${period:-30}"
    algo="$(extract_param   "$uri" algorithm)"; algo="${algo:-SHA1}"

    code="$(oathtool --base32 "--totp=$algo" "--digits=$digits" \
              "--time-step-size=${period}s" "$secret" 2>/dev/null || echo ERR)"

    rem=$(( period - now % period ))
    filled=$(( rem * BAR_WIDTH / period ))
    empty=$(( BAR_WIDTH - filled ))
    bar="$(make_bar "$filled" "$empty")"

    lshow="$label"
    [[ ${#lshow} -gt 40 ]] && lshow="${lshow:0:37}..."

    printf '[%s]   %-40s  %-10s  %-4s  [%s]\n' \
      "${LETTERS[$idx]}" "$lshow" "$code" "${rem}s" "$bar"
    idx=$((idx+1))
  done < "$OTP_STORE"

  if [[ $capped -eq 1 ]]; then
    printf '(more than 26 entries — narrow with a filter to see the rest)\n'
  fi
}

# copy_by_letter LETTER : looks up the Nth matching entry, copies its code,
# forks a one-shot clipboard clear for rotation. Always-succeed; prints one
# status line on stdout.
copy_by_letter() {
  local letter="${1,}"            # lowercase
  local target=$(( $(printf '%d' "'$letter") - 97 ))
  [[ $target -ge 0 && $target -lt 26 ]] || { printf 'bad key'; return 0; }

  local n=0 uri raw label secret digits period algo code rem now
  while IFS= read -r uri; do
    [[ "$uri" == otpauth://totp/* ]] || continue
    raw="${uri#otpauth://totp/}"; raw="${raw%%\?*}"
    label="$(urldecode "$raw")"
    label_matches "$label" || continue

    if [[ $n -eq $target ]]; then
      secret="$(extract_secret "$uri")"
      [[ -n "$secret" ]] || { printf 'no secret for "%s"' "$label"; return 0; }
      digits="$(extract_param "$uri" digits)";    digits="${digits:-6}"
      period="$(extract_param "$uri" period)";    period="${period:-30}"
      algo="$(extract_param   "$uri" algorithm)"; algo="${algo:-SHA1}"

      code="$(oathtool --base32 "--totp=$algo" "--digits=$digits" \
                "--time-step-size=${period}s" "$secret" 2>/dev/null || true)"
      [[ -n "$code" ]] || { printf 'oathtool failed for "%s"' "$label"; return 0; }

      now=$(date +%s); rem=$(( period - now % period ))

      if ! printf '%s' "$code" | clipboard_write_text 2>/dev/null; then
        printf 'clipboard write failed (install wl-clipboard or xclip)'
        return 0
      fi

      # Auto-clear when the code rotates, only if clipboard still holds THIS code.
      (
        sleep "$((rem + 2))"
        current="$(clipboard_read_text || true)"
        [[ "$current" == "$code" ]] && clipboard_clear
      ) </dev/null >/dev/null 2>&1 &
      disown

      printf 'copied: %s  (valid %ds; auto-clears at rotation)' "$label" "$rem"
      return 0
    fi
    n=$((n+1))
  done < "$OTP_STORE"
  printf 'no entry at [%s]' "$letter"
}

if [[ $WATCH -eq 1 ]]; then
  command -v tput >/dev/null && tput civis
  # Cleanup only on EXIT. INT/TERM must actually exit (not just run a
  # handler and resume), otherwise Ctrl-C turns into an advisory signal
  # and the loop keeps redrawing. exit 130 triggers the EXIT trap.
  trap 'command -v tput >/dev/null && tput cnorm; echo' EXIT
  trap 'exit 130' INT TERM

  first=1
  lines=0
  status="press a-z to copy, Ctrl-C to exit"

  while true; do
    frame="$(
      date '+%H:%M:%S'
      echo
      render
      echo
      printf '%s' "$status"
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

    # Wait up to 1s for a key (cbreak mode; -s suppresses echo)
    key=""
    if read -rsn1 -t 1 key 2>/dev/null; then
      case "$key" in
        [a-zA-Z]) status="$(copy_by_letter "$key")" ;;
        "")       ;;
      esac
    fi
  done
else
  render
fi
