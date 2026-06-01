#!/usr/bin/env bash
# cmd-copy.sh — copy the current TOTP code for a single matching entry
# onto the system clipboard. Auto-clears when the code rotates.

set -euo pipefail
source "$(dirname "$0")/common.sh"

KEEP=0
FILTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep|--no-clear) KEEP=1; shift ;;
    --help|-h)
      cat <<'EOF'
usage: otp copy FILTER [--no-clear]

Puts the current TOTP code for the single entry whose label contains
FILTER (case-insensitive) onto the clipboard. Exactly one match is
required; ambiguous filters print the candidates and abort.

Default: the clipboard is cleared when the code rotates (plus ~2s),
but only if it still holds THIS code — so if you've copied something
else in the meantime we won't clobber it. --no-clear disables that.

The code itself is never printed to the terminal.
EOF
      exit 0 ;;
    -*) die "unknown flag: $1" ;;
    *)
      [[ -z "$FILTER" ]] || die "only one filter allowed"
      FILTER="$1"; shift ;;
  esac
done

[[ -n "$FILTER" ]] || die "filter required (use 'otp show' to list entries)"

require_bins oathtool
ensure_store

matches=()
while IFS= read -r uri; do
  [[ "$uri" == otpauth://totp/* ]] || continue
  raw="${uri#otpauth://totp/}"; raw="${raw%%\?*}"
  label="$(urldecode "$raw")"
  shopt -s nocasematch
  if [[ "$label" == *"$FILTER"* ]]; then
    matches+=("$uri"$'\t'"$label")
  fi
  shopt -u nocasematch
done < "$OTP_STORE"

if [[ ${#matches[@]} -eq 0 ]]; then
  die "no entries matching '$FILTER'"
fi

if [[ ${#matches[@]} -gt 1 ]]; then
  printf 'ambiguous: "%s" matches %d entries:\n' "$FILTER" "${#matches[@]}" >&2
  for m in "${matches[@]}"; do
    printf '  %s\n' "${m#*$'\t'}" >&2
  done
  die "narrow the filter"
fi

entry="${matches[0]}"
uri="${entry%%$'\t'*}"
label="${entry#*$'\t'}"

secret="$(extract_secret "$uri")"
[[ -n "$secret" ]] || die "matched entry has no secret"
digits="$(extract_param "$uri" digits)";    digits="${digits:-6}"
period="$(extract_param "$uri" period)";    period="${period:-30}"
algo="$(extract_param   "$uri" algorithm)"; algo="${algo:-SHA1}"

code="$(oathtool --base32 "--totp=$algo" "--digits=$digits" \
          "--time-step-size=${period}s" "$secret" 2>/dev/null)" \
  || die "oathtool failed"

now=$(date +%s)
rem=$(( period - now % period ))

printf '%s' "$code" | clipboard_write_text

if [[ $KEEP -eq 0 ]]; then
  (
    sleep "$((rem + 2))"
    current="$(clipboard_read_text || true)"
    if [[ "$current" == "$code" ]]; then
      clipboard_clear
    fi
  ) </dev/null >/dev/null 2>&1 &
  disown
  log "copied: $label   (valid ${rem}s; clipboard auto-clears at rotation)"
else
  log "copied: $label   (valid ${rem}s; --no-clear: left on clipboard)"
fi
