# common.sh — sourced by subcommand scripts. Not meant to run directly.
# Expects the caller to have set `set -euo pipefail`.

: "${OTP_HOME:="$HOME/.otp"}"
: "${OTP_STORE:="$OTP_HOME/secrets.txt"}"
: "${OTP_LIB:="$OTP_HOME/lib"}"

log() { printf '%s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_bins() {
  local missing=()
  for b in "$@"; do
    command -v "$b" >/dev/null || missing+=("$b")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    die "missing: ${missing[*]}  (install via pacman / AUR)"
  fi
}

ensure_store() {
  mkdir -p "$(dirname "$OTP_STORE")"
  chmod 700 "$(dirname "$OTP_STORE")" 2>/dev/null || true
  if [[ ! -f "$OTP_STORE" ]]; then
    touch "$OTP_STORE"; chmod 600 "$OTP_STORE"
  fi
}

urldecode() { local s="${1//+/ }"; printf '%b' "${s//%/\\x}"; }

detect_session() {
  if [[ -n "${WAYLAND_DISPLAY:-}" ]] || [[ "${XDG_SESSION_TYPE:-}" == wayland ]]; then
    echo wayland
  elif [[ -n "${DISPLAY:-}" ]]; then
    echo x11
  else
    echo unknown
  fi
}

# Write stdin to system clipboard
clipboard_write_text() {
  case "$(detect_session)" in
    wayland) require_bins wl-copy; wl-copy ;;
    x11)     require_bins xclip;   xclip -selection clipboard -in ;;
    *)       die "no display server (WAYLAND_DISPLAY / DISPLAY unset)" ;;
  esac
}

# Read current clipboard text to stdout (may be empty; never errors on missing)
clipboard_read_text() {
  case "$(detect_session)" in
    wayland) command -v wl-paste >/dev/null && wl-paste 2>/dev/null || true ;;
    x11)     command -v xclip    >/dev/null && xclip -selection clipboard -o 2>/dev/null || true ;;
    *)       return 0 ;;
  esac
}

clipboard_clear() {
  case "$(detect_session)" in
    wayland) command -v wl-copy >/dev/null && wl-copy --clear 2>/dev/null || true ;;
    x11)     command -v xclip   >/dev/null && printf '' | xclip -selection clipboard -in 2>/dev/null || true ;;
    *)       return 0 ;;
  esac
}

extract_label() {
  local uri="$1" raw
  raw="${uri#otpauth://*/}"
  raw="${raw%%\?*}"
  urldecode "$raw"
}

extract_param() {
  # extract_param URI NAME -> prints value (possibly empty). Always returns 0
  # so `set -e` callers don't abort when the key is absent.
  local uri="$1" key="$2" query p
  query="${uri#*\?}"
  IFS='&' read -ra parts <<< "$query"
  for p in "${parts[@]}"; do
    [[ "$p" == "$key"=* ]] && { printf '%s' "${p#*=}"; return 0; }
  done
  return 0
}

extract_secret() { extract_param "$1" secret; }

# append_uri URI
# Validates, dedupes against store, appends on new. Prints one status line:
#   added <label>   |   duplicate <label>   |   rejected <snippet>
append_uri() {
  local uri="$1" label
  case "$uri" in
    otpauth://totp/*|otpauth://hotp/*|otpauth-migration://*) ;;
    *) printf 'rejected %s\n' "${uri:0:60}..."; return 0 ;;
  esac
  if grep -qxF "$uri" "$OTP_STORE"; then
    case "$uri" in
      otpauth-migration://*) label='<migration-blob>' ;;
      *) label="$(extract_label "$uri" 2>/dev/null || echo '?')" ;;
    esac
    printf 'duplicate %s\n' "$label"
    return 0
  fi
  printf '%s\n' "$uri" >> "$OTP_STORE"
  case "$uri" in
    otpauth-migration://*) label='<migration-blob>' ;;
    *) label="$(extract_label "$uri")" ;;
  esac
  printf 'added %s\n' "$label"
}

# process_uris [COUNT_VAR]
# Reads URIs from stdin, calls append_uri on each, prints a '✓/·/?' status
# line per URI. If COUNT_VAR is the name of a variable in the caller's scope,
# the number of newly-added entries is added to it (so callers can aggregate
# across multiple captures — see cmd-reload.sh).
process_uris() {
  local ref="${1:-}"
  local added=0 uri status
  while IFS= read -r uri; do
    [[ -z "$uri" ]] && continue
    status="$(append_uri "$uri")"
    case "$status" in
      added*)     added=$((added+1)); printf '  ✓ %s\n' "$status" ;;
      duplicate*) printf '  · %s\n' "$status" ;;
      rejected*)  printf '  ? %s\n' "$status" ;;
    esac
  done
  [[ -n "$ref" ]] && printf -v "$ref" '%d' $(( ${!ref:-0} + added ))
}

# decode_image IMAGE_PATH -> prints URIs on stdout, one per line (empty if none)
decode_image() {
  require_bins zbarimg
  zbarimg --raw -q "$1" 2>/dev/null || true
}

# Expand any otpauth-migration:// lines currently in the store in-place.
# Backs up first. Prints a summary to stderr. No-op if no migration lines.
expand_migrations() {
  local migrations
  migrations="$(grep '^otpauth-migration://' "$OTP_STORE" || true)"
  [[ -z "$migrations" ]] && return 0
  require_bins python3

  local tmp expanded rc=0 other backup n
  tmp="$(mktemp -d)"
  expanded="$tmp/expanded.txt"
  printf '%s\n' "$migrations" | python3 "$OTP_LIB/migration.py" > "$expanded" || rc=$?
  if [[ $rc -ne 0 ]]; then
    rm -rf "$tmp"; die "migration decode failed"
  fi
  if [[ ! -s "$expanded" ]]; then
    rm -rf "$tmp"; return 0
  fi

  backup="$OTP_STORE.bak.$(date +%Y%m%d-%H%M%S)"
  cp -p "$OTP_STORE" "$backup"
  other="$(grep -v '^otpauth-migration://' "$OTP_STORE" || true)"
  {
    printf '%s\n' "$other"
    cat "$expanded"
  } | awk 'NF && !seen[$0]++' > "$tmp/new.txt"
  mv "$tmp/new.txt" "$OTP_STORE"
  chmod 600 "$OTP_STORE"

  n=$(wc -l < "$expanded" | tr -d ' ')
  log "expanded migration blob: $n account(s). backup: $backup"
  rm -rf "$tmp"
}
