#!/usr/bin/env bash
# cmd-config.sh — lifecycle commands for the otp CLI.
#
# Subcommands:
#   install             symlink otp onto $PATH; report dep status
#   uninstall           remove the symlink only if we own it (fenced)
#   update              git fetch + fast-forward (no-op if no remote)
#   wipe                shred secrets.txt + bak files (phrase-gated)
#   transfer [FILTER]   build a Google Authenticator import QR

set -euo pipefail
source "$(dirname "$0")/common.sh"

# ---------- install ----------------------------------------------------------

REQUIRED_BINS=(zbarimg oathtool python3)
CAMERA_BINS=(mpv socat)
CLIP_BINS_EITHER=(wl-paste xclip)
TRANSFER_BINS=(qrencode)

PACMAN_PKGS="mpv socat zbar oath-toolkit qrencode wl-clipboard xclip"

do_install() {
  local bindir="$HOME/.local/bin"
  local target="$OTP_HOME/otp"
  mkdir -p "$bindir"

  if [[ -L "$bindir/otp" && "$(readlink "$bindir/otp")" == "$target" ]]; then
    log "already linked: $bindir/otp -> $target"
  elif [[ -e "$bindir/otp" ]]; then
    die "$bindir/otp exists and is not our symlink; remove it first"
  else
    ln -s "$target" "$bindir/otp"
    log "linked: $bindir/otp -> $target"
  fi

  case ":$PATH:" in
    *":$bindir:"*) ;;
    *) log "warning: $bindir is not on \$PATH — add it to your shell rc" ;;
  esac

  echo
  echo "dependency check:"
  local missing=()
  check_bin() {
    local bin="$1" tier="$2"
    if command -v "$bin" >/dev/null; then
      printf '  ✓ %-12s (%s)\n' "$bin" "$tier"
    else
      printf '  ✗ %-12s (%s)\n' "$bin" "$tier"
      missing+=("$bin")
    fi
  }

  for b in "${REQUIRED_BINS[@]}";  do check_bin "$b" "required"; done
  for b in "${CAMERA_BINS[@]}";    do check_bin "$b" "for otp reload"; done
  for b in "${TRANSFER_BINS[@]}";  do check_bin "$b" "for otp config transfer"; done

  local have_clip=0
  for b in "${CLIP_BINS_EITHER[@]}"; do
    if command -v "$b" >/dev/null; then
      printf '  ✓ %-12s (for otp clip)\n' "$b"
      have_clip=1
    fi
  done
  [[ $have_clip -eq 0 ]] && printf '  ✗ %-12s (need one for otp clip)\n' "wl-paste/xclip"

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo
    echo "install missing deps:"
    echo "  sudo pacman -S $PACMAN_PKGS"
  fi
}

# ---------- uninstall --------------------------------------------------------

do_uninstall() {
  local bindir="$HOME/.local/bin"
  local target="$OTP_HOME/otp"
  local link="$bindir/otp"

  if [[ ! -L "$link" && ! -e "$link" ]]; then
    log "not installed: $link does not exist"
    return 0
  fi

  if [[ ! -L "$link" ]]; then
    die "$link is not a symlink — refusing to remove (not ours)"
  fi

  local current
  current="$(readlink "$link")"
  if [[ "$current" != "$target" ]]; then
    die "$link points to $current, not $target — refusing to remove"
  fi

  rm "$link"
  log "removed: $link"
  log "(secrets.txt and the $OTP_HOME dir untouched; use 'otp config wipe' for secrets)"
}

# ---------- update -----------------------------------------------------------

do_update() {
  cd "$OTP_HOME"
  if [[ ! -d .git ]]; then
    log "not a git checkout ($OTP_HOME); nothing to update"
    return 0
  fi
  local remote
  remote="$(git remote 2>/dev/null | head -1 || true)"
  if [[ -z "$remote" ]]; then
    log "no git remote configured"
    log "HEAD: $(git rev-parse --short HEAD) — $(git log -1 --format=%s)"
    return 0
  fi

  log "fetching from $remote..."
  git fetch "$remote"

  local dirty
  dirty="$(git status --porcelain)"
  if [[ -n "$dirty" ]]; then
    log "local changes present; refusing auto-pull:"
    printf '  %s\n' "$dirty" >&2
    log "resolve manually: cd $OTP_HOME && git status"
    return 1
  fi

  git pull --ff-only "$remote" "$(git branch --show-current)"
  log "HEAD: $(git rev-parse --short HEAD) — $(git log -1 --format=%s)"
}

# ---------- wipe -------------------------------------------------------------

do_wipe() {
  local confirm_phrase=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --confirm-phrase) confirm_phrase="$2"; shift 2 ;;
      --help|-h)
        cat <<'EOF'
usage: otp config wipe [--confirm-phrase "exact phrase"]

Irrecoverably shreds secrets.txt and every secrets.txt.bak.* in the
store directory. The phrase is generated dynamically from the current
file and secret counts — you must read it and type it back verbatim.
There is no -y/--yes shortcut by design.
EOF
        return 0 ;;
      *) die "unknown arg: $1" ;;
    esac
  done

  local files=() total=0 f n
  for f in "$OTP_STORE" "$OTP_HOME"/secrets.txt.bak.*; do
    [[ -f "$f" ]] || continue
    files+=("$f")
    n=$(grep -c '^otpauth' "$f" 2>/dev/null || true); n="${n:-0}"
    total=$((total + n))
  done

  if [[ ${#files[@]} -eq 0 ]]; then
    log "nothing to wipe (no secrets.txt or bak files in $OTP_HOME)"
    return 0
  fi

  local phrase="wipe ${#files[@]} file(s) containing $total secret(s)"

  cat <<EOF

This will PERMANENTLY destroy the files below.
  action: shred -u  (not moved to trash; not recoverable)

EOF
  for f in "${files[@]}"; do
    n=$(grep -c '^otpauth' "$f" 2>/dev/null || true); n="${n:-0}"
    printf '  %s  (%d secret line(s))\n' "$f" "$n"
  done

  cat <<EOF

To proceed, type this phrase verbatim (case-sensitive):

  $phrase

EOF

  local answer
  if [[ -n "$confirm_phrase" ]]; then
    answer="$confirm_phrase"
    log "(using --confirm-phrase)"
  else
    # Read from the controlling tty so a piped `yes` can't feed us.
    if [[ -t 0 ]]; then
      read -rp "> " answer
    elif [[ -r /dev/tty ]]; then
      printf '> ' >&2
      IFS= read -r answer < /dev/tty
    else
      die "no tty for confirmation (use --confirm-phrase for scripting)"
    fi
  fi

  if [[ "$answer" != "$phrase" ]]; then
    die "phrase did not match; aborted — nothing wiped"
  fi

  local tool=(rm -f)
  command -v shred >/dev/null && tool=(shred -u)
  for f in "${files[@]}"; do
    "${tool[@]}" "$f"
    log "  shredded $f"
  done
  log "wiped ${#files[@]} file(s), $total secret line(s)"
}

# ---------- transfer ---------------------------------------------------------

do_transfer() {
  local filter="" outfile="" format="ANSIUTF8"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output) outfile="$2"; shift 2 ;;
      -t|--format) format="$2"; shift 2 ;;
      --help|-h)
        cat <<'EOF'
usage: otp config transfer [FILTER] [-o FILE] [-t FORMAT]

Builds a Google Authenticator migration QR from the current store.
FILTER is an optional label substring (case-insensitive).
Default renders to the terminal (format ANSIUTF8). -o writes an image.

SECURITY: the QR is a complete bearer export of the included secrets.
If you -o to disk, shred the file as soon as you've scanned it.
EOF
        return 0 ;;
      -*) die "unknown flag: $1" ;;
      *) filter="$1"; shift ;;
    esac
  done

  require_bins python3 qrencode
  [[ -f "$OTP_STORE" ]] || die "no store at $OTP_STORE"

  local tmp matching count
  tmp="$(mktemp -d)"
  matching="$tmp/matching.txt"

  local uri raw label
  while IFS= read -r uri; do
    case "$uri" in
      otpauth://totp/*|otpauth://hotp/*) ;;
      *) continue ;;
    esac
    if [[ -n "$filter" ]]; then
      raw="${uri#otpauth://*/}"; raw="${raw%%\?*}"
      label="$(urldecode "$raw")"
      shopt -s nocasematch
      if [[ "$label" != *"$filter"* ]]; then shopt -u nocasematch; continue; fi
      shopt -u nocasematch
    fi
    printf '%s\n' "$uri" >> "$matching"
  done < "$OTP_STORE"

  count=$(wc -l < "$matching" 2>/dev/null | tr -d ' ' || echo 0)
  if [[ "$count" -eq 0 ]]; then
    rm -rf "$tmp"
    die "no matching entries to export"
  fi

  local migration_uri
  if ! migration_uri="$(python3 "$OTP_LIB/migration_encode.py" < "$matching")"; then
    rm -rf "$tmp"; die "encode failed"
  fi
  rm -rf "$tmp"

  log "encoded $count account(s) into a migration blob"

  if [[ -n "$outfile" ]]; then
    printf '%s' "$migration_uri" | qrencode -o "$outfile" -s 8
    chmod 600 "$outfile" 2>/dev/null || true
    cat <<EOF

wrote QR to: $outfile

This file is a complete 2FA export. After scanning it into Google
Authenticator, destroy it:

  shred -u "$outfile"
EOF
  else
    echo
    printf '%s' "$migration_uri" | qrencode -t "$format" -o -
    cat <<'EOF'

scan with Google Authenticator:
  menu → Transfer accounts → Import accounts → Scan QR code

(the QR lives only in your terminal scrollback — clear it when done)
EOF
  fi
}

# ---------- dispatch ---------------------------------------------------------

usage() {
  cat <<'EOF'
usage: otp config <sub> [args]

subcommands:
  install              symlink otp onto $PATH and report dep status
  uninstall            remove the symlink (only if it points to our otp)
  update               git fetch + fast-forward (safe; no force ops)
  wipe                 shred secrets.txt and bak files (phrase-gated)
  transfer [FILTER]    build Google Authenticator migration QR

run `otp config <sub> --help` for sub-specific flags.
EOF
}

sub="${1:-}"
[[ $# -gt 0 ]] && shift

case "$sub" in
  install)           do_install   "$@" ;;
  uninstall|remove)  do_uninstall "$@" ;;
  update)            do_update    "$@" ;;
  wipe)              do_wipe     "$@" ;;
  transfer|export)   do_transfer "$@" ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *) printf 'unknown: %s\n\n' "$sub" >&2; usage >&2; exit 2 ;;
esac
