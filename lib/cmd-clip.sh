#!/usr/bin/env bash
# cmd-clip.sh — enroll QR(s) from an image currently on the system clipboard.
# Use Flameshot / KDE Spectacle / gnome-screenshot → "copy" first.

set -euo pipefail
source "$(dirname "$0")/common.sh"

require_bins zbarimg
ensure_store

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
img="$tmp/clip.png"

detect_session() {
  if [[ -n "${WAYLAND_DISPLAY:-}" ]] || [[ "${XDG_SESSION_TYPE:-}" == wayland ]]; then
    echo wayland
  elif [[ -n "${DISPLAY:-}" ]]; then
    echo x11
  else
    echo unknown
  fi
}

case "$(detect_session)" in
  wayland)
    require_bins wl-paste
    mime="$(wl-paste -l 2>/dev/null | grep -m1 '^image/' || true)"
    [[ -n "$mime" ]] || die "clipboard has no image (copy a QR first)"
    wl-paste -t "$mime" > "$img"
    ;;
  x11)
    require_bins xclip
    targets="$(xclip -selection clipboard -t TARGETS -o 2>/dev/null || true)"
    mime="$(printf '%s\n' "$targets" | grep -m1 '^image/' || true)"
    [[ -n "$mime" ]] || die "clipboard has no image (copy a QR first)"
    xclip -selection clipboard -t "$mime" -o > "$img"
    ;;
  *)
    die "can't detect display server (WAYLAND_DISPLAY / DISPLAY both unset)"
    ;;
esac

[[ -s "$img" ]] || die "clipboard image empty"

decoded="$(decode_image "$img")"
[[ -n "$decoded" ]] || die "no QR found in clipboard image"

while IFS= read -r uri; do
  [[ -z "$uri" ]] && continue
  status="$(append_uri "$uri")"
  case "$status" in
    added*)     printf '  ✓ %s\n' "$status" ;;
    duplicate*) printf '  · %s\n' "$status" ;;
    rejected*)  printf '  ? %s\n' "$status" ;;
  esac
done <<< "$decoded"

expand_migrations
