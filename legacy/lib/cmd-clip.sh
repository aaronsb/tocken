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

process_uris <<< "$decoded"
expand_migrations
