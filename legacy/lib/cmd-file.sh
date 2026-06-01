#!/usr/bin/env bash
# cmd-file.sh — enroll QR(s) from an image file.

set -euo pipefail
source "$(dirname "$0")/common.sh"

case "${1:-}" in
  ""|-h|--help) echo "usage: otp file <image-path>"; exit 0 ;;
esac

require_bins zbarimg
ensure_store

img="$1"
[[ -f "$img" ]] || die "not a file: $img"

decoded="$(decode_image "$img")"
[[ -n "$decoded" ]] || die "no QR found in $img"

process_uris <<< "$decoded"
expand_migrations
