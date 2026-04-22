#!/usr/bin/env bash
# cmd-reload.sh — live webcam preview + on-demand QR snapshot loop.
# Auto-expands any migration blob(s) captured during the session.

set -euo pipefail
source "$(dirname "$0")/common.sh"

DEVICE="/dev/video0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --device|-d) DEVICE="$2"; shift 2 ;;
    --help|-h) echo "usage: otp reload [--device /dev/videoN]"; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

require_bins mpv socat zbarimg
ensure_store

tmp="$(mktemp -d)"
sock="$tmp/mpv.sock"
mpv_pid=""
cleanup() {
  [[ -n "$mpv_pid" ]] && kill "$mpv_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

mpv_cmd() {
  printf '{"command":%s}\n' "$1" | socat - "UNIX-CONNECT:$sock" >/dev/null
}

mpv \
  --no-terminal \
  --input-ipc-server="$sock" \
  --profile=low-latency \
  --untimed \
  --no-osc \
  --force-window=immediate \
  --title="otp reload — Enter in terminal to snapshot, q to quit" \
  "av://v4l2:$DEVICE" >/dev/null 2>&1 &
mpv_pid=$!

for _ in $(seq 1 50); do
  [[ -S "$sock" ]] && break
  sleep 0.1
done
[[ -S "$sock" ]] || die "mpv failed to open $DEVICE (device busy?)"

existing=$(wc -l < "$OTP_STORE" | tr -d ' ')
new=0

cat <<EOF

store  : $OTP_STORE  ($existing existing)
camera : $DEVICE   (mpv pid $mpv_pid)
keys   : Enter = snapshot, q = quit

EOF

while true; do
  printf -- '[%d new] > ' "$new"
  if ! read -r line; then break; fi
  case "$line" in q|Q|quit|exit) break ;; esac

  if ! kill -0 "$mpv_pid" 2>/dev/null; then
    log "preview closed"
    break
  fi

  shot="$tmp/shot-$(date +%s%N).jpg"
  if ! mpv_cmd "[\"screenshot-to-file\",\"$shot\"]"; then
    log "  ✗ screenshot IPC failed"; continue
  fi
  for _ in $(seq 1 20); do [[ -s "$shot" ]] && break; sleep 0.05; done
  [[ -s "$shot" ]] || { log "  ✗ no image produced"; continue; }

  decoded="$(decode_image "$shot")"
  if [[ -z "$decoded" ]]; then
    log "  ✗ no QR — reframe, more light, 15–25cm away"
    continue
  fi

  while IFS= read -r uri; do
    [[ -z "$uri" ]] && continue
    status="$(append_uri "$uri")"
    case "$status" in
      added*)     new=$((new+1)); printf '  ✓ %s\n' "$status" ;;
      duplicate*) printf '  · %s\n' "$status" ;;
      rejected*)  printf '  ? %s\n' "$status" ;;
    esac
  done <<< "$decoded"
done

echo
[[ $new -gt 0 ]] && log "$new new line(s) stored"
expand_migrations
