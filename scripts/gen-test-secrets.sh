#!/usr/bin/env bash
# scripts/gen-test-secrets.sh — generate a fixture file for smoke-
# testing tocken's enrollment file picker. Random secrets each run;
# the script prints them so you can cross-check the codes tocken
# displays against `oathtool --totp --base32 <secret>` or any other
# TOTP tool.
#
# Usage:
#   scripts/gen-test-secrets.sh [OUTPUT_PATH]
#
# Default output: /tmp/tocken-import-test.txt

set -euo pipefail

OUT="${1:-/tmp/tocken-import-test.txt}"

# Strip base32 padding + newlines. `head -c N /dev/urandom | base32`
# yields ~ceil(N*8/5) base32 chars; truncate to the exact length the
# caller wants.
strong_secret() { head -c 20 /dev/urandom | base32 | tr -d '=\n' | head -c 32; }
weak_secret()   { head -c 10 /dev/urandom | base32 | tr -d '=\n' | head -c 16; }

S1="$(strong_secret)"
S2="$(strong_secret)"
S3="$(weak_secret)"
S4="$(strong_secret)"

cat > "$OUT" <<EOF
# tocken file-picker smoke fixture — generated $(date -Iseconds)
# Cross-check generated codes with \`oathtool --totp --base32 <secret>\`
# or any TOTP tool against the secrets printed by this script.

# 1. Strong (160-bit), 6-digit, 30s
otpauth://totp/TestA:alice@example.com?secret=${S1}&issuer=TestA&digits=6&period=30

# 2. Strong (160-bit), 6-digit, 30s
otpauth://totp/TestB:bob@example.com?secret=${S2}&issuer=TestB&digits=6&period=30

# 3. Weak (80-bit) — should trigger ADR-101 "Use anyway" per-row affordance
otpauth://totp/Legacy:carol@example.com?secret=${S3}&issuer=Legacy&digits=6&period=30

# 4. Strong (160-bit), 8-digit, 60s
otpauth://totp/Long:dave@example.com?secret=${S4}&issuer=Long&digits=8&period=60

# 5. Garbage — should appear as a disabled parse-error row
not-a-valid-uri-just-for-testing

# 6. Migration URI — deferred to #7, should show "needs #7"
otpauth-migration://offline?data=fake-base64-payload
EOF

cat <<EOF
wrote $OUT

secrets (cross-check codes against these):
  TestA  $S1
  TestB  $S2
  Legacy $S3   (weak; commit requires opt-in via per-row checkbox)
  Long   $S4   (8 digits, 60s period)

next:
  make dev → +Add → "Pick a file (image or text)" → $OUT

teardown:
  the post-commit prompt offers to overwrite-and-delete the file,
  or rm it manually after import.
EOF
