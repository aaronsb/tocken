#!/usr/bin/env bash
# cmd-expand.sh — expand any Google Authenticator migration blob(s)
# currently in the store into per-account otpauth:// URIs. No-op if there
# are none. The camera / clip / file flows already run this automatically;
# this command exists for when a blob was added outside those flows.

set -euo pipefail
source "$(dirname "$0")/common.sh"

ensure_store
expand_migrations
