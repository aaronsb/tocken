# tocken

![License](https://img.shields.io/github/license/aaronsb/tocken)
![GitHub stars](https://img.shields.io/github/stars/aaronsb/tocken?style=social)
![Latest Release](https://img.shields.io/github/v/release/aaronsb/tocken?include_prereleases&label=version)

A **local-first TOTP store** with hardware-key unlock. Your 2FA seeds live in a single
`age`-encrypted file you fully control — daily unlock with a touch of a YubiKey, recoverable
with a passphrase if the key is ever lost. No cloud, no account, no vendor.

The encrypted store is just bytes: copy it between machines, sync it, even post it somewhere
public — without the right keys it's useless. Decrypt it with standard `age` tooling and read
the contents directly; tocken doesn't need to be installed to recover your seeds.
(See [ADR-100](docs/architecture/security/ADR-100-encrypted-seed-store-format-and-recipient-model.md)
for the full store format and recipient model.)

## Two implementations

This repo holds **two generations** of the same tool, side by side.

| | What it is | Where | Status |
|---|---|---|---|
| **v1 — bash CLI** | The original, working tool: a `bash` entry point delegating to per-command shell scripts, with Python helpers for Google Authenticator migration blobs. | [`legacy/`](legacy/) | Stable, in daily use |
| **v2 — Rust + Slint app** | A native desktop rewrite: a tray-resident GUI built on Slint, backed by a UI-agnostic Rust core. | [`crates/`](crates/) | In progress |

The v2 rewrite exists because every native surface the GUI needed — camera, clipboard, file
picker, tray — was a fight under the original web-shell (Tauri) approach. The crypto and store
logic were always pure Rust; the project pivoted the *UI layer* from Tauri to Slint so that
hardware access happens in-process instead of through a webview. The full reasoning is in
[ADR-300](docs/architecture/system/ADR-300-pivot-ui-framework-from-tauri-to-slint.md).

Both generations share the same security model and the same on-disk store format.

## v1 — the bash CLI (`legacy/`)

Self-contained: `legacy/otp` resolves its own `lib/` directory, so a symlink onto your `PATH`
is all the install you need.

```bash
ln -s "$PWD/legacy/otp" ~/.local/bin/otp

otp show              # print current codes with countdowns
otp show -w           # watch mode, refresh every second
otp copy <filter>     # copy one code to the clipboard (auto-clears)
otp reload            # camera preview → enroll QR(s)
otp clip              # enroll QR from a clipboard image
otp file <path>       # enroll QR(s) from an image file
otp expand            # expand Google Authenticator migration blobs
otp config <sub>      # install / update / wipe / transfer
```

Run `otp` with no arguments for the full usage text.

## v2 — the Rust + Slint app (`crates/`)

A Cargo workspace:

- **[`tocken-core`](crates/tocken-core/)** — UI-agnostic crypto, store, session, enrollment,
  and wizard logic. `age` envelope encryption, `totp-rs` code generation, `rqrr` QR decode, and
  an `otpauth-migration://` parser for Google Authenticator exports.
- **[`tocken-ui-slint`](crates/tocken-ui-slint/)** — the Slint desktop front end (binary name:
  `tocken`). Camera enrollment via xdg-desktop-portal + PipeWire, clipboard via `arboard`, file
  picker via `rfd`.

```bash
make slint-dev        # run the Slint app in dev mode
make build            # cargo build (debug, workspace)
make check            # fmt-check + clippy + tests (pre-PR gate)
```

Run `make help` for all targets. The `app/` directory holds the superseded Tauri shell, kept
until the Slint rewrite reaches parity.

## Repository layout

```
legacy/          v1 bash CLI (otp + lib/)
crates/          v2 Rust workspace
  tocken-core/     crypto / store / session / enrollment / wizard
  tocken-ui-slint/ Slint desktop UI (binary: tocken)
app/             superseded Tauri shell (pre-ADR-300)
docs/            ADRs and architecture notes
scripts/         dev helpers (e.g. test-secret generation)
Makefile         workspace build / test / lint targets
```

## Architecture decisions

Design rationale lives in [`docs/architecture/`](docs/architecture/):

- **ADR-100** — encrypted seed store format and recipient model
- **ADR-101** — TOTP secret length compliance posture
- **ADR-300** — pivot UI framework from Tauri to Slint
