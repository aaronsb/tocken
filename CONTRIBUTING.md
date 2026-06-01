# Contributing to tocken

Thanks for your interest. tocken is a local-first TOTP store with hardware-key
unlock — small surface, high stakes (it handles 2FA secrets), so changes lean on
a few conventions to stay reviewable and reversible.

## Ground rules

- **Pull requests for everything**, including solo work. A PR is a decision record
  and a CI gate even with no second reviewer. Lightweight is fine — a title and a
  few bullets.
- **Conventional commits.** `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
  with a scope matching the area (`core`, `slint`, `legacy`, `adr`, `docs`, ...).
  Focus the message on the *why*.
- **Atomic commits.** One logical change each.

## Architecture decisions

Non-trivial design choices are recorded as ADRs in [`docs/architecture/`](docs/architecture/).
Before a structural change, check whether an ADR covers it — and if your change
*is* a structural decision, write one. Tooling:

```bash
make adr-list      # list ADRs
make adr-lint      # validate ADR frontmatter
```

Reference relevant ADRs in your PR description.

## Pre-PR gate

The repo is a Cargo workspace plus a legacy bash CLI. Before opening a PR, run:

```bash
make check         # cargo fmt --check + clippy -D warnings + tests
```

Hardware-gated tests (require a YubiKey) run separately:

```bash
make check-yubi    # check + #[ignore]'d hardware tests; touch the key when prompted
```

## Repo layout

- `crates/tocken-core` — UI-agnostic crypto / store / session / enrollment / wizard
- `crates/tocken-ui-slint` — the Slint desktop app (binary: `tocken`)
- `legacy/` — the original bash CLI (v1), still maintained
- `app/` — superseded Tauri shell (pre-ADR-300)
- `docs/` — ADRs and architecture notes

See the [README](README.md) for the full picture and `make help` for all targets.

## Security

Please do **not** open public issues for security vulnerabilities — see
[SECURITY.md](SECURITY.md) for private reporting.
