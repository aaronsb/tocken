# Security Policy

tocken stores TOTP seed material — the secrets behind your second factor. Security
issues here matter, and responsible disclosure is appreciated.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately via GitHub's [private vulnerability reporting](https://github.com/aaronsb/tocken/security/advisories/new)
(Security tab → "Report a vulnerability"). If that's unavailable, email the
maintainer (see the commit history for the address).

Please include:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept
- Affected version / commit
- Any suggested mitigation

## What to expect

This is a small, primarily solo-maintained project — there is no formal SLA. You can
expect a good-faith acknowledgement and, for confirmed issues, a fix or mitigation
plan before public disclosure. Coordinated disclosure is preferred.

## Scope

Most relevant to the threat model:

- The `age`-encrypted store format and recipient/recovery model (see
  [ADR-100](docs/architecture/security/ADR-100-encrypted-seed-store-format-and-recipient-model.md))
- Handling of decrypted seed material in memory
- Clipboard / camera / file enrollment paths
- TOTP secret-length handling (see
  [ADR-101](docs/architecture/security/ADR-101-totp-secret-length-compliance-posture.md))

The cryptography relies on the upstream `age` crate; report crypto-primitive issues to
that project directly.
