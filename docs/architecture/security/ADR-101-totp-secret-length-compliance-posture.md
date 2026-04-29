---
status: Accepted
date: 2026-04-29
deciders:
  - aaronsb
  - claude
related:
  - "ADR-100"
  - "GH#23"
  - "GH#6"
  - "GH#7"
---

# ADR-101: TOTP secret-length compliance posture

## Context

`totp-rs` 5.7.1 (the library `tocken` uses for code generation) enforces RFC 4226's 128-bit minimum on shared secrets. `TOTP::new` calls `assert_secret_length`, which returns `Rfc6238Error::SecretTooSmall(bits)` for any secret under 16 bytes. `TOTP::new_unchecked` skips that check.

RFC 4226 §4 R6 says: *"The length of the shared secret MUST be at least 128 bits. This document RECOMMENDs a shared secret length of 160 bits."* RFC 6238 (TOTP) inherits this guidance.

Reality at the upstream-service edge:

- A non-trivial fraction of legacy TOTP secrets are 80 or 96 bits. Early-2010s services often issued 16-character base32 strings (80 bits).
- The most-cited demo secret on the open web, `JBSWY3DPEHPK3PXP`, is 80 bits.
- Google Authenticator, Authy, Aegis, and most other authenticators accept these without warning. Strict rejection makes `tocken` an outlier among authenticators, not among standards-compliant tools.

Surfacing `Err(TotpError::Totp("secret length is N bits, expected at least 128"))` raw at enrollment (#6) is hostile UX: users paste a secret that works in their other authenticator, get a cryptic error, and conclude `tocken` is broken.

This decision shapes:

- **#6** — enrollment error handling and confirmation flow
- **#7 / #12** — GA migration import/export (some imported secrets will be sub-128-bit)
- The runtime call site in `session::totp::generate`, which currently uses `TOTP::new` and would fail every 30 seconds for any sub-128-bit entry that somehow landed in the store

The decision is not whether to accept weak secrets — `tocken`'s design ceiling (ADR-100 §7) already accepts that the user's secret material is what the upstream service issued. It's whether to surface that fact to the user, accept it deliberately, and make it auditable.

## Decision

### 1. Permissive with explicit user confirmation at enrollment

Enrollment (all paths: camera, clipboard image, `otpauth://` URI, manual entry, file picker) validates secret length before construction. If the decoded secret is under 128 bits:

1. **Surface** a confirmation dialog naming the actual bit length and the cause: *"This service issues a non-standard short secret (N bits, less than the 128-bit RFC 4226 minimum). `tocken` cannot lengthen it. Most authenticators accept these. Use anyway?"*
2. **On confirmation**, the entry is added to the store like any other.
3. **On cancel**, no entry is added; the import surface returns to its starting state.

The same prompt fires regardless of import source. There is no per-source override.

### 2. Runtime code generation uses `TOTP::new_unchecked`

`session::totp::generate` switches from `TOTP::new` to `TOTP::new_unchecked`. Stored entries are trusted by construction — they passed the enrollment-time check (or the user confirmed past it). Re-validating every 30 seconds adds nothing and would break code display for legitimately-stored weak entries.

Other validation (base32 decoding, digit count) happens at the same call site and remains unchanged. Only the length check moves to enrollment.

### 3. `weak_secret` is derived, not stored

The store schema (ADR-100 §3) does **not** gain a `weak_secret: bool` field. Whether an entry is weak is recomputable from `secret.len() * 8 < 128` after base32 decode. Stored flags can drift; derived flags cannot.

The audit path: a settings panel can iterate `entries`, decode each `secret`, and list issuers/accounts whose entries are sub-128-bit. The user can then rotate where the upstream service supports it (via the user's normal "regenerate 2FA" flow on the service's site) and re-enroll.

This keeps the v1 schema unchanged. The decision is reversible: if a future use case (e.g., bulk audit performance, cross-machine sync of audit annotations) justifies a stored field, the version field reserves room.

### 4. The threshold is 128 bits (MUST), not 160 (RECOMMENDED)

RFC 4226 distinguishes MUST (128) from RECOMMENDED (160). `tocken` uses 128 as the warning threshold:

- Matches `totp-rs`'s default validation — keeps the library boundary aligned
- A 160-bit threshold would flag the majority of compliant modern secrets, making the warning noise
- The audit signal "your service issues secrets the RFC says are out of spec" is meaningful at 128; "your service issues secrets that meet the MUST but not the RECOMMENDED" is not actionable for the user

### 5. HOTP is covered by the same policy

`EntryKind::Hotp` is in scope. RFC 4226 is literally the HOTP spec; the secret-length guidance applies identically. Every reference to "TOTP secret" in this ADR applies to HOTP secrets too. The single enrollment-time check covers both kinds.

## Consequences

### Positive

- **Real-world imports work.** Users with legacy GA / Authy entries from sub-128-bit services can bring them to `tocken` without conditional handling per service.
- **The user is informed.** The confirmation dialog tells them *why* it's a weak secret (upstream service issued it short, not anything `tocken` can fix), so they don't blame `tocken` and don't dismiss the warning as ceremonial.
- **Audit capability without schema bump.** The store stays at v1; weak-entry enumeration is a derived computation.
- **Library boundary stays clean.** `tocken` calls `TOTP::new_unchecked` at runtime with secrets it has already screened. No double-validation.

### Negative

- **Enrollment UX gains a confirmation branch.** #6 has to render the prompt, route the "use anyway" through to the backend, and handle cancellation. Not a heavy lift but it's UX surface that a strict-rejection posture would skip.
- **Marginally weaker entropy is an accepted state.** A determined attacker who somehow obtains a stream of TOTP codes (network MITM combined with screen capture or similar) faces ~80 bits of brute-force resistance instead of ~128. Practically infeasible for either, and not the threat model `tocken`'s design defends against (ADR-100 §7), but worth naming.
- **Derived `weak_secret` requires a base32 decode at audit time.** Cheap; we do it for code generation anyway. Negligible.

### Neutral

- The existing test fixture `REALISTIC_SECRET` in `session::totp::tests` (which doubles `JBSWY3DPEHPK3PXP` to clear 128 bits) becomes unnecessary when the runtime call site moves to `new_unchecked`. Cleanup, not a blocker.

## Alternatives Considered

### Strict rejection at enrollment (issue #23 option 1)

Reject sub-128-bit secrets with a clear error, no override path. Defensible position — RFC compliance is a feature, and the user gets pushed toward services that issue compliant secrets.

Rejected because it converts `tocken`'s job from "unify the user's TOTP usage" to "unify the subset of TOTP usage that meets RFC 4226." The user keeps using the legacy entries in another authenticator, defeating the unification goal that motivated the project. Strict rejection doesn't make the user safer — the secret still exists at the issuing service and in whatever app accepted it.

A weaker variant — strict by default with a config flag to permit — was considered and rejected as the worst of both: documentation burden, a hidden setting users won't find when they hit the wall, and no audit story for the entries that get through.

### Stored `weak_secret: bool` field on `Entry` (issue #23 acceptance criterion)

A schema field on each entry, set at enrollment, used for audit. Mentioned in #23 as a likely shape.

Rejected in favor of a derived computation. The flag's value is a function of the secret's length; storing it adds a way for the two to diverge (a hand-edited TOML, a future bulk re-encrypt that mishandles defaults) without adding any information not already present. ADR-100 §3 says the schema is extensible — extensibility we don't need is tax we don't pay.

### 160-bit threshold (RFC 4226 RECOMMENDED)

Warn on anything below 160 bits, matching the RFC's RECOMMENDED rather than MUST.

Rejected. Most modern compliant secrets are exactly 128 bits (16 bytes). A 160-bit threshold would prompt on the majority of imports, training the user to dismiss the warning. The warning's value depends on it firing rarely and meaningfully.

### Per-source policy (e.g., strict for manual entry, permissive for QR/clipboard)

Manual entry is the path most likely to involve a copy-paste mistake; strict rejection there could catch typos. Other paths (QR, clipboard image) are reading what the upstream service produced.

Rejected as cleverness that buys little. A typo'd manual secret usually base32-decodes to *some* byte string of the right approximate length, not specifically a sub-128-bit one. Length is a poor proxy for "user mistyped." The single uniform policy is easier to reason about and to document.

### Switch off `totp-rs` to a library without the length check

`oath-toolkit` and the lower-level `hmac-sha1` + manual HOTP construction don't enforce the check. A switch would eliminate the `TOTP::new` vs `TOTP::new_unchecked` distinction.

Rejected. `totp-rs` is fine; the policy issue isn't the library's fault. `new_unchecked` is the upstream's documented escape hatch for exactly this case. Swapping libraries to avoid using a documented API is over-rotation.
