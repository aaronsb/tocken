---
status: Draft
date: 2026-04-29
deciders:
  - aaronsb
  - claude
related:
  - "GH#2"
  - "GH#5"
  - "GH#10"
  - "GH#13"
---

# ADR-100: Encrypted seed store format and recipient model

## Context

`tocken` stores TOTP seed material on disk. The user's design constraints (from issue #2 and surrounding discussion):

1. **Portable** — the encrypted file is bytes; the user can copy or sync it across machines, post it to a public location, or restore it on a fresh laptop. Without the right keys it's useless.
2. **Recoverable** — losing the YubiKey doesn't lock the user out. A "main secret" (passphrase) is a fallback unlock path.
3. **No roll-your-own crypto** — primitives must be well-vetted; `tocken` should not invent or re-implement an envelope-encryption scheme.
4. **Inspectable when decrypted** — the user (or a recovery process) should be able to decrypt the file with standard tools and read the contents, not depend on `tocken` being installed.
5. **Hardware-key as daily unlock, not as gate** — touching the YubiKey is the convenience path; the passphrase is the underlying authority.

These constraints rule out the obvious shortcuts: KDE Wallet / GNOME Keyring (not portable), KeePassXC (composite key model — lose either component, lose access), and any in-house format wrapping HMAC + AEAD (#3 is the "ridicule risk" the user explicitly named).

## Decision

### 1. Use `age` (multi-recipient envelope encryption)

The seed store is an [`age`](https://github.com/FiloSottile/age) file with multiple recipients. Each recipient is independently capable of decrypting the file. Standard format, written spec, audited primitives, broad ecosystem (`age` CLI, [`rage`](https://github.com/str4d/rage), `age` Rust crate).

This follows the pattern Filippo Valsorda described in [*My age+YubiKeys Password Management Solution*](https://words.filippo.io/passage/) (the reference implementation, `passage`).

### 2. Two-file design: `master.age` + `store.age`

The `age` spec does not allow mixing passphrase (scrypt) recipients with public-key recipients in a single file. Workaround:

| File | Encryption | Purpose |
|---|---|---|
| `master.age` | Passphrase (scrypt, via `age -p`) | Holds a master X25519 identity (the actual secret material) |
| `store.age` | Public-key recipients | Holds the TOTP seeds. Recipients: master identity public key + YubiKey identity (+ optional backup YubiKey) |

**Daily unlock path:** YubiKey decrypts `store.age` directly via `age-plugin-yubikey`.

**Recovery path:** passphrase decrypts `master.age` → master X25519 identity → decrypts `store.age`.

Either path produces the same plaintext. The user's constraint ("if I know the main secret, the blob is portable") is satisfied: passphrase + `master.age` + `store.age` is sufficient on any machine, even a fresh one with no YubiKey.

### 3. Inner payload: TOML with schema versioning

The plaintext inside `store.age` is TOML. Reasons:

- Human-readable when decrypted (`age -d store.age` produces something a user can `grep` / `head`)
- `serde` + `toml` crate gives trivial round-trip in Rust
- Comments allowed (we use a header comment as a self-documenting marker)
- Extensible — adding fields is forward-compatible

Schema:

```toml
# tocken store v1 — do not edit by hand unless you know what you're doing

version = 1

[[entries]]
id = "01h9z0e3mq6kngd5gp7w4tnsx2"   # ULID, stable across edits
issuer = "Google"
account = "user@example.com"
secret = "JBSWY3DPEHPK3PXP"           # base32 RFC 4648
digits = 6                             # 6 or 8
period = 30                            # seconds
algorithm = "SHA1"                     # SHA1 | SHA256 | SHA512
type = "totp"                          # totp | hotp
created_at = "2026-04-29T10:00:00Z"

[[entries]]
# ...
```

The top-level `version` field reserves migration capacity. A v2 format that changes the schema bumps this; loaders dispatch on `version`.

`id` is a ULID (lexicographically sortable, stable across rename/edit/reorder). UUIDv4 is acceptable too; ULID is preferred for the stable-sort property.

### 4. XDG-compliant file paths

| Path | Contents |
|---|---|
| `$XDG_CONFIG_HOME/tocken/master.age` | Passphrase-encrypted master identity (default `~/.config/tocken/master.age`) |
| `$XDG_CONFIG_HOME/tocken/store.age` | Encrypted seed store |
| `$XDG_CONFIG_HOME/tocken/config.toml` | Plaintext UX/behavior config (#3, #8) |
| `$XDG_CONFIG_HOME/tocken/recipients.txt` | Plaintext list of recipient strings used at last encryption (informational; redundant with `store.age` header but useful for audit) |

`$XDG_STATE_HOME/tocken/` is reserved for runtime state (currently empty; defaults to `~/.local/state/tocken/`).

### 5. Atomic writes with fsync + rename

Every write to `master.age` or `store.age` follows:

1. Write ciphertext to a temp file in the same directory (e.g., `store.age.tmp.<pid>`)
2. `fsync` the temp file
3. `rename` over the target (POSIX-atomic)
4. `fsync` the parent directory

`tempfile::NamedTempFile::persist()` in Rust gives us this. Critical for re-encrypt operations: a YubiKey unplug or process kill mid-write must never corrupt the existing store.

### 6. Recipients are append-only at unlock time, replaceable at re-encrypt time

The store's recipient list is set when the file is encrypted and is fixed for that ciphertext. Changing recipients (adding a backup YubiKey, removing a compromised key) requires:

1. Decrypt the store (via any current recipient)
2. Re-encrypt to the new recipient set
3. Atomic-write back

Removing a recipient does **not** retroactively invalidate copies of the old file — anyone with the removed key and an old copy can still decrypt it. This is a fundamental property of `age` (and of all envelope encryption). Documented as a limitation; not a bug.

## Consequences

### Positive

- **Portability achieved.** `store.age` is bytes; `master.age` is bytes. Copy them anywhere; with passphrase or YubiKey, you can decrypt.
- **Standard format.** `age -d` works forever, even if `tocken` is abandoned. Recovery doesn't depend on this project's continued existence.
- **No roll-your-own.** Crypto stays in `age` and `age-plugin-yubikey`. Bug surface in `tocken` is limited to file I/O, serialization, and recipient bookkeeping.
- **Multi-recipient is native.** Adding a backup YubiKey is a re-encryption with one more recipient — no protocol invention needed.
- **Memory hygiene compatible** (#13). Decryption produces a `Vec<u8>` that we can wrap in `Zeroizing<>` and `mlock`.
- **Inner format inspectable.** When the user needs to manually verify what's stored, `age -d store.age | head` shows them.

### Negative

- **Two files to manage** instead of one. `master.age` and `store.age` must travel together for recovery to work. Not a usability issue (we copy them as a pair) but it's two paths in the file model.
- **Re-encryption is touch-gated.** Any structural change (add/remove recipient, edit entry, delete entry) re-encrypts the file, which means reading the existing one — which means a YubiKey touch. Batch edits in #9 (account management) become a UX consideration.
- **Recipient removal isn't retroactive.** If a YubiKey is compromised and we remove its recipient, old copies of the file are still decryptable by the compromised key. We document this; no in-band remediation possible.
- **Adds two system dependencies** beyond `age-plugin-yubikey`: the `age` Rust crate (or `age` CLI shell-out — TBD in implementation) and a TOML parser. Both are well-maintained and small.

### Neutral

- The choice between using the [`age` Rust crate](https://docs.rs/age) natively versus shelling out to the `age` binary is **deferred to implementation**. The on-disk format is identical either way; only the in-process API differs. Lean toward native (consistent with the "no shell-out for runtime data paths" decision in #6/#7) but the `age` binary is acceptable for v0 if native plugin support is fiddly.
- ULID vs UUIDv4 for entry IDs is a minor preference (chosen ULID for sortability); either works.

## Alternatives Considered

### Roll our own envelope (HMAC-SHA1 → HKDF → ChaCha20-Poly1305)
The original proposal in issue #2's first draft. Rejected: reinvents what `age` already does correctly. Even if the primitives are right, the format isn't standard, recovery is locked to `tocken` forever, and it carries the "ridicule risk" the user named explicitly.

### Secret Service API (KDE Wallet, GNOME Keyring)
Examined and rejected. Storage is not portable across machines (tied to the user account on the host). YubiKey isn't a native unlock mechanism for the wallet itself. Cross-DE story is fractured (KDE wallet ≠ GNOME keyring). Loses the "copy the file anywhere" property that drove this design.

### KeePassXC composite-key model (passphrase AND YubiKey, both required)
Different recovery model — losing either component locks the user out. Conflicts with the explicit constraint "if I know the main secret, blob is portable" (which means passphrase alone must be sufficient).

### Yubico Authenticator (seeds on hardware)
The official Yubico solution. Rejected: ~32-credential cap, touch per code (UX friction), seeds tied to one piece of hardware (no portability). The design constraints we're solving don't apply to that product's threat model.

### Single-file format with custom recipient slots
Roll a binary format with multiple "slots" (passphrase slot, YubiKey slot, etc.) — like LUKS keyslots but for files. Rejected: re-implements what `age` already standardized. Loses interoperability with `age` CLI for recovery. Carries the same "rolled crypto" risk we're explicitly avoiding.

### Inner format JSON instead of TOML
Strong contender. JSON is universal; every tool reads it. TOML chosen for human readability and comment support — when a user decrypts the file by hand for recovery, TOML is friendlier to scan. Reversible decision; if the JSON ecosystem's tooling makes JSON clearly better in practice, we can migrate via the `version` field.

### Keep version history (`store.age.bak.1`, `.bak.2`, ...)
Rejected. Backup history belongs to the OS / user's chosen backup tooling (BTRFS snapshots, `syncthing` history, Time Machine, etc.). Baking in our own history would duplicate work poorly, eat disk for the same gain, and fight with copy-on-write filesystems. Atomic writes prevent corruption; they're not a substitute for backups.
