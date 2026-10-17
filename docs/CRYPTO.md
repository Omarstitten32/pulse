# Pulse — Cryptography

> Status: v1.12.1 · Last updated: 2026-10-16

This document explains the cryptographic design of `pulse sign` and
`pulse verify`. It is intended for users who need to reason about
the security properties of these commands, and for auditors.

## What signing gives you

`pulse sign` produces a detached Ed25519 signature over the sha256
hash of a file. `pulse verify` re-computes the hash and checks the
signature.

The design answers one question:

> **Was this exact file produced by a holder of the private key
> derived from this device's HWID?**

It does **not** answer any other question. See "What signing does not
give you" below.

## Non-goals

- Confidentiality. Signed files are not encrypted.
- Authentication of the signer's human identity. The key identifies
  a device, not a person.
- Revocation. There is no mechanism to mark a key as compromised.
- Timestamping. `pulse sign` does not record when the signature was
  produced.

## Algorithm

- **Signature scheme:** Ed25519 (RFC 8032).
- **Library:** `ed25519-dalek` 2.2 with `default-features = false,
  features = ["std"]`. This variant compiles into the binary; it is
  not loaded at runtime.
- **Hash:** SHA-256. Two implementations are used:
  - `pulse-platform::sha256` (pure Rust, no external crate) — used
    for the file hash.
  - The `sha2` crate — pulled in transitively by `ed25519-dalek`.
    Used internally by the signer.

### Why Ed25519

| Property | Ed25519 | ECDSA (P-256) | RSA-2048 |
|---|---:|---:|---:|
| Signature size | 64 B | 64 B | 256 B |
| Public key size | 32 B | 33 B | 256 B |
| Deterministic | yes | no (needs RNG) | no (needs RNG) |
| Verification speed | fast | medium | slow |
| Malleability | no | yes (needs low-S) | no |

Deterministic signatures matter for Pulse: signing the same file
twice with the same key produces the exact same signature. This is
required for reproducible `.sig` envelopes and byte-identical
release artifacts.

### Why not HMAC

HMAC requires a shared secret between signer and verifier. Pulse
signatures must be verifiable by anyone holding only the public key.
Ed25519 provides this; HMAC does not.

## Key Derivation

The signing key is derived deterministically from the device HWID:

    seed (32 bytes) = hex_decode(hwid)          // hwid is 64 hex chars
    signing_key     = Ed25519::from_seed(seed)
    verifying_key   = signing_key.public_key()

There is no key file, no passphrase, no key management. Running
`pulse sign` on the same device always produces signatures under the
same public key.

### Why HWID-derived keys

- **Zero setup.** A user can sign immediately after installing Pulse.
- **No key loss.** There is no key to lose. The device *is* the key.
- **Portable across reinstall.** As long as the HWID sources remain
  stable (they are designed to), the key survives OS reinstall.

### Why this is a trade-off

A device-derived key has a weaker threat model than a randomly
generated key stored in a secure enclave. Specifically:

- **HWID is not secret.** It can be read by any process with access
  to the sources used by `pulse hwid`. Anyone who can read the HWID
  and knows the derivation function can re-derive the private key.

- **No forward secrecy.** If the HWID is compromised once, all past
  and future signatures under that key are attributable to the
  attacker.

Therefore: **use Pulse signatures for integrity, not for
authentication against a motivated attacker.** See "Threat Model"
below for the full picture.

## The `.sig` Envelope

`pulse sign <file>` writes `<file>.sig` next to the input. The
envelope is JSON with exactly seven fields:

    {
      "version": 1,
      "algorithm": "ed25519",
      "file": "/path/to/input",
      "size": 1234,
      "sha256": "hex of sha256(file bytes)",
      "public_key": "hex of 32-byte verifying key",
      "signature": "hex of 64-byte signature"
    }

### What is signed

The signature is over `sha256(file)`, not over the file bytes
directly. This means:

- Signing time is independent of file size.
- The signature is over 32 bytes, not over N bytes.
- Verification recomputes the hash, compares it against the stored
  value, and only then verifies the signature.

### Why the extra fields matter

- `version` allows future formats without ambiguity.
- `algorithm` makes the scheme explicit, not implicit.
- `file` records the original path (informational; the verifier
  uses the path given on the command line).
- `size` is redundant with the hash but lets a human sanity-check
  at a glance.
- `public_key` is embedded so the signature is self-verifying. A
  verifier does not need a separate trust store to run `pulse
  verify`.
- `signature` is the Ed25519 signature over `sha256`.

## Threat Model

### What `pulse verify` protects against

| Threat | Protected? | How |
|---|---|---|
| File modified after signing | **Yes** | sha256 mismatch → INVALID |
| Signature forged | **Yes** | Ed25519 verification fails |
| Wrong signer (different key) | **Yes** | `--pubkey=` check fails |
| Truncated `.sig` | **Yes** | JSON parse error, non-zero exit |
| Hex tampering in `.sig` | **Yes** | Signature or hash mismatch |

### What `pulse verify` does **not** protect against

| Threat | Reason |
|---|---|
| Malicious file signed by the device owner | The signature is valid; only the owner decides what to sign. |
| Replay of an old `.sig` on a new file | sha256 binds signature to file content; but if the attacker also replaces the file with the original, the pair is valid. |
| Compromised HWID | Anyone who can read the HWID can derive the key and sign arbitrary content. |
| Firmware-level tampering | The HWID sources themselves could be spoofed by a kernel-level attacker. |
| Side-channel attacks on Ed25519 | Out of scope; `ed25519-dalek` uses constant-time operations. |

### Recommendation

Use `pulse sign`/`pulse verify` for:

- **Integrity of release artifacts.** Sign a binary before
  distribution; verifiers check the signature against a published
  `public_key`.
- **Tamper evidence for configuration files.** Sign `/etc/ssh/sshd_config`
  before deployment; `pulse verify` flags post-deployment edits.
- **Snapshot attestation.** Sign a `pulse snapshot` output to prove
  the state at a given moment.

Do **not** use Pulse signatures for:

- Signing legal documents.
- Identity verification across untrusted parties.
- Any scenario where the threat model includes an attacker with
  read access to the device.

## Implementation

### File

`crates/pulse-core/src/sign.rs` — 130 lines.

Public API:

    pub struct SigningKey;
    pub struct VerifyingKey;
    pub struct Signature;

    impl SigningKey {
        pub fn from_seed(seed: &[u8; 32]) -> Self;
        pub fn from_hwid(hwid: &str) -> Result<Self, SignError>;
        pub fn sign(&self, message: &[u8]) -> Signature;
        pub fn verifying_key(&self) -> VerifyingKey;
    }

    impl VerifyingKey {
        pub fn from_hex(s: &str) -> Result<Self, SignError>;
        pub fn to_hex(&self) -> String;
        pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool;
    }

    impl Signature {
        pub fn to_bytes(&self) -> [u8; 64];
        pub fn from_bytes(b: &[u8; 64]) -> Self;
        pub fn to_hex(&self) -> String;
        pub fn from_hex(s: &str) -> Result<Self, SignError>;
    }

    pub enum SignError {
        InvalidHwid,
        InvalidHex,
        InvalidLength,
    }

Hex encoding and decoding are implemented in-file (20 lines total).
This avoids pulling a `hex` crate for two functions.

### Tests

- 11 unit tests in `crates/pulse-core/tests/sign_test.rs`:
  seed determinism, key distinctness, sign/verify roundtrip,
  tamper rejection, wrong-key rejection, hex roundtrips, invalid
  hex rejection, HWID-derived key determinism and distinctness.
- 7 integration tests in `crates/pulse-cli/tests/sign_cli_test.rs`:
  end-to-end CLI verification via `CARGO_BIN_EXE_pulse`.

All 46 workspace tests pass in v1.8.0.

### Verifying the implementation yourself

    # Build from source at tag v1.8.0
    git checkout v1.8.0
    cargo build --release --target=aarch64-unknown-linux-musl
    sha256sum target/aarch64-unknown-linux-musl/release/pulse
    # Expected: fdb0b18d4155ab74db21027b5e8d96f80ebd25934c1313fa4e6f1095698c367e

    # Sign a file
    ./pulse sign /etc/hostname

    # Inspect the envelope
    cat /etc/hostname.sig

    # Verify
    ./pulse verify /etc/hostname
    # Expected: VALID: /etc/hostname ...
