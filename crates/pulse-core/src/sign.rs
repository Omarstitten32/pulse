//! Ed25519 signing for Pulse snapshots.
//!
//! Zero runtime dependencies — ed25519-dalek is build-time only.
//! The resulting binary remains statically linked.

use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey as DalekSigningKey, Verifier,
    VerifyingKey as DalekVerifyingKey,
};

/// Errors returned by signing operations.
#[derive(Debug)]
pub enum SignError {
    /// HWID is not a valid 32-byte hex string.
    InvalidHwid,
    /// Input contains characters that are not hex digits.
    InvalidHex,
    /// Input has the wrong byte length for its type.
    InvalidLength,
}

/// Private key for Ed25519 signing.
pub struct SigningKey(DalekSigningKey);

/// Public key for Ed25519 verification.
#[derive(Clone)]
pub struct VerifyingKey(DalekVerifyingKey);

/// Ed25519 signature (64 bytes).
pub struct Signature(DalekSignature);

impl SigningKey {
    /// Derive from a 32-byte seed. Deterministic.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(DalekSigningKey::from_bytes(seed))
    }

    /// Derive from a HWID (64 hex chars = 32 bytes).
    /// The same HWID always produces the same key.
    pub fn from_hwid(hwid: &str) -> Result<Self, SignError> {
        let bytes = decode_hex(hwid)?;
        if bytes.len() != 32 {
            return Err(SignError::InvalidHwid);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(&seed))
    }

    /// Sign an arbitrary message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }

    /// Return the corresponding public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

impl VerifyingKey {
    /// Decode from hex.
    pub fn from_hex(s: &str) -> Result<Self, SignError> {
        let bytes = decode_hex(s)?;
        if bytes.len() != 32 {
            return Err(SignError::InvalidLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        DalekVerifyingKey::from_bytes(&arr)
            .map(VerifyingKey)
            .map_err(|_| SignError::InvalidHwid)
    }

    /// Encode to lowercase hex.
    pub fn to_hex(&self) -> String {
        encode_hex(self.0.as_bytes())
    }

    /// Verify a signature over a message.
    pub fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        self.0.verify(message, &sig.0).is_ok()
    }
}

impl Signature {
    /// Raw 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Construct from raw 64 bytes.
    pub fn from_bytes(b: &[u8; 64]) -> Self {
        Self(DalekSignature::from_bytes(b))
    }

    /// Encode to lowercase hex (128 chars).
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0.to_bytes())
    }

    /// Decode from hex.
    pub fn from_hex(s: &str) -> Result<Self, SignError> {
        let bytes = decode_hex(s)?;
        if bytes.len() != 64 {
            return Err(SignError::InvalidLength);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&arr))
    }
}

// ---------------------------------------------------------------
// Hex helpers (no external crate)
// ---------------------------------------------------------------

fn decode_hex(s: &str) -> Result<Vec<u8>, SignError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(SignError::InvalidLength);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, SignError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(SignError::InvalidHex),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
