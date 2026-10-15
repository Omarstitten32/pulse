//! Ed25519 signing tests.
//! All tests must FAIL before `pulse_core::sign` exists.

use pulse_core::sign::{SignError, Signature, SigningKey, VerifyingKey};

// ---------------------------------------------------------------
// Test 1: from_seed is deterministic
// ---------------------------------------------------------------
#[test]
fn from_seed_deterministic() {
    let s1 = SigningKey::from_seed(&[0u8; 32]);
    let s2 = SigningKey::from_seed(&[0u8; 32]);
    assert_eq!(s1.verifying_key().to_hex(), s2.verifying_key().to_hex());
}

// ---------------------------------------------------------------
// Test 2: different seeds produce different keys
// ---------------------------------------------------------------
#[test]
fn from_seed_distinct() {
    let s1 = SigningKey::from_seed(&[0u8; 32]);
    let s2 = SigningKey::from_seed(&[1u8; 32]);
    assert_ne!(s1.verifying_key().to_hex(), s2.verifying_key().to_hex());
}

// ---------------------------------------------------------------
// Test 3: sign + verify succeeds on unmodified message
// ---------------------------------------------------------------
#[test]
fn sign_verify_roundtrip() {
    let sk = SigningKey::from_seed(&[0u8; 32]);
    let vk = sk.verifying_key();
    let sig = sk.sign(b"pulse snapshot payload");
    assert!(vk.verify(b"pulse snapshot payload", &sig));
}

// ---------------------------------------------------------------
// Test 4: verify fails on tampered message
// ---------------------------------------------------------------
#[test]
fn verify_rejects_tampered_message() {
    let sk = SigningKey::from_seed(&[0u8; 32]);
    let vk = sk.verifying_key();
    let sig = sk.sign(b"original");
    assert!(!vk.verify(b"tampered", &sig));
}

// ---------------------------------------------------------------
// Test 5: verify fails with wrong public key
// ---------------------------------------------------------------
#[test]
fn verify_rejects_wrong_key() {
    let sk1 = SigningKey::from_seed(&[0u8; 32]);
    let sk2 = SigningKey::from_seed(&[1u8; 32]);
    let sig = sk1.sign(b"msg");
    assert!(!sk2.verifying_key().verify(b"msg", &sig));
}

// ---------------------------------------------------------------
// Test 6: Signature hex roundtrip
// ---------------------------------------------------------------
#[test]
fn signature_hex_roundtrip() {
    let sk = SigningKey::from_seed(&[0u8; 32]);
    let sig = sk.sign(b"msg");
    let hex = sig.to_hex();
    let sig2 = Signature::from_hex(&hex).expect("hex parse");
    assert_eq!(sig.to_bytes(), sig2.to_bytes());
}

// ---------------------------------------------------------------
// Test 7: VerifyingKey hex roundtrip
// ---------------------------------------------------------------
#[test]
fn verifying_key_hex_roundtrip() {
    let sk = SigningKey::from_seed(&[0u8; 32]);
    let vk = sk.verifying_key();
    let hex = vk.to_hex();
    let vk2 = VerifyingKey::from_hex(&hex).expect("hex parse");
    assert_eq!(vk.to_hex(), vk2.to_hex());
}

// ---------------------------------------------------------------
// Test 8: from_hex rejects wrong length
// ---------------------------------------------------------------
#[test]
fn signature_from_hex_rejects_short() {
    let err = Signature::from_hex("abcd");
    assert!(matches!(err, Err(SignError::InvalidLength)));
}

// ---------------------------------------------------------------
// Test 9: from_hex rejects non-hex characters
// ---------------------------------------------------------------
#[test]
fn signature_from_hex_rejects_non_hex() {
    let bad = "zz".repeat(64);
    let err = Signature::from_hex(&bad);
    assert!(matches!(err, Err(SignError::InvalidHex)));
}

// ---------------------------------------------------------------
// Test 10: from_hwid is deterministic
// ---------------------------------------------------------------
#[test]
fn from_hwid_deterministic() {
    let hwid = "7be2fc58eab0fedc29743d5352a9a4a9e9f585df8dae92b93b12e83cf3f301f3";
    let k1 = SigningKey::from_hwid(hwid).expect("hwid parse");
    let k2 = SigningKey::from_hwid(hwid).expect("hwid parse");
    assert_eq!(k1.verifying_key().to_hex(), k2.verifying_key().to_hex());
}

// ---------------------------------------------------------------
// Test 11: different HWIDs produce different keys
// ---------------------------------------------------------------
#[test]
fn from_hwid_distinct() {
    let a = "0".repeat(64);
    let b = "f".repeat(64);
    let k1 = SigningKey::from_hwid(&a).expect("hwid a");
    let k2 = SigningKey::from_hwid(&b).expect("hwid b");
    assert_ne!(k1.verifying_key().to_hex(), k2.verifying_key().to_hex());
}
