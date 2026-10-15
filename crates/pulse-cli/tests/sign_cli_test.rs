//! End-to-end tests for `pulse sign` and `pulse verify`.
//! All must FAIL before the commands are added to main.rs.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn pulse_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pulse"))
}

fn temp_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let pid = std::process::id();
    p.push(format!("pulse_sign_test_{tag}_{pid}.txt"));
    p
}

fn cleanup(base: &PathBuf) {
    let _ = fs::remove_file(base);
    let _ = fs::remove_file(format!("{}.sig", base.display()));
}

// ---------------------------------------------------------------
// Test 1: sign creates a .sig file next to the input
// ---------------------------------------------------------------
#[test]
fn sign_creates_sig_file() {
    let file = temp_path("create");
    cleanup(&file);
    fs::write(&file, b"hello world").expect("write input");

    let out = pulse_bin()
        .arg("sign")
        .arg(&file)
        .output()
        .expect("run pulse sign");

    assert!(
        out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let sig_path = format!("{}.sig", file.display());
    assert!(
        std::path::Path::new(&sig_path).exists(),
        ".sig file was not created"
    );

    cleanup(&file);
}

// ---------------------------------------------------------------
// Test 2: .sig is valid JSON with the expected fields
// ---------------------------------------------------------------
#[test]
fn sig_file_has_expected_fields() {
    let file = temp_path("fields");
    cleanup(&file);
    fs::write(&file, b"content").expect("write input");

    let out = pulse_bin().arg("sign").arg(&file).output().expect("run");
    assert!(out.status.success(), "sign failed");

    let sig_path = format!("{}.sig", file.display());
    let json = fs::read_to_string(&sig_path).expect("read .sig");

    for key in [
        "version",
        "algorithm",
        "file",
        "size",
        "sha256",
        "public_key",
        "signature",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", key)),
            "missing field '{}' in .sig\n{}",
            key,
            json
        );
    }
    assert!(json.contains("\"ed25519\""), "algorithm must be ed25519");

    cleanup(&file);
}

// ---------------------------------------------------------------
// Test 3: verify succeeds on unmodified file
// ---------------------------------------------------------------
#[test]
fn verify_succeeds_on_unmodified_file() {
    let file = temp_path("verify_ok");
    cleanup(&file);
    fs::write(&file, b"payload").expect("write");

    let s = pulse_bin().arg("sign").arg(&file).output().expect("sign");
    assert!(s.status.success());

    let v = pulse_bin()
        .arg("verify")
        .arg(&file)
        .output()
        .expect("verify");
    let stdout = String::from_utf8_lossy(&v.stdout).to_lowercase();

    assert!(v.status.success(), "verify exit != 0: {:?}", v.status);
    assert!(
        stdout.contains("valid") && !stdout.contains("invalid"),
        "expected VALID, got: {}",
        stdout
    );

    cleanup(&file);
}

// ---------------------------------------------------------------
// Test 4: verify fails after the file is modified
// ---------------------------------------------------------------
#[test]
fn verify_rejects_modified_file() {
    let file = temp_path("tampered");
    cleanup(&file);
    fs::write(&file, b"original").expect("write");

    let s = pulse_bin().arg("sign").arg(&file).output().expect("sign");
    assert!(s.status.success());

    fs::write(&file, b"modified content").expect("tamper");

    let v = pulse_bin()
        .arg("verify")
        .arg(&file)
        .output()
        .expect("verify");
    let stdout = String::from_utf8_lossy(&v.stdout).to_lowercase();

    assert!(
        stdout.contains("invalid") || stdout.contains("modified"),
        "expected INVALID, got: {}",
        stdout
    );

    cleanup(&file);
}

// ---------------------------------------------------------------
// Test 5: verify fails when .sig is missing
// ---------------------------------------------------------------
#[test]
fn verify_fails_without_sig() {
    let file = temp_path("no_sig");
    cleanup(&file);
    fs::write(&file, b"data").expect("write");

    let v = pulse_bin()
        .arg("verify")
        .arg(&file)
        .output()
        .expect("verify");

    assert!(!v.status.success(), "verify should fail without .sig");
    let stderr = String::from_utf8_lossy(&v.stderr).to_lowercase();
    assert!(
        stderr.contains("cannot read") || stderr.contains("no such"),
        "unexpected error: {}",
        stderr
    );

    cleanup(&file);
}

// ---------------------------------------------------------------
// Test 6: verify with matching --pubkey succeeds
// ---------------------------------------------------------------
#[test]
fn verify_with_correct_pubkey_succeeds() {
    let file = temp_path("pubkey_ok");
    cleanup(&file);
    fs::write(&file, b"payload").expect("write");

    let s = pulse_bin().arg("sign").arg(&file).output().expect("sign");
    assert!(s.status.success());

    let sig_path = format!("{}.sig", file.display());
    let json = fs::read_to_string(&sig_path).expect("read sig");
    let pubkey = extract_field(&json, "public_key");

    let v = pulse_bin()
        .arg("verify")
        .arg(&file)
        .arg(format!("--pubkey={pubkey}"))
        .output()
        .expect("verify");

    let stdout = String::from_utf8_lossy(&v.stdout).to_lowercase();
    assert!(v.status.success());
    assert!(stdout.contains("valid") && !stdout.contains("invalid"));

    cleanup(&file);
}

// ---------------------------------------------------------------
// Test 7: verify with wrong --pubkey fails
// ---------------------------------------------------------------
#[test]
fn verify_with_wrong_pubkey_fails() {
    let file = temp_path("pubkey_bad");
    cleanup(&file);
    fs::write(&file, b"payload").expect("write");

    let s = pulse_bin().arg("sign").arg(&file).output().expect("sign");
    assert!(s.status.success());

    let wrong = "0".repeat(64);
    let v = pulse_bin()
        .arg("verify")
        .arg(&file)
        .arg(format!("--pubkey={wrong}"))
        .output()
        .expect("verify");

    let stdout = String::from_utf8_lossy(&v.stdout).to_lowercase();
    assert!(
        stdout.contains("invalid") || stdout.contains("mismatch"),
        "expected INVALID on wrong pubkey, got: {}",
        stdout
    );

    cleanup(&file);
}

// ---------------------------------------------------------------
// Minimal JSON field extractor (mirrors the implementation)
// ---------------------------------------------------------------
fn extract_field(json: &str, field: &str) -> String {
    let pattern = format!("\"{}\"", field);
    let start = json.find(&pattern).expect("field missing");
    let after = &json[start + pattern.len()..];
    let colon = after.find(':').expect("malformed");
    let rest = after[colon + 1..].trim_start();
    let rest = rest.trim_start_matches('"');
    let end = rest.find('"').expect("unterminated");
    rest[..end].to_string()
}
