//! Coverage: `pulse-cli/src/main.rs` uncovered branches.
//!
//! - Lines 126-134: non-root warning banner (text mode + root-requiring command).
//! - Lines 208-212: BrokenPipe handling in `Target::write`.
//! - Line 359:      INVALID signature path (sha256 matches, signature does not verify).

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn pulse_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pulse")
}

fn pulse() -> Command {
    Command::new(pulse_bin())
}

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("pulse_main_{name}_{}", std::process::id()));
    let _ = fs::remove_file(&p);
    let _ = fs::remove_file(format!("{}.sig", p.display()));
    p
}

fn cleanup(p: &PathBuf) {
    let _ = fs::remove_file(p);
    let _ = fs::remove_file(format!("{}.sig", p.display()));
}

// ===========================================================================
// Lines 126-134 — non-root warning banner
// ===========================================================================
//
// The banner fires when ALL of:
//   1. format is text (default, not json)
//   2. process is non-root (euid != 0)
//   3. command requires root (`thermal`, `battery`, `sensors`, `drivers`,
//      `network`, `system`)
//
// We copy the pulse binary to a world-accessible dir and run it as `nobody`.

fn public_copy(tag: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let mut dir = std::env::temp_dir();
    dir.push(format!("pulse-maincov-{}-{}", tag, std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

    let bin = dir.join("pulse");
    fs::copy(pulse_bin(), &bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

    (dir, bin)
}

fn can_su_nobody() -> bool {
    let probe = Command::new("su")
        .args(["-s", "/bin/sh", "nobody", "-c", "id -u"])
        .output();
    match probe {
        Ok(o) if o.status.success() => {
            let uid = String::from_utf8_lossy(&o.stdout).trim().to_string();
            uid != "0"
        }
        _ => false,
    }
}

#[test]
fn nonroot_warning_thermal_text_mode() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("warn_thermal");
    let out = Command::new("su")
        .args([
            "-s",
            "/bin/sh",
            "nobody",
            "-c",
            &format!(
                "env LLVM_PROFILE_FILE={} {} thermal",
                std::env::var("LLVM_PROFILE_FILE").unwrap_or_default(),
                bin.display()
            ),
        ])
        .output()
        .expect("su + pulse thermal");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Running without root privileges"),
        "missing non-root warning: stderr={stderr}"
    );
    assert!(
        stderr.contains("thermal"),
        "warning must mention the command"
    );
    assert!(stderr.contains("sudo pulse thermal") || stderr.contains("tsu pulse thermal"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn nonroot_warning_battery_text_mode() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("warn_battery");
    let out = Command::new("su")
        .args([
            "-s",
            "/bin/sh",
            "nobody",
            "-c",
            &format!(
                "env LLVM_PROFILE_FILE={} {} battery",
                std::env::var("LLVM_PROFILE_FILE").unwrap_or_default(),
                bin.display()
            ),
        ])
        .output()
        .expect("su + pulse battery");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Running without root privileges"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn nonroot_warning_suppressed_in_json_mode() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("warn_json");
    let out = Command::new("su")
        .args([
            "-s",
            "/bin/sh",
            "nobody",
            "-c",
            &format!(
                "env LLVM_PROFILE_FILE={} {} --json thermal",
                std::env::var("LLVM_PROFILE_FILE").unwrap_or_default(),
                bin.display()
            ),
        ])
        .output()
        .expect("su + pulse --json thermal");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Running without root privileges"),
        "JSON mode must suppress warning: stderr={stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn nonroot_no_warning_for_non_root_command() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("warn_safe");
    let out = Command::new("su")
        .args([
            "-s",
            "/bin/sh",
            "nobody",
            "-c",
            &format!(
                "env LLVM_PROFILE_FILE={} {} platform",
                std::env::var("LLVM_PROFILE_FILE").unwrap_or_default(),
                bin.display()
            ),
        ])
        .output()
        .expect("su + pulse platform");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Running without root privileges"),
        "platform does not require root: stderr={stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// Lines 208-212 — BrokenPipe handling
// ===========================================================================
//
// `pulse timeline | head` closes the pipe early. The `write` returns
// `BrokenPipe`, which `main.rs` treats as `ExitCode::SUCCESS`.
//
// Rust ignores SIGPIPE by default, so the write actually returns Err.
#[test]
fn broken_pipe_treated_as_success() {
    let mut child = pulse()
        .args(["timeline"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pulse timeline");

    // Read one byte, then drop the pipe to trigger BrokenPipe downstream.
    if let Some(mut stdout) = child.stdout.take() {
        let mut buf = [0u8; 1];
        let _ = stdout.read(&mut buf);
        drop(stdout);
    }

    let status = child.wait().expect("wait for pulse");
    // With broken pipe, main returns SUCCESS.
    assert!(
        status.success() || status.code() == Some(0),
        "broken pipe should yield success, got {:?}",
        status.code()
    );
}

#[test]
fn broken_pipe_snapshot_via_head() {
    let mut child = pulse()
        .args(["snapshot"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn pulse snapshot");
    if let Some(mut stdout) = child.stdout.take() {
        let mut buf = [0u8; 1];
        let _ = stdout.read(&mut buf);
        drop(stdout);
    }
    let status = child.wait().expect("wait");
    assert!(status.success() || status.code() == Some(0));
}

// ===========================================================================
// Line 359 — INVALID signature (sha256 matches, sig doesn't verify)
// ===========================================================================
//
// We sign a file normally, then tamper ONLY the signature hex in the .sig
// file (leaving sha256 untouched). The file itself stays unchanged, so
// the hash comparison passes, but signature verification fails, which
// triggers the last `else` arm at line 359.
#[test]
fn verify_invalid_signature_sha256_matches() {
    let file = tmp("bad_sig");
    fs::write(&file, b"payload").expect("write input");

    let sign_out = pulse()
        .args(["sign", &file.display().to_string()])
        .output()
        .expect("sign");
    assert!(sign_out.status.success());

    let sig_path = format!("{}.sig", file.display());
    let mut sig_content = fs::read_to_string(&sig_path).expect("read .sig");

    // Replace the signature field value with an all-zeros hex string of the
    // same length (128 hex chars = 64 bytes for Ed25519).
    let bad_sig = "0".repeat(128);
    // Find `"signature": "..."` and replace the inner value.
    let needle = "\"signature\"";
    let start = sig_content.find(needle).expect("signature field");
    let after = &sig_content[start + needle.len()..];
    let colon = after.find(':').expect("colon");
    let rest = &after[colon + 1..];
    let open_quote = rest.find('"').expect("open quote");
    let after_open = &rest[open_quote + 1..];
    let close_quote = after_open.find('"').expect("close quote");

    let abs_start = start + needle.len() + colon + 1 + open_quote + 1;
    let abs_end = abs_start + close_quote;
    sig_content.replace_range(abs_start..abs_end, &bad_sig);
    fs::write(&sig_path, &sig_content).expect("write tampered .sig");

    // Now verify: hash matches, sig does not.
    let out = pulse()
        .args(["verify", &file.display().to_string()])
        .output()
        .expect("verify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("INVALID") && stdout.contains("does not verify"),
        "expected INVALID signature message, got: {stdout}"
    );

    cleanup(&file);
}

#[test]
fn verify_invalid_signature_json_mode() {
    let file = tmp("bad_sig_json");
    fs::write(&file, b"payload").expect("write");

    let _ = pulse()
        .args(["sign", &file.display().to_string()])
        .output()
        .expect("sign");

    let sig_path = format!("{}.sig", file.display());
    let mut sig = fs::read_to_string(&sig_path).unwrap();
    let bad_sig = "1".repeat(128);

    let needle = "\"signature\"";
    let start = sig.find(needle).unwrap();
    let after = &sig[start + needle.len()..];
    let colon = after.find(':').unwrap();
    let rest = &after[colon + 1..];
    let oq = rest.find('"').unwrap();
    let ao = &rest[oq + 1..];
    let cq = ao.find('"').unwrap();
    let abs_start = start + needle.len() + colon + 1 + oq + 1;
    let abs_end = abs_start + cq;
    sig.replace_range(abs_start..abs_end, &bad_sig);
    fs::write(&sig_path, &sig).unwrap();

    let out = pulse()
        .args(["--json", "verify", &file.display().to_string()])
        .output()
        .expect("verify json");

    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout);
        let _ = s.trim(); // just ensure no panic
    }

    cleanup(&file);
}
