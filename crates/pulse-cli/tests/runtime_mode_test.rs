//! Coverage: `pulse-platform/src/lib.rs:369` — the `RuntimeMode::User` branch.
//!
//! `runtime_mode()` returns `Root` when `geteuid() == 0` and `User` otherwise.
//! The test suite runs as root, so we exercise the `User` branch by
//! launching a copy of `pulse` as `nobody` via `su`.
//!
//! Important: the binary must be reachable by `nobody`, so we copy it
//! out of `/root` (mode 0700) into a world-accessible directory first.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn pulse_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pulse")
}

fn public_copy() -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("pulse-public-{}", std::process::id()));
    fs::create_dir_all(&p).expect("create public test dir");
    let mut perms = fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&p, perms).expect("chmod 755 on public dir");

    let dst = p.join("pulse");
    fs::copy(pulse_bin(), &dst).expect("copy pulse binary to public dir");

    let mut perms = fs::metadata(&dst).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&dst, perms).expect("chmod 755 on pulse binary");

    dst
}

fn cleanup(dir: &PathBuf) {
    let _ = fs::remove_dir_all(dir);
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
fn platform_as_nobody_covers_user_runtime_mode() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` is not available");
        return;
    }

    let dir = public_copy();
    let bin = dir.display().to_string();

    let out = Command::new("su")
        .args(["-s", "/bin/sh", "nobody", "-c", &format!("{bin} platform")])
        .output()
        .expect("su + pulse platform");

    assert!(
        out.status.success(),
        "pulse platform as nobody failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("arch"), "output missing arch: {stdout}");

    cleanup(&dir);
}

#[test]
fn cpu_as_nobody_covers_user_runtime_mode_and_output() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` is not available");
        return;
    }

    let dir = public_copy();
    let bin = dir.display().to_string();

    let out = Command::new("su")
        .args(["-s", "/bin/sh", "nobody", "-c", &format!("{bin} cpu")])
        .output()
        .expect("su + pulse cpu");

    assert_ne!(out.status.code(), Some(101), "pulse cpu panicked as nobody");

    cleanup(&dir);
}

#[test]
fn trust_as_nobody_covers_full_unknown_path() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` is not available");
        return;
    }

    let dir = public_copy();
    let bin = dir.display().to_string();

    // `trust` reads /etc/shadow, /etc/ssh/sshd_config, /tmp, etc.
    // As `nobody`, many reads fail → exercises the Unknown branches.
    let out = Command::new("su")
        .args(["-s", "/bin/sh", "nobody", "-c", &format!("{bin} trust")])
        .output()
        .expect("su + pulse trust");

    assert_ne!(
        out.status.code(),
        Some(101),
        "pulse trust panicked as nobody"
    );

    cleanup(&dir);
}
