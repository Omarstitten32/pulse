//! Coverage: subprocess branches in `pulse-core/src/trust.rs`.
//!
//! Many trust signals behave differently when running as non-root:
//! - `/etc/shadow` becomes unreadable → Unknown branch
//! - `/tmp` file ownership differs → different branch
//! - SELinux context may be "unconfined"
//! - SSH configuration becomes partially readable
//!
//! We exercise these by running `pulse trust` as `nobody`.
//! To preserve LLVM coverage, we redirect the child's profraw output
//! to /tmp (since /root is not writable by `nobody`) and copy the
//! resulting profraw files into the parent's coverage directory.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn pulse_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pulse")
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

fn public_copy(tag: &str) -> (PathBuf, PathBuf) {
    let mut dir = std::env::temp_dir();
    dir.push(format!("pulse-trustsub-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

    let bin = dir.join("pulse");
    fs::copy(pulse_bin(), &bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

    (dir, bin)
}

/// Runs `pulse <args>` as `nobody`, preserving LLVM coverage by writing
/// the child's profraw to /tmp and copying it to the parent's coverage dir.
fn run_as_nobody_coverage(bin: &std::path::Path, args: &str, tag: &str) -> std::process::Output {
    let tmp_dir = std::env::temp_dir().join(format!("pulse-cov-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).unwrap();
    fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o777)).unwrap();

    let prof_template = format!("{}/child-%p-%m.profraw", tmp_dir.display());
    let cmd = format!(
        "env LLVM_PROFILE_FILE={} {} {}",
        prof_template,
        bin.display(),
        args
    );

    let out = Command::new("su")
        .args(["-s", "/bin/sh", "nobody", "-c", &cmd])
        .output()
        .expect("su + pulse");

    // Copy child profraw files into the parent's coverage dir so that
    // cargo-llvm-cov merges them with the parent's profile.
    if let Ok(parent_template) = std::env::var("LLVM_PROFILE_FILE") {
        if let Some(parent_dir) = std::path::Path::new(&parent_template).parent() {
            if let Ok(entries) = fs::read_dir(&tmp_dir) {
                for e in entries.flatten() {
                    let src = e.path();
                    if src.extension().map(|x| x == "profraw").unwrap_or(false) {
                        if let Some(name) = src.file_name() {
                            let dst = parent_dir.join(name);
                            let _ = fs::copy(&src, &dst);
                        }
                    }
                }
            }
        }
    }

    let _ = fs::remove_dir_all(&tmp_dir);
    out
}

#[test]
fn trust_as_nobody_text() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("trust_text");
    let out = run_as_nobody_coverage(&bin, "trust", "trust_text");
    assert_ne!(out.status.code(), Some(101), "panicked as nobody");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn trust_as_nobody_json() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("trust_json");
    let out = run_as_nobody_coverage(&bin, "--json trust", "trust_json");
    assert_ne!(out.status.code(), Some(101));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn trust_as_nobody_markdown() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("trust_md");
    let out = run_as_nobody_coverage(&bin, "--format=markdown trust", "trust_md");
    assert_ne!(out.status.code(), Some(101));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn hwid_as_nobody_json() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("hwid_json");
    let out = run_as_nobody_coverage(&bin, "--json hwid", "hwid_json");
    assert_ne!(out.status.code(), Some(101));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn system_as_nobody() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("system");
    let out = run_as_nobody_coverage(&bin, "--json system", "system_json");
    assert_ne!(out.status.code(), Some(101));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn drivers_as_nobody() {
    if !can_su_nobody() {
        eprintln!("skipping: `su nobody` unavailable");
        return;
    }
    let (dir, bin) = public_copy("drivers");
    let out = run_as_nobody_coverage(&bin, "--json drivers", "drivers_json");
    assert_ne!(out.status.code(), Some(101));
    let _ = fs::remove_dir_all(&dir);
}
