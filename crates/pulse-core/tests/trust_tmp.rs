//! Integration test for /tmp executables signal.
//! Fails BEFORE the fix: user-owned test binaries trigger Warn.
//! Passes AFTER the fix: only non-self-owned executables trigger Warn.

use pulse_core::trust::{build_trust_report, SignalState};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

fn tmp_signal() -> pulse_core::trust::Signal {
    build_trust_report()
        .signals
        .into_iter()
        .find(|s| s.id == "tmp_exec")
        .expect("tmp_exec signal must exist")
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn create_test_binary(name: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from("/tmp").join(name);
    fs::write(&path, b"#!/bin/sh\necho test\n").expect("write /tmp test file");
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod +x");
    path
}

#[test]
fn user_owned_tmp_binaries_do_not_warn() {
    let uid_before = current_uid();

    // Create a user-owned test binary in /tmp
    let path = create_test_binary("pulse_test_user_owned");

    let md = fs::metadata(&path).expect("stat test file");
    assert_eq!(
        md.uid(),
        uid_before,
        "test file must be owned by current uid"
    );

    let sig = tmp_signal();

    // Cleanup
    let _ = fs::remove_file(&path);

    eprintln!(
        "uid={} | tmp_state={:?} | tmp_detail='{}'",
        uid_before, sig.state, sig.detail
    );

    // The current user's own binaries in /tmp must NOT trigger a warning.
    assert_eq!(
        sig.state,
        SignalState::Good,
        "User-owned binaries in /tmp should not warn (state={:?}, detail='{}')",
        sig.state,
        sig.detail
    );
}

#[test]
fn tmp_detail_mentions_ownership_when_warn() {
    // If the state is Warn, the detail must indicate that the
    // executables are NOT owned by the current user (i.e. suspicious).
    let sig = tmp_signal();
    if sig.state == SignalState::Warn {
        assert!(
            sig.detail.contains("other")
                || sig.detail.contains("foreign")
                || sig.detail.contains("unowned")
                || sig.detail.contains("uid"),
            "Warn on /tmp executables must explain ownership: '{}'",
            sig.detail
        );
    }
}
