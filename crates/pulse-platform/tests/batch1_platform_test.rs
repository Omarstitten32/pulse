//! Batch 1 — targeted tests for uncovered lines in pulse-platform.
//!
//! Focus on the public API that we can hit from a normal (non-root)
//! process using subprocess execution.

// ===========================================================================
// platform/lib.rs:369 — RuntimeMode::User branch
// ===========================================================================
//
// The User branch (euid != 0) is exercised from pulse-cli tests, where
// CARGO_BIN_EXE_pulse is available and we can subprocess into `nobody`.
// This file only tests the Root branch (we run as root here).

#[test]
fn runtime_mode_is_root_when_euid_zero() {
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(
            pulse_platform::runtime_mode(),
            pulse_platform::RuntimeMode::Root,
            "running as root must report RuntimeMode::Root"
        );
    }
}

// ===========================================================================
// platform/lib.rs:37 — endianness() "big" branch
// ===========================================================================
//
// On the current target (aarch64), the system is little-endian, so the
// `"big"` branch is not reachable at runtime. We only verify that the
// little-endian path returns "little".
#[test]
fn endianness_returns_little_on_this_target() {
    if cfg!(target_endian = "little") {
        assert_eq!(pulse_platform::endianness(), "little");
    } else {
        assert_eq!(pulse_platform::endianness(), "big");
    }
}

// ===========================================================================
// platform/lib.rs — pointer_width and family already covered.
// ===========================================================================

#[test]
fn pointer_width_matches_usize_size() {
    let expected = (std::mem::size_of::<usize>() * 8) as u8;
    assert_eq!(pulse_platform::pointer_width(), expected);
}

#[test]
fn family_is_one_of_known() {
    let f = pulse_platform::family();
    assert!(
        matches!(f, "unix" | "windows" | "wasm"),
        "unexpected family: {f}"
    );
}
