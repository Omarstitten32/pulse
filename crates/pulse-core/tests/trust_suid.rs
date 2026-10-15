//! Integration test for SUID binaries signal.
//! Fails BEFORE the fix on Kali (threshold too low at 15).
//! Passes AFTER the fix (Kali-aware threshold at 60).

use pulse_core::trust::{build_trust_report, SignalState};

fn os_id() -> String {
    std::fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("ID="))
        .unwrap_or("")
        .trim_matches('"')
        .to_lowercase()
}

fn suid_signal() -> pulse_core::trust::Signal {
    build_trust_report()
        .signals
        .into_iter()
        .find(|s| s.id == "suid_bins")
        .expect("suid_bins signal must exist")
}

#[test]
fn suid_on_kali_is_not_warn_under_60() {
    let id = os_id();

    // This test is meaningful only on security-focused distros
    if !matches!(id.as_str(), "kali" | "parrot" | "blackarch") {
        eprintln!("skipping: not a security-focused distro (ID={})", id);
        return;
    }

    let sig = suid_signal();
    let count: u32 = sig
        .detail
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    eprintln!(
        "os_id={} | suid_count={} | state={:?} | detail='{}'",
        id, count, sig.state, sig.detail
    );

    // On Kali/Parrot/BlackArch, 40-60 SUID binaries are normal
    // because pentest tools ship with elevated privileges.
    if count > 0 && count < 60 {
        assert_eq!(
            sig.state,
            SignalState::Good,
            "On {} with {} SUID binaries (<60), state must be Good, got {:?}",
            id,
            count,
            sig.state
        );
    }
}

#[test]
fn suid_zero_is_always_good() {
    // Sanity: if there are no SUID binaries, we must not Warn
    let sig = suid_signal();
    let count: u32 = sig
        .detail
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if count == 0 {
        assert_eq!(sig.state, SignalState::Good);
    }
}
