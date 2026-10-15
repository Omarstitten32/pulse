//! Integration test for SELinux detection signal.
//! Fails BEFORE the fix, passes AFTER.

use pulse_core::trust::{build_trust_report, SignalState};

#[test]
fn selinux_detected_via_proc_self_attr() {
    let report = build_trust_report();

    let mac_signal = report
        .signals
        .iter()
        .find(|s| s.id == "selinux")
        .expect("SELinux signal must exist");

    // On a system with SELinux active (like KSU), we must NOT see
    // the "Neither SELinux nor AppArmor detected" message.
    // The correct detection source is /proc/self/attr/current.

    let ctx = std::fs::read_to_string("/proc/self/attr/current").unwrap_or_default();
    let has_selinux_context =
        ctx.contains(":s0") || ctx.contains("u:r:") || ctx.contains("system_u:");

    if has_selinux_context {
        assert_ne!(
            mac_signal.state,
            SignalState::Warn,
            "SELinux context '{}' is active but Pulse reports Warn (bug). Detail: {}",
            ctx.trim(),
            mac_signal.detail
        );
    }
}

#[test]
fn selinux_signal_state_is_never_warn_when_context_exists() {
    let ctx = std::fs::read_to_string("/proc/self/attr/current")
        .unwrap_or_default()
        .trim()
        .to_string();

    // Skip test if no SELinux context
    if ctx.is_empty() || ctx == "unconfined" {
        eprintln!("skipping: no SELinux context on this system");
        return;
    }

    let report = build_trust_report();
    let mac = report.signals.iter().find(|s| s.id == "selinux").unwrap();

    eprintln!("context: {}", ctx);
    eprintln!("mac state: {:?}", mac.state);
    eprintln!("mac detail: {}", mac.detail);

    assert!(
        matches!(mac.state, SignalState::Good | SignalState::Unknown),
        "MAC signal must be Good or Unknown when SELinux context exists, got {:?}",
        mac.state
    );
}
