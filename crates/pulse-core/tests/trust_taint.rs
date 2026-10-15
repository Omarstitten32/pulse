//! Integration test for kernel taint signal.
//! Fails BEFORE the fix on Android/KSU: taint!=0 treated as Warn.
//! Passes AFTER: Android kernel taint is informational, not Warn.

use pulse_core::trust::{build_trust_report, SignalState};

fn taint_signal() -> pulse_core::trust::Signal {
    build_trust_report()
        .signals
        .into_iter()
        .find(|s| s.id == "kernel_tainted")
        .expect("kernel_tainted signal must exist")
}

fn is_android_kernel() -> bool {
    let Ok(v) = std::fs::read_to_string("/proc/version") else {
        return false;
    };
    let lv = v.to_lowercase();
    lv.contains("android") || lv.contains("-gki") || lv.contains("gki-")
}

fn read_tainted() -> i64 {
    std::fs::read_to_string("/proc/sys/kernel/tainted")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

#[test]
fn android_taint_is_not_warn() {
    if !is_android_kernel() {
        eprintln!("skipping: not an Android kernel");
        return;
    }
    let t = read_tainted();
    if t == 0 {
        eprintln!("skipping: kernel not tainted");
        return;
    }

    let sig = taint_signal();
    eprintln!(
        "android={} tainted={} state={:?} detail='{}'",
        is_android_kernel(),
        t,
        sig.state,
        sig.detail
    );

    assert_ne!(
        sig.state,
        SignalState::Warn,
        "Android kernel with taint={} must not Warn (detail='{}')",
        t,
        sig.detail
    );
}

#[test]
fn taint_detail_mentions_android_when_applicable() {
    if !is_android_kernel() {
        return;
    }
    let sig = taint_signal();
    if sig.detail.to_lowercase().contains("taint") {
        // When we do print taint info, it must clarify the Android context
        assert!(
            sig.detail.to_lowercase().contains("android")
                || sig.detail.to_lowercase().contains("expected")
                || sig.detail.to_lowercase().contains("normal"),
            "Taint message should clarify Android context, got: '{}'",
            sig.detail
        );
    }
}
