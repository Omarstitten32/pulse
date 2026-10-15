//! Integration test for SSH root login signal.
//! Fails BEFORE the fix: sshd not running but Pulse still FAILs.
//! Passes AFTER: only signals FAIL if sshd is actually active.

use pulse_core::trust::{build_trust_report, SignalState};
use std::fs;

fn ssh_signal() -> pulse_core::trust::Signal {
    build_trust_report()
        .signals
        .into_iter()
        .find(|s| s.id == "ssh_root")
        .expect("ssh_root signal must exist")
}

fn is_sshd_running() -> bool {
    let Ok(rd) = fs::read_dir("/proc") else {
        return false;
    };
    for e in rd.flatten() {
        let Some(name) = e.file_name().to_str().map(String::from) else {
            continue;
        };
        if name.parse::<u32>().is_err() {
            continue;
        }
        let comm = format!("/proc/{}/comm", name);
        if let Ok(s) = fs::read_to_string(&comm) {
            if s.trim() == "sshd" {
                return true;
            }
        }
    }
    false
}

fn port_22_listening() -> bool {
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let state = parts[3];
            if state != "0A" {
                continue;
            } // LISTEN
            if let Some(p) = parts[1].split(':').nth(1) {
                if p == "0016" {
                    return true;
                } // 22 in hex
            }
        }
    }
    false
}

#[test]
fn ssh_inactive_must_not_fail() {
    let sshd = is_sshd_running();
    let port22 = port_22_listening();

    eprintln!("sshd_running={} port_22_listening={}", sshd, port22);

    if sshd || port22 {
        eprintln!("skipping: sshd is actually active on this system");
        return;
    }

    let sig = ssh_signal();
    eprintln!("state={:?} detail='{}'", sig.state, sig.detail);

    // When no sshd is running and no port 22 is bound,
    // the sshd_config contents are theoretical and must not FAIL.
    assert_ne!(
        sig.state,
        SignalState::Bad,
        "sshd inactive but Pulse FAILs SSH signal (state={:?}, detail='{}')",
        sig.state,
        sig.detail
    );
}

#[test]
fn ssh_inactive_message_mentions_service_state() {
    let sshd = is_sshd_running();
    let port22 = port_22_listening();
    if sshd || port22 {
        return;
    }

    let sig = ssh_signal();
    // The message must clarify that SSH service is inactive
    // (not that "root login is enabled" which is misleading).
    if matches!(sig.state, SignalState::Good | SignalState::Unknown) {
        assert!(
            sig.detail.to_lowercase().contains("not running")
                || sig.detail.to_lowercase().contains("inactive")
                || sig.detail.to_lowercase().contains("service"),
            "Message should explain SSH service state, got: '{}'",
            sig.detail
        );
    }
}
