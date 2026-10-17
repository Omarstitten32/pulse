#![allow(clippy::field_reassign_with_default)]
//! Seccomp (Secure Computing Mode) analysis module.
//!
//! Detects if Seccomp is enabled, and what mode it operates in (strict, filter, disabled).
//! Reads from `/proc/self/status` and `/proc/sys/kernel/seccomp/actions_avail`.

use serde::Serialize;
use std::fs;

#[derive(Debug, Default, Serialize)]
pub struct SeccompReport {
    pub available: bool,
    pub mode: String,
    pub available_actions: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: String,
    pub message: String,
    pub evidence: String,
}

impl SeccompReport {
    pub fn collect() -> Self {
        let mut r = Self::default();

        // 1. Detect current process Seccomp mode
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("Seccomp:") {
                    r.available = true;
                    let mode_val = line.split_whitespace().nth(1).unwrap_or("0");
                    r.mode = match mode_val {
                        "0" => "disabled".to_string(),
                        "1" => "strict".to_string(),
                        "2" => "filter".to_string(),
                        _ => "unknown".to_string(),
                    };
                    break;
                }
            }
        }

        // 2. Detect available actions in kernel
        if let Ok(actions) = fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail") {
            r.available_actions = actions.split_whitespace().map(|s| s.to_string()).collect();
        }

        // 3. Generate findings based on state
        if r.available {
            if r.mode == "disabled" {
                r.findings.push(Finding {
                    severity: "WARN".to_string(),
                    message: "Seccomp is disabled for this process.".to_string(),
                    evidence: "No sandboxing active. System calls are unrestricted.".to_string(),
                });
            } else if r.mode == "filter" {
                r.findings.push(Finding {
                    severity: "GOOD".to_string(),
                    message: "Seccomp is active in filter mode.".to_string(),
                    evidence: "System calls are being filtered.".to_string(),
                });
            }
        } else {
            r.findings.push(Finding {
                severity: "INFO".to_string(),
                message: "Seccomp status not found.".to_string(),
                evidence: "/proc/self/status is missing the Seccomp field.".to_string(),
            });
        }

        r
    }
}

// --- SNIPER TESTS FOR SECCOMP ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_does_not_panic() {
        let report = SeccompReport::collect();
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_parse_seccomp_modes() {
        // We can't easily mock /proc, but we can test the match logic indirectly if we refactor,
        // or just ensure the report structure is valid.
        let report = SeccompReport::collect();
        assert!(
            report.mode == "disabled"
                || report.mode == "strict"
                || report.mode == "filter"
                || report.mode == "unknown"
        );
    }
}
