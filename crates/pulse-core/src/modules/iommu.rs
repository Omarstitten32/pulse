#![allow(clippy::field_reassign_with_default)]
//! IOMMU (Input-Output Memory Management Unit) analysis module.
//!
//! Detects if IOMMU is enabled and active. IOMMU protects the system
//! against malicious DMA (Direct Memory Access) attacks from peripherals.
//! It reads from `/sys/class/iommu` and `/proc/cmdline`.

use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Serialize)]
pub struct IommuReport {
    pub available: bool,
    pub details: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: String,
    pub message: String,
    pub evidence: String,
}

impl IommuReport {
    pub fn collect() -> Self {
        let mut r = Self::default();

        let (is_active, count) = detect_and_count();
        r.available = is_active;

        if is_active {
            r.details
                .push(format!("IOMMU is active with {} group(s) detected.", count));

            // Check if kernel cmdline explicitly requested it
            if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
                if cmdline.contains("intel_iommu=on") || cmdline.contains("amd_iommu=on") {
                    r.details
                        .push("IOMMU explicitly enabled via kernel cmdline.".to_string());
                }
            }
        } else {
            r.findings.push(Finding {
                severity: "WARN".to_string(),
                message: "IOMMU is disabled or unavailable.".to_string(),
                evidence:
                    "Missing /sys/class/iommu entries. System may be vulnerable to DMA attacks."
                        .to_string(),
            });
        }

        r
    }
}

fn detect_and_count() -> (bool, usize) {
    let path = Path::new("/sys/class/iommu");
    if path.exists() {
        if let Ok(entries) = fs::read_dir(path) {
            let count = entries.filter_map(|e| e.ok()).count();
            if count > 0 {
                return (true, count);
            }
        }
    }
    (false, 0)
}

// --- SNIPER TESTS FOR IOMMU ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_and_count_does_not_panic() {
        let (_, _) = detect_and_count();
    }

    #[test]
    fn test_collect_returns_valid_report() {
        let report = IommuReport::collect();
        if !report.available {
            assert_eq!(report.findings.len(), 1);
            assert_eq!(report.findings[0].severity, "WARN");
        } else {
            assert!(!report.details.is_empty());
        }
    }
}
