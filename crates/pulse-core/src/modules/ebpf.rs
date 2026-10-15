#![allow(clippy::field_reassign_with_default)]
//! ebpf analysis module.
//!
//! Collects state from /proc, /sys, and platform-specific APIs.

use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct EbpfReport {
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

impl EbpfReport {
    pub fn collect() -> Self {
        let mut r = Self::default();
        r.available = detect();
        r
    }
}

fn detect() -> bool {
    false
}
