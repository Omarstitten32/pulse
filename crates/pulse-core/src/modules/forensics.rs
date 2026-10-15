#![allow(clippy::field_reassign_with_default)]
//! forensics analysis module.
//!
//! Collects state from /proc, /sys, and platform-specific APIs.

use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct ForensicsReport {
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

impl ForensicsReport {
    pub fn collect() -> Self {
        let mut r = Self::default();
        r.available = detect();
        r
    }
}

fn detect() -> bool {
    false
}
