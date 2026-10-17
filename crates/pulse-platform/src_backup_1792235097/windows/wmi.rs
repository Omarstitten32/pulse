//! Minimal WMI stub.
//!
//! Full WMI integration requires the COM API and is intentionally
//! kept out of the platform layer. Consumers that need WMI should
//! call PowerShell directly or enable the `wmi` feature.

use crate::error::{PulseError, PulseResult};

/// Returns CPU model via environment fallback (no COM).
pub fn cpu_model() -> PulseResult<String> {
    std::env::var("PROCESSOR_IDENTIFIER")
        .map_err(|_| PulseError::Platform("PROCESSOR_IDENTIFIER not set".into()))
}

/// Returns the OS description from environment.
pub fn os_description() -> PulseResult<String> {
    std::env::var("OS").map_err(|_| PulseError::Platform("OS env var not set".into()))
}
