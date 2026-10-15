//! Composite report aggregating all modules.

use crate::render;
use pulse_platform::{
    CpuInfo, DiskInfo, MemoryInfo, NetworkInfo, PlatformError, ProcessInfo, SystemInfo,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FullReport {
    pub pulse_version: String,
    pub generated_at_unix: u64,
    pub system: SystemInfo,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<DiskInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
}

pub fn build_full_report() -> Result<FullReport, PlatformError> {
    let generated_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(FullReport {
        pulse_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at_unix,
        system: pulse_platform::system_info()?,
        cpu: pulse_platform::cpu_info()?,
        memory: pulse_platform::memory_info()?,
        disk: pulse_platform::disk_info().ok(),
        network: pulse_platform::network_info().ok(),
        process: pulse_platform::process_info().ok(),
    })
}

impl FullReport {
    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        s.push_str("=== PULSE FULL REPORT ===\n\n");
        let _ = writeln!(s, "Pulse Version   : {}", self.pulse_version);
        let _ = writeln!(s, "Generated (unix): {}", self.generated_at_unix);
        s.push('\n');
        s.push_str("--- SYSTEM ---\n");
        s.push_str(&render::system_text(&self.system));
        s.push('\n');
        s.push_str("--- CPU ---\n");
        s.push_str(&render::cpu_text(&self.cpu));
        s.push('\n');
        s.push_str("--- MEMORY ---\n");
        s.push_str(&render::memory_text(&self.memory));
        if let Some(d) = &self.disk {
            s.push('\n');
            s.push_str("--- DISK ---\n");
            s.push_str(&render::disk_text(d));
        }
        if let Some(n) = &self.network {
            s.push('\n');
            s.push_str("--- NETWORK ---\n");
            s.push_str(&render::network_text(n));
        }
        if let Some(p) = &self.process {
            s.push('\n');
            s.push_str("--- PROCESSES ---\n");
            s.push_str(&render::process_text(p));
        }
        s
    }

    pub fn render_markdown(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        s.push_str("# Pulse Full Report\n\n");
        let _ = writeln!(s, "- **Pulse Version:** {}", self.pulse_version);
        let _ = writeln!(s, "- **Generated (unix):** {}", self.generated_at_unix);
        s.push_str("\n## System\n\n");
        s.push_str(&render::system_markdown(&self.system));
        s.push_str("\n## CPU\n\n");
        s.push_str(&render::cpu_markdown(&self.cpu));
        s.push_str("\n## Memory\n\n");
        s.push_str(&render::memory_markdown(&self.memory));
        if let Some(d) = &self.disk {
            s.push_str("\n## Disk\n\n");
            s.push_str(&render::disk_markdown(d));
        }
        if let Some(n) = &self.network {
            s.push_str("\n## Network\n\n");
            s.push_str(&render::network_markdown(n));
        }
        if let Some(p) = &self.process {
            s.push_str("\n## Processes\n\n");
            s.push_str(&render::process_markdown(p));
        }
        s
    }
}
