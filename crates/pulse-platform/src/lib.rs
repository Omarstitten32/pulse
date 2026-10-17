//! Pulse Platform Abstraction Layer
//!
//! Real system introspection via platform-native interfaces.
//! On Linux/Android: reads /proc and /sys directly.
//! Never returns simulated data.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

pub mod error;
pub mod hwid;
pub mod sha256;
pub mod types;

pub use error::{PlatformError, Result};
pub use types::{CoreInfo, CpuInfo, MemoryInfo, PlatformInfo, SystemInfo};

// ---------------- Basic (env-based, always available) ----------------

pub fn arch() -> &'static str {
    std::env::consts::ARCH
}
pub fn os() -> &'static str {
    // Runtime detection first: a static musl binary compiled for
    // aarch64-unknown-linux-musl reports consts::OS == "linux", but
    // when it runs on Android the environment is Android, not Linux.
    // Probe for Android-specific markers before falling back.
    if is_android_runtime() {
        "android"
    } else {
        std::env::consts::OS
    }
}

/// Detect an Android runtime by looking for well-known markers.
/// These exist on all Android devices (Google's CTS requires them)
/// and on no conventional Linux distribution.
pub(crate) fn is_android_runtime() -> bool {
    // 1. Google-mandated build metadata
    if std::path::Path::new("/system/build.prop").exists() {
        return true;
    }
    // 2. Android init process
    if let Ok(comm) = std::fs::read_to_string("/proc/1/comm") {
        if comm.trim() == "init" {
            // Distinguish from systemd (which is also "init" on some distros)
            // by checking for Android-specific init properties
            if std::path::Path::new("/system/bin/init").exists() {
                return true;
            }
        }
    }
    // 3. Android root directory layout
    if std::path::Path::new("/system/bin/app_process").exists() {
        return true;
    }
    false
}
pub fn family() -> &'static str {
    std::env::consts::FAMILY
}
pub fn pointer_width() -> u8 {
    (std::mem::size_of::<usize>() * 8) as u8
}
pub fn endianness() -> &'static str {
    if cfg!(target_endian = "little") {
        "little"
    } else {
        "big"
    }
}

/// Structured view of [`arch()`], [`os()`], [`family()`], [`pointer_width()`],
/// and [`endianness()`] suitable for serialization.
pub fn platform_info() -> Result<PlatformInfo> {
    Ok(PlatformInfo {
        arch: arch().to_string(),
        os: os().to_string(),
        family: family().to_string(),
        pointer_width: pointer_width(),
        endianness: endianness().to_string(),
    })
}

// ---------------- Real system introspection ----------------

pub fn system_info() -> Result<SystemInfo> {
    #[cfg(target_os = "linux")]
    return linux::system_info();
    #[cfg(target_os = "windows")]
    return windows::system_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("system_info"));
}

pub fn cpu_info() -> Result<CpuInfo> {
    #[cfg(target_os = "linux")]
    return linux::cpu_info();
    #[cfg(target_os = "windows")]
    return windows::cpu_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("cpu_info"));
}

pub fn memory_info() -> Result<MemoryInfo> {
    #[cfg(target_os = "linux")]
    return linux::memory_info();
    #[cfg(target_os = "windows")]
    return windows::memory_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("memory_info"));
}

/// Read boot time directly (with fallback to uptime-derived value).
/// Works without root if /proc/uptime is readable.
pub fn boot_time_unix() -> Result<u64> {
    #[cfg(target_os = "linux")]
    return linux::read_boot_time();
    #[cfg(target_os = "windows")]
    return windows::boot_time_unix();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("boot_time_unix"));
}

// ---------------- Disk / Network / Process ----------------

pub fn disk_info() -> Result<crate::types::DiskInfo> {
    #[cfg(target_os = "linux")]
    return linux::disk_info();
    #[cfg(target_os = "windows")]
    return windows::disk_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("disk_info"));
}

pub fn network_info() -> Result<crate::types::NetworkInfo> {
    #[cfg(target_os = "linux")]
    return linux::network_info();
    #[cfg(target_os = "windows")]
    return windows::network_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("network_info"));
}

pub fn process_info() -> Result<crate::types::ProcessInfo> {
    #[cfg(target_os = "linux")]
    return linux::process_info();
    #[cfg(target_os = "windows")]
    return windows::process_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("process_info"));
}

pub use types::{
    BatteryEntry, BatteryInfo, BrowserEntry, BrowsersInfo, ContainersInfo, CoreTimes, CpuTimes,
    CronInfo, CryptoInfo, DiskInfo, DriverModule, DriversInfo, EnvEntry, EnvInfo, FsInfo, FsNode,
    GpuDevice, GpuInfo, GroupEntry, HwidInfo, HwidSource, LoadAvg, MemoryDetail, MountInfo,
    NetInterface, NetworkInfo, PackageEntry, PackagesInfo, PciDevice, PciInfo, ProcessEntry,
    ProcessInfo, SensorChip, SensorReading, SensorsInfo, ServiceEntry, ServicesInfo, ThermalInfo,
    ThermalZone, UsbDevice, UsbInfo, UserEntry, UsersInfo, VmInfo, VmStat,
};

pub fn thermal_info() -> Result<crate::types::ThermalInfo> {
    #[cfg(target_os = "linux")]
    return linux::thermal_info();
    #[cfg(target_os = "windows")]
    return windows::thermal_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("thermal_info"));
}

pub fn gpu_info() -> Result<crate::types::GpuInfo> {
    #[cfg(target_os = "linux")]
    return linux::gpu_info();
    #[cfg(target_os = "windows")]
    return windows::gpu_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("gpu_info"));
}

pub fn memory_detail() -> Result<crate::types::MemoryDetail> {
    #[cfg(target_os = "linux")]
    return linux::memory_detail();
    #[cfg(target_os = "windows")]
    return windows::memory_detail();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("memory_detail"));
}
pub fn load_avg() -> Result<crate::types::LoadAvg> {
    #[cfg(target_os = "linux")]
    return linux::load_avg();
    #[cfg(target_os = "windows")]
    return windows::load_avg();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("load_avg"));
}
pub fn vmstat() -> Result<crate::types::VmStat> {
    #[cfg(target_os = "linux")]
    return linux::vmstat();
    #[cfg(target_os = "windows")]
    return windows::vmstat();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("vmstat"));
}
pub fn cpu_times() -> Result<crate::types::CpuTimes> {
    #[cfg(target_os = "linux")]
    return linux::cpu_times();
    #[cfg(target_os = "windows")]
    return windows::cpu_times();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("cpu_times"));
}

pub fn users_info() -> Result<crate::types::UsersInfo> {
    #[cfg(target_os = "linux")]
    return linux::users_info();
    #[cfg(target_os = "windows")]
    return windows::users_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("users_info"));
}
pub fn packages_info() -> Result<crate::types::PackagesInfo> {
    #[cfg(target_os = "linux")]
    return linux::packages_info();
    #[cfg(target_os = "windows")]
    return windows::packages_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("packages_info"));
}
pub fn services_info() -> Result<crate::types::ServicesInfo> {
    #[cfg(target_os = "linux")]
    return linux::services_info();
    #[cfg(target_os = "windows")]
    return windows::services_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("services_info"));
}
pub fn filesystem_info() -> Result<crate::types::FsInfo> {
    #[cfg(target_os = "linux")]
    return linux::filesystem_info();
    #[cfg(target_os = "windows")]
    return windows::filesystem_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("filesystem_info"));
}
pub fn env_info() -> Result<crate::types::EnvInfo> {
    #[cfg(target_os = "linux")]
    return linux::env_info();
    #[cfg(target_os = "windows")]
    return windows::env_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("env_info"));
}

pub fn usb_info() -> Result<crate::types::UsbInfo> {
    #[cfg(target_os = "linux")]
    return linux::usb_info();
    #[cfg(target_os = "windows")]
    return windows::usb_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("usb_info"));
}
pub fn pci_info() -> Result<crate::types::PciInfo> {
    #[cfg(target_os = "linux")]
    return linux::pci_info();
    #[cfg(target_os = "windows")]
    return windows::pci_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("pci_info"));
}
pub fn battery_info() -> Result<crate::types::BatteryInfo> {
    #[cfg(target_os = "linux")]
    return linux::battery_info();
    #[cfg(target_os = "windows")]
    return windows::battery_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("battery_info"));
}
pub fn sensors_info() -> Result<crate::types::SensorsInfo> {
    #[cfg(target_os = "linux")]
    return linux::sensors_info();
    #[cfg(target_os = "windows")]
    return windows::sensors_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("sensors_info"));
}
pub fn drivers_info() -> Result<crate::types::DriversInfo> {
    #[cfg(target_os = "linux")]
    return linux::drivers_info();
    #[cfg(target_os = "windows")]
    return windows::drivers_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("drivers_info"));
}

pub fn containers_info() -> Result<crate::types::ContainersInfo> {
    #[cfg(target_os = "linux")]
    return linux::containers_info();
    #[cfg(target_os = "windows")]
    return windows::containers_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("containers_info"));
}
pub fn vm_info() -> Result<crate::types::VmInfo> {
    #[cfg(target_os = "linux")]
    return linux::vm_info();
    #[cfg(target_os = "windows")]
    return windows::vm_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("vm_info"));
}
pub fn browsers_info() -> Result<crate::types::BrowsersInfo> {
    #[cfg(target_os = "linux")]
    return linux::browsers_info();
    #[cfg(target_os = "windows")]
    return windows::browsers_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("browsers_info"));
}
pub fn crypto_info() -> Result<crate::types::CryptoInfo> {
    #[cfg(target_os = "linux")]
    return linux::crypto_info();
    #[cfg(target_os = "windows")]
    return windows::crypto_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("crypto_info"));
}
pub fn cron_info() -> Result<crate::types::CronInfo> {
    #[cfg(target_os = "linux")]
    return linux::cron_info();
    #[cfg(target_os = "windows")]
    return windows::cron_info();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return Err(crate::error::PlatformError::unsupported("cron_info"));
}

pub fn hwid_info(context: Option<&str>) -> Result<crate::types::HwidInfo> {
    crate::hwid::hwid_info(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_is_known() {
        let a = arch();
        assert!(!a.is_empty());
        assert!(matches!(a, "aarch64" | "x86_64" | "x86" | "arm"));
    }

    #[test]
    fn pointer_width_is_32_or_64() {
        assert!(matches!(pointer_width(), 32 | 64));
    }

    #[test]
    fn system_info_reads_hostname() {
        let info = system_info().expect("system_info should succeed on Linux/Android");
        assert!(!info.hostname.is_empty(), "hostname should not be empty");
        assert!(info.pointer_width == 32 || info.pointer_width == 64);
    }

    #[test]
    fn cpu_info_reads_cores() {
        let info = cpu_info().expect("cpu_info should succeed");
        assert!(info.cores > 0, "should detect at least one core");
        assert_eq!(info.per_core.len(), info.cores as usize);
    }

    #[test]
    fn memory_info_reads_total() {
        let info = memory_info().expect("memory_info should succeed");
        assert!(info.total_kb > 0, "MemTotal should be > 0");
    }
}

// ---------------- Runtime mode detection ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Root,
    User,
    Unknown,
}

pub fn runtime_mode() -> RuntimeMode {
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            RuntimeMode::Root
        } else {
            RuntimeMode::User
        }
    }
    #[cfg(not(unix))]
    {
        RuntimeMode::Unknown
    }
}

pub fn is_root() -> bool {
    matches!(runtime_mode(), RuntimeMode::Root)
}

/// Returns true if the command typically needs root on Linux/Android.
pub fn command_needs_root(cmd: &str) -> bool {
    matches!(
        cmd,
        "thermal" | "battery" | "sensors" | "drivers" | "network" | "system"
    )
}

// ---------------------------------------------------------------------------
// Multi-platform support
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

/// Returns the normalized host OS identifier.
pub const fn host_os() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "android")]
    {
        "android"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "freebsd")]
    {
        "freebsd"
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows",
        target_os = "macos",
        target_os = "freebsd"
    )))]
    {
        "unknown"
    }
}
