//! Pulse Platform Abstraction Layer
//!
//! Real system introspection via platform-native interfaces.
//! On Linux/Android: reads /proc and /sys directly.
//! Never returns simulated data.

pub mod error;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod hwid;
pub mod sha256;
pub mod types;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;

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
fn is_android_runtime() -> bool {
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

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn system_info() -> Result<SystemInfo> {
    linux::system_info()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn cpu_info() -> Result<CpuInfo> {
    linux::cpu_info()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn memory_info() -> Result<MemoryInfo> {
    linux::memory_info()
}

/// Read boot time directly (with fallback to uptime-derived value).
/// Works without root if /proc/uptime is readable.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn boot_time_unix() -> Result<u64> {
    linux::read_boot_time()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn system_info() -> Result<SystemInfo> {
    Err(PlatformError::unsupported(
        "system_info (only Linux/Android currently supported)",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn cpu_info() -> Result<CpuInfo> {
    Err(PlatformError::unsupported(
        "cpu_info (only Linux/Android currently supported)",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn memory_info() -> Result<MemoryInfo> {
    Err(PlatformError::unsupported(
        "memory_info (only Linux/Android currently supported)",
    ))
}

// ---------------- Disk / Network / Process ----------------

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn disk_info() -> Result<crate::types::DiskInfo> {
    linux::disk_info()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn network_info() -> Result<crate::types::NetworkInfo> {
    linux::network_info()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn process_info() -> Result<crate::types::ProcessInfo> {
    linux::process_info()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn disk_info() -> Result<crate::types::DiskInfo> {
    Err(PlatformError::unsupported("disk_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn network_info() -> Result<crate::types::NetworkInfo> {
    Err(PlatformError::unsupported("network_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn process_info() -> Result<crate::types::ProcessInfo> {
    Err(PlatformError::unsupported("process_info"))
}

pub use types::{
    BatteryEntry, BatteryInfo, BrowserEntry, BrowsersInfo, ContainersInfo, CoreTimes, CpuTimes,
    CronInfo, CryptoInfo, DiskInfo, DriverModule, DriversInfo, EnvEntry, EnvInfo, FsInfo, FsNode,
    GpuDevice, GpuInfo, GroupEntry, HwidInfo, HwidSource, LoadAvg, MemoryDetail, MountInfo,
    NetInterface, NetworkInfo, PackageEntry, PackagesInfo, PciDevice, PciInfo, ProcessEntry,
    ProcessInfo, SensorChip, SensorReading, SensorsInfo, ServiceEntry, ServicesInfo, ThermalInfo,
    ThermalZone, UsbDevice, UsbInfo, UserEntry, UsersInfo, VmInfo, VmStat,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn thermal_info() -> Result<crate::types::ThermalInfo> {
    linux::thermal_info()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn gpu_info() -> Result<crate::types::GpuInfo> {
    linux::gpu_info()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn thermal_info() -> Result<crate::types::ThermalInfo> {
    Err(PlatformError::unsupported("thermal_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn gpu_info() -> Result<crate::types::GpuInfo> {
    Err(PlatformError::unsupported("gpu_info"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn memory_detail() -> Result<crate::types::MemoryDetail> {
    linux::memory_detail()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn load_avg() -> Result<crate::types::LoadAvg> {
    linux::load_avg()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn vmstat() -> Result<crate::types::VmStat> {
    linux::vmstat()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn cpu_times() -> Result<crate::types::CpuTimes> {
    linux::cpu_times()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn memory_detail() -> Result<crate::types::MemoryDetail> {
    Err(PlatformError::unsupported("memory_detail"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn load_avg() -> Result<crate::types::LoadAvg> {
    Err(PlatformError::unsupported("load_avg"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn vmstat() -> Result<crate::types::VmStat> {
    Err(PlatformError::unsupported("vmstat"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn cpu_times() -> Result<crate::types::CpuTimes> {
    Err(PlatformError::unsupported("cpu_times"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn users_info() -> Result<crate::types::UsersInfo> {
    linux::users_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn packages_info() -> Result<crate::types::PackagesInfo> {
    linux::packages_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn services_info() -> Result<crate::types::ServicesInfo> {
    linux::services_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn filesystem_info() -> Result<crate::types::FsInfo> {
    linux::filesystem_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn env_info() -> Result<crate::types::EnvInfo> {
    linux::env_info()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn users_info() -> Result<crate::types::UsersInfo> {
    Err(PlatformError::unsupported("users_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn packages_info() -> Result<crate::types::PackagesInfo> {
    Err(PlatformError::unsupported("packages_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn services_info() -> Result<crate::types::ServicesInfo> {
    Err(PlatformError::unsupported("services_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn filesystem_info() -> Result<crate::types::FsInfo> {
    Err(PlatformError::unsupported("filesystem_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn env_info() -> Result<crate::types::EnvInfo> {
    Err(PlatformError::unsupported("env_info"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn usb_info() -> Result<crate::types::UsbInfo> {
    linux::usb_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn pci_info() -> Result<crate::types::PciInfo> {
    linux::pci_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn battery_info() -> Result<crate::types::BatteryInfo> {
    linux::battery_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn sensors_info() -> Result<crate::types::SensorsInfo> {
    linux::sensors_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn drivers_info() -> Result<crate::types::DriversInfo> {
    linux::drivers_info()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn usb_info() -> Result<crate::types::UsbInfo> {
    Err(PlatformError::unsupported("usb_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn pci_info() -> Result<crate::types::PciInfo> {
    Err(PlatformError::unsupported("pci_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn battery_info() -> Result<crate::types::BatteryInfo> {
    Err(PlatformError::unsupported("battery_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn sensors_info() -> Result<crate::types::SensorsInfo> {
    Err(PlatformError::unsupported("sensors_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn drivers_info() -> Result<crate::types::DriversInfo> {
    Err(PlatformError::unsupported("drivers_info"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn containers_info() -> Result<crate::types::ContainersInfo> {
    linux::containers_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn vm_info() -> Result<crate::types::VmInfo> {
    linux::vm_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn browsers_info() -> Result<crate::types::BrowsersInfo> {
    linux::browsers_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn crypto_info() -> Result<crate::types::CryptoInfo> {
    linux::crypto_info()
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn cron_info() -> Result<crate::types::CronInfo> {
    linux::cron_info()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn containers_info() -> Result<crate::types::ContainersInfo> {
    Err(PlatformError::unsupported("containers_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn vm_info() -> Result<crate::types::VmInfo> {
    Err(PlatformError::unsupported("vm_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn browsers_info() -> Result<crate::types::BrowsersInfo> {
    Err(PlatformError::unsupported("browsers_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn crypto_info() -> Result<crate::types::CryptoInfo> {
    Err(PlatformError::unsupported("crypto_info"))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn cron_info() -> Result<crate::types::CronInfo> {
    Err(PlatformError::unsupported("cron_info"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn hwid_info(context: Option<&str>) -> Result<crate::types::HwidInfo> {
    crate::hwid::hwid_info(context)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn hwid_info(_context: Option<&str>) -> Result<crate::types::HwidInfo> {
    Err(PlatformError::unsupported("hwid_info"))
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn system_info_reads_hostname() {
        let info = system_info().expect("system_info should succeed on Linux/Android");
        assert!(!info.hostname.is_empty(), "hostname should not be empty");
        assert!(info.pointer_width == 32 || info.pointer_width == 64);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn cpu_info_reads_cores() {
        let info = cpu_info().expect("cpu_info should succeed");
        assert!(info.cores > 0, "should detect at least one core");
        assert_eq!(info.per_core.len(), info.cores as usize);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
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

#[cfg(unix)]
pub fn runtime_mode() -> RuntimeMode {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        RuntimeMode::Root
    } else {
        RuntimeMode::User
    }
}

#[cfg(not(unix))]
pub fn runtime_mode() -> RuntimeMode {
    RuntimeMode::Unknown
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

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn boot_time_unix() -> Result<u64> {
    Err(PlatformError::unsupported("boot_time_unix"))
}

// ---------------------------------------------------------------------------
// Multi-platform support
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub mod windows;

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
        target_os = "freebsd",
    )))]
    {
        "unknown"
    }
}
