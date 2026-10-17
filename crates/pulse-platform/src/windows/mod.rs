//! Windows-specific implementations for Pulse Platform.
//! Uses windows-sys for native API calls.

use crate::error::Result;
use crate::types::*;
use std::env;

macro_rules! stub {
    ($name:ident, $ret:ty) => {
        pub fn $name() -> Result<$ret> {
            unimplemented!("Windows $name not yet implemented")
        }
    };
    ($name:ident, $ret:ty, $arg:ty) => {
        pub fn $name(_arg: $arg) -> Result<$ret> {
            unimplemented!("Windows $name not yet implemented")
        }
    };
}

pub fn system_info() -> Result<SystemInfo> {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;

    let hostname = env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());
    let uptime = unsafe { GetTickCount64() / 1000 };
    let boot_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        - uptime;

    Ok(SystemInfo {
        os_name: "Windows".to_string(),
        os_version: "Unknown (API Pending)".to_string(),
        kernel_version: "Windows NT".to_string(),
        hostname,
        architecture: env::consts::ARCH.to_string(),
        uptime_seconds: uptime,
        boot_time_unix: boot_time,
        pointer_width: (std::mem::size_of::<usize>() * 8) as u8,
        endianness: "little".to_string(),
    })
}

pub fn cpu_info() -> Result<CpuInfo> {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut sys_info) };

    Ok(CpuInfo {
        model: "Windows Processor".to_string(),
        architecture: env::consts::ARCH.to_string(),
        cores: sys_info.dwNumberOfProcessors, // Already u32 in windows-sys
        per_core: vec![],
        features: vec![],
    })
}

pub fn memory_info() -> Result<MemoryInfo> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut mem_status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

    let success = unsafe { GlobalMemoryStatusEx(&mut mem_status) };
    if success == 0 {
        return Err(crate::error::PlatformError::unsupported(
            "GlobalMemoryStatusEx failed",
        ));
    }

    let total = mem_status.ullTotalPhys / 1024;
    let free = mem_status.ullAvailPhys / 1024;

    Ok(MemoryInfo {
        total_kb: total,
        free_kb: free,
        available_kb: free,
        buffers_kb: 0,
        cached_kb: 0,
        swap_total_kb: mem_status.ullTotalPageFile / 1024,
        swap_free_kb: mem_status.ullAvailPageFile / 1024,
    })
}

// Keep stubs for the rest
stub!(boot_time_unix, u64);
stub!(disk_info, DiskInfo);
stub!(network_info, NetworkInfo);
stub!(process_info, ProcessInfo);
stub!(thermal_info, ThermalInfo);
stub!(gpu_info, GpuInfo);
stub!(memory_detail, MemoryDetail);
stub!(load_avg, LoadAvg);
stub!(vmstat, VmStat);
stub!(cpu_times, CpuTimes);
stub!(users_info, UsersInfo);
stub!(packages_info, PackagesInfo);
stub!(services_info, ServicesInfo);
stub!(filesystem_info, FsInfo);
stub!(env_info, EnvInfo);
stub!(usb_info, UsbInfo);
stub!(pci_info, PciInfo);
stub!(battery_info, BatteryInfo);
stub!(sensors_info, SensorsInfo);
stub!(drivers_info, DriversInfo);
stub!(containers_info, ContainersInfo);
stub!(vm_info, VmInfo);
stub!(browsers_info, BrowsersInfo);
stub!(crypto_info, CryptoInfo);
stub!(cron_info, CronInfo);
stub!(hwid_info, HwidInfo, Option<&str>);
