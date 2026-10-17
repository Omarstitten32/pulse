//! Windows backend using native Win32 API.

pub mod registry;
pub mod wmi;

use crate::error::{PulseError, PulseResult};
use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::SystemInformation::*;

/// Returns the Windows kernel version string.
pub fn kernel_version() -> PulseResult<String> {
    let mut info = OSVERSIONINFOW::default();
    info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

    #[link(name = "ntdll")]
    extern "system" {
        fn RtlGetVersion(ver: *mut OSVERSIONINFOW) -> i32;
    }

    let rc = unsafe { RtlGetVersion(&mut info) };
    if rc == 0 {
        Ok(format!(
            "{}.{}.{}",
            info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber
        ))
    } else {
        Err(PulseError::Platform(format!(
            "RtlGetVersion failed with code {rc}"
        )))
    }
}

/// Returns the system uptime in seconds.
pub fn uptime_secs() -> PulseResult<u64> {
    let ticks = unsafe { GetTickCount64() };
    Ok(ticks / 1000)
}

/// Returns the computer name.
pub fn computer_name() -> PulseResult<String> {
    let mut buf = [0u16; 256];
    let mut size = buf.len() as u32;
    unsafe {
        GetComputerNameW(&mut buf, &mut size)
            .map_err(|e| PulseError::Platform(format!("GetComputerNameW: {e}")))?;
    }
    Ok(String::from_utf16_lossy(&buf[..size as usize]))
}

/// Returns the page size in bytes.
pub fn page_size() -> PulseResult<u64> {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut info) };
    Ok(info.dwPageSize as u64)
}

/// Returns the number of logical processors.
pub fn processor_count() -> PulseResult<u32> {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut info) };
    Ok(info.dwNumberOfProcessors)
}

/// Returns the physical memory in bytes.
pub fn physical_memory() -> PulseResult<u64> {
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    unsafe {
        GlobalMemoryStatusEx(&mut status)
            .map_err(|e| PulseError::Platform(format!("GlobalMemoryStatusEx: {e}")))?;
    }
    Ok(status.ullTotalPhys)
}

/// Reads a registry string value.
pub fn read_registry_string(root: HKEY, path: &str, key: &str) -> PulseResult<String> {
    registry::read_string(root, path, key)
}

/// Helper: converts a Rust string to a null-terminated UTF-16 vector.
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Helper: PCWSTR from a wide vector.
pub(crate) fn pcwstr(v: &[u16]) -> PCWSTR {
    PCWSTR(v.as_ptr())
}
