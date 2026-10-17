//! macOS backend using sysctl, IOKit (via FFI), and libproc.

use crate::error::{PlatformError, Result};

pub mod sysctl;

/// Returns the macOS kernel version.
pub fn kernel_version() -> Result<String> {
    sysctl::string("kern.osrelease")
}

/// Returns the system uptime in seconds.
pub fn uptime_secs() -> Result<u64> {
    use std::mem::MaybeUninit;
    let mut info = MaybeUninit::<libc::timeval>::uninit();
    let mut size = std::mem::size_of::<libc::timeval>();
    let name = b"kern.boottime\0";
    let rc = unsafe {
        libc::sysctl(
            name.as_ptr() as *mut _,
            2,
            info.as_mut_ptr() as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(PlatformError::Platform(
            "sysctl kern.boottime failed".into(),
        ));
    }
    let tv = unsafe { info.assume_init() };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(now.saturating_sub(tv.tv_sec as u64))
}

/// Returns the number of logical CPUs.
pub fn processor_count() -> Result<u32> {
    Ok(sysctl::u32("hw.logicalcpu")?)
}

/// Returns the physical memory in bytes.
pub fn physical_memory() -> Result<u64> {
    Ok(sysctl::u64("hw.memsize")?)
}
