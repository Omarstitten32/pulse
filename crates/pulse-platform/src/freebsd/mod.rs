//! FreeBSD backend using sysctl and kvm.

use crate::error::{PlatformError, Result};

pub mod sysctl;

/// Returns the FreeBSD kernel release.
pub fn kernel_version() -> Result<String> {
    sysctl::string("kern.osrelease")
}

/// Returns the system uptime in seconds.
pub fn uptime_secs() -> Result<u64> {
    Ok(sysctl::u64("kern.boottime")? & 0xFFFFFFFF)
}

/// Returns the number of logical CPUs.
pub fn processor_count() -> Result<u32> {
    Ok(sysctl::u32("hw.ncpu")?)
}

/// Returns the physical memory in bytes.
pub fn physical_memory() -> Result<u64> {
    Ok(sysctl::u64("hw.physmem")?)
}
