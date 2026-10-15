//! FreeBSD sysctl wrapper.

use crate::error::{PulseError, PulseResult};

fn sysctl_raw(name: &str, buf: &mut [u8]) -> PulseResult<usize> {
    let name_c = format!("{name}\0");
    let mut size = buf.len();
    let rc = unsafe {
        libc::sysctlbyname(
            name_c.as_ptr() as *const _,
            buf.as_mut_ptr() as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(PulseError::Platform(format!("sysctl({name}) failed")));
    }
    Ok(size)
}

/// Reads a sysctl as a UTF-8 string.
pub fn string(name: &str) -> PulseResult<String> {
    let mut buf = vec![0u8; 4096];
    let n = sysctl_raw(name, &mut buf)?;
    let trimmed = buf[..n]
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .collect::<Vec<u8>>();
    String::from_utf8(trimmed)
        .map_err(|_| PulseError::Platform(format!("sysctl({name}) not UTF-8")))
}

/// Reads a sysctl as u32.
pub fn u32(name: &str) -> PulseResult<u32> {
    let mut buf = [0u8; 4];
    sysctl_raw(name, &mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

/// Reads a sysctl as u64.
pub fn u64(name: &str) -> PulseResult<u64> {
    let mut buf = [0u8; 8];
    sysctl_raw(name, &mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}
