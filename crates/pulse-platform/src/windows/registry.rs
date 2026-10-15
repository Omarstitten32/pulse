//! Windows Registry reader.

use crate::error::{PulseError, PulseResult};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HKEY;
use windows::Win32::System::Registry::*;

/// Reads a REG_SZ value from the registry.
pub fn read_string(root: HKEY, path: &str, name: &str) -> PulseResult<String> {
    let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let mut hkey = HKEY::default();
    let rc = unsafe { RegOpenKeyExW(root, PCWSTR(path_w.as_ptr()), Some(0), KEY_READ, &mut hkey) };
    if rc.is_err() {
        return Err(PulseError::Platform(format!(
            "RegOpenKeyExW({path}) failed"
        )));
    }

    let mut buf = vec![0u8; 4096];
    let mut size = buf.len() as u32;
    let mut kind = REG_NONE;

    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut kind as *mut _),
            Some(buf.as_mut_ptr()),
            Some(&mut size as *mut _),
        )
    };

    let _ = unsafe { RegCloseKey(hkey) };

    if rc.is_err() {
        return Err(PulseError::Platform(format!(
            "RegQueryValueExW({name}) failed"
        )));
    }

    if kind != REG_SZ && kind != REG_EXPAND_SZ {
        return Err(PulseError::Platform(format!(
            "registry value {name} is not a string"
        )));
    }

    let wide: Vec<u16> = buf[..size as usize]
        .chunks_exact(2)
        .map(|c| u16::from_ne_bytes([c[0], c[1]]))
        .collect();
    let trimmed: Vec<u16> = wide.into_iter().take_while(|&c| c != 0).collect();
    Ok(String::from_utf16_lossy(&trimmed))
}
