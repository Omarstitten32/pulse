//! Cross-platform shims for Unix-specific filesystem and process APIs.

#[cfg(not(unix))]
pub trait MetadataExt {
    fn mode(&self) -> u32;
    fn uid(&self) -> u32;
    fn ctime(&self) -> i64;
    fn size(&self) -> u64;
}

#[cfg(not(unix))]
impl MetadataExt for std::fs::Metadata {
    fn mode(&self) -> u32 {
        0
    }
    fn uid(&self) -> u32 {
        0
    }
    fn ctime(&self) -> i64 {
        0
    }
    fn size(&self) -> u64 {
        self.len()
    }
}

#[cfg(not(unix))]
pub trait PermissionsExt {
    fn mode(&self) -> u32;
}

#[cfg(not(unix))]
impl PermissionsExt for std::fs::Permissions {
    fn mode(&self) -> u32 {
        0
    }
}

#[cfg(not(unix))]
pub fn getuid() -> u32 {
    0
}
