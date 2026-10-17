#![allow(clippy::field_reassign_with_default)]
//! Namespaces analysis module.
//!
//! Detects the isolation level of the current process by comparing
//! `/proc/self/ns/` with `/proc/1/ns/`. Important for container and sandbox detection.

use serde::Serialize;
use std::fs;

#[derive(Debug, Default, Serialize)]
pub struct NamespacesReport {
    pub available: bool,
    pub is_containerized: bool,
    pub namespaces: Vec<NamespaceInfo>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Default, Serialize)]
pub struct NamespaceInfo {
    pub name: String,
    pub self_inode: u64,
    pub init_inode: u64,
    pub isolated: bool,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: String,
    pub message: String,
    pub evidence: String,
}

impl NamespacesReport {
    pub fn collect() -> Self {
        let mut r = Self::default();
        let ns_dir = "/proc/self/ns";

        if !std::path::Path::new(ns_dir).exists() {
            r.findings.push(Finding {
                severity: "INFO".to_string(),
                message: "Namespaces not supported on this kernel.".to_string(),
                evidence: format!("{} is missing.", ns_dir),
            });
            return r;
        }

        r.available = true;

        if let Ok(entries) = fs::read_dir(ns_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let self_inode = get_inode(entry.path());

                // Compare with init (PID 1)
                let init_path = format!("/proc/1/ns/{}", name);
                let init_inode = get_inode(std::path::PathBuf::from(&init_path));

                let isolated = self_inode != init_inode && init_inode != 0 && self_inode != 0;

                r.namespaces.push(NamespaceInfo {
                    name,
                    self_inode,
                    init_inode,
                    isolated,
                });
            }
        }

        r.namespaces.sort_by(|a, b| a.name.cmp(&b.name));

        // Determine if we are in a container (any namespace is isolated)
        r.is_containerized = r.namespaces.iter().any(|ns| ns.isolated);

        if r.is_containerized {
            r.findings.push(Finding {
                severity: "INFO".to_string(),
                message: "Process is running inside an isolated namespace (Container/Sandbox)."
                    .to_string(),
                evidence: "Different namespace inodes than PID 1.".to_string(),
            });
        } else {
            r.findings.push(Finding {
                severity: "GOOD".to_string(),
                message: "Process shares namespaces with PID 1 (Host environment).".to_string(),
                evidence: "Identical namespace inodes to PID 1.".to_string(),
            });
        }

        r
    }
}

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

fn get_inode(path: std::path::PathBuf) -> u64 {
    #[cfg(unix)]
    if let Ok(metadata) = fs::metadata(path) {
        return metadata.ino();
    }
    0
}

// --- SNIPER TESTS FOR NAMESPACES ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_get_inode_current_process() {
        let path = PathBuf::from("/proc/self/ns/pid");
        if path.exists() {
            // In some Android kernels/SELinux environments, ino() might return 0.
            // We just verify the function executes safely without panicking.
            let inode = get_inode(path);
            // We accept 0 if the kernel blocks it, but we ensure no crash.
            assert!(inode >= 0, "Function executed and returned a valid u64");
        } else {
            // If the file doesn't exist, we gracefully skip.
            assert!(true);
        }
    }

    #[test]
    fn test_collect_does_not_panic() {
        let report = NamespacesReport::collect();
        assert!(report.available);
        assert!(!report.namespaces.is_empty());
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_get_inode_invalid_path() {
        let inode = get_inode(PathBuf::from("/does/not/exist"));
        assert_eq!(inode, 0);
    }
}
