#![allow(clippy::field_reassign_with_default)]
//! NUMA (Non-Uniform Memory Access) analysis module.
//!
//! Detects NUMA nodes, their associated CPUs, and memory layout.
//! Reads from `/sys/devices/system/node/`.

use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Serialize)]
pub struct NumaReport {
    pub available: bool,
    pub node_count: usize,
    pub nodes: Vec<NumaNode>,
    pub details: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Default, Serialize)]
pub struct NumaNode {
    pub id: u32,
    pub cpulist: String,
    pub mem_total_kb: u64,
    pub mem_free_kb: u64,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: String,
    pub message: String,
    pub evidence: String,
}

impl NumaReport {
    pub fn collect() -> Self {
        let mut r = Self::default();
        let base_path = Path::new("/sys/devices/system/node");

        if !base_path.exists() {
            r.details
                .push("NUMA is not supported or disabled on this kernel.".to_string());
            return r;
        }

        if let Ok(entries) = fs::read_dir(base_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    if name.starts_with("node") {
                        if let Ok(id) = name[4..].parse::<u32>() {
                            let node = parse_node(id, &path);
                            r.nodes.push(node);
                        }
                    }
                }
            }
        }

        r.node_count = r.nodes.len();
        r.available = r.node_count > 0;

        if r.available {
            r.details
                .push(format!("NUMA is active with {} node(s).", r.node_count));
            // Sort by ID for deterministic output
            r.nodes.sort_by_key(|n| n.id);
        } else {
            r.findings.push(Finding {
                severity: "INFO".to_string(),
                message: "No NUMA nodes detected.".to_string(),
                evidence: "/sys/devices/system/node is empty or unreadable.".to_string(),
            });
        }

        r
    }
}

fn parse_node(id: u32, path: &Path) -> NumaNode {
    let mut node = NumaNode::default();
    node.id = id;

    // Read CPU list
    if let Ok(cpulist) = fs::read_to_string(path.join("cpulist")) {
        node.cpulist = cpulist.trim().to_string();
    }

    // Read Memory Info
    if let Ok(meminfo) = fs::read_to_string(path.join("meminfo")) {
        for line in meminfo.lines() {
            if line.contains("MemTotal:") {
                node.mem_total_kb = extract_kb(line);
            } else if line.contains("MemFree:") {
                node.mem_free_kb = extract_kb(line);
            }
        }
    }

    node
}

fn extract_kb(line: &str) -> u64 {
    line.split_whitespace()
        .nth(3) // Format: "Node 0 MemTotal: 12345 kB"
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

// --- SNIPER TESTS FOR NUMA ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_kb_valid() {
        let line = "Node 0 MemTotal:   16384000 kB";
        assert_eq!(extract_kb(line), 16384000);
    }

    #[test]
    fn test_extract_kb_invalid() {
        let line = "Node 0 MemTotal:   invalid kB";
        assert_eq!(extract_kb(line), 0);
    }

    #[test]
    fn test_collect_does_not_panic() {
        let report = NumaReport::collect();
        if report.available {
            assert!(!report.nodes.is_empty());
        }
    }
}
