//! Hardware Identifier (HWID) — stable machine fingerprint.
//! Combines multiple hardware identifiers into one SHA-256 hash.
//! Stable across reinstall/hostname change. Changes only on hardware change.

use crate::error::Result;
use crate::sha256::sha256_hex;
use crate::types::{HwidInfo, HwidSource};

const VERSION_TAG: &str = "pulse-hwid-v1";

fn read_source(name: &str, path: &str, weight: u32) -> HwidSource {
    let value = std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().trim_end_matches('\0').to_string())
        .filter(|s| !s.is_empty() && s != "None" && s != "To be filled by O.E.M.");
    HwidSource {
        name: name.to_string(),
        available: value.is_some(),
        value,
        weight,
    }
}

fn read_first_disk_serial() -> Option<String> {
    let entries = std::fs::read_dir("/sys/block").ok()?;
    let mut candidates: Vec<(String, String)> = Vec::new();
    for e in entries.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("dm-")
            || name.starts_with("md")
        {
            continue;
        }
        let base = format!("/sys/block/{name}");
        for path in &[
            format!("{base}/device/serial"),
            format!("{base}/serial"),
            format!("{base}/device/wwid"),
            format!("{base}/wwid"),
        ] {
            if let Ok(s) = std::fs::read_to_string(path) {
                let s = s.trim().to_string();
                if !s.is_empty() && s != "0" {
                    candidates.push((name.clone(), s));
                    break;
                }
            }
        }
    }
    candidates.sort();
    candidates.into_iter().next().map(|(_, s)| s)
}

fn read_first_physical_mac() -> Option<String> {
    let entries = std::fs::read_dir("/sys/class/net").ok()?;
    let mut candidates: Vec<String> = Vec::new();

    // Skip virtual/tunnel/pseudo interfaces only
    const SKIP_PREFIXES: &[&str] = &[
        "veth", "docker", "br-", "virbr", "tun", "tap", "dummy", "ifb", "lo", "gre", "gretap",
        "erspan", "sit", "tunl", "ip6", "ip_vti", "miw_oem", "p2p",
    ];

    for e in entries.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };

        if SKIP_PREFIXES.iter().any(|p| name.starts_with(*p)) {
            continue;
        }

        let base = format!("/sys/class/net/{name}");
        let Ok(mac) = std::fs::read_to_string(format!("{base}/address")) else {
            continue;
        };
        let mac = mac.trim().to_string();

        if !is_valid_mac(&mac) {
            continue;
        }

        // NOTE: Android uses locally-administered (randomized) MACs by design.
        // We accept them — they are stable within a given network context.

        candidates.push(format!("{name}={mac}"));
    }

    sort_mac_candidates(candidates).into_iter().next()
}

/// Returns true when a MAC address string is usable as a stable identifier.
/// Rejects empty strings and any MAC where every octet is zero.
pub(crate) fn is_valid_mac(mac: &str) -> bool {
    if mac.is_empty() {
        return false;
    }
    if mac == "00:00:00:00:00:00" {
        return false;
    }
    if mac.chars().filter(|c| *c != ':').all(|c| c == '0') {
        return false;
    }
    true
}

/// Sorts MAC candidates by preferred-name priority, then alphabetically.
/// Priority order: wlan0 > eth0 > wlp > enp > eno > wlan1 > eth1 > others.
pub(crate) fn sort_mac_candidates(mut candidates: Vec<String>) -> Vec<String> {
    const PREFERRED: &[&str] = &["wlan0", "eth0", "wlp", "enp", "eno", "wlan1", "eth1"];
    candidates.sort_by_key(|c| {
        let name = c.split('=').next().unwrap_or("");
        let priority = PREFERRED
            .iter()
            .position(|p| name.starts_with(p))
            .map(|i| i as u32)
            .unwrap_or(999);
        (priority, c.clone())
    });
    candidates
}

/// Sorts PCI slot identifiers and joins them with commas.
pub(crate) fn format_pci_slots(mut slots: Vec<String>) -> String {
    slots.sort();
    slots.join(",")
}

fn collect_sources() -> Vec<HwidSource> {
    let mut sources = Vec::with_capacity(8);

    sources.push(read_source(
        "dmi.product_uuid",
        "/sys/class/dmi/id/product_uuid",
        20,
    ));
    sources.push(read_source(
        "dmi.board_serial",
        "/sys/class/dmi/id/board_serial",
        15,
    ));
    sources.push(read_source(
        "dmi.bios_version",
        "/sys/class/dmi/id/bios_version",
        5,
    ));

    let cpu_val = crate::cpu_info()
        .ok()
        .map(|c| format!("{}|{}", c.model, c.cores));
    sources.push(HwidSource {
        name: "cpu.signature".into(),
        available: cpu_val.is_some(),
        value: cpu_val,
        weight: 10,
    });

    let ram_val = crate::memory_info().ok().map(|m| m.total_kb.to_string());
    sources.push(HwidSource {
        name: "ram.total".into(),
        available: ram_val.is_some(),
        value: ram_val,
        weight: 5,
    });

    let disk_val = read_first_disk_serial();
    sources.push(HwidSource {
        name: "disk.serial".into(),
        available: disk_val.is_some(),
        value: disk_val,
        weight: 15,
    });

    let mac_val = read_first_physical_mac();
    sources.push(HwidSource {
        name: "network.mac".into(),
        available: mac_val.is_some(),
        value: mac_val,
        weight: 10,
    });

    let pci_val = crate::pci_info().ok().and_then(|p| {
        if p.total == 0 {
            None
        } else {
            let slots: Vec<String> = p.devices.iter().take(10).map(|d| d.slot.clone()).collect();
            Some(format_pci_slots(slots))
        }
    });
    sources.push(HwidSource {
        name: "pci.topology".into(),
        available: pci_val.is_some(),
        value: pci_val,
        weight: 8,
    });

    sources
}

/// Returns the base mode label derived from context presence.
pub(crate) fn compute_mode(context: Option<&str>) -> &'static str {
    match context {
        Some(c) if !c.is_empty() => "private",
        _ => "stable",
    }
}

/// Downgrades "stable" to "partial" when confidence is below 0.5.
pub(crate) fn apply_confidence_to_mode(mode: &str, confidence: f32) -> String {
    if confidence < 0.5 && mode == "stable" {
        "partial".to_string()
    } else {
        mode.to_string()
    }
}

pub fn hwid_info(context: Option<&str>) -> Result<HwidInfo> {
    let sources = collect_sources();

    let mut input = String::with_capacity(512);
    input.push_str(VERSION_TAG);
    input.push('\n');
    for s in &sources {
        input.push_str(&s.name);
        input.push('=');
        input.push_str(s.value.as_deref().unwrap_or("(unavailable)"));
        input.push('\n');
    }

    let mode = compute_mode(context);
    if let Some(c) = context {
        if !c.is_empty() {
            input.push_str("context=");
            input.push_str(c);
            input.push('\n');
        }
    }

    let hash = sha256_hex(input.as_bytes());
    let active_count = sources.iter().filter(|s| s.available).count() as u32;
    let total_count = sources.len() as u32;
    let confidence = if total_count > 0 {
        active_count as f32 / total_count as f32
    } else {
        0.0
    };

    let final_mode = apply_confidence_to_mode(mode, confidence);

    Ok(HwidInfo {
        hash,
        mode: final_mode,
        context: context.filter(|c| !c.is_empty()).map(String::from),
        active_count,
        total_count,
        confidence,
        sources,
    })
}

#[cfg(test)]
mod hwid_helper_tests {
    use super::*;

    // ===== is_valid_mac =====

    #[test]
    fn mac_valid_normal() {
        assert!(is_valid_mac("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn mac_valid_randomized() {
        assert!(is_valid_mac("a2:70:2f:b8:8d:4c"));
    }

    #[test]
    fn mac_invalid_empty() {
        assert!(!is_valid_mac(""));
    }

    #[test]
    fn mac_invalid_all_zeros_colon() {
        assert!(!is_valid_mac("00:00:00:00:00:00"));
    }

    #[test]
    fn mac_invalid_all_zeros_no_colon() {
        assert!(!is_valid_mac("000000000000"));
    }

    #[test]
    fn mac_invalid_zeros_with_colon_variants() {
        assert!(!is_valid_mac("00:00:00:00:00:0"));
    }

    #[test]
    fn mac_valid_one_nonzero_octet() {
        assert!(is_valid_mac("01:00:00:00:00:00"));
    }

    #[test]
    fn mac_valid_uppercase() {
        assert!(is_valid_mac("AA:BB:CC:DD:EE:FF"));
    }

    // ===== sort_mac_candidates =====

    #[test]
    fn sort_empty_vec() {
        assert!(sort_mac_candidates(vec![]).is_empty());
    }

    #[test]
    fn sort_single_element() {
        let r = sort_mac_candidates(vec!["eth0=aabb".into()]);
        assert_eq!(r, vec!["eth0=aabb"]);
    }

    #[test]
    fn sort_prioritizes_wlan0_over_eth0() {
        let r = sort_mac_candidates(vec!["eth0=ff".into(), "wlan0=aa".into()]);
        assert_eq!(r[0], "wlan0=aa");
        assert_eq!(r[1], "eth0=ff");
    }

    #[test]
    fn sort_prioritizes_eth0_over_wlp() {
        let r = sort_mac_candidates(vec!["wlp2s0=ff".into(), "eth0=aa".into()]);
        assert_eq!(r[0], "eth0=aa");
    }

    #[test]
    fn sort_unknown_name_last() {
        let r = sort_mac_candidates(vec!["zzz=ff".into(), "eth0=aa".into(), "yyy=bb".into()]);
        assert_eq!(r[0], "eth0=aa");
        assert!(r[1].starts_with('y') || r[1].starts_with('z'));
    }

    #[test]
    fn sort_unknown_alphabetical_within_same_priority() {
        let r = sort_mac_candidates(vec!["zzz=1".into(), "aaa=2".into()]);
        assert_eq!(r[0], "aaa=2");
        assert_eq!(r[1], "zzz=1");
    }

    #[test]
    fn sort_prefers_wlp_over_enp() {
        let r = sort_mac_candidates(vec!["enp3s0=bb".into(), "wlp2s0=aa".into()]);
        assert_eq!(r[0], "wlp2s0=aa");
    }

    #[test]
    fn sort_prefers_enp_over_eno() {
        let r = sort_mac_candidates(vec!["eno1=bb".into(), "enp3s0=aa".into()]);
        assert_eq!(r[0], "enp3s0=aa");
    }

    #[test]
    fn sort_prefers_wlan1_over_eth1() {
        let r = sort_mac_candidates(vec!["eth1=bb".into(), "wlan1=aa".into()]);
        assert_eq!(r[0], "wlan1=aa");
    }

    #[test]
    fn sort_preserves_wlan0_first() {
        let r = sort_mac_candidates(vec!["wlan1=cc".into(), "eth0=bb".into(), "wlan0=aa".into()]);
        assert_eq!(r[0], "wlan0=aa");
        assert_eq!(r[1], "eth0=bb");
        assert_eq!(r[2], "wlan1=cc");
    }

    // ===== format_pci_slots =====

    #[test]
    fn pci_slots_empty() {
        assert_eq!(format_pci_slots(vec![]), "");
    }

    #[test]
    fn pci_slots_single() {
        assert_eq!(
            format_pci_slots(vec!["0000:00:00.0".into()]),
            "0000:00:00.0"
        );
    }

    #[test]
    fn pci_slots_sorted_alphabetically() {
        let r = format_pci_slots(vec![
            "0000:00:02.0".into(),
            "0000:00:00.0".into(),
            "0000:00:01.0".into(),
        ]);
        assert_eq!(r, "0000:00:00.0,0000:00:01.0,0000:00:02.0");
    }

    #[test]
    fn pci_slots_sorted_by_hex_prefix() {
        let r = format_pci_slots(vec!["0000:01:00.0".into(), "0000:00:1f.0".into()]);
        assert_eq!(r, "0000:00:1f.0,0000:01:00.0");
    }

    // ===== compute_mode =====

    #[test]
    fn mode_none_is_stable() {
        assert_eq!(compute_mode(None), "stable");
    }

    #[test]
    fn mode_empty_context_is_stable() {
        assert_eq!(compute_mode(Some("")), "stable");
    }

    #[test]
    fn mode_with_context_is_private() {
        assert_eq!(compute_mode(Some("integration-test")), "private");
    }

    #[test]
    fn mode_with_single_char_context() {
        assert_eq!(compute_mode(Some("x")), "private");
    }

    // ===== apply_confidence_to_mode =====

    #[test]
    fn mode_stable_high_confidence_stays_stable() {
        assert_eq!(apply_confidence_to_mode("stable", 0.9), "stable");
    }

    #[test]
    fn mode_stable_confidence_at_threshold() {
        // 0.5 is not < 0.5, so stays stable
        assert_eq!(apply_confidence_to_mode("stable", 0.5), "stable");
    }

    #[test]
    fn mode_stable_low_confidence_becomes_partial() {
        assert_eq!(apply_confidence_to_mode("stable", 0.4), "partial");
    }

    #[test]
    fn mode_stable_zero_confidence() {
        assert_eq!(apply_confidence_to_mode("stable", 0.0), "partial");
    }

    #[test]
    fn mode_private_low_confidence_unchanged() {
        assert_eq!(apply_confidence_to_mode("private", 0.1), "private");
    }

    #[test]
    fn mode_private_high_confidence_unchanged() {
        assert_eq!(apply_confidence_to_mode("private", 0.99), "private");
    }

    #[test]
    fn mode_unknown_low_confidence_unchanged() {
        assert_eq!(apply_confidence_to_mode("weird", 0.0), "weird");
    }
}

#[cfg(test)]
mod io_path_tests {
    use super::*;

    #[test]
    fn read_first_disk_serial_returns_clean_option() {
        let r = read_first_disk_serial();
        if let Some(s) = r {
            assert!(!s.is_empty(), "disk serial must not be empty string");
            assert_ne!(s, "0", "disk serial must not be '0'");
            assert_eq!(s, s.trim(), "disk serial must be trimmed");
        }
    }

    #[test]
    fn read_first_physical_mac_returns_clean_option() {
        let r = read_first_physical_mac();
        if let Some(s) = r {
            assert!(s.contains('='), "mac candidate must be name=mac: {s}");
            let parts: Vec<&str> = s.splitn(2, '=').collect();
            assert_eq!(parts.len(), 2);
            assert!(!parts[0].is_empty(), "iface name must not be empty");
            assert!(!parts[1].is_empty(), "mac address must not be empty");
            assert!(is_valid_mac(parts[1]), "mac must pass is_valid_mac");
        }
    }

    #[test]
    fn read_first_disk_serial_is_stable() {
        let a = read_first_disk_serial();
        let b = read_first_disk_serial();
        assert_eq!(a, b, "disk serial must be deterministic");
    }

    #[test]
    fn read_first_physical_mac_is_stable() {
        let a = read_first_physical_mac();
        let b = read_first_physical_mac();
        assert_eq!(a, b, "physical mac must be deterministic");
    }
}
