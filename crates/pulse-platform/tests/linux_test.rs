//! Integration tests for the Linux/Android platform backend.

#![cfg(any(target_os = "linux", target_os = "android"))]

use pulse_platform::linux::*;

#[test]
fn system_info_returns_linux_kernel_string() {
    let info = system_info().expect("system_info must succeed");
    assert!(!info.kernel_version.is_empty());
    assert!(info.kernel_version.contains("Linux"));
}

#[test]
fn system_info_hostname_is_non_empty() {
    let info = system_info().unwrap();
    assert!(!info.hostname.is_empty());
}

#[test]
fn system_info_pointer_width_is_32_or_64() {
    let info = system_info().unwrap();
    assert!(info.pointer_width == 32 || info.pointer_width == 64);
}

#[test]
fn system_info_endianness_is_known() {
    let info = system_info().unwrap();
    assert!(info.endianness == "little" || info.endianness == "big");
}

#[test]
fn system_info_architecture_matches_env_consts() {
    let info = system_info().unwrap();
    assert_eq!(info.architecture, std::env::consts::ARCH);
}

#[test]
fn system_info_uptime_is_positive() {
    let info = system_info().unwrap();
    assert!(info.uptime_seconds > 0);
}

#[test]
fn system_info_boot_time_is_plausible() {
    let info = system_info().unwrap();
    assert!(info.boot_time_unix > 946_684_800);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(info.boot_time_unix <= now + 60);
}

#[test]
fn system_info_os_name_is_non_empty() {
    let info = system_info().unwrap();
    assert!(!info.os_name.is_empty());
}

#[test]
fn read_boot_time_is_plausible() {
    let bt = read_boot_time().expect("boot time must be obtainable");
    assert!(bt > 946_684_800);
}

#[test]
fn cpu_info_reports_at_least_one_core() {
    let info = cpu_info().expect("cpu_info must succeed");
    assert!(info.cores > 0);
}

#[test]
fn cpu_info_model_is_non_empty() {
    let info = cpu_info().unwrap();
    assert!(!info.model.is_empty());
}

#[test]
fn cpu_info_per_core_len_matches_cores() {
    let info = cpu_info().unwrap();
    assert_eq!(info.per_core.len() as u32, info.cores);
}

#[test]
fn cpu_info_architecture_matches_env_consts() {
    let info = cpu_info().unwrap();
    assert_eq!(info.architecture, std::env::consts::ARCH);
}

#[test]
fn cpu_info_features_sorted_stable_between_calls() {
    let a = cpu_info().unwrap();
    let b = cpu_info().unwrap();
    assert_eq!(a.features, b.features);
}

#[test]
fn memory_info_total_is_positive() {
    let info = memory_info().expect("memory_info must succeed");
    assert!(info.total_kb > 0);
}

#[test]
fn memory_info_free_does_not_exceed_total() {
    let info = memory_info().unwrap();
    assert!(info.free_kb <= info.total_kb);
}

#[test]
fn memory_info_available_does_not_exceed_total() {
    let info = memory_info().unwrap();
    assert!(info.available_kb <= info.total_kb);
}

#[test]
fn memory_info_swap_free_does_not_exceed_swap_total() {
    let info = memory_info().unwrap();
    assert!(info.swap_free_kb <= info.swap_total_kb);
}

#[test]
fn memory_detail_total_equals_memory_info_total() {
    let simple = memory_info().unwrap();
    let detail = memory_detail().expect("memory_detail must succeed");
    assert_eq!(simple.total_kb, detail.total_kb);
    assert_eq!(simple.free_kb, detail.free_kb);
    assert_eq!(simple.swap_total_kb, detail.swap_total_kb);
}

#[test]
fn memory_detail_hugepagesize_plausible() {
    let d = memory_detail().unwrap();
    assert!(d.hugepagesize_kb == 0 || d.hugepagesize_kb >= 4);
}

#[test]
fn disk_info_skips_virtual_filesystems() {
    let info = disk_info().expect("disk_info must succeed");
    for m in &info.mounts {
        assert_ne!(m.fs_type, "proc");
        assert_ne!(m.fs_type, "sysfs");
        assert_ne!(m.fs_type, "tmpfs");
        assert_ne!(m.fs_type, "cgroup");
        assert_ne!(m.fs_type, "cgroup2");
        assert_ne!(m.fs_type, "devpts");
        assert_ne!(m.fs_type, "debugfs");
        assert_ne!(m.fs_type, "tracefs");
    }
}

#[test]
fn disk_info_mount_points_are_absolute() {
    let info = disk_info().unwrap();
    for m in &info.mounts {
        assert!(m.mount_point.starts_with('/'));
    }
}

#[test]
fn disk_info_percent_within_bounds() {
    let info = disk_info().unwrap();
    for m in &info.mounts {
        if let Some(p) = m.use_percent {
            assert!((0.0..=100.5).contains(&p));
        }
    }
}

#[test]
fn network_info_contains_loopback() {
    let info = network_info().expect("network_info must succeed");
    assert!(info.interfaces.iter().any(|i| i.name == "lo"));
}

#[test]
fn network_info_sorted_by_name() {
    let info = network_info().unwrap();
    let mut names: Vec<String> = info.interfaces.iter().map(|i| i.name.clone()).collect();
    let original = names.clone();
    names.sort();
    assert_eq!(original, names);
}

#[test]
fn process_info_has_pid_1() {
    let info = process_info().expect("process_info must succeed");
    assert!(info.total > 0);
    assert!(info.processes.iter().any(|p| p.pid == 1));
}

#[test]
fn process_info_sorted_by_pid() {
    let info = process_info().unwrap();
    let mut pids: Vec<u32> = info.processes.iter().map(|p| p.pid).collect();
    let original = pids.clone();
    pids.sort();
    assert_eq!(original, pids);
}

#[test]
fn process_info_names_are_non_empty() {
    let info = process_info().unwrap();
    for p in &info.processes {
        assert!(!p.name.is_empty());
    }
}

#[test]
fn thermal_info_does_not_panic() {
    let _ = thermal_info().expect("thermal_info must succeed");
}

#[test]
fn thermal_info_sorted_descending() {
    let info = thermal_info().unwrap();
    for w in info.zones.windows(2) {
        assert!(w[0].temp_celsius >= w[1].temp_celsius);
    }
}

#[test]
fn gpu_info_does_not_panic() {
    let _ = gpu_info().expect("gpu_info must succeed");
}

#[test]
fn gpu_info_paths_are_unique() {
    let info = gpu_info().unwrap();
    let mut paths: Vec<&String> = info.detected.iter().map(|d| &d.path).collect();
    let original = paths.clone();
    paths.sort();
    paths.dedup();
    assert_eq!(original.len(), paths.len());
}

#[test]
fn load_avg_is_non_negative() {
    let info = load_avg().expect("load_avg must succeed");
    assert!(info.load1 >= 0.0);
    assert!(info.load5 >= 0.0);
    assert!(info.load15 >= 0.0);
}

#[test]
fn load_avg_total_tasks_positive() {
    let info = load_avg().unwrap();
    assert!(info.total_tasks > 0);
}

#[test]
fn load_avg_running_does_not_exceed_total() {
    let info = load_avg().unwrap();
    assert!(info.running_tasks <= info.total_tasks);
}

#[test]
fn vmstat_nr_free_pages_is_positive() {
    let info = vmstat().expect("vmstat must succeed");
    assert!(info.nr_free_pages > 0);
}

#[test]
fn cpu_times_total_id_is_minus_one() {
    let info = cpu_times().expect("cpu_times must succeed");
    assert_eq!(info.total.id, -1);
}

#[test]
fn cpu_times_per_core_is_non_empty() {
    let info = cpu_times().unwrap();
    assert!(!info.per_core.is_empty());
}

#[test]
fn cpu_times_per_core_sorted_by_id() {
    let info = cpu_times().unwrap();
    let mut ids: Vec<i32> = info.per_core.iter().map(|c| c.id).collect();
    let original = ids.clone();
    ids.sort();
    assert_eq!(original, ids);
}

#[test]
fn cpu_times_idle_is_positive() {
    let info = cpu_times().unwrap();
    assert!(info.total.idle > 0);
}

#[test]
fn users_info_contains_root_uid_0() {
    let info = users_info().expect("users_info must succeed");
    assert!(info.users.iter().any(|u| u.uid == 0));
}

#[test]
fn users_info_contains_root_group() {
    let info = users_info().unwrap();
    assert!(info.groups.iter().any(|g| g.gid == 0));
}

#[test]
fn users_info_sorted_by_uid() {
    let info = users_info().unwrap();
    let mut uids: Vec<u32> = info.users.iter().map(|u| u.uid).collect();
    let original = uids.clone();
    uids.sort();
    assert_eq!(original, uids);
}

#[test]
fn users_info_groups_sorted_by_gid() {
    let info = users_info().unwrap();
    let mut gids: Vec<u32> = info.groups.iter().map(|g| g.gid).collect();
    let original = gids.clone();
    gids.sort();
    assert_eq!(original, gids);
}

#[test]
fn services_info_total_matches_len() {
    let info = services_info().expect("services_info must succeed");
    assert_eq!(info.total as usize, info.services.len());
}

#[test]
fn filesystem_info_returns_only_existing_paths() {
    let info = filesystem_info().expect("filesystem_info must succeed");
    for node in &info.roots {
        assert!(std::path::Path::new(&node.path).exists());
    }
}

#[test]
fn env_info_total_is_non_zero() {
    let info = env_info().expect("env_info must succeed");
    assert!(info.total > 0);
    assert_eq!(info.total as usize, info.entries.len());
}

#[test]
fn env_info_sorted_by_key() {
    let info = env_info().unwrap();
    let mut keys: Vec<String> = info.entries.iter().map(|e| e.key.clone()).collect();
    let original = keys.clone();
    keys.sort();
    assert_eq!(original, keys);
}

#[test]
fn usb_info_total_matches_len() {
    let info = usb_info().expect("usb_info must succeed");
    assert_eq!(info.total as usize, info.devices.len());
}

#[test]
fn pci_info_total_matches_len() {
    let info = pci_info().expect("pci_info must succeed");
    assert_eq!(info.total as usize, info.devices.len());
}

#[test]
fn battery_info_total_matches_len() {
    let info = battery_info().expect("battery_info must succeed");
    assert_eq!(info.total as usize, info.batteries.len());
}

#[test]
fn sensors_info_total_matches_len() {
    let info = sensors_info().expect("sensors_info must succeed");
    assert_eq!(info.total as usize, info.chips.len());
}

#[test]
fn drivers_info_total_matches_len() {
    let info = drivers_info().expect("drivers_info must succeed");
    assert_eq!(info.total as usize, info.modules.len());
}

#[test]
fn drivers_info_sorted_by_name() {
    let info = drivers_info().unwrap();
    let mut names: Vec<String> = info.modules.iter().map(|m| m.name.clone()).collect();
    let original = names.clone();
    names.sort();
    assert_eq!(original, names);
}

#[test]
fn containers_info_detected_consistent_with_evidence() {
    let info = containers_info().expect("containers_info must succeed");
    if info.detected {
        assert!(!info.evidences.is_empty());
    } else {
        assert!(info.evidences.is_empty());
    }
}

#[test]
fn vm_info_detected_consistent_with_evidence() {
    let info = vm_info().expect("vm_info must succeed");
    if info.is_vm {
        assert!(!info.evidences.is_empty());
    } else {
        assert!(info.evidences.is_empty());
    }
}

#[test]
fn browsers_info_total_matches_len() {
    let info = browsers_info().expect("browsers_info must succeed");
    assert_eq!(info.total as usize, info.detected.len());
}

#[test]
fn crypto_info_consistency() {
    let info = crypto_info().expect("crypto_info must succeed");
    assert_eq!(info.has_gnupg, info.gnupg_path.is_some());
}

#[test]
fn cron_info_does_not_panic() {
    let _ = cron_info().expect("cron_info must succeed");
}

#[test]
fn repeated_calls_stable_for_stable_fields() {
    let a = system_info().unwrap();
    let b = system_info().unwrap();
    assert_eq!(a.architecture, b.architecture);
    assert_eq!(a.pointer_width, b.pointer_width);
    assert_eq!(a.endianness, b.endianness);
    assert_eq!(a.kernel_version, b.kernel_version);

    let ca = cpu_info().unwrap();
    let cb = cpu_info().unwrap();
    assert_eq!(ca.model, cb.model);
    assert_eq!(ca.cores, cb.cores);

    let ma = memory_info().unwrap();
    let mb = memory_info().unwrap();
    assert_eq!(ma.total_kb, mb.total_kb);
}
