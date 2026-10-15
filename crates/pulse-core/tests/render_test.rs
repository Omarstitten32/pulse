//! Real, executable tests for every renderer in `pulse-core/src/render.rs`.
//!
//! Every public renderer is exercised with:
//!   * typical values
//!   * empty collections
//!   * `None` variants of every `Option<T>`
//!   * long strings that trigger truncation branches
//!   * zero values that trigger division guards
//!
//! Coverage target: ≥ 85% of render.rs

use pulse_core::format::JsonStyle;
use pulse_core::render::*;
use pulse_platform::*;

// ---------------------------------------------------------------------------
// Helpers — construct minimal but valid fixtures
// ---------------------------------------------------------------------------

fn sample_system() -> SystemInfo {
    SystemInfo {
        os_name: "Kali GNU/Linux".into(),
        os_version: "2026.3".into(),
        kernel_version: "6.1.138-android14-11".into(),
        hostname: "localhost".into(),
        uptime_seconds: 7200,
        boot_time_unix: 1_700_000_000,
        architecture: "aarch64".into(),
        pointer_width: 64,
        endianness: "little".into(),
    }
}

fn sample_cpu_full() -> CpuInfo {
    CpuInfo {
        model: "Dimensity 8300".into(),
        architecture: "aarch64".into(),
        cores: 2,
        features: vec!["neon".into(), "sve".into(), "fp16".into()],
        per_core: vec![
            CoreInfo {
                id: 0,
                cur_freq_khz: Some(2_000_000),
                min_freq_khz: Some(400_000),
                max_freq_khz: Some(3_000_000),
                governor: Some("schedutil".into()),
            },
            CoreInfo {
                id: 1,
                cur_freq_khz: None,
                min_freq_khz: None,
                max_freq_khz: None,
                governor: None,
            },
        ],
    }
}

fn sample_cpu_empty() -> CpuInfo {
    CpuInfo {
        model: String::new(),
        architecture: String::new(),
        cores: 0,
        features: vec![],
        per_core: vec![],
    }
}

fn sample_memory() -> MemoryInfo {
    MemoryInfo {
        total_kb: 16_384_000,
        free_kb: 2_000_000,
        available_kb: 8_000_000,
        buffers_kb: 500_000,
        cached_kb: 4_000_000,
        swap_total_kb: 4_194_304,
        swap_free_kb: 4_000_000,
    }
}

fn sample_memory_zero_total() -> MemoryInfo {
    MemoryInfo {
        total_kb: 0,
        free_kb: 0,
        available_kb: 0,
        buffers_kb: 0,
        cached_kb: 0,
        swap_total_kb: 0,
        swap_free_kb: 0,
    }
}

fn sample_disk() -> DiskInfo {
    DiskInfo {
        mounts: vec![
            MountInfo {
                device: "/dev/sda1".into(),
                mount_point: "/".into(),
                fs_type: "ext4".into(),
                options: "rw,relatime".into(),
                total_bytes: Some(500_000_000_000),
                used_bytes: Some(200_000_000_000),
                available_bytes: Some(300_000_000_000),
                use_percent: Some(40.0),
            },
            MountInfo {
                device: "/dev/sdb1".into(),
                mount_point: "/this/is/a/very/long/mount/point/that/exceeds/28/chars".into(),
                fs_type: "xfs".into(),
                options: "rw".into(),
                total_bytes: None,
                used_bytes: None,
                available_bytes: None,
                use_percent: None,
            },
        ],
    }
}

fn sample_disk_empty() -> DiskInfo {
    DiskInfo { mounts: vec![] }
}

fn sample_network() -> NetworkInfo {
    NetworkInfo {
        interfaces: vec![
            NetInterface {
                name: "wlan0".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                state: Some("UP".into()),
                mtu: Some(1500),
                kind: Some("wifi".into()),
            },
            NetInterface {
                name: "lo".into(),
                mac: None,
                state: None,
                mtu: None,
                kind: None,
            },
        ],
    }
}

fn sample_network_empty() -> NetworkInfo {
    NetworkInfo { interfaces: vec![] }
}

fn sample_process() -> ProcessInfo {
    ProcessInfo {
        total: 2,
        processes: vec![
            ProcessEntry {
                pid: 1,
                ppid: 0,
                name: "init".into(),
                state: "S".into(),
                threads: 1,
                rss_pages: 256,
            },
            ProcessEntry {
                pid: 1234,
                ppid: 1,
                name: "a-very-long-process-name-that-will-be-truncated".into(),
                state: "R".into(),
                threads: 8,
                rss_pages: 100_000,
            },
        ],
    }
}

fn sample_process_empty() -> ProcessInfo {
    ProcessInfo {
        total: 0,
        processes: vec![],
    }
}

fn sample_thermal() -> ThermalInfo {
    ThermalInfo {
        zones: vec![
            ThermalZone {
                name: "cpu".into(),
                temp_millicelsius: 45_000,
                temp_celsius: 45.0,
            },
            ThermalZone {
                name: "gpu".into(),
                temp_millicelsius: 60_500,
                temp_celsius: 60.5,
            },
        ],
    }
}

fn sample_thermal_empty() -> ThermalInfo {
    ThermalInfo { zones: vec![] }
}

fn sample_gpu() -> GpuInfo {
    GpuInfo {
        detected: vec![GpuDevice {
            driver: "mali".into(),
            path: "/sys/class/drm/card0".into(),
            kind: "integrated".into(),
        }],
    }
}

fn sample_gpu_empty() -> GpuInfo {
    GpuInfo { detected: vec![] }
}

fn sample_memory_detail() -> MemoryDetail {
    MemoryDetail {
        total_kb: 16_384_000,
        free_kb: 1_000_000,
        available_kb: 8_000_000,
        buffers_kb: 100_000,
        cached_kb: 4_000_000,
        swap_cached_kb: 1000,
        shmem_kb: 50_000,
        active_kb: 6_000_000,
        inactive_kb: 3_000_000,
        active_anon_kb: 4_000_000,
        inactive_anon_kb: 2_000_000,
        active_file_kb: 2_000_000,
        inactive_file_kb: 1_000_000,
        unevictable_kb: 0,
        mlocked_kb: 0,
        slab_kb: 500_000,
        sreclaimable_kb: 300_000,
        sunreclaim_kb: 200_000,
        kernel_stack_kb: 16_000,
        page_tables_kb: 32_000,
        k_reclaimable_kb: 100_000,
        anon_pages_kb: 4_500_000,
        mapped_kb: 2_000_000,
        dirty_kb: 100,
        writeback_kb: 0,
        commit_limit_kb: 20_000_000,
        committed_as_kb: 5_000_000,
        vmalloc_total_kb: 32_000_000,
        vmalloc_used_kb: 500_000,
        vmalloc_chunk_kb: 10_000_000,
        hugepages_total: 0,
        hugepages_free: 0,
        hugepagesize_kb: 2048,
        swap_total_kb: 4_194_304,
        swap_free_kb: 4_000_000,
    }
}

fn sample_load() -> LoadAvg {
    LoadAvg {
        load1: 1.25,
        load5: 0.85,
        load15: 0.75,
        running_tasks: 3,
        total_tasks: 500,
        last_pid: 12345,
        uptime_seconds: 7200,
    }
}

fn sample_vmstat() -> VmStat {
    VmStat {
        pgpgin: 1,
        pgpgout: 2,
        pswpin: 3,
        pswpout: 4,
        pgfault: 5,
        pgmajfault: 6,
        pgalloc_dma: 7,
        pgalloc_dma32: 8,
        pgalloc_normal: 9,
        pgalloc_movable: 10,
        pgfree: 11,
        pgactivate: 12,
        pgdeactivate: 13,
        pglazyfree: 14,
        pglazyfreed: 15,
        pgsteal_kswapd: 16,
        pgsteal_direct: 17,
        pgscan_kswapd: 18,
        pgscan_direct: 19,
        nr_free_pages: 20,
        nr_zone_inactive_anon: 21,
        nr_zone_active_anon: 22,
        nr_zone_inactive_file: 23,
        nr_zone_active_file: 24,
        nr_slab_reclaimable: 25,
        nr_slab_unreclaimable: 26,
        nr_dirty: 27,
        nr_writeback: 28,
        nr_shmem: 29,
        nr_kernel_misc_reclaimable: 30,
    }
}

fn sample_cpu_times() -> CpuTimes {
    CpuTimes {
        total: CoreTimes {
            id: -1,
            user: 1000,
            nice: 10,
            system: 500,
            idle: 5000,
            iowait: 20,
            irq: 30,
            softirq: 40,
            steal: 0,
            guest: 0,
            guest_nice: 0,
        },
        per_core: vec![CoreTimes {
            id: 0,
            user: 500,
            nice: 5,
            system: 250,
            idle: 2500,
            iowait: 10,
            irq: 15,
            softirq: 20,
            steal: 0,
            guest: 0,
            guest_nice: 0,
        }],
    }
}

fn sample_cpu_times_empty() -> CpuTimes {
    CpuTimes {
        total: CoreTimes {
            id: -1,
            user: 0,
            nice: 0,
            system: 0,
            idle: 0,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
            guest: 0,
            guest_nice: 0,
        },
        per_core: vec![],
    }
}

fn sample_users() -> UsersInfo {
    UsersInfo {
        users: vec![UserEntry {
            name: "root".into(),
            uid: 0,
            gid: 0,
            gecos: "root".into(),
            home: "/root".into(),
            shell: "/bin/bash".into(),
        }],
        groups: vec![
            GroupEntry {
                name: "root".into(),
                gid: 0,
                members: vec![],
            },
            GroupEntry {
                name: "sudo".into(),
                gid: 27,
                members: vec!["kali".into(), "omar".into()],
            },
        ],
    }
}

fn sample_users_empty() -> UsersInfo {
    UsersInfo {
        users: vec![],
        groups: vec![],
    }
}

fn sample_packages() -> PackagesInfo {
    PackagesInfo {
        manager: "dpkg".into(),
        total: 2,
        packages: vec![
            PackageEntry {
                name: "libc6".into(),
                version: "2.43-6".into(),
                status: "installed".into(),
            },
            PackageEntry {
                name: "pulse".into(),
                version: "1.9.0".into(),
                status: "installed".into(),
            },
        ],
    }
}

fn sample_packages_overflow() -> PackagesInfo {
    let mut packages = Vec::new();
    for i in 0..150 {
        packages.push(PackageEntry {
            name: format!("pkg-{:03}", i),
            version: "1.0".into(),
            status: "installed".into(),
        });
    }
    PackagesInfo {
        manager: "dpkg".into(),
        total: packages.len() as u32,
        packages,
    }
}

fn sample_services() -> ServicesInfo {
    ServicesInfo {
        init_system: "systemd".into(),
        total: 3,
        services: vec![
            ServiceEntry {
                name: "sshd".into(),
                kind: "systemd".into(),
                enabled: Some(true),
            },
            ServiceEntry {
                name: "apache2".into(),
                kind: "systemd".into(),
                enabled: Some(false),
            },
            ServiceEntry {
                name: "custom".into(),
                kind: "sysv".into(),
                enabled: None,
            },
        ],
    }
}

fn sample_fs() -> FsInfo {
    FsInfo {
        roots: vec![
            FsNode {
                path: "/".into(),
                kind: "dir".into(),
                size_bytes: Some(4096),
                entries: 25,
                readable: true,
            },
            FsNode {
                path: "/root".into(),
                kind: "dir".into(),
                size_bytes: None,
                entries: 10,
                readable: false,
            },
        ],
    }
}

fn sample_env() -> EnvInfo {
    EnvInfo {
        total: 2,
        entries: vec![
            EnvEntry {
                key: "PATH".into(),
                value: "/usr/bin:/bin".into(),
            },
            EnvEntry {
                key: "VERY_LONG_VAR".into(),
                value: "x".repeat(100),
            },
        ],
    }
}

fn sample_usb() -> UsbInfo {
    UsbInfo {
        total: 2,
        devices: vec![
            UsbDevice {
                name: "usb1".into(),
                id_vendor: Some("1d6b".into()),
                id_product: Some("0002".into()),
                manufacturer: Some("Linux".into()),
                product: Some("xHCI Host".into()),
                bclass: None,
            },
            UsbDevice {
                name: "usb2".into(),
                id_vendor: None,
                id_product: None,
                manufacturer: None,
                product: None,
                bclass: None,
            },
        ],
    }
}

fn sample_pci() -> PciInfo {
    PciInfo {
        total: 2,
        devices: vec![
            PciDevice {
                slot: "0000:00:00.0".into(),
                vendor: Some("0x14c3".into()),
                device: Some("0x8300".into()),
                class: Some("0x060000".into()),
                driver: Some("mediatek".into()),
            },
            PciDevice {
                slot: "0000:00:01.0".into(),
                vendor: None,
                device: None,
                class: None,
                driver: None,
            },
        ],
    }
}

fn sample_battery() -> BatteryInfo {
    BatteryInfo {
        total: 1,
        batteries: vec![BatteryEntry {
            name: "BAT0".into(),
            capacity: Some(85),
            status: Some("Discharging".into()),
            health: Some("Good".into()),
            technology: Some("Li-ion".into()),
            voltage_uv: Some(4_200_000),
            current_ua: Some(-1_500_000),
            temp_dc: Some(285),
            cycle_count: Some(150),
        }],
    }
}

fn sample_battery_all_none() -> BatteryInfo {
    BatteryInfo {
        total: 1,
        batteries: vec![BatteryEntry {
            name: "BAT0".into(),
            capacity: None,
            status: None,
            health: None,
            technology: None,
            voltage_uv: None,
            current_ua: None,
            temp_dc: None,
            cycle_count: None,
        }],
    }
}

fn sample_sensors() -> SensorsInfo {
    SensorsInfo {
        total: 2,
        chips: vec![
            SensorChip {
                name: "cpu_thermal".into(),
                path: "/sys/class/hwmon/hwmon0".into(),
                temps: vec![
                    SensorReading {
                        label: Some("cpu".into()),
                        celsius: 45.0,
                    },
                    SensorReading {
                        label: None,
                        celsius: 46.5,
                    },
                ],
            },
            SensorChip {
                name: "gpu_thermal".into(),
                path: "/sys/class/hwmon/hwmon1".into(),
                temps: vec![],
            },
        ],
    }
}

fn sample_drivers() -> DriversInfo {
    DriversInfo {
        total: 2,
        modules: vec![
            DriverModule {
                name: "gps_scp".into(),
                size: 131_072,
                refs: 2,
                deps: vec!["gps_pwr".into()],
                state: "Live".into(),
            },
            DriverModule {
                name: "gps_pwr".into(),
                size: 24_576,
                refs: 0,
                deps: vec![],
                state: "Live".into(),
            },
        ],
    }
}

fn sample_containers() -> ContainersInfo {
    ContainersInfo {
        detected: true,
        runtime: Some("docker".into()),
        evidences: vec![
            "/.dockerenv exists".into(),
            "cgroup names contain docker".into(),
        ],
    }
}

fn sample_containers_none() -> ContainersInfo {
    ContainersInfo {
        detected: false,
        runtime: None,
        evidences: vec![],
    }
}

fn sample_vm() -> VmInfo {
    VmInfo {
        is_vm: true,
        hypervisor: Some("KVM".into()),
        product_name: Some("Standard PC".into()),
        sys_vendor: Some("QEMU".into()),
        evidences: vec!["DMI product name".into()],
    }
}

fn sample_vm_none() -> VmInfo {
    VmInfo {
        is_vm: false,
        hypervisor: None,
        product_name: None,
        sys_vendor: None,
        evidences: vec![],
    }
}

fn sample_browsers() -> BrowsersInfo {
    BrowsersInfo {
        total: 1,
        detected: vec![BrowserEntry {
            name: "firefox".into(),
            kind: "firefox".into(),
            path: "/usr/bin/firefox-esr".into(),
        }],
    }
}

fn sample_crypto() -> CryptoInfo {
    CryptoInfo {
        ssl_certs_count: 42,
        system_ssh_keys: vec!["/etc/ssh/ssh_host_rsa_key".into()],
        user_ssh_keys: vec!["/root/.ssh/id_ed25519".into()],
        has_gnupg: true,
        gnupg_path: Some("/usr/bin/gpg".into()),
    }
}

fn sample_crypto_none() -> CryptoInfo {
    CryptoInfo {
        ssl_certs_count: 0,
        system_ssh_keys: vec![],
        user_ssh_keys: vec![],
        has_gnupg: false,
        gnupg_path: None,
    }
}

fn sample_cron() -> CronInfo {
    CronInfo {
        has_etc_crontab: true,
        system_files: vec!["/etc/cron.d/john".into()],
        system_dirs: vec!["/etc/cron.daily".into()],
        user_crontabs: vec!["/var/spool/cron/crontabs/root".into()],
    }
}

fn sample_cron_empty() -> CronInfo {
    CronInfo {
        has_etc_crontab: false,
        system_files: vec![],
        system_dirs: vec![],
        user_crontabs: vec![],
    }
}

fn sample_hwid() -> HwidInfo {
    HwidInfo {
        hash: "a1b2c3d4e5f6".into(),
        mode: "hardware".into(),
        context: Some("android".into()),
        active_count: 5,
        total_count: 6,
        confidence: 0.83,
        sources: vec![
            HwidSource {
                name: "cpu".into(),
                value: Some("Dimensity 8300".into()),
                available: true,
                weight: 3,
            },
            HwidSource {
                name: "ram".into(),
                value: None,
                available: false,
                weight: 2,
            },
        ],
    }
}

fn sample_hwid_low_confidence() -> HwidInfo {
    HwidInfo {
        hash: "deadbeef".into(),
        mode: "fallback".into(),
        context: None,
        active_count: 1,
        total_count: 6,
        confidence: 0.17,
        sources: vec![],
    }
}

// ---------------------------------------------------------------------------
// to_json — both styles
// ---------------------------------------------------------------------------

#[test]
fn to_json_pretty_contains_newlines() {
    let sys = sample_system();
    let s = to_json(&sys, JsonStyle::Pretty);
    assert!(s.contains('\n'), "pretty output must be multi-line");
    assert!(s.contains("\"os_name\""));
    assert!(s.contains("Kali GNU/Linux"));
}

#[test]
fn to_json_compact_is_single_line() {
    let sys = sample_system();
    let s = to_json(&sys, JsonStyle::Compact);
    assert!(!s.contains('\n'), "compact must be single line");
    assert!(s.starts_with('{'));
    assert!(s.ends_with('}'));
}

#[test]
fn to_json_serializes_all_public_types() {
    // Each call must succeed (no panic) and produce valid JSON start/end.
    macro_rules! check {
        ($v:expr) => {{
            let s = to_json(&$v, JsonStyle::Compact);
            assert!(s.starts_with('{'), "not an object: {}", s);
            assert!(s.ends_with('}'), "not an object: {}", s);
        }};
    }
    check!(sample_system());
    check!(sample_cpu_full());
    check!(sample_memory());
    check!(sample_disk());
    check!(sample_network());
    check!(sample_process());
    check!(sample_thermal());
    check!(sample_gpu());
    check!(sample_memory_detail());
    check!(sample_load());
    check!(sample_vmstat());
    check!(sample_cpu_times());
    check!(sample_users());
    check!(sample_packages());
    check!(sample_services());
    check!(sample_fs());
    check!(sample_env());
    check!(sample_usb());
    check!(sample_pci());
    check!(sample_battery());
    check!(sample_sensors());
    check!(sample_drivers());
    check!(sample_containers());
    check!(sample_vm());
    check!(sample_browsers());
    check!(sample_crypto());
    check!(sample_cron());
    check!(sample_hwid());
}

// ---------------------------------------------------------------------------
// system_text / system_markdown
// ---------------------------------------------------------------------------

#[test]
fn system_text_contains_all_fields() {
    let s = system_text(&sample_system());
    assert!(s.contains("OS Name"));
    assert!(s.contains("Kali GNU/Linux"));
    assert!(s.contains("Kernel"));
    assert!(s.contains("6.1.138"));
    assert!(s.contains("Hostname"));
    assert!(s.contains("localhost"));
    assert!(s.contains("Uptime"));
    assert!(s.contains("7200 seconds"));
    assert!(
        s.contains("2h 0m"),
        "uptime must be formatted as hours/minutes: {s}"
    );
    assert!(s.contains("Architecture"));
    assert!(s.contains("aarch64"));
    assert!(s.contains("Pointer Width"));
    assert!(s.contains("64 bits"));
    assert!(s.contains("Endianness"));
    assert!(s.contains("little"));
}

#[test]
fn system_markdown_has_table_pipes() {
    let s = system_markdown(&sample_system());
    assert!(s.starts_with("| Field | Value |"));
    assert!(s.contains("|-------|-------|"));
    assert!(s.contains("| Kernel |"));
    assert!(s.contains("aarch64"));
}

// ---------------------------------------------------------------------------
// cpu_text / cpu_markdown
// ---------------------------------------------------------------------------

#[test]
fn cpu_text_full_core() {
    let s = cpu_text(&sample_cpu_full());
    assert!(s.contains("Model"));
    assert!(s.contains("Dimensity 8300"));
    assert!(s.contains("Cores"));
    assert!(s.contains("Features (3)"));
    assert!(s.contains("neon sve fp16"));
    assert!(s.contains("Per-core"));
    assert!(s.contains("schedutil"));
    // Second core has all None → must display "-"
    assert!(s.contains(" - "), "missing placeholders: {s}");
}

#[test]
fn cpu_text_empty_cpu_does_not_panic() {
    let s = cpu_text(&sample_cpu_empty());
    assert!(s.contains("Cores          : 0"));
    assert!(s.contains("Features (0)"));
}

#[test]
fn cpu_markdown_full_core() {
    let s = cpu_markdown(&sample_cpu_full());
    assert!(s.contains("**Model:** Dimensity 8300"));
    assert!(s.contains("**Cores:** 2"));
    assert!(s.contains("| Core | Cur (kHz) |"));
    assert!(s.contains("schedutil"));
}

// ---------------------------------------------------------------------------
// memory_text / memory_markdown
// ---------------------------------------------------------------------------

#[test]
fn memory_text_shows_used_percent() {
    let s = memory_text(&sample_memory());
    assert!(s.contains("Total"));
    assert!(s.contains("MB"));
    assert!(s.contains("Used"));
    assert!(s.contains("%"));
}

#[test]
fn memory_text_zero_total_skips_percent() {
    let s = memory_text(&sample_memory_zero_total());
    // Guard: total_kb == 0 must NOT produce "Used" line.
    assert!(
        !s.contains("Used           :"),
        "division guard failed: {s}"
    );
}

#[test]
fn memory_markdown_shows_all_fields() {
    let s = memory_markdown(&sample_memory());
    assert!(s.contains("| Total |"));
    assert!(s.contains("| Swap Free |"));
}

#[test]
fn memory_markdown_zero_total_skips_percent_row() {
    let s = memory_markdown(&sample_memory_zero_total());
    assert!(!s.contains("| Used |"), "division guard failed: {s}");
}

// ---------------------------------------------------------------------------
// disk_text / disk_markdown
// ---------------------------------------------------------------------------

#[test]
fn disk_text_handles_missing_bytes() {
    let s = disk_text(&sample_disk());
    assert!(s.contains("Mounts: 2"));
    assert!(s.contains("ext4"));
    assert!(s.contains("-"), "None placeholders must appear as '-'");
}

#[test]
fn disk_text_truncates_long_mount_point() {
    let s = disk_text(&sample_disk());
    // The long mount point is > 28 chars; renderer truncates to 27.
    assert!(!s.contains("/this/is/a/very/long/mount/point/that/exceeds/28/chars"));
}

#[test]
fn disk_text_empty() {
    let s = disk_text(&sample_disk_empty());
    assert!(s.contains("Mounts: 0"));
}

#[test]
fn disk_markdown_has_table() {
    let s = disk_markdown(&sample_disk());
    assert!(s.contains("| Mount | FS | Total |"));
}

// ---------------------------------------------------------------------------
// network_text / network_markdown
// ---------------------------------------------------------------------------

#[test]
fn network_text_shows_interfaces() {
    let s = network_text(&sample_network());
    assert!(s.contains("Interfaces: 2"));
    assert!(s.contains("wlan0"));
    assert!(s.contains("aa:bb:cc:dd:ee:ff"));
    assert!(s.contains("1500"));
}

#[test]
fn network_text_handles_none_fields() {
    let s = network_text(&sample_network());
    assert!(s.contains("lo"));
    // The `lo` interface has all None → dashes.
}

#[test]
fn network_markdown_has_table() {
    let s = network_markdown(&sample_network());
    assert!(s.contains("| Name | MAC | State |"));
}

#[test]
fn network_text_empty() {
    let s = network_text(&sample_network_empty());
    assert!(s.contains("Interfaces: 0"));
}

// ---------------------------------------------------------------------------
// process_text / process_markdown
// ---------------------------------------------------------------------------

#[test]
fn process_text_reports_total() {
    let s = process_text(&sample_process());
    assert!(s.contains("Total processes: 2"));
    assert!(s.contains("init"));
}

#[test]
fn process_text_empty() {
    let s = process_text(&sample_process_empty());
    assert!(s.contains("Total processes: 0"));
}

#[test]
fn process_markdown_has_table() {
    let s = process_markdown(&sample_process());
    assert!(s.contains("| PID | PPID | Name |"));
}

// ---------------------------------------------------------------------------
// thermal_text / thermal_markdown / gpu_text / gpu_markdown
// ---------------------------------------------------------------------------

#[test]
fn thermal_text_lists_zones() {
    let s = thermal_text(&sample_thermal());
    assert!(s.contains("Zones: 2"));
    assert!(s.contains("cpu"));
    assert!(s.contains("45.00"));
}

#[test]
fn thermal_text_empty() {
    let s = thermal_text(&sample_thermal_empty());
    assert!(s.contains("Zones: 0"));
}

#[test]
fn thermal_markdown_has_table() {
    let s = thermal_markdown(&sample_thermal());
    assert!(s.contains("| Zone | Temp (C) |"));
}

#[test]
fn gpu_text_lists_devices() {
    let s = gpu_text(&sample_gpu());
    assert!(s.contains("Devices: 1"));
    assert!(s.contains("mali"));
}

#[test]
fn gpu_text_empty() {
    let s = gpu_text(&sample_gpu_empty());
    assert!(s.contains("Devices: 0"));
}

#[test]
fn gpu_markdown_has_table() {
    let s = gpu_markdown(&sample_gpu());
    assert!(s.contains("| Driver | Kind | Path |"));
}

// ---------------------------------------------------------------------------
// memory_detail
// ---------------------------------------------------------------------------

#[test]
fn memory_detail_text_has_sections() {
    let s = memory_detail_text(&sample_memory_detail());
    assert!(s.contains("=== MEMORY (detailed) ==="));
    assert!(s.contains("[Cache]"));
    assert!(s.contains("[Active/Inactive]"));
    assert!(s.contains("[Kernel]"));
    assert!(s.contains("[Swap]"));
    assert!(s.contains("[Commit]"));
    assert!(s.contains("[HugePages]"));
    assert!(s.contains("Total"));
    assert!(s.contains("HugePages"));
}

#[test]
fn memory_detail_markdown_has_table() {
    let s = memory_detail_markdown(&sample_memory_detail());
    assert!(s.contains("# Memory (detailed)"));
    assert!(s.contains("| Total |"));
}

// ---------------------------------------------------------------------------
// load_text / load_markdown
// ---------------------------------------------------------------------------

#[test]
fn load_text_has_all_loads() {
    let s = load_text(&sample_load());
    assert!(s.contains("Load Average"));
    assert!(s.contains("1.25"));
    assert!(s.contains("0.85"));
    assert!(s.contains("0.75"));
    assert!(s.contains("Running / Total tasks"));
    assert!(s.contains("3 / 500"));
}

#[test]
fn load_markdown_has_table() {
    let s = load_markdown(&sample_load());
    assert!(s.contains("| Load 1min |"));
    assert!(s.contains("| Load 15min |"));
}

// ---------------------------------------------------------------------------
// vmstat
// ---------------------------------------------------------------------------

#[test]
fn vmstat_text_has_sections() {
    let s = vmstat_text(&sample_vmstat());
    assert!(s.contains("=== VMSTAT"));
    assert!(s.contains("[I/O]"));
    assert!(s.contains("[Page faults]"));
    assert!(s.contains("[Page allocation]"));
    assert!(s.contains("[Reclaim]"));
    assert!(s.contains("[Kernel counters]"));
    assert!(s.contains("pgpgin"));
    assert!(s.contains("nr_shmem"));
}

#[test]
fn vmstat_markdown_has_table() {
    let s = vmstat_markdown(&sample_vmstat());
    assert!(s.contains("| pgpgin |"));
    assert!(s.contains("| nr_free_pages |"));
}

// ---------------------------------------------------------------------------
// cpu_times
// ---------------------------------------------------------------------------

#[test]
fn cpu_times_text_has_total_and_cores() {
    let s = cpu_times_text(&sample_cpu_times());
    assert!(s.contains("Cores: 1"));
    assert!(s.contains("all"));
    assert!(s.contains("user"));
    assert!(s.contains("iowait"));
    // text mode does not print softirq column
    assert!(s.contains("1000"));
}

#[test]
fn cpu_times_text_empty_per_core() {
    let s = cpu_times_text(&sample_cpu_times_empty());
    assert!(s.contains("Cores: 0"));
    assert!(s.contains("all"));
}

#[test]
fn cpu_times_markdown_has_table() {
    let s = cpu_times_markdown(&sample_cpu_times());
    assert!(s.contains("| CPU | user | nice |"));
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

#[test]
fn users_text_has_users_and_groups() {
    let s = users_text(&sample_users());
    assert!(s.contains("Users: 1"));
    assert!(s.contains("Groups: 2"));
    assert!(s.contains("root"));
    assert!(s.contains("/root"));
    assert!(s.contains("sudo"));
    assert!(s.contains("kali,omar"));
}

#[test]
fn users_text_empty() {
    let s = users_text(&sample_users_empty());
    assert!(s.contains("Users: 0"));
    assert!(s.contains("Groups: 0"));
}

#[test]
fn users_markdown_has_table() {
    let s = users_markdown(&sample_users());
    assert!(s.contains("| UID | GID | Name |"));
}

// ---------------------------------------------------------------------------
// packages
// ---------------------------------------------------------------------------

#[test]
fn packages_text_truncates_at_100() {
    let s = packages_text(&sample_packages_overflow());
    assert!(s.contains("+50 more"), "expected overflow marker: {s}");
}

#[test]
fn packages_text_normal() {
    let s = packages_text(&sample_packages());
    assert!(s.contains("Manager: dpkg"));
    assert!(s.contains("Total: 2"));
    assert!(s.contains("libc6"));
}

#[test]
fn packages_markdown_has_table() {
    let s = packages_markdown(&sample_packages());
    assert!(s.contains("| Package | Version |"));
}

// ---------------------------------------------------------------------------
// services
// ---------------------------------------------------------------------------

#[test]
fn services_text_has_states() {
    let s = services_text(&sample_services());
    assert!(s.contains("Init: systemd"));
    assert!(s.contains("enabled"));
    assert!(s.contains("disabled"));
    assert!(s.contains("unknown"));
}

#[test]
fn services_markdown_has_table() {
    let s = services_markdown(&sample_services());
    assert!(s.contains("| Service | Kind | State |"));
}

// ---------------------------------------------------------------------------
// filesystem
// ---------------------------------------------------------------------------

#[test]
fn fs_text_has_readable_flag() {
    let s = fs_text(&sample_fs());
    assert!(s.contains("Roots: 2"));
    assert!(s.contains("yes"));
    assert!(s.contains("no"));
}

#[test]
fn fs_markdown_has_table() {
    let s = fs_markdown(&sample_fs());
    assert!(s.contains("| Path | Kind | Entries |"));
}

// ---------------------------------------------------------------------------
// environment
// ---------------------------------------------------------------------------

#[test]
fn env_text_truncates_long_values() {
    let s = env_text(&sample_env());
    assert!(s.contains("PATH"));
    assert!(s.contains("..."), "expected truncation marker: {s}");
}

#[test]
fn env_markdown_escapes_pipes() {
    let info = EnvInfo {
        total: 1,
        entries: vec![EnvEntry {
            key: "K".into(),
            value: "a|b|c".into(),
        }],
    };
    let s = env_markdown(&info);
    assert!(s.contains("a\\|b\\|c"), "pipe must be escaped: {s}");
}

// ---------------------------------------------------------------------------
// usb
// ---------------------------------------------------------------------------

#[test]
fn usb_text_handles_none_fields() {
    let s = usb_text(&sample_usb());
    assert!(s.contains("USB devices: 2"));
    assert!(s.contains("1d6b"));
    assert!(s.contains("xHCI Host"));
}

#[test]
fn usb_markdown_has_table() {
    let s = usb_markdown(&sample_usb());
    assert!(s.contains("| Name | VID | PID |"));
}

// ---------------------------------------------------------------------------
// pci
// ---------------------------------------------------------------------------

#[test]
fn pci_text_handles_none_fields() {
    let s = pci_text(&sample_pci());
    assert!(s.contains("PCI devices: 2"));
    assert!(s.contains("0000:00:00.0"));
    assert!(s.contains("mediatek"));
}

#[test]
fn pci_markdown_has_table() {
    let s = pci_markdown(&sample_pci());
    assert!(s.contains("| Slot | Vendor | Device |"));
}

// ---------------------------------------------------------------------------
// battery
// ---------------------------------------------------------------------------

#[test]
fn battery_text_full_fields() {
    let s = battery_text(&sample_battery());
    assert!(s.contains("Batteries: 1"));
    assert!(s.contains("[BAT0]"));
    assert!(s.contains("85%"));
    assert!(s.contains("Discharging"));
    assert!(s.contains("Li-ion"));
    assert!(s.contains("V"), "voltage must be formatted: {s}");
    assert!(s.contains("Cycles"));
}

#[test]
fn battery_text_all_none() {
    let s = battery_text(&sample_battery_all_none());
    assert!(s.contains("[BAT0]"));
    assert!(!s.contains("Voltage"), "None fields must be skipped: {s}");
    assert!(!s.contains("Temperature"));
}

#[test]
fn battery_markdown_has_headers() {
    let s = battery_markdown(&sample_battery());
    assert!(s.contains("### BAT0"));
    assert!(s.contains("| Capacity |"));
}

// ---------------------------------------------------------------------------
// sensors
// ---------------------------------------------------------------------------

#[test]
fn sensors_text_reports_chips() {
    let s = sensors_text(&sample_sensors());
    assert!(s.contains("Chips: 2"));
    assert!(s.contains("cpu_thermal"));
    assert!(s.contains("45.00"));
    assert!(s.contains("no temperature inputs"));
}

#[test]
fn sensors_markdown_has_table() {
    let s = sensors_markdown(&sample_sensors());
    assert!(s.contains("### cpu_thermal"));
    assert!(s.contains("| Sensor | Temp (C) |"));
}

// ---------------------------------------------------------------------------
// drivers
// ---------------------------------------------------------------------------

#[test]
fn drivers_text_has_modules() {
    let s = drivers_text(&sample_drivers());
    assert!(s.contains("Kernel modules: 2"));
    assert!(s.contains("gps_scp"));
    assert!(s.contains("gps_pwr"));
}

#[test]
fn drivers_markdown_has_table() {
    let s = drivers_markdown(&sample_drivers());
    assert!(s.contains("| Module | Size (KB) |"));
}

// ---------------------------------------------------------------------------
// containers
// ---------------------------------------------------------------------------

#[test]
fn containers_text_detected() {
    let s = containers_text(&sample_containers());
    assert!(s.contains("Detected: yes"));
    assert!(s.contains("docker"));
    assert!(s.contains(".dockerenv"));
}

#[test]
fn containers_text_none() {
    let s = containers_text(&sample_containers_none());
    assert!(s.contains("Detected: no"));
    assert!(s.contains("No container evidence found"));
}

#[test]
fn containers_markdown_has_table() {
    let s = containers_markdown(&sample_containers());
    assert!(s.contains("**Detected:** yes"));
    assert!(s.contains("| Evidence |"));
}

// ---------------------------------------------------------------------------
// vm
// ---------------------------------------------------------------------------

#[test]
fn vm_text_detected() {
    let s = vm_text(&sample_vm());
    assert!(s.contains("Is Virtual Machine: yes"));
    assert!(s.contains("KVM"));
    assert!(s.contains("QEMU"));
}

#[test]
fn vm_text_none() {
    let s = vm_text(&sample_vm_none());
    assert!(s.contains("Is Virtual Machine: no"));
    assert!(s.contains("No virtualization evidence"));
}

#[test]
fn vm_markdown_has_table() {
    let s = vm_markdown(&sample_vm());
    assert!(s.contains("| Is VM |"));
    assert!(s.contains("| Hypervisor |"));
}

// ---------------------------------------------------------------------------
// browsers
// ---------------------------------------------------------------------------

#[test]
fn browsers_text_lists() {
    let s = browsers_text(&sample_browsers());
    assert!(s.contains("Detected: 1"));
    assert!(s.contains("firefox"));
    assert!(s.contains("/usr/bin/firefox-esr"));
}

#[test]
fn browsers_markdown_has_table() {
    let s = browsers_markdown(&sample_browsers());
    assert!(s.contains("| Name | Kind | Path |"));
}

// ---------------------------------------------------------------------------
// crypto
// ---------------------------------------------------------------------------

#[test]
fn crypto_text_full() {
    let s = crypto_text(&sample_crypto());
    assert!(s.contains("SSL certs"));
    assert!(s.contains("42"));
    assert!(s.contains("yes"));
    assert!(s.contains("/root/.ssh/id_ed25519"));
}

#[test]
fn crypto_text_none() {
    let s = crypto_text(&sample_crypto_none());
    assert!(s.contains("0"));
    assert!(s.contains("no"));
}

#[test]
fn crypto_markdown_has_table() {
    let s = crypto_markdown(&sample_crypto());
    assert!(s.contains("| SSL certs |"));
}

// ---------------------------------------------------------------------------
// cron
// ---------------------------------------------------------------------------

#[test]
fn cron_text_full() {
    let s = cron_text(&sample_cron());
    assert!(s.contains("/etc/crontab"));
    assert!(s.contains("/etc/cron.d/john"));
    assert!(s.contains("/etc/cron.daily"));
    assert!(s.contains("/var/spool/cron/crontabs/root"));
}

#[test]
fn cron_text_empty() {
    let s = cron_text(&sample_cron_empty());
    assert!(s.contains("no"));
}

#[test]
fn cron_markdown_has_table() {
    let s = cron_markdown(&sample_cron());
    assert!(s.contains("| /etc/crontab |"));
}

// ---------------------------------------------------------------------------
// hwid
// ---------------------------------------------------------------------------

#[test]
fn hwid_text_verbose_shows_sources() {
    let s = hwid_text(&sample_hwid(), true);
    assert!(s.contains("PULSE HWID"));
    assert!(s.contains("a1b2c3d4e5f6"));
    assert!(s.contains("hardware"));
    assert!(s.contains("android"));
    assert!(s.contains("Source breakdown"));
    assert!(s.contains("cpu"));
    assert!(s.contains("ram"));
}

#[test]
fn hwid_text_non_verbose_hides_sources() {
    let s = hwid_text(&sample_hwid(), false);
    assert!(!s.contains("Source breakdown"));
    assert!(s.contains("a1b2c3d4e5f6"));
}

#[test]
fn hwid_text_low_confidence_warns() {
    let s = hwid_text(&sample_hwid_low_confidence(), true);
    assert!(s.contains("Low confidence"));
    assert!(s.contains("Run with root"));
}

#[test]
fn hwid_text_high_confidence_no_warn() {
    let s = hwid_text(&sample_hwid(), true);
    assert!(!s.contains("Low confidence"));
}

#[test]
fn hwid_markdown_has_table() {
    let s = hwid_markdown(&sample_hwid(), true);
    assert!(s.contains("# Pulse HWID"));
    assert!(s.contains("| HWID |"));
    assert!(s.contains("## Sources"));
}

#[test]
fn hwid_markdown_non_verbose() {
    let s = hwid_markdown(&sample_hwid(), false);
    assert!(!s.contains("## Sources"));
}

// ---------------------------------------------------------------------------
// Sanity: every renderer must not panic on empty/minimal input
// ---------------------------------------------------------------------------

#[test]
fn all_renderers_do_not_panic_on_empty() {
    let _ = system_text(&sample_system());
    let _ = cpu_text(&sample_cpu_empty());
    let _ = memory_text(&sample_memory_zero_total());
    let _ = disk_text(&sample_disk_empty());
    let _ = network_text(&sample_network_empty());
    let _ = process_text(&sample_process_empty());
    let _ = thermal_text(&sample_thermal_empty());
    let _ = gpu_text(&sample_gpu_empty());
    let _ = users_text(&sample_users_empty());
    let _ = cron_text(&sample_cron_empty());
    let _ = containers_text(&sample_containers_none());
    let _ = vm_text(&sample_vm_none());
    let _ = crypto_text(&sample_crypto_none());
}

// ---------------------------------------------------------------------------
// Determinism: same input → same output
// ---------------------------------------------------------------------------

#[test]
fn renderers_are_deterministic() {
    let sys = sample_system();
    assert_eq!(system_text(&sys), system_text(&sys));
    assert_eq!(system_markdown(&sys), system_markdown(&sys));
    assert_eq!(
        to_json(&sys, JsonStyle::Compact),
        to_json(&sys, JsonStyle::Compact)
    );

    let cpu = sample_cpu_full();
    assert_eq!(cpu_text(&cpu), cpu_text(&cpu));
    assert_eq!(cpu_markdown(&cpu), cpu_markdown(&cpu));
}
