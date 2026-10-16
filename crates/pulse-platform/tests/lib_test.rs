//! Integration tests for the public surface of `pulse-platform`'s lib root.
//!
//! Focus on functions that are NOT thin wrappers around `linux::*`:
//! environment constants, runtime mode detection, and the root-requirement
//! helper. Wrappers are exercised via `linux_test.rs`.

use pulse_platform::{
    arch, battery_info, boot_time_unix, browsers_info, command_needs_root, containers_info,
    cpu_info, cpu_times, cron_info, crypto_info, disk_info, drivers_info, endianness, env_info,
    family, filesystem_info, gpu_info, host_os, hwid_info, is_root, load_avg, memory_detail,
    memory_info, network_info, os, packages_info, pci_info, pointer_width, process_info,
    runtime_mode, sensors_info, services_info, system_info, thermal_info, usb_info, users_info,
    vm_info, vmstat, RuntimeMode,
};

// ---------------------------------------------------------------------------
// Environment constants (always available, no OS calls)
// ---------------------------------------------------------------------------

#[test]
fn arch_matches_env_consts() {
    assert_eq!(arch(), std::env::consts::ARCH);
}

#[test]
fn arch_is_non_empty() {
    assert!(!arch().is_empty());
}

#[test]
fn os_matches_env_consts() {
    // On Linux without Android markers, os() should equal consts::OS.
    // On an Android runtime (e.g. a static musl binary running on
    // Termux), os() correctly returns "android" while consts::OS is
    // the compile-time value ("linux"). This test only asserts the
    // equality in the non-Android case.
    if !std::path::Path::new("/system/build.prop").exists() {
        assert_eq!(os(), std::env::consts::OS);
    }
}

#[test]
fn os_is_non_empty() {
    assert!(!os().is_empty());
}

#[test]
fn family_matches_env_consts() {
    assert_eq!(family(), std::env::consts::FAMILY);
}

#[test]
fn family_is_non_empty() {
    assert!(!family().is_empty());
}

#[test]
fn pointer_width_is_32_or_64() {
    let w = pointer_width();
    assert!(w == 32 || w == 64, "unexpected pointer width: {w}");
}

#[test]
fn pointer_width_matches_size_of_usize() {
    let expected = (std::mem::size_of::<usize>() * 8) as u8;
    assert_eq!(pointer_width(), expected);
}

#[test]
fn endianness_is_known() {
    let e = endianness();
    assert!(e == "little" || e == "big", "unexpected endianness: {e}");
}

#[test]
fn endianness_matches_target_endian() {
    if cfg!(target_endian = "little") {
        assert_eq!(endianness(), "little");
    } else {
        assert_eq!(endianness(), "big");
    }
}

// ---------------------------------------------------------------------------
// host_os
// ---------------------------------------------------------------------------

#[test]
fn host_os_is_known() {
    let h = host_os();
    assert!(
        matches!(
            h,
            "linux" | "android" | "windows" | "macos" | "freebsd" | "unknown"
        ),
        "unexpected host_os: {h}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn host_os_is_linux_on_linux() {
    assert_eq!(host_os(), "linux");
}

// ---------------------------------------------------------------------------
// runtime_mode / is_root
// ---------------------------------------------------------------------------

#[test]
fn runtime_mode_is_a_known_variant() {
    let m = runtime_mode();
    assert!(matches!(
        m,
        RuntimeMode::Root | RuntimeMode::User | RuntimeMode::Unknown
    ));
}

#[test]
fn is_root_agrees_with_runtime_mode() {
    let expected = matches!(runtime_mode(), RuntimeMode::Root);
    assert_eq!(is_root(), expected);
}

#[test]
#[cfg(unix)]
fn runtime_mode_matches_geteuid() {
    let euid = unsafe { libc::geteuid() };
    let expected = if euid == 0 {
        RuntimeMode::Root
    } else {
        RuntimeMode::User
    };
    assert_eq!(runtime_mode(), expected);
}

#[test]
fn runtime_mode_is_copy_and_eq() {
    let a = runtime_mode();
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn runtime_mode_debug_is_non_empty() {
    assert!(!format!("{:?}", runtime_mode()).is_empty());
}

// ---------------------------------------------------------------------------
// command_needs_root
// ---------------------------------------------------------------------------

#[test]
fn command_needs_root_thermal() {
    assert!(command_needs_root("thermal"));
}

#[test]
fn command_needs_root_battery() {
    assert!(command_needs_root("battery"));
}

#[test]
fn command_needs_root_sensors() {
    assert!(command_needs_root("sensors"));
}

#[test]
fn command_needs_root_drivers() {
    assert!(command_needs_root("drivers"));
}

#[test]
fn command_needs_root_network() {
    assert!(command_needs_root("network"));
}

#[test]
fn command_needs_root_system() {
    assert!(command_needs_root("system"));
}

#[test]
fn command_needs_root_cpu_is_false() {
    assert!(!command_needs_root("cpu"));
}

#[test]
fn command_needs_root_memory_is_false() {
    assert!(!command_needs_root("memory"));
}

#[test]
fn command_needs_root_platform_is_false() {
    assert!(!command_needs_root("platform"));
}

#[test]
fn command_needs_root_help_is_false() {
    assert!(!command_needs_root("help"));
}

#[test]
fn command_needs_root_empty_is_false() {
    assert!(!command_needs_root(""));
}

#[test]
fn command_needs_root_unknown_is_false() {
    assert!(!command_needs_root("this-is-not-a-command"));
}

#[test]
fn command_needs_root_is_case_sensitive() {
    assert!(!command_needs_root("Thermal"));
    assert!(!command_needs_root("THERMAL"));
}

// ---------------------------------------------------------------------------
// Wrapper functions — basic smoke (linux_test covers details)
// ---------------------------------------------------------------------------

#[test]
fn system_info_wrapper_succeeds() {
    let info = system_info().expect("system_info must succeed");
    assert!(!info.hostname.is_empty());
}

#[test]
fn cpu_info_wrapper_succeeds() {
    let info = cpu_info().expect("cpu_info must succeed");
    assert!(info.cores > 0);
}

#[test]
fn memory_info_wrapper_succeeds() {
    let info = memory_info().expect("memory_info must succeed");
    assert!(info.total_kb > 0);
}

#[test]
fn boot_time_unix_wrapper_succeeds() {
    let bt = boot_time_unix().expect("boot_time_unix must succeed");
    assert!(bt > 946_684_800);
}

#[test]
fn disk_info_wrapper_succeeds() {
    let _ = disk_info().expect("disk_info must succeed");
}

#[test]
fn network_info_wrapper_succeeds() {
    let info = network_info().expect("network_info must succeed");
    assert!(!info.interfaces.is_empty());
}

#[test]
fn process_info_wrapper_succeeds() {
    let info = process_info().expect("process_info must succeed");
    assert!(info.total > 0);
}

#[test]
fn thermal_info_wrapper_succeeds() {
    let _ = thermal_info().expect("thermal_info must succeed");
}

#[test]
fn gpu_info_wrapper_succeeds() {
    let _ = gpu_info().expect("gpu_info must succeed");
}

#[test]
fn memory_detail_wrapper_succeeds() {
    let _ = memory_detail().expect("memory_detail must succeed");
}

#[test]
fn load_avg_wrapper_succeeds() {
    let info = load_avg().expect("load_avg must succeed");
    assert!(info.total_tasks > 0);
}

#[test]
fn vmstat_wrapper_succeeds() {
    let _ = vmstat().expect("vmstat must succeed");
}

#[test]
fn cpu_times_wrapper_succeeds() {
    let info = cpu_times().expect("cpu_times must succeed");
    assert_eq!(info.total.id, -1);
}

#[test]
fn users_info_wrapper_succeeds() {
    let info = users_info().expect("users_info must succeed");
    assert!(!info.users.is_empty());
}

#[test]
fn packages_info_wrapper_does_not_panic() {
    let _ = packages_info();
}

#[test]
fn services_info_wrapper_succeeds() {
    let _ = services_info().expect("services_info must succeed");
}

#[test]
fn filesystem_info_wrapper_succeeds() {
    let _ = filesystem_info().expect("filesystem_info must succeed");
}

#[test]
fn env_info_wrapper_succeeds() {
    let info = env_info().expect("env_info must succeed");
    assert!(info.total > 0);
}

#[test]
fn usb_info_wrapper_succeeds() {
    let _ = usb_info().expect("usb_info must succeed");
}

#[test]
fn pci_info_wrapper_succeeds() {
    let _ = pci_info().expect("pci_info must succeed");
}

#[test]
fn battery_info_wrapper_succeeds() {
    let _ = battery_info().expect("battery_info must succeed");
}

#[test]
fn sensors_info_wrapper_succeeds() {
    let _ = sensors_info().expect("sensors_info must succeed");
}

#[test]
fn drivers_info_wrapper_succeeds() {
    let _ = drivers_info().expect("drivers_info must succeed");
}

#[test]
fn containers_info_wrapper_succeeds() {
    let _ = containers_info().expect("containers_info must succeed");
}

#[test]
fn vm_info_wrapper_succeeds() {
    let _ = vm_info().expect("vm_info must succeed");
}

#[test]
fn browsers_info_wrapper_succeeds() {
    let _ = browsers_info().expect("browsers_info must succeed");
}

#[test]
fn crypto_info_wrapper_succeeds() {
    let _ = crypto_info().expect("crypto_info must succeed");
}

#[test]
fn cron_info_wrapper_succeeds() {
    let _ = cron_info().expect("cron_info must succeed");
}

// ---------------------------------------------------------------------------
// hwid_info wrapper
// ---------------------------------------------------------------------------

#[test]
fn hwid_info_without_context_succeeds() {
    let info = hwid_info(None).expect("hwid_info must succeed");
    assert!(!info.hash.is_empty());
    assert!(!info.mode.is_empty());
    assert!(info.confidence >= 0.0 && info.confidence <= 1.0);
}

#[test]
fn hwid_info_with_context_succeeds() {
    let info = hwid_info(Some("pulse-test")).expect("hwid_info must succeed");
    assert_eq!(info.context.as_deref(), Some("pulse-test"));
}

#[test]
fn hwid_info_is_deterministic_without_context() {
    let a = hwid_info(None).expect("first call");
    let b = hwid_info(None).expect("second call");
    assert_eq!(a.hash, b.hash);
}

#[test]
fn hwid_info_changes_with_different_context() {
    let a = hwid_info(Some("ctx-a")).expect("ctx-a");
    let b = hwid_info(Some("ctx-b")).expect("ctx-b");
    assert_ne!(a.hash, b.hash);
}

// ---------------------------------------------------------------------------
// Type re-exports (compile-time check)
// ---------------------------------------------------------------------------

#[test]
fn public_types_are_reexported() {
    use pulse_platform::{
        BatteryEntry, BatteryInfo, CoreInfo, CpuInfo, DiskInfo, MemoryInfo, NetworkInfo,
        ProcessInfo, SystemInfo, ThermalInfo, UsersInfo,
    };
    // This test passes if the file compiles.
    let _ = std::mem::size_of::<SystemInfo>();
    let _ = std::mem::size_of::<CpuInfo>();
    let _ = std::mem::size_of::<CoreInfo>();
    let _ = std::mem::size_of::<MemoryInfo>();
    let _ = std::mem::size_of::<DiskInfo>();
    let _ = std::mem::size_of::<NetworkInfo>();
    let _ = std::mem::size_of::<ProcessInfo>();
    let _ = std::mem::size_of::<ThermalInfo>();
    let _ = std::mem::size_of::<UsersInfo>();
    let _ = std::mem::size_of::<BatteryInfo>();
    let _ = std::mem::size_of::<BatteryEntry>();
}

#[test]
fn public_error_type_reexported() {
    use pulse_platform::{PlatformError, Result};
    let r: Result<u32> = Err(PlatformError::unsupported("test"));
    assert!(r.is_err());
}
