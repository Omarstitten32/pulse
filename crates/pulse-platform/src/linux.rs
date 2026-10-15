//! Linux / Android introspection via /proc and /sys.

use crate::error::{PlatformError, Result};
use crate::types::{CoreInfo, CpuInfo, MemoryInfo, SystemInfo};
use std::fs;

fn read_file(path: &str) -> Result<String> {
    fs::read_to_string(path).map_err(|e| PlatformError::io(path, e))
}

// -----------------------------------------------------------
// System info
// -----------------------------------------------------------

pub fn system_info() -> Result<SystemInfo> {
    let kernel_version = read_file("/proc/version")?
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    let hostname = read_file("/proc/sys/kernel/hostname")?.trim().to_string();

    let os_name = read_os_name();

    Ok(SystemInfo {
        os_name,
        os_version: read_os_version(),
        kernel_version,
        hostname,
        uptime_seconds: read_uptime()?,
        boot_time_unix: read_boot_time()?,
        architecture: std::env::consts::ARCH.to_string(),
        pointer_width: (std::mem::size_of::<usize>() * 8) as u8,
        endianness: if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        }
        .to_string(),
    })
}

pub(crate) fn parse_os_release(content: &str) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut version = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            name = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version = Some(v.trim_matches('"').to_string());
        }
    }
    (name, version)
}

fn read_os_name() -> String {
    if cfg!(target_os = "android") {
        return "Android".to_string();
    }
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        if let Some(n) = parse_os_release(&content).0 {
            return n;
        }
    }
    "Linux".to_string()
}

fn read_os_version() -> String {
    if cfg!(target_os = "android") {
        if let Ok(content) = fs::read_to_string("/system/build.prop") {
            for line in content.lines() {
                if let Some(v) = line.strip_prefix("ro.build.version.release=") {
                    return v.trim().to_string();
                }
            }
        }
    }
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        if let Some(v) = parse_os_release(&content).1 {
            return v;
        }
    }
    String::new()
}

fn read_uptime() -> Result<u64> {
    // Try /proc/uptime first
    if let Ok(s) = read_file("/proc/uptime") {
        if let Some(first) = s.split_whitespace().next() {
            if let Ok(secs) = first.parse::<f64>() {
                if secs > 0.0 {
                    return Ok(secs as u64);
                }
            }
        }
    }

    // Fallback: syscall clock_gettime(CLOCK_BOOTTIME)
    // Works without root — does not touch /proc
    #[cfg(unix)]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
        if rc == 0 && ts.tv_sec > 0 {
            return Ok(ts.tv_sec as u64);
        }
    }

    Err(PlatformError::parse(
        "uptime",
        "neither /proc/uptime nor CLOCK_BOOTTIME available",
    ))
}

pub(crate) fn parse_btime(content: &str) -> Option<u64> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            if let Ok(v) = rest.trim().parse::<u64>() {
                if v > 0 {
                    return Some(v);
                }
            }
        }
    }
    None
}

pub fn read_boot_time() -> Result<u64> {
    if let Ok(s) = read_file("/proc/stat") {
        if let Some(v) = parse_btime(&s) {
            return Ok(v);
        }
    }

    // Fallback: derive from uptime + current time
    let uptime = read_uptime().unwrap_or(0);
    if uptime == 0 {
        return Err(PlatformError::parse(
            "/proc/stat (btime)",
            "btime unavailable and uptime is 0",
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if now == 0 {
        return Err(PlatformError::parse(
            "/proc/stat (btime)",
            "system time unavailable",
        ));
    }

    Ok(now.saturating_sub(uptime))
}

// -----------------------------------------------------------
// CPU info
// -----------------------------------------------------------

pub fn cpu_info() -> Result<CpuInfo> {
    let raw = read_file("/proc/cpuinfo")?;

    let mut cores_set = std::collections::BTreeSet::new();
    let mut features: Vec<String> = Vec::new();
    let mut hardware = String::new();
    let mut model_name = String::new();

    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        match k {
            "processor" => {
                if let Ok(id) = v.parse::<u32>() {
                    cores_set.insert(id);
                }
            }
            "Features" => {
                if features.is_empty() {
                    features = v.split_whitespace().map(str::to_string).collect();
                }
            }
            "Hardware" => hardware = v.to_string(),
            "model name" => model_name = v.to_string(),
            _ => {}
        }
    }

    let model = if !hardware.is_empty() {
        hardware
    } else if !model_name.is_empty() {
        model_name
    } else {
        detect_android_soc_model().unwrap_or_else(|| "Unknown CPU".to_string())
    };

    let cores: Vec<u32> = cores_set.into_iter().collect();
    let core_count = cores.len() as u32;

    let mut per_core = Vec::with_capacity(core_count as usize);
    for id in cores {
        per_core.push(read_core_info(id));
    }

    Ok(CpuInfo {
        model,
        architecture: std::env::consts::ARCH.to_string(),
        cores: core_count,
        features,
        per_core,
    })
}

fn detect_android_soc_model() -> Option<String> {
    // Android/Linux SoC detection fallbacks (in priority order)
    const CANDIDATES: &[&str] = &[
        "/sys/devices/soc0/machine",
        "/sys/devices/soc0/soc_id",
        "/proc/device-tree/model",
        "/sys/firmware/devicetree/base/model",
    ];
    for path in CANDIDATES {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim_matches('\0').trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

fn read_core_info(id: u32) -> CoreInfo {
    let base = format!("/sys/devices/system/cpu/cpu{id}/cpufreq");
    CoreInfo {
        id,
        cur_freq_khz: read_u64(&format!("{base}/scaling_cur_freq")),
        min_freq_khz: read_u64(&format!("{base}/cpuinfo_min_freq")),
        max_freq_khz: read_u64(&format!("{base}/cpuinfo_max_freq")),
        governor: read_trim(&format!("{base}/scaling_governor")),
    }
}

fn read_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

fn read_trim(path: &str) -> Option<String> {
    Some(fs::read_to_string(path).ok()?.trim().to_string())
}

// -----------------------------------------------------------
// Memory info
// -----------------------------------------------------------

pub fn memory_info() -> Result<MemoryInfo> {
    let raw = read_file("/proc/meminfo")?;

    let mut total = 0u64;
    let mut free = 0u64;
    let mut available = 0u64;
    let mut buffers = 0u64;
    let mut cached = 0u64;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;

    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let val = v
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        match k {
            "MemTotal" => total = val,
            "MemFree" => free = val,
            "MemAvailable" => available = val,
            "Buffers" => buffers = val,
            "Cached" => cached = val,
            "SwapTotal" => swap_total = val,
            "SwapFree" => swap_free = val,
            _ => {}
        }
    }

    Ok(MemoryInfo {
        total_kb: total,
        free_kb: free,
        available_kb: available,
        buffers_kb: buffers,
        cached_kb: cached,
        swap_total_kb: swap_total,
        swap_free_kb: swap_free,
    })
}

// -----------------------------------------------------------
// Disk info (/proc/mounts + statvfs)
// -----------------------------------------------------------

use crate::types::{DiskInfo, MountInfo, NetInterface, NetworkInfo, ProcessEntry, ProcessInfo};

fn statvfs_size(path: &str) -> Option<(u64, u64, u64)> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;
        let c_path = CString::new(path).ok()?;
        let mut buf = MaybeUninit::<libc::statvfs>::uninit();
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), buf.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        let s = unsafe { buf.assume_init() };
        let bsize = s.f_frsize;
        let total = s.f_blocks.saturating_mul(bsize);
        let free = s.f_bfree.saturating_mul(bsize);
        let avail = s.f_bavail.saturating_mul(bsize);
        let used = total.saturating_sub(free);
        Some((total, used, avail))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

pub fn disk_info() -> Result<DiskInfo> {
    let raw = read_file("/proc/mounts")?;
    let mut mounts = Vec::new();
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let device = parts[0].to_string();
        let mount_point = parts[1].to_string();
        let fs_type = parts[2].to_string();
        let options = parts[3].to_string();

        // Skip virtual/psuedo filesystems that don't have meaningful size
        const SKIP_FS: &[&str] = &[
            "proc",
            "sysfs",
            "devpts",
            "tmpfs",
            "cgroup",
            "cgroup2",
            "pstore",
            "bpf",
            "tracefs",
            "debugfs",
            "securityfs",
            "configfs",
            "fusectl",
            "mqueue",
            "hugetlbfs",
            "binfmt_misc",
            "autofs",
            "efivarfs",
        ];
        if SKIP_FS.contains(&fs_type.as_str()) {
            continue;
        }

        let (total, used, avail, pct) = match statvfs_size(&mount_point) {
            Some((t, u, a)) if t > 0 => {
                let p = 100.0 * (u as f64) / (t as f64);
                (Some(t), Some(u), Some(a), Some(p))
            }
            _ => (None, None, None, None),
        };

        mounts.push(MountInfo {
            device,
            mount_point,
            fs_type,
            options,
            total_bytes: total,
            used_bytes: used,
            available_bytes: avail,
            use_percent: pct,
        });
    }
    Ok(DiskInfo { mounts })
}

// -----------------------------------------------------------
// Network info (/sys/class/net/*)
// -----------------------------------------------------------

fn read_opt(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn classify_iface(path: &str) -> Option<String> {
    let raw = read_opt(&format!("{path}/type"))?;
    let n: u32 = raw.parse().ok()?;
    let name = match n {
        1 => "ethernet",
        772 => "loopback",
        803 => "wifi",
        65534 => "tunnel",
        _ => "other",
    };
    Some(name.to_string())
}

pub fn network_info() -> Result<NetworkInfo> {
    let mut interfaces = Vec::new();
    let entries =
        std::fs::read_dir("/sys/class/net").map_err(|e| PlatformError::io("/sys/class/net", e))?;
    let mut names: Vec<String> = Vec::new();
    for e in entries.flatten() {
        if let Some(n) = e.file_name().to_str() {
            names.push(n.to_string());
        }
    }
    names.sort();

    for name in names {
        let base = format!("/sys/class/net/{name}");
        let mac = read_opt(&format!("{base}/address"));
        let state = read_opt(&format!("{base}/operstate"));
        let mtu = read_opt(&format!("{base}/mtu")).and_then(|s| s.parse::<u64>().ok());
        let kind = classify_iface(&base);
        interfaces.push(NetInterface {
            name,
            mac,
            state,
            mtu,
            kind,
        });
    }
    Ok(NetworkInfo { interfaces })
}

// -----------------------------------------------------------
// Process info (/proc/[pid]/stat)
// -----------------------------------------------------------

fn read_process_entry(pid: u32) -> Option<ProcessEntry> {
    let stat_path = format!("/proc/{pid}/stat");
    let raw = std::fs::read_to_string(&stat_path).ok()?;

    // Format: pid (comm) state ppid ... (fields numbered from 1)
    let lparen = raw.find('(')?;
    let rparen = raw.rfind(')')?;
    if rparen <= lparen {
        return None;
    }
    let name = {
        let n = raw[lparen + 1..rparen].to_string();
        if n.is_empty() {
            format!("[pid:{}]", pid)
        } else {
            n
        }
    };
    let rest = raw[rparen + 1..].trim();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] = state (field 3)
    // fields[1] = ppid  (field 4)
    // fields[17] = num_threads (field 20)
    // fields[21] = rss (field 24, pages)
    if fields.len() < 22 {
        return None;
    }
    let state = fields[0].to_string();
    let ppid: u32 = fields[1].parse().ok()?;
    let threads: u32 = fields[17].parse().ok()?;
    let rss_pages: u64 = fields[21].parse().unwrap_or(0);

    Some(ProcessEntry {
        pid,
        ppid,
        name,
        state,
        threads,
        rss_pages,
    })
}

pub fn process_info() -> Result<ProcessInfo> {
    let mut processes = Vec::new();
    let dir = std::fs::read_dir("/proc").map_err(|e| PlatformError::io("/proc", e))?;
    for entry in dir.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Ok(pid) = name.parse::<u32>() {
            if let Some(p) = read_process_entry(pid) {
                processes.push(p);
            }
        }
    }
    processes.sort_by_key(|p| p.pid);
    let total = processes.len() as u32;
    Ok(ProcessInfo { total, processes })
}

// -----------------------------------------------------------
// Thermal zones
// -----------------------------------------------------------

use crate::types::{GpuDevice, GpuInfo, ThermalInfo, ThermalZone};

pub fn thermal_info() -> Result<ThermalInfo> {
    let mut zones = Vec::new();
    let entries = std::fs::read_dir("/sys/class/thermal")
        .map_err(|e| PlatformError::io("/sys/class/thermal", e))?;

    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with("thermal_zone") {
            continue;
        }

        let base = format!("/sys/class/thermal/{name_str}");
        let zone_type = read_opt(&format!("{base}/type")).unwrap_or_else(|| name_str.to_string());
        let Some(temp_raw) = read_opt(&format!("{base}/temp")) else {
            continue;
        };
        let Ok(temp_milli) = temp_raw.parse::<i64>() else {
            continue;
        };

        if temp_milli < -100000 {
            continue;
        }

        zones.push(ThermalZone {
            name: zone_type,
            temp_millicelsius: temp_milli,
            temp_celsius: temp_milli as f64 / 1000.0,
        });
    }

    zones.sort_by(|a, b| {
        b.temp_celsius
            .partial_cmp(&a.temp_celsius)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(ThermalInfo { zones })
}

pub fn gpu_info() -> Result<GpuInfo> {
    let mut detected = Vec::new();

    if std::path::Path::new("/sys/class/misc/mali0").exists() {
        detected.push(GpuDevice {
            driver: "mali".to_string(),
            path: "/sys/class/misc/mali0".to_string(),
            kind: "ARM Mali".to_string(),
        });
    }

    if std::path::Path::new("/sys/class/kgsl/kgsl-3d0").exists() {
        detected.push(GpuDevice {
            driver: "kgsl".to_string(),
            path: "/sys/class/kgsl/kgsl-3d0".to_string(),
            kind: "Qualcomm Adreno".to_string(),
        });
    }

    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for e in entries.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.starts_with("card") && !name.contains('-') {
                let path = format!("/sys/class/drm/{name}");
                detected.push(GpuDevice {
                    driver: "drm".to_string(),
                    path,
                    kind: "DRM".to_string(),
                });
            }
        }
    }

    detected.sort_by(|a, b| a.path.cmp(&b.path));
    detected.dedup_by(|a, b| a.path == b.path);

    Ok(GpuInfo { detected })
}

// -----------------------------------------------------------
// Extended memory (/proc/meminfo)
// -----------------------------------------------------------

use crate::types::{CoreTimes, CpuTimes, LoadAvg, MemoryDetail, VmStat};

fn parse_meminfo_field(raw: &str, key: &str) -> u64 {
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(rest) = rest.strip_prefix(':') {
                return rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
    }
    0
}

pub fn memory_detail() -> Result<MemoryDetail> {
    let raw = read_file("/proc/meminfo")?;
    Ok(MemoryDetail {
        total_kb: parse_meminfo_field(&raw, "MemTotal"),
        free_kb: parse_meminfo_field(&raw, "MemFree"),
        available_kb: parse_meminfo_field(&raw, "MemAvailable"),
        buffers_kb: parse_meminfo_field(&raw, "Buffers"),
        cached_kb: parse_meminfo_field(&raw, "Cached"),
        swap_cached_kb: parse_meminfo_field(&raw, "SwapCached"),
        shmem_kb: parse_meminfo_field(&raw, "Shmem"),
        active_kb: parse_meminfo_field(&raw, "Active"),
        inactive_kb: parse_meminfo_field(&raw, "Inactive"),
        active_anon_kb: parse_meminfo_field(&raw, "Active(anon)"),
        inactive_anon_kb: parse_meminfo_field(&raw, "Inactive(anon)"),
        active_file_kb: parse_meminfo_field(&raw, "Active(file)"),
        inactive_file_kb: parse_meminfo_field(&raw, "Inactive(file)"),
        unevictable_kb: parse_meminfo_field(&raw, "Unevictable"),
        mlocked_kb: parse_meminfo_field(&raw, "Mlocked"),
        slab_kb: parse_meminfo_field(&raw, "Slab"),
        sreclaimable_kb: parse_meminfo_field(&raw, "SReclaimable"),
        sunreclaim_kb: parse_meminfo_field(&raw, "SUnreclaim"),
        kernel_stack_kb: parse_meminfo_field(&raw, "KernelStack"),
        page_tables_kb: parse_meminfo_field(&raw, "PageTables"),
        k_reclaimable_kb: parse_meminfo_field(&raw, "KReclaimable"),
        anon_pages_kb: parse_meminfo_field(&raw, "AnonPages"),
        mapped_kb: parse_meminfo_field(&raw, "Mapped"),
        dirty_kb: parse_meminfo_field(&raw, "Dirty"),
        writeback_kb: parse_meminfo_field(&raw, "Writeback"),
        commit_limit_kb: parse_meminfo_field(&raw, "CommitLimit"),
        committed_as_kb: parse_meminfo_field(&raw, "Committed_AS"),
        vmalloc_total_kb: parse_meminfo_field(&raw, "VmallocTotal"),
        vmalloc_used_kb: parse_meminfo_field(&raw, "VmallocUsed"),
        vmalloc_chunk_kb: parse_meminfo_field(&raw, "VmallocChunk"),
        hugepages_total: parse_meminfo_field(&raw, "HugePages_Total"),
        hugepages_free: parse_meminfo_field(&raw, "HugePages_Free"),
        hugepagesize_kb: parse_meminfo_field(&raw, "Hugepagesize"),
        swap_total_kb: parse_meminfo_field(&raw, "SwapTotal"),
        swap_free_kb: parse_meminfo_field(&raw, "SwapFree"),
    })
}

// -----------------------------------------------------------
// Load Average (/proc/loadavg)
// -----------------------------------------------------------

pub fn load_avg() -> Result<LoadAvg> {
    let raw = read_file("/proc/loadavg")?;
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() < 5 {
        return Err(PlatformError::parse(
            "/proc/loadavg",
            "expected at least 5 fields",
        ));
    }
    let load1: f64 = parts[0]
        .parse()
        .map_err(|e| PlatformError::parse("/proc/loadavg", format!("load1: {e}")))?;
    let load5: f64 = parts[1]
        .parse()
        .map_err(|e| PlatformError::parse("/proc/loadavg", format!("load5: {e}")))?;
    let load15: f64 = parts[2]
        .parse()
        .map_err(|e| PlatformError::parse("/proc/loadavg", format!("load15: {e}")))?;

    // "1/945" — running/total
    let tasks: Vec<&str> = parts[3].split('/').collect();
    let running: u32 = tasks.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let total: u32 = tasks.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let last_pid: u32 = parts[4].parse().unwrap_or(0);
    let uptime = read_uptime().unwrap_or(0);

    Ok(LoadAvg {
        load1,
        load5,
        load15,
        running_tasks: running,
        total_tasks: total,
        last_pid,
        uptime_seconds: uptime,
    })
}

// -----------------------------------------------------------
// VMStat (/proc/vmstat)
// -----------------------------------------------------------

pub fn vmstat() -> Result<VmStat> {
    let raw = read_file("/proc/vmstat")?;
    let get = |key: &str| -> u64 {
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix(key) {
                if rest.starts_with(' ') {
                    return rest.trim().parse().unwrap_or(0);
                }
            }
        }
        0
    };
    Ok(VmStat {
        pgpgin: get("pgpgin"),
        pgpgout: get("pgpgout"),
        pswpin: get("pswpin"),
        pswpout: get("pswpout"),
        pgfault: get("pgfault"),
        pgmajfault: get("pgmajfault"),
        pgalloc_dma: get("pgalloc_dma"),
        pgalloc_dma32: get("pgalloc_dma32"),
        pgalloc_normal: get("pgalloc_normal"),
        pgalloc_movable: get("pgalloc_movable"),
        pgfree: get("pgfree"),
        pgactivate: get("pgactivate"),
        pgdeactivate: get("pgdeactivate"),
        pglazyfree: get("pglazyfree"),
        pglazyfreed: get("pglazyfreed"),
        pgsteal_kswapd: get("pgsteal_kswapd"),
        pgsteal_direct: get("pgsteal_direct"),
        pgscan_kswapd: get("pgscan_kswapd"),
        pgscan_direct: get("pgscan_direct"),
        nr_free_pages: get("nr_free_pages"),
        nr_zone_inactive_anon: get("nr_zone_inactive_anon"),
        nr_zone_active_anon: get("nr_zone_active_anon"),
        nr_zone_inactive_file: get("nr_zone_inactive_file"),
        nr_zone_active_file: get("nr_zone_active_file"),
        nr_slab_reclaimable: get("nr_slab_reclaimable"),
        nr_slab_unreclaimable: get("nr_slab_unreclaimable"),
        nr_dirty: get("nr_dirty"),
        nr_writeback: get("nr_writeback"),
        nr_shmem: get("nr_shmem"),
        nr_kernel_misc_reclaimable: get("nr_kernel_misc_reclaimable"),
    })
}

// -----------------------------------------------------------
// CPU Times (/proc/stat)
// -----------------------------------------------------------

fn parse_cpu_line(line: &str, id: i32) -> Option<CoreTimes> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let p = |i: usize| -> u64 { parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0) };
    Some(CoreTimes {
        id,
        user: p(1),
        nice: p(2),
        system: p(3),
        idle: p(4),
        iowait: p(5),
        irq: p(6),
        softirq: p(7),
        steal: p(8),
        guest: p(9),
        guest_nice: p(10),
    })
}

pub fn cpu_times() -> Result<CpuTimes> {
    let raw = read_file("/proc/stat")?;
    let mut per_core = Vec::new();
    let mut total: Option<CoreTimes> = None;

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("cpu") {
            let (id, is_total) = if rest.starts_with(' ') {
                (-1i32, true)
            } else if let Some((num, _)) = rest.split_once(' ') {
                (num.parse::<i32>().unwrap_or(-2), false)
            } else {
                continue;
            };
            if let Some(t) = parse_cpu_line(line, id) {
                if is_total {
                    total = Some(t);
                } else if id >= 0 {
                    per_core.push(t);
                }
            }
        }
    }

    let total = total.ok_or_else(|| PlatformError::parse("/proc/stat", "no aggregate cpu line"))?;
    per_core.sort_by_key(|c| c.id);
    Ok(CpuTimes { per_core, total })
}

// -----------------------------------------------------------
// Users (/etc/passwd, /etc/group)
// -----------------------------------------------------------

use crate::types::{
    EnvEntry, EnvInfo, FsInfo, FsNode, GroupEntry, PackageEntry, PackagesInfo, ServiceEntry,
    ServicesInfo, UserEntry, UsersInfo,
};

pub(crate) fn parse_passwd(content: &str) -> Vec<UserEntry> {
    let mut users = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 7 {
            continue;
        }
        let Ok(uid) = parts[2].parse::<u32>() else {
            continue;
        };
        let Ok(gid) = parts[3].parse::<u32>() else {
            continue;
        };
        users.push(UserEntry {
            name: parts[0].to_string(),
            uid,
            gid,
            gecos: parts[4].to_string(),
            home: parts[5].to_string(),
            shell: parts[6].to_string(),
        });
    }
    users.sort_by_key(|u| u.uid);
    users
}

pub(crate) fn parse_group(content: &str) -> Vec<GroupEntry> {
    let mut groups = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let Ok(gid) = parts[2].parse::<u32>() else {
            continue;
        };
        let members: Vec<String> = if parts[3].is_empty() {
            Vec::new()
        } else {
            parts[3]
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };
        groups.push(GroupEntry {
            name: parts[0].to_string(),
            gid,
            members,
        });
    }
    groups.sort_by_key(|g| g.gid);
    groups
}

pub fn users_info() -> Result<UsersInfo> {
    let users = std::fs::read_to_string("/etc/passwd")
        .map(|s| parse_passwd(&s))
        .unwrap_or_default();
    let groups = std::fs::read_to_string("/etc/group")
        .map(|s| parse_group(&s))
        .unwrap_or_default();
    Ok(UsersInfo { users, groups })
}

// -----------------------------------------------------------
// Packages (dpkg/apk/rpm)
// -----------------------------------------------------------

pub(crate) fn parse_dpkg_content(content: &str) -> Vec<PackageEntry> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_status: Option<String> = None;

    let flush = |name: &Option<String>,
                 version: &Option<String>,
                 status: &Option<String>,
                 out: &mut Vec<PackageEntry>| {
        if let (Some(n), Some(v), Some(s)) = (name, version, status) {
            if s.contains("install ok installed") {
                out.push(PackageEntry {
                    name: n.clone(),
                    version: v.clone(),
                    status: s.clone(),
                });
            }
        }
    };

    for line in content.lines() {
        if line.is_empty() {
            flush(
                &current_name,
                &current_version,
                &current_status,
                &mut packages,
            );
            current_name = None;
            current_version = None;
            current_status = None;
        } else if let Some(v) = line.strip_prefix("Package: ") {
            current_name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version: ") {
            current_version = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Status: ") {
            current_status = Some(v.trim().to_string());
        }
    }
    flush(
        &current_name,
        &current_version,
        &current_status,
        &mut packages,
    );
    packages
}

fn parse_dpkg_status() -> Option<(u32, Vec<PackageEntry>)> {
    let raw = std::fs::read_to_string("/var/lib/dpkg/status").ok()?;
    let packages = parse_dpkg_content(&raw);
    let total = packages.len() as u32;
    Some((total, packages))
}

pub(crate) fn parse_apk_content(content: &str) -> Vec<PackageEntry> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        if line.is_empty() {
            if let (Some(n), Some(v)) = (current_name.take(), current_version.take()) {
                packages.push(PackageEntry {
                    name: n,
                    version: v,
                    status: "installed".into(),
                });
            }
        } else if let Some(v) = line.strip_prefix("P:") {
            current_name = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("V:") {
            current_version = Some(v.to_string());
        }
    }
    if let (Some(n), Some(v)) = (current_name.take(), current_version.take()) {
        packages.push(PackageEntry {
            name: n,
            version: v,
            status: "installed".into(),
        });
    }
    packages
}

fn parse_apk_db() -> Option<(u32, Vec<PackageEntry>)> {
    let raw = std::fs::read_to_string("/lib/apk/db/installed").ok()?;
    let packages = parse_apk_content(&raw);
    let total = packages.len() as u32;
    Some((total, packages))
}

pub fn packages_info() -> Result<PackagesInfo> {
    if let Some((total, packages)) = parse_dpkg_status() {
        return Ok(PackagesInfo {
            manager: "dpkg".into(),
            total,
            packages,
        });
    }
    if let Some((total, packages)) = parse_apk_db() {
        return Ok(PackagesInfo {
            manager: "apk".into(),
            total,
            packages,
        });
    }
    Err(PlatformError::unsupported(
        "no known package manager database found",
    ))
}

// -----------------------------------------------------------
// Services (systemd / init.d)
// -----------------------------------------------------------

fn list_service_files(dir: &str, ext: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let Some(n) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if n.ends_with(ext) {
            out.push(n);
        }
    }
    out.sort();
    out
}

pub fn services_info() -> Result<ServicesInfo> {
    // systemd
    if std::path::Path::new("/run/systemd/system").exists() {
        let services = list_service_files("/etc/systemd/system", ".service");
        let total = services.len() as u32;
        return Ok(ServicesInfo {
            init_system: "systemd".into(),
            total,
            services: services
                .into_iter()
                .map(|n| {
                    let enabled = std::path::Path::new(&format!(
                        "/etc/systemd/system/multi-user.target.wants/{n}"
                    ))
                    .exists();
                    ServiceEntry {
                        name: n,
                        kind: "systemd".into(),
                        enabled: Some(enabled),
                    }
                })
                .collect(),
        });
    }

    // SysV init.d
    let scripts = list_service_files("/etc/init.d", "");
    if !scripts.is_empty() {
        let total = scripts.len() as u32;
        return Ok(ServicesInfo {
            init_system: "sysvinit".into(),
            total,
            services: scripts
                .into_iter()
                .map(|n| ServiceEntry {
                    name: n,
                    kind: "sysv".into(),
                    enabled: None,
                })
                .collect(),
        });
    }

    Ok(ServicesInfo {
        init_system: "unknown".into(),
        total: 0,
        services: Vec::new(),
    })
}

// -----------------------------------------------------------
// Filesystem (top-level roots with entry counts)
// -----------------------------------------------------------

pub fn filesystem_info() -> Result<FsInfo> {
    const ROOTS: &[&str] = &["/etc", "/var", "/usr", "/home", "/opt", "/tmp"];

    let mut nodes = Vec::new();
    for root in ROOTS {
        let p = std::path::Path::new(root);
        if !p.exists() {
            continue;
        }

        match std::fs::read_dir(root) {
            Ok(entries) => {
                let count = entries.flatten().count() as u32;
                nodes.push(FsNode {
                    path: root.to_string(),
                    kind: "directory".into(),
                    size_bytes: None,
                    entries: count,
                    readable: true,
                });
            }
            Err(_) => {
                nodes.push(FsNode {
                    path: root.to_string(),
                    kind: "directory".into(),
                    size_bytes: None,
                    entries: 0,
                    readable: false,
                });
            }
        }
    }

    Ok(FsInfo { roots: nodes })
}

// -----------------------------------------------------------
// Environment (/proc/self/environ)
// -----------------------------------------------------------

pub(crate) fn parse_environ(raw: &[u8]) -> Vec<EnvEntry> {
    let mut entries = Vec::new();
    for chunk in raw.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let Ok(s) = std::str::from_utf8(chunk) else {
            continue;
        };
        if let Some((k, v)) = s.split_once('=') {
            entries.push(EnvEntry {
                key: k.to_string(),
                value: v.to_string(),
            });
        }
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    entries
}

pub fn env_info() -> Result<EnvInfo> {
    let raw = std::fs::read("/proc/self/environ")
        .map_err(|e| PlatformError::io("/proc/self/environ", e))?;
    let entries = parse_environ(&raw);
    let total = entries.len() as u32;
    Ok(EnvInfo { total, entries })
}

// -----------------------------------------------------------
// USB devices (/sys/bus/usb/devices)
// -----------------------------------------------------------

use crate::types::{
    BatteryEntry, BatteryInfo, DriverModule, DriversInfo, PciDevice, PciInfo, SensorChip,
    SensorReading, SensorsInfo, UsbDevice, UsbInfo,
};

pub fn usb_info() -> Result<UsbInfo> {
    let mut devices = Vec::new();
    let dir = match std::fs::read_dir("/sys/bus/usb/devices") {
        Ok(d) => d,
        Err(_) => {
            return Ok(UsbInfo {
                total: 0,
                devices: Vec::new(),
            })
        }
    };
    for e in dir.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.contains(':') {
            continue;
        }
        let base = format!("/sys/bus/usb/devices/{name}");
        devices.push(UsbDevice {
            name,
            id_vendor: read_opt(&format!("{base}/idVendor")),
            id_product: read_opt(&format!("{base}/idProduct")),
            manufacturer: read_opt(&format!("{base}/manufacturer")),
            product: read_opt(&format!("{base}/product")),
            bclass: read_opt(&format!("{base}/bDeviceClass")),
        });
    }
    devices.sort_by(|a, b| a.name.cmp(&b.name));
    let total = devices.len() as u32;
    Ok(UsbInfo { total, devices })
}

// -----------------------------------------------------------
// PCI devices (/sys/bus/pci/devices)
// -----------------------------------------------------------

fn read_pci_driver(base: &str) -> Option<String> {
    std::fs::read_link(format!("{base}/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
}

pub fn pci_info() -> Result<PciInfo> {
    let mut devices = Vec::new();
    let dir = match std::fs::read_dir("/sys/bus/pci/devices") {
        Ok(d) => d,
        Err(_) => {
            return Ok(PciInfo {
                total: 0,
                devices: Vec::new(),
            })
        }
    };
    for e in dir.flatten() {
        let Some(slot) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let base = format!("/sys/bus/pci/devices/{slot}");
        devices.push(PciDevice {
            slot,
            vendor: read_opt(&format!("{base}/vendor")),
            device: read_opt(&format!("{base}/device")),
            class: read_opt(&format!("{base}/class")),
            driver: read_pci_driver(&base),
        });
    }
    devices.sort_by(|a, b| a.slot.cmp(&b.slot));
    let total = devices.len() as u32;
    Ok(PciInfo { total, devices })
}

// -----------------------------------------------------------
// Battery (/sys/class/power_supply)
// -----------------------------------------------------------

pub fn battery_info() -> Result<BatteryInfo> {
    let mut batteries = Vec::new();
    let dir = match std::fs::read_dir("/sys/class/power_supply") {
        Ok(d) => d,
        Err(_) => {
            return Ok(BatteryInfo {
                total: 0,
                batteries: Vec::new(),
            })
        }
    };
    for e in dir.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let base = format!("/sys/class/power_supply/{name}");
        let ty = read_opt(&format!("{base}/type")).unwrap_or_default();
        if ty != "Battery" {
            continue;
        }
        batteries.push(BatteryEntry {
            name,
            capacity: read_opt(&format!("{base}/capacity")).and_then(|s| s.parse().ok()),
            status: read_opt(&format!("{base}/status")),
            health: read_opt(&format!("{base}/health")),
            technology: read_opt(&format!("{base}/technology")),
            voltage_uv: read_opt(&format!("{base}/voltage_now")).and_then(|s| s.parse().ok()),
            current_ua: read_opt(&format!("{base}/current_now")).and_then(|s| s.parse().ok()),
            temp_dc: read_opt(&format!("{base}/temp")).and_then(|s| s.parse().ok()),
            cycle_count: read_opt(&format!("{base}/cycle_count")).and_then(|s| s.parse().ok()),
        });
    }
    batteries.sort_by(|a, b| a.name.cmp(&b.name));
    let total = batteries.len() as u32;
    Ok(BatteryInfo { total, batteries })
}

// -----------------------------------------------------------
// Sensors (hwmon)
// -----------------------------------------------------------

pub fn sensors_info() -> Result<SensorsInfo> {
    let mut chips = Vec::new();
    let dir = match std::fs::read_dir("/sys/class/hwmon") {
        Ok(d) => d,
        Err(_) => {
            return Ok(SensorsInfo {
                total: 0,
                chips: Vec::new(),
            })
        }
    };
    for e in dir.flatten() {
        let Some(chip_name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let base = format!("/sys/class/hwmon/{chip_name}");
        let name = read_opt(&format!("{base}/name")).unwrap_or_else(|| chip_name.clone());

        let mut temps = Vec::new();
        // Try temp1_input .. temp32_input
        for i in 1..=32 {
            let input_path = format!("{base}/temp{i}_input");
            if let Some(raw) = read_opt(&input_path) {
                if let Ok(milli) = raw.parse::<i64>() {
                    let label = read_opt(&format!("{base}/temp{i}_label"));
                    temps.push(SensorReading {
                        label,
                        celsius: milli as f64 / 1000.0,
                    });
                }
            }
        }
        chips.push(SensorChip {
            name,
            path: base,
            temps,
        });
    }
    chips.sort_by(|a, b| a.path.cmp(&b.path));
    let total = chips.len() as u32;
    Ok(SensorsInfo { total, chips })
}

// -----------------------------------------------------------
// Drivers (/proc/modules)
// -----------------------------------------------------------

pub(crate) fn parse_modules(content: &str) -> Vec<DriverModule> {
    let mut modules = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let name = parts[0].to_string();
        let size = parts[1].parse::<u64>().unwrap_or(0);
        let refs = parts[2].parse::<u32>().unwrap_or(0);
        let deps: Vec<String> = if parts[3] == "-" {
            Vec::new()
        } else {
            parts[3]
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };
        let state = parts[4].to_string();
        modules.push(DriverModule {
            name,
            size,
            refs,
            deps,
            state,
        });
    }
    modules.sort_by(|a, b| a.name.cmp(&b.name));
    modules
}

pub fn drivers_info() -> Result<DriversInfo> {
    let raw = read_file("/proc/modules")?;
    let modules = parse_modules(&raw);
    let total = modules.len() as u32;
    Ok(DriversInfo { total, modules })
}

// -----------------------------------------------------------
// Containers
// -----------------------------------------------------------

use crate::types::{BrowserEntry, BrowsersInfo, ContainersInfo, CronInfo, CryptoInfo, VmInfo};

pub(crate) fn detect_runtime_from_cgroup(cgroup: &str) -> Option<(&'static str, &'static str)> {
    for line in cgroup.lines() {
        for (needle, name) in [
            ("docker", "docker"),
            ("kubepods", "kubernetes"),
            ("lxc", "lxc"),
            ("podman", "podman"),
            ("containerd", "containerd"),
        ] {
            if line.contains(needle) {
                return Some((name, needle));
            }
        }
    }
    None
}

pub fn containers_info() -> Result<ContainersInfo> {
    let mut evidences = Vec::new();
    let mut runtime: Option<String> = None;

    if let Ok(raw) = std::fs::read_to_string("/proc/1/cgroup") {
        if let Some((rt, needle)) = detect_runtime_from_cgroup(&raw) {
            runtime = Some(rt.to_string());
            evidences.push(format!("cgroup: {needle}"));
        }
    }

    // Check sockets
    for (path, name) in [
        ("/var/run/docker.sock", "docker.sock"),
        ("/run/podman/podman.sock", "podman.sock"),
        ("/run/containerd/containerd.sock", "containerd.sock"),
    ] {
        if std::path::Path::new(path).exists() {
            evidences.push(format!("socket: {name}"));
            if runtime.is_none() {
                runtime = Some(name.trim_end_matches(".sock").to_string());
            }
        }
    }

    // Check directories
    for (path, name) in [
        ("/var/lib/docker", "docker-dir"),
        ("/var/lib/containers", "containers-dir"),
        ("/etc/containers", "etc-containers"),
    ] {
        if std::path::Path::new(path).exists() {
            evidences.push(format!("path: {name}"));
        }
    }

    Ok(ContainersInfo {
        detected: !evidences.is_empty(),
        runtime,
        evidences,
    })
}

// -----------------------------------------------------------
// Virtualization
// -----------------------------------------------------------

pub(crate) fn detect_hypervisor_from_product(
    product: &str,
) -> Option<(&'static str, &'static str)> {
    let pl = product.to_lowercase();
    for (needle, name) in [
        ("vmware", "VMware"),
        ("virtualbox", "VirtualBox"),
        ("qemu", "QEMU"),
        ("kvm", "KVM"),
        ("xen", "Xen"),
        ("hyper-v", "Hyper-V"),
        ("bhyve", "bhyve"),
    ] {
        if pl.contains(needle) {
            return Some((name, needle));
        }
    }
    None
}

pub fn vm_info() -> Result<VmInfo> {
    let mut evidences = Vec::new();
    let mut hypervisor: Option<String> = None;

    // Check /proc/cpuinfo for hypervisor flag
    if let Ok(raw) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in raw.lines() {
            if line.starts_with("flags") && line.contains(" hypervisor") {
                evidences.push("cpuinfo: hypervisor flag".to_string());
                break;
            }
        }
    }

    // Check /sys/hypervisor
    if std::path::Path::new("/sys/hypervisor").exists() {
        evidences.push("path: /sys/hypervisor".to_string());
    }

    // Read DMI product name
    let product_name = read_opt("/sys/class/dmi/id/product_name");
    let sys_vendor = read_opt("/sys/class/dmi/id/sys_vendor");

    if let Some(ref p) = product_name {
        if let Some((hy, needle)) = detect_hypervisor_from_product(p) {
            hypervisor = Some(hy.to_string());
            evidences.push(format!("dmi.product: {needle}"));
        }
    }

    Ok(VmInfo {
        is_vm: !evidences.is_empty(),
        hypervisor,
        product_name,
        sys_vendor,
        evidences,
    })
}

// -----------------------------------------------------------
// Browsers
// -----------------------------------------------------------

pub fn browsers_info() -> Result<BrowsersInfo> {
    const CANDIDATES: &[(&str, &str, &str)] = &[
        // (name, kind, path)
        ("Chrome", "config", "/root/.config/google-chrome"),
        ("Chrome", "install", "/opt/google/chrome"),
        ("Chromium", "config", "/root/.config/chromium"),
        ("Firefox", "config", "/root/.mozilla/firefox"),
        ("Edge", "config", "/root/.config/microsoft-edge"),
        ("Brave", "config", "/root/.config/BraveSoftware"),
        ("Opera", "config", "/root/.config/opera"),
        ("Vivaldi", "config", "/root/.config/vivaldi"),
        ("Tor", "config", "/root/.config/torbrowser"),
    ];

    let mut detected = Vec::new();
    for (name, kind, path) in CANDIDATES {
        if std::path::Path::new(path).exists() {
            detected.push(BrowserEntry {
                name: (*name).to_string(),
                kind: (*kind).to_string(),
                path: (*path).to_string(),
            });
        }
    }
    let total = detected.len() as u32;
    Ok(BrowsersInfo { total, detected })
}

// -----------------------------------------------------------
// Crypto
// -----------------------------------------------------------

fn list_dir_files(dir: &str, suffix: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let Some(n) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if suffix.is_empty() || n.ends_with(suffix) {
            out.push(n);
        }
    }
    out.sort();
    out
}

pub fn crypto_info() -> Result<CryptoInfo> {
    // SSL certificates
    let ssl_certs_count = list_dir_files("/etc/ssl/certs", ".pem").len() as u32
        + list_dir_files("/etc/ssl/certs", ".crt").len() as u32;

    // System SSH host keys
    let system_ssh_keys = list_dir_files("/etc/ssh", ".pub");

    // User SSH keys
    let user_ssh_keys = list_dir_files("/root/.ssh", ".pub");

    // GPG
    let gnupg_path = if std::path::Path::new("/root/.gnupg").exists() {
        Some("/root/.gnupg".to_string())
    } else if std::path::Path::new("/etc/gnupg").exists() {
        Some("/etc/gnupg".to_string())
    } else {
        None
    };
    let has_gnupg = gnupg_path.is_some();

    Ok(CryptoInfo {
        ssl_certs_count,
        system_ssh_keys,
        user_ssh_keys,
        has_gnupg,
        gnupg_path,
    })
}

// -----------------------------------------------------------
// Cron
// -----------------------------------------------------------

pub fn cron_info() -> Result<CronInfo> {
    let has_etc_crontab = std::path::Path::new("/etc/crontab").exists();

    let system_files = {
        let mut v = list_dir_files("/etc/cron.d", "");
        if has_etc_crontab {
            v.insert(0, "crontab".to_string());
        }
        v
    };

    let system_dirs: Vec<String> = [
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]
    .iter()
    .filter(|d| std::path::Path::new(d).exists())
    .map(|s| s.to_string())
    .collect();

    let user_crontabs = {
        let mut v = list_dir_files("/var/spool/cron/crontabs", "");
        if v.is_empty() {
            v = list_dir_files("/var/spool/cron", "");
        }
        v
    };

    Ok(CronInfo {
        has_etc_crontab,
        system_files,
        system_dirs,
        user_crontabs,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn parse_meminfo_field_extracts_number() {
        let raw = "MemTotal:       16384000 kB\nMemFree:         2000000 kB\n";
        assert_eq!(parse_meminfo_field(raw, "MemTotal"), 16_384_000);
        assert_eq!(parse_meminfo_field(raw, "MemFree"), 2_000_000);
    }

    #[test]
    fn parse_meminfo_field_returns_zero_on_missing_key() {
        let raw = "MemTotal: 100 kB\n";
        assert_eq!(parse_meminfo_field(raw, "NotPresent"), 0);
    }

    #[test]
    fn parse_meminfo_field_skips_lines_without_colon() {
        let raw = "garbage\nMemTotal: 42 kB\n";
        assert_eq!(parse_meminfo_field(raw, "MemTotal"), 42);
    }

    #[test]
    fn parse_meminfo_field_zero_on_bad_value() {
        let raw = "MemTotal: nota_number kB\n";
        assert_eq!(parse_meminfo_field(raw, "MemTotal"), 0);
    }

    #[test]
    fn parse_cpu_line_aggregate_full() {
        let line = "cpu  100 5 50 500 2 3 4 0 0 0";
        let t = parse_cpu_line(line, -1).unwrap();
        assert_eq!(t.id, -1);
        assert_eq!(t.user, 100);
        assert_eq!(t.nice, 5);
        assert_eq!(t.system, 50);
        assert_eq!(t.idle, 500);
        assert_eq!(t.iowait, 2);
        assert_eq!(t.irq, 3);
        assert_eq!(t.softirq, 4);
        assert_eq!(t.steal, 0);
    }

    #[test]
    fn parse_cpu_line_rejects_short_line() {
        assert!(parse_cpu_line("cpu 1 2", 0).is_none());
    }

    #[test]
    fn parse_cpu_line_missing_trailing_fields_default_zero() {
        let line = "cpu0 1 2 3 4";
        let t = parse_cpu_line(line, 0).unwrap();
        assert_eq!(t.user, 1);
        assert_eq!(t.nice, 2);
        assert_eq!(t.system, 3);
        assert_eq!(t.idle, 4);
        assert_eq!(t.iowait, 0);
        assert_eq!(t.guest_nice, 0);
    }

    #[test]
    fn parse_cpu_line_handles_extra_whitespace() {
        let line = "cpu    100   200    300   400";
        let t = parse_cpu_line(line, -1).unwrap();
        assert_eq!(t.user, 100);
        assert_eq!(t.idle, 400);
    }

    #[test]
    fn read_u64_missing_path_returns_none() {
        assert!(read_u64("/__pulse_nonexistent__/file").is_none());
    }

    #[test]
    fn read_opt_missing_path_returns_none() {
        assert!(read_opt("/__pulse_nonexistent__/file").is_none());
    }

    #[test]
    fn read_trim_missing_path_returns_none() {
        assert!(read_trim("/__pulse_nonexistent__/file").is_none());
    }

    #[test]
    fn read_file_missing_path_returns_err() {
        assert!(read_file("/__pulse_nonexistent__/file").is_err());
    }

    #[test]
    fn statvfs_missing_path_returns_none() {
        assert!(statvfs_size("/__pulse_nonexistent__/path").is_none());
    }

    #[test]
    fn statvfs_root_is_positive() {
        let r = statvfs_size("/");
        assert!(r.is_some());
        let (total, _used, avail) = r.unwrap();
        assert!(total > 0);
        assert!(avail <= total);
    }

    #[test]
    fn classify_iface_loopback_is_detected() {
        if std::path::Path::new("/sys/class/net/lo").exists() {
            let c = classify_iface("/sys/class/net/lo");
            assert_eq!(c.as_deref(), Some("loopback"));
        }
    }

    #[test]
    fn classify_iface_missing_path_returns_none() {
        assert!(classify_iface("/__pulse_nonexistent__").is_none());
    }

    #[test]
    fn list_dir_files_missing_returns_empty() {
        assert!(list_dir_files("/__pulse_nonexistent__", ".pub").is_empty());
    }

    #[test]
    fn list_service_files_missing_returns_empty() {
        assert!(list_service_files("/__pulse_nonexistent__", ".service").is_empty());
    }

    #[test]
    fn detect_soc_does_not_panic() {
        let _ = detect_android_soc_model();
    }

    #[test]
    fn read_process_entry_pid1_exists() {
        let entry = read_process_entry(1);
        assert!(entry.is_some(), "PID 1 must be readable");
        let e = entry.unwrap();
        assert_eq!(e.pid, 1);
        assert!(!e.name.is_empty());
    }

    #[test]
    fn read_process_entry_nonexistent_pid_returns_none() {
        assert!(read_process_entry(999_999_999).is_none());
    }

    #[test]
    fn read_pci_driver_missing_path_returns_none() {
        assert!(read_pci_driver("/__pulse_nonexistent__").is_none());
    }

    #[test]
    fn read_os_name_is_non_empty() {
        assert!(!read_os_name().is_empty());
    }

    #[test]
    fn read_os_version_does_not_panic() {
        let _ = read_os_version();
    }

    #[test]
    fn parse_dpkg_status_does_not_panic() {
        let _ = parse_dpkg_status();
    }

    #[test]
    fn parse_apk_db_does_not_panic() {
        let _ = parse_apk_db();
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn os_release_both_fields_present() {
        let c = "PRETTY_NAME=\"Kali GNU/Linux\"\nVERSION_ID=\"2026.3\"\n";
        let (n, v) = parse_os_release(c);
        assert_eq!(n.as_deref(), Some("Kali GNU/Linux"));
        assert_eq!(v.as_deref(), Some("2026.3"));
    }

    #[test]
    fn os_release_only_name() {
        let c = "PRETTY_NAME=\"Ubuntu\"\nID=ubuntu\n";
        let (n, v) = parse_os_release(c);
        assert_eq!(n.as_deref(), Some("Ubuntu"));
        assert!(v.is_none());
    }

    #[test]
    fn os_release_only_version() {
        let c = "ID=x\nVERSION_ID=42\n";
        let (n, v) = parse_os_release(c);
        assert!(n.is_none());
        assert_eq!(v.as_deref(), Some("42"));
    }

    #[test]
    fn os_release_empty_returns_none_pair() {
        let (n, v) = parse_os_release("");
        assert!(n.is_none());
        assert!(v.is_none());
    }

    #[test]
    fn os_release_garbage_lines_ignored() {
        let c = "garbage\n# comment\nPRETTY_NAME=Test\n";
        let (n, _) = parse_os_release(c);
        assert_eq!(n.as_deref(), Some("Test"));
    }

    #[test]
    fn os_release_unquoted_values() {
        let c = "PRETTY_NAME=Debian\nVERSION_ID=12\n";
        let (n, v) = parse_os_release(c);
        assert_eq!(n.as_deref(), Some("Debian"));
        assert_eq!(v.as_deref(), Some("12"));
    }

    #[test]
    fn btime_present_returns_value() {
        let c = "cpu  100 200\nbtime 1700000000\nintr 12345\n";
        assert_eq!(parse_btime(c), Some(1_700_000_000));
    }

    #[test]
    fn btime_missing_returns_none() {
        let c = "cpu  100 200\nintr 12345\n";
        assert_eq!(parse_btime(c), None);
    }

    #[test]
    fn btime_zero_rejected() {
        assert_eq!(parse_btime("btime 0\n"), None);
    }

    #[test]
    fn btime_non_numeric_rejected() {
        assert_eq!(parse_btime("btime abc\n"), None);
    }

    #[test]
    fn btime_empty_returns_none() {
        assert_eq!(parse_btime(""), None);
    }

    #[test]
    fn passwd_parses_single_user() {
        let c = "root:x:0:0:root:/root:/bin/bash\n";
        let users = parse_passwd(c);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "root");
        assert_eq!(users[0].uid, 0);
        assert_eq!(users[0].home, "/root");
        assert_eq!(users[0].shell, "/bin/bash");
    }

    #[test]
    fn passwd_skips_malformed_lines() {
        let c = "root:x:0:0:root:/root:/bin/bash\nshort:x:0\n";
        assert_eq!(parse_passwd(c).len(), 1);
    }

    #[test]
    fn passwd_skips_bad_uid() {
        let c = "bad:x:notanum:0:x:/home:/bin/sh\n";
        assert!(parse_passwd(c).is_empty());
    }

    #[test]
    fn passwd_skips_bad_gid() {
        let c = "bad:x:100:notanum:x:/home:/bin/sh\n";
        assert!(parse_passwd(c).is_empty());
    }

    #[test]
    fn passwd_sorted_by_uid() {
        let c = "b:x:100:100:b:/h:/sh\na:x:50:50:a:/h:/sh\nc:x:200:200:c:/h:/sh\n";
        let users = parse_passwd(c);
        let uids: Vec<u32> = users.iter().map(|u| u.uid).collect();
        assert_eq!(uids, vec![50, 100, 200]);
    }

    #[test]
    fn passwd_empty_input() {
        assert!(parse_passwd("").is_empty());
    }

    #[test]
    fn passwd_only_garbage() {
        assert!(parse_passwd("garbage\nmore garbage\n").is_empty());
    }

    #[test]
    fn passwd_preserves_gecos() {
        let c = "user:x:1000:1000:Real Name,,,:/home/user:/bin/zsh\n";
        assert_eq!(parse_passwd(c)[0].gecos, "Real Name,,,");
    }

    #[test]
    fn group_parses_single() {
        let c = "root:x:0:\n";
        let groups = parse_group(c);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "root");
        assert!(groups[0].members.is_empty());
    }

    #[test]
    fn group_with_members() {
        let c = "sudo:x:27:kali,omar\n";
        assert_eq!(parse_group(c)[0].members, vec!["kali", "omar"]);
    }

    #[test]
    fn group_empty_members_string() {
        let c = "wheel:x:10:\n";
        assert!(parse_group(c)[0].members.is_empty());
    }

    #[test]
    fn group_skips_malformed() {
        let c = "root:x:0:\nshort:x\n";
        assert_eq!(parse_group(c).len(), 1);
    }

    #[test]
    fn group_skips_bad_gid() {
        assert!(parse_group("bad:x:notanum:\n").is_empty());
    }

    #[test]
    fn group_sorted_by_gid() {
        let c = "b:x:100:\na:x:50:\nc:x:200:\n";
        let gids: Vec<u32> = parse_group(c).iter().map(|g| g.gid).collect();
        assert_eq!(gids, vec![50, 100, 200]);
    }

    #[test]
    fn group_empty_input() {
        assert!(parse_group("").is_empty());
    }

    #[test]
    fn dpkg_parses_one_installed() {
        let c = "Package: libc6\nVersion: 2.43-6\nStatus: install ok installed\n\n";
        let pkgs = parse_dpkg_content(c);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "libc6");
    }

    #[test]
    fn dpkg_skips_not_installed() {
        let c = "Package: p\nVersion: 1\nStatus: deinstall ok config-files\n\n";
        assert!(parse_dpkg_content(c).is_empty());
    }

    #[test]
    fn dpkg_multiple_packages() {
        let c = "Package: a\nVersion: 1\nStatus: install ok installed\n\nPackage: b\nVersion: 2\nStatus: install ok installed\n\n";
        assert_eq!(parse_dpkg_content(c).len(), 2);
    }

    #[test]
    fn dpkg_final_paragraph_no_trailing_blank() {
        let c = "Package: last\nVersion: 9\nStatus: install ok installed";
        let pkgs = parse_dpkg_content(c);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "last");
    }

    #[test]
    fn dpkg_missing_status_skipped() {
        let c = "Package: x\nVersion: 1\n\n";
        assert!(parse_dpkg_content(c).is_empty());
    }

    #[test]
    fn dpkg_empty_input() {
        assert!(parse_dpkg_content("").is_empty());
    }

    #[test]
    fn dpkg_trims_whitespace() {
        let c = "Package:   spaced   \nVersion:   1.0   \nStatus: install ok installed\n\n";
        let pkgs = parse_dpkg_content(c);
        assert_eq!(pkgs[0].name, "spaced");
        assert_eq!(pkgs[0].version, "1.0");
    }

    #[test]
    fn apk_parses_single() {
        let c = "P:musl\nV:1.2.6\n\n";
        let pkgs = parse_apk_content(c);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "musl");
        assert_eq!(pkgs[0].version, "1.2.6");
        assert_eq!(pkgs[0].status, "installed");
    }

    #[test]
    fn apk_final_paragraph_no_blank() {
        let c = "P:last\nV:9";
        assert_eq!(parse_apk_content(c).len(), 1);
    }

    #[test]
    fn apk_multiple() {
        let c = "P:a\nV:1\n\nP:b\nV:2\n\n";
        assert_eq!(parse_apk_content(c).len(), 2);
    }

    #[test]
    fn apk_missing_version_skipped() {
        assert!(parse_apk_content("P:onlyname\n\n").is_empty());
    }

    #[test]
    fn apk_empty_input() {
        assert!(parse_apk_content("").is_empty());
    }

    #[test]
    fn apk_ignores_other_fields() {
        let c = "C:Q1abc\nP:pkg\nV:1.0\nT:description\n\n";
        assert_eq!(parse_apk_content(c)[0].name, "pkg");
    }

    #[test]
    fn modules_parses_one_line() {
        let c = "gps_scp 131072 2 gps_pwr Live 0x0\n";
        let m = parse_modules(c);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "gps_scp");
        assert_eq!(m[0].size, 131_072);
        assert_eq!(m[0].refs, 2);
        assert_eq!(m[0].deps, vec!["gps_pwr"]);
    }

    #[test]
    fn modules_no_deps_dash() {
        let c = "lonely 4096 0 - Live 0x0\n";
        assert!(parse_modules(c)[0].deps.is_empty());
    }

    #[test]
    fn modules_multiple_deps() {
        let c = "pkg 100 1 a,b,c Live 0x0\n";
        assert_eq!(parse_modules(c)[0].deps, vec!["a", "b", "c"]);
    }

    #[test]
    fn modules_skips_short_lines() {
        assert!(parse_modules("gps_scp 131072 2\n").is_empty());
    }

    #[test]
    fn modules_sorted_by_name() {
        let c = "z 1 0 - Live 0x0\na 1 0 - Live 0x0\nm 1 0 - Live 0x0\n";
        let names: Vec<String> = parse_modules(c).iter().map(|x| x.name.clone()).collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn modules_empty() {
        assert!(parse_modules("").is_empty());
    }

    #[test]
    fn environ_parses_simple() {
        let raw = b"PATH=/usr/bin\0HOME=/root\0";
        let e = parse_environ(raw);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].key, "HOME");
        assert_eq!(e[0].value, "/root");
    }

    #[test]
    fn environ_empty_input() {
        assert!(parse_environ(b"").is_empty());
    }

    #[test]
    fn environ_skips_empty_chunks() {
        let raw = b"\0PATH=/bin\0\0";
        assert_eq!(parse_environ(raw).len(), 1);
    }

    #[test]
    fn environ_skips_no_equals() {
        let raw = b"PATH=/bin\0NOEQUALS\0";
        assert_eq!(parse_environ(raw).len(), 1);
    }

    #[test]
    fn environ_skips_invalid_utf8() {
        let raw = b"PATH=/bin\0\xFF\xFE=bad\0";
        assert_eq!(parse_environ(raw).len(), 1);
    }

    #[test]
    fn environ_sorted_by_key() {
        let raw = b"Z=1\0A=2\0M=3\0";
        let keys: Vec<String> = parse_environ(raw).iter().map(|x| x.key.clone()).collect();
        assert_eq!(keys, vec!["A", "M", "Z"]);
    }

    #[test]
    fn environ_value_with_equals() {
        let raw = b"URL=https://x.com/?a=b\0";
        let e = parse_environ(raw);
        assert_eq!(e[0].key, "URL");
        assert_eq!(e[0].value, "https://x.com/?a=b");
    }

    #[test]
    fn hypervisor_vmware() {
        assert_eq!(
            detect_hypervisor_from_product("VMware Virtual Platform"),
            Some(("VMware", "vmware"))
        );
    }

    #[test]
    fn hypervisor_virtualbox() {
        assert_eq!(
            detect_hypervisor_from_product("VirtualBox"),
            Some(("VirtualBox", "virtualbox"))
        );
    }

    #[test]
    fn hypervisor_qemu() {
        assert_eq!(
            detect_hypervisor_from_product("QEMU Standard PC"),
            Some(("QEMU", "qemu"))
        );
    }

    #[test]
    fn hypervisor_kvm() {
        assert_eq!(detect_hypervisor_from_product("KVM"), Some(("KVM", "kvm")));
    }

    #[test]
    fn hypervisor_xen() {
        assert_eq!(
            detect_hypervisor_from_product("Xen HVM"),
            Some(("Xen", "xen"))
        );
    }

    #[test]
    fn hypervisor_hyper_v() {
        assert_eq!(
            detect_hypervisor_from_product("Microsoft Hyper-V"),
            Some(("Hyper-V", "hyper-v"))
        );
    }

    #[test]
    fn hypervisor_bhyve() {
        assert_eq!(
            detect_hypervisor_from_product("BHYVE"),
            Some(("bhyve", "bhyve"))
        );
    }

    #[test]
    fn hypervisor_unknown() {
        assert!(detect_hypervisor_from_product("Real Hardware").is_none());
    }

    #[test]
    fn hypervisor_empty() {
        assert!(detect_hypervisor_from_product("").is_none());
    }

    #[test]
    fn cgroup_docker() {
        assert_eq!(
            detect_runtime_from_cgroup("1:name=systemd:/docker/abc"),
            Some(("docker", "docker"))
        );
    }

    #[test]
    fn cgroup_kubepods() {
        assert_eq!(
            detect_runtime_from_cgroup("0::/kubepods/besteffort"),
            Some(("kubernetes", "kubepods"))
        );
    }

    #[test]
    fn cgroup_lxc() {
        assert_eq!(
            detect_runtime_from_cgroup("0::/lxc/payload"),
            Some(("lxc", "lxc"))
        );
    }

    #[test]
    fn cgroup_podman() {
        assert_eq!(
            detect_runtime_from_cgroup("0::/podman/xyz"),
            Some(("podman", "podman"))
        );
    }

    #[test]
    fn cgroup_containerd() {
        assert_eq!(
            detect_runtime_from_cgroup("0::/containerd/xyz"),
            Some(("containerd", "containerd"))
        );
    }

    #[test]
    fn cgroup_no_match() {
        assert!(detect_runtime_from_cgroup("0::/init.scope").is_none());
    }

    #[test]
    fn cgroup_empty() {
        assert!(detect_runtime_from_cgroup("").is_none());
    }

    #[test]
    fn cgroup_first_match() {
        let c = "1:name=systemd:/\n0::/docker/abc\n";
        assert_eq!(detect_runtime_from_cgroup(c), Some(("docker", "docker")));
    }
}
