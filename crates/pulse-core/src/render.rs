//! Renderers for platform data structures.

use crate::format::JsonStyle;
use pulse_platform::{CpuInfo, MemoryInfo, SystemInfo};
use serde::Serialize;

// ---------- generic JSON helper ----------

pub fn to_json<T: Serialize>(value: &T, style: JsonStyle) -> String {
    let result = match style {
        JsonStyle::Pretty => serde_json::to_string_pretty(value),
        JsonStyle::Compact => serde_json::to_string(value),
    };
    result.unwrap_or_else(|e| format!("{{\"error\":\"json_encode: {e}\"}}"))
}

// ---------- SystemInfo ----------

pub fn system_text(info: &SystemInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "OS Name        : {}", info.os_name);
    let _ = writeln!(s, "OS Version     : {}", info.os_version);
    let _ = writeln!(s, "Kernel         : {}", info.kernel_version);
    let _ = writeln!(s, "Hostname       : {}", info.hostname);
    let _ = writeln!(
        s,
        "Uptime         : {} seconds ({}h {}m)",
        info.uptime_seconds,
        info.uptime_seconds / 3600,
        (info.uptime_seconds % 3600) / 60
    );
    let _ = writeln!(s, "Boot Time      : {} (unix)", info.boot_time_unix);
    let _ = writeln!(s, "Architecture   : {}", info.architecture);
    let _ = writeln!(s, "Pointer Width  : {} bits", info.pointer_width);
    let _ = writeln!(s, "Endianness     : {}", info.endianness);
    s
}

pub fn system_markdown(info: &SystemInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("| Field | Value |\n");
    s.push_str("|-------|-------|\n");
    let _ = writeln!(s, "| OS Name | {} |", info.os_name);
    let _ = writeln!(s, "| OS Version | {} |", info.os_version);
    let _ = writeln!(
        s,
        "| Kernel | `{}` |",
        info.kernel_version.replace('|', "\\|")
    );
    let _ = writeln!(s, "| Hostname | {} |", info.hostname);
    let _ = writeln!(s, "| Uptime | {} seconds |", info.uptime_seconds);
    let _ = writeln!(s, "| Boot Time | {} |", info.boot_time_unix);
    let _ = writeln!(s, "| Architecture | {} |", info.architecture);
    let _ = writeln!(s, "| Pointer Width | {} bits |", info.pointer_width);
    let _ = writeln!(s, "| Endianness | {} |", info.endianness);
    s
}

// ---------- CpuInfo ----------

pub fn cpu_text(info: &CpuInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Model          : {}", info.model);
    let _ = writeln!(s, "Architecture   : {}", info.architecture);
    let _ = writeln!(s, "Cores          : {}", info.cores);
    let _ = writeln!(
        s,
        "Features ({})  : {}",
        info.features.len(),
        info.features.join(" ")
    );
    s.push('\n');
    s.push_str("Per-core:\n");
    let _ = writeln!(
        s,
        "{:<6} {:>12} {:>12} {:>12}  {:<10}",
        "core", "cur(kHz)", "min(kHz)", "max(kHz)", "governor"
    );
    for c in &info.per_core {
        let _ = writeln!(
            s,
            "{:<6} {:>12} {:>12} {:>12}  {:<10}",
            c.id,
            c.cur_freq_khz
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            c.min_freq_khz
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            c.max_freq_khz
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            c.governor.as_deref().unwrap_or("-")
        );
    }
    s
}

pub fn cpu_markdown(info: &CpuInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Model:** {}", info.model);
    let _ = writeln!(s, "**Architecture:** {}", info.architecture);
    let _ = writeln!(s, "**Cores:** {}", info.cores);
    let _ = writeln!(
        s,
        "**Features ({}):** `{}`",
        info.features.len(),
        info.features.join(" ")
    );
    s.push('\n');
    s.push_str("| Core | Cur (kHz) | Min (kHz) | Max (kHz) | Governor |\n");
    s.push_str("|------|-----------|-----------|-----------|----------|\n");
    for c in &info.per_core {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} |",
            c.id,
            c.cur_freq_khz
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            c.min_freq_khz
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            c.max_freq_khz
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            c.governor.as_deref().unwrap_or("-")
        );
    }
    s
}

// ---------- MemoryInfo ----------

fn kb_to_mb(kb: u64) -> String {
    format!("{:.1} MB", kb as f64 / 1024.0)
}

pub fn memory_text(info: &MemoryInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Total          : {}", kb_to_mb(info.total_kb));
    let _ = writeln!(s, "Free           : {}", kb_to_mb(info.free_kb));
    let _ = writeln!(s, "Available      : {}", kb_to_mb(info.available_kb));
    let _ = writeln!(s, "Buffers        : {}", kb_to_mb(info.buffers_kb));
    let _ = writeln!(s, "Cached         : {}", kb_to_mb(info.cached_kb));
    let _ = writeln!(s, "Swap Total     : {}", kb_to_mb(info.swap_total_kb));
    let _ = writeln!(s, "Swap Free      : {}", kb_to_mb(info.swap_free_kb));
    if info.total_kb > 0 {
        let used_pct = 100.0 * (1.0 - info.available_kb as f64 / info.total_kb as f64);
        let _ = writeln!(s, "Used           : {:.1}%", used_pct);
    }
    s
}

pub fn memory_markdown(info: &MemoryInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("| Field | Value |\n");
    s.push_str("|-------|-------|\n");
    let _ = writeln!(s, "| Total | {} |", kb_to_mb(info.total_kb));
    let _ = writeln!(s, "| Free | {} |", kb_to_mb(info.free_kb));
    let _ = writeln!(s, "| Available | {} |", kb_to_mb(info.available_kb));
    let _ = writeln!(s, "| Buffers | {} |", kb_to_mb(info.buffers_kb));
    let _ = writeln!(s, "| Cached | {} |", kb_to_mb(info.cached_kb));
    let _ = writeln!(s, "| Swap Total | {} |", kb_to_mb(info.swap_total_kb));
    let _ = writeln!(s, "| Swap Free | {} |", kb_to_mb(info.swap_free_kb));
    if info.total_kb > 0 {
        let used_pct = 100.0 * (1.0 - info.available_kb as f64 / info.total_kb as f64);
        let _ = writeln!(s, "| Used | {:.1}% |", used_pct);
    }
    s
}

// ============================================================
// Disk
// ============================================================
use pulse_platform::{DiskInfo, NetworkInfo, ProcessInfo};

fn human_bytes(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", b, UNITS[i])
    } else {
        format!("{:.1} {}", v, UNITS[i])
    }
}

pub fn disk_text(info: &DiskInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Mounts: {}", info.mounts.len());
    s.push('\n');
    let _ = writeln!(
        s,
        "{:<28} {:<10} {:>12} {:>12} {:>12} {:>6}",
        "mount_point", "fs_type", "total", "used", "avail", "use%"
    );
    for m in &info.mounts {
        let total = m.total_bytes.map(human_bytes).unwrap_or_else(|| "-".into());
        let used = m.used_bytes.map(human_bytes).unwrap_or_else(|| "-".into());
        let avail = m
            .available_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "-".into());
        let pct = m
            .use_percent
            .map(|p| format!("{p:.1}"))
            .unwrap_or_else(|| "-".into());
        let mp = if m.mount_point.len() > 28 {
            &m.mount_point[..27]
        } else {
            &m.mount_point
        };
        let _ = writeln!(
            s,
            "{:<28} {:<10} {:>12} {:>12} {:>12} {:>6}",
            mp, m.fs_type, total, used, avail, pct
        );
    }
    s
}

pub fn disk_markdown(info: &DiskInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Mounts:** {}\n", info.mounts.len());
    s.push_str("| Mount | FS | Total | Used | Avail | Use% |\n");
    s.push_str("|-------|-----|-------|------|-------|------|\n");
    for m in &info.mounts {
        let total = m.total_bytes.map(human_bytes).unwrap_or_else(|| "-".into());
        let used = m.used_bytes.map(human_bytes).unwrap_or_else(|| "-".into());
        let avail = m
            .available_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "-".into());
        let pct = m
            .use_percent
            .map(|p| format!("{p:.1}"))
            .unwrap_or_else(|| "-".into());
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} | {} |",
            m.mount_point, m.fs_type, total, used, avail, pct
        );
    }
    s
}

// ============================================================
// Network
// ============================================================

pub fn network_text(info: &NetworkInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Interfaces: {}", info.interfaces.len());
    s.push('\n');
    let _ = writeln!(
        s,
        "{:<14} {:<20} {:<12} {:>6} {:<10}",
        "name", "mac", "state", "mtu", "kind"
    );
    for i in &info.interfaces {
        let _ = writeln!(
            s,
            "{:<14} {:<20} {:<12} {:>6} {:<10}",
            i.name,
            i.mac.as_deref().unwrap_or("-"),
            i.state.as_deref().unwrap_or("-"),
            i.mtu.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            i.kind.as_deref().unwrap_or("-")
        );
    }
    s
}

pub fn network_markdown(info: &NetworkInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Interfaces:** {}\n", info.interfaces.len());
    s.push_str("| Name | MAC | State | MTU | Kind |\n");
    s.push_str("|------|-----|-------|-----|------|\n");
    for i in &info.interfaces {
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} |",
            i.name,
            i.mac.as_deref().unwrap_or("-"),
            i.state.as_deref().unwrap_or("-"),
            i.mtu.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            i.kind.as_deref().unwrap_or("-")
        );
    }
    s
}

// ============================================================
// Process
// ============================================================

pub fn process_text(info: &ProcessInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Total processes: {}", info.total);
    s.push('\n');
    let _ = writeln!(
        s,
        "{:>7} {:>7} {:<24} {:<6} {:>8} {:>10}",
        "pid", "ppid", "name", "state", "threads", "rss(MB)"
    );
    for p in &info.processes {
        let rss_mb = (p.rss_pages as f64 * 4.0) / 1024.0;
        let name = if p.name.len() > 24 {
            &p.name[..24]
        } else {
            &p.name
        };
        let _ = writeln!(
            s,
            "{:>7} {:>7} {:<24} {:<6} {:>8} {:>10.1}",
            p.pid, p.ppid, name, p.state, p.threads, rss_mb
        );
    }
    s
}

pub fn process_markdown(info: &ProcessInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Total processes:** {}\n", info.total);
    s.push_str("| PID | PPID | Name | State | Threads | RSS (MB) |\n");
    s.push_str("|-----|------|------|-------|---------|----------|\n");
    for p in &info.processes {
        let rss_mb = (p.rss_pages as f64 * 4.0) / 1024.0;
        let _ = writeln!(
            s,
            "| {} | {} | `{}` | {} | {} | {:.1} |",
            p.pid, p.ppid, p.name, p.state, p.threads, rss_mb
        );
    }
    s
}

// ============================================================
// Thermal
// ============================================================
use pulse_platform::{GpuInfo, ThermalInfo};

pub fn thermal_text(info: &ThermalInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Zones: {}", info.zones.len());
    s.push('\n');
    let _ = writeln!(s, "{:<30} {:>12}", "zone", "temp (C)");
    for z in &info.zones {
        let _ = writeln!(s, "{:<30} {:>12.2}", z.name, z.temp_celsius);
    }
    s
}

pub fn thermal_markdown(info: &ThermalInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Zones:** {}\n", info.zones.len());
    s.push_str("| Zone | Temp (C) |\n|------|----------|\n");
    for z in &info.zones {
        let _ = writeln!(s, "| `{}` | {:.2} |", z.name, z.temp_celsius);
    }
    s
}

pub fn gpu_text(info: &GpuInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Devices: {}", info.detected.len());
    s.push('\n');
    let _ = writeln!(s, "{:<16} {:<24} path", "driver", "kind");
    for d in &info.detected {
        let _ = writeln!(s, "{:<16} {:<24} {}", d.driver, d.kind, d.path);
    }
    s
}

pub fn gpu_markdown(info: &GpuInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Devices:** {}\n", info.detected.len());
    s.push_str("| Driver | Kind | Path |\n|--------|------|------|\n");
    for d in &info.detected {
        let _ = writeln!(s, "| {} | {} | `{}` |", d.driver, d.kind, d.path);
    }
    s
}

// ============================================================
// Memory Detail
// ============================================================
use pulse_platform::{CpuTimes, LoadAvg, MemoryDetail, VmStat};

pub fn memory_detail_text(info: &MemoryDetail) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let mb = |k: u64| format!("{:>10.1} MB", k as f64 / 1024.0);
    let _ = writeln!(s, "=== MEMORY (detailed) ===\n");
    let _ = writeln!(s, "Total           {}", mb(info.total_kb));
    let _ = writeln!(s, "Free            {}", mb(info.free_kb));
    let _ = writeln!(s, "Available       {}", mb(info.available_kb));
    s.push('\n');
    let _ = writeln!(s, "[Cache]");
    let _ = writeln!(s, "Buffers         {}", mb(info.buffers_kb));
    let _ = writeln!(s, "Cached          {}", mb(info.cached_kb));
    let _ = writeln!(s, "SwapCached      {}", mb(info.swap_cached_kb));
    let _ = writeln!(s, "Shmem           {}", mb(info.shmem_kb));
    s.push('\n');
    let _ = writeln!(s, "[Active/Inactive]");
    let _ = writeln!(s, "Active          {}", mb(info.active_kb));
    let _ = writeln!(s, "Inactive        {}", mb(info.inactive_kb));
    let _ = writeln!(s, "Active(anon)    {}", mb(info.active_anon_kb));
    let _ = writeln!(s, "Inactive(anon)  {}", mb(info.inactive_anon_kb));
    let _ = writeln!(s, "Active(file)    {}", mb(info.active_file_kb));
    let _ = writeln!(s, "Inactive(file)  {}", mb(info.inactive_file_kb));
    s.push('\n');
    let _ = writeln!(s, "[Kernel]");
    let _ = writeln!(s, "Slab            {}", mb(info.slab_kb));
    let _ = writeln!(s, "SReclaimable    {}", mb(info.sreclaimable_kb));
    let _ = writeln!(s, "SUnreclaim      {}", mb(info.sunreclaim_kb));
    let _ = writeln!(s, "KernelStack     {}", mb(info.kernel_stack_kb));
    let _ = writeln!(s, "PageTables      {}", mb(info.page_tables_kb));
    let _ = writeln!(s, "KReclaimable    {}", mb(info.k_reclaimable_kb));
    s.push('\n');
    let _ = writeln!(s, "[Anonymous/Mapped]");
    let _ = writeln!(s, "AnonPages       {}", mb(info.anon_pages_kb));
    let _ = writeln!(s, "Mapped          {}", mb(info.mapped_kb));
    s.push('\n');
    let _ = writeln!(s, "[Swap]");
    let _ = writeln!(s, "Total           {}", mb(info.swap_total_kb));
    let _ = writeln!(s, "Free            {}", mb(info.swap_free_kb));
    s.push('\n');
    let _ = writeln!(s, "[Commit]");
    let _ = writeln!(s, "CommitLimit     {}", mb(info.commit_limit_kb));
    let _ = writeln!(s, "Committed_AS    {}", mb(info.committed_as_kb));
    s.push('\n');
    let _ = writeln!(s, "[HugePages]");
    let _ = writeln!(s, "Total           {}", info.hugepages_total);
    let _ = writeln!(s, "Free            {}", info.hugepages_free);
    let _ = writeln!(s, "Size            {} KB", info.hugepagesize_kb);
    s
}

pub fn memory_detail_markdown(info: &MemoryDetail) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let mb = |k: u64| format!("{:.1} MB", k as f64 / 1024.0);
    s.push_str("# Memory (detailed)\n\n");
    s.push_str("| Field | Value |\n|-------|-------|\n");
    let _ = writeln!(s, "| Total | {} |", mb(info.total_kb));
    let _ = writeln!(s, "| Free | {} |", mb(info.free_kb));
    let _ = writeln!(s, "| Available | {} |", mb(info.available_kb));
    let _ = writeln!(s, "| Buffers | {} |", mb(info.buffers_kb));
    let _ = writeln!(s, "| Cached | {} |", mb(info.cached_kb));
    let _ = writeln!(s, "| Active | {} |", mb(info.active_kb));
    let _ = writeln!(s, "| Inactive | {} |", mb(info.inactive_kb));
    let _ = writeln!(s, "| Slab | {} |", mb(info.slab_kb));
    let _ = writeln!(s, "| SReclaimable | {} |", mb(info.sreclaimable_kb));
    let _ = writeln!(s, "| SUnreclaim | {} |", mb(info.sunreclaim_kb));
    let _ = writeln!(s, "| KernelStack | {} |", mb(info.kernel_stack_kb));
    let _ = writeln!(s, "| PageTables | {} |", mb(info.page_tables_kb));
    let _ = writeln!(s, "| AnonPages | {} |", mb(info.anon_pages_kb));
    let _ = writeln!(s, "| Mapped | {} |", mb(info.mapped_kb));
    let _ = writeln!(s, "| SwapTotal | {} |", mb(info.swap_total_kb));
    let _ = writeln!(s, "| SwapFree | {} |", mb(info.swap_free_kb));
    s
}

// ============================================================
// Load Average
// ============================================================

pub fn load_text(info: &LoadAvg) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "Load Average (1/5/15 min): {:.2}  {:.2}  {:.2}",
        info.load1, info.load5, info.load15
    );
    let _ = writeln!(
        s,
        "Running / Total tasks    : {} / {}",
        info.running_tasks, info.total_tasks
    );
    let _ = writeln!(s, "Last PID                 : {}", info.last_pid);
    let _ = writeln!(
        s,
        "Uptime                   : {} seconds ({}h {}m)",
        info.uptime_seconds,
        info.uptime_seconds / 3600,
        (info.uptime_seconds % 3600) / 60
    );
    s
}

pub fn load_markdown(info: &LoadAvg) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("| Metric | Value |\n|--------|-------|\n");
    let _ = writeln!(s, "| Load 1min | {:.2} |", info.load1);
    let _ = writeln!(s, "| Load 5min | {:.2} |", info.load5);
    let _ = writeln!(s, "| Load 15min | {:.2} |", info.load15);
    let _ = writeln!(
        s,
        "| Running/Total | {}/{} |",
        info.running_tasks, info.total_tasks
    );
    let _ = writeln!(s, "| Uptime | {} s |", info.uptime_seconds);
    s
}

// ============================================================
// VMStat
// ============================================================

pub fn vmstat_text(info: &VmStat) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("=== VMSTAT (cumulative) ===\n\n");
    let _ = writeln!(s, "[I/O]");
    let _ = writeln!(s, "pgpgin          {}", info.pgpgin);
    let _ = writeln!(s, "pgpgout         {}", info.pgpgout);
    let _ = writeln!(s, "pswpin          {}", info.pswpin);
    let _ = writeln!(s, "pswpout         {}", info.pswpout);
    s.push('\n');
    let _ = writeln!(s, "[Page faults]");
    let _ = writeln!(s, "pgfault         {}", info.pgfault);
    let _ = writeln!(s, "pgmajfault      {}", info.pgmajfault);
    s.push('\n');
    let _ = writeln!(s, "[Page allocation]");
    let _ = writeln!(s, "pgalloc_normal  {}", info.pgalloc_normal);
    let _ = writeln!(s, "pgalloc_movable {}", info.pgalloc_movable);
    let _ = writeln!(s, "pgfree          {}", info.pgfree);
    s.push('\n');
    let _ = writeln!(s, "[Reclaim]");
    let _ = writeln!(s, "pgsteal_kswapd  {}", info.pgsteal_kswapd);
    let _ = writeln!(s, "pgsteal_direct  {}", info.pgsteal_direct);
    let _ = writeln!(s, "pgscan_kswapd   {}", info.pgscan_kswapd);
    let _ = writeln!(s, "pgscan_direct   {}", info.pgscan_direct);
    s.push('\n');
    let _ = writeln!(s, "[Kernel counters]");
    let _ = writeln!(s, "nr_free_pages   {}", info.nr_free_pages);
    let _ = writeln!(s, "nr_active_anon  {}", info.nr_zone_active_anon);
    let _ = writeln!(s, "nr_active_file  {}", info.nr_zone_active_file);
    let _ = writeln!(s, "nr_inactive_anon {}", info.nr_zone_inactive_anon);
    let _ = writeln!(s, "nr_inactive_file {}", info.nr_zone_inactive_file);
    let _ = writeln!(s, "nr_slab_recl    {}", info.nr_slab_reclaimable);
    let _ = writeln!(s, "nr_slab_unrecl  {}", info.nr_slab_unreclaimable);
    let _ = writeln!(s, "nr_dirty        {}", info.nr_dirty);
    let _ = writeln!(s, "nr_writeback    {}", info.nr_writeback);
    let _ = writeln!(s, "nr_shmem        {}", info.nr_shmem);
    s
}

pub fn vmstat_markdown(info: &VmStat) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# VMStat\n\n| Metric | Value |\n|--------|-------|\n");
    let _ = writeln!(s, "| pgpgin | {} |", info.pgpgin);
    let _ = writeln!(s, "| pgpgout | {} |", info.pgpgout);
    let _ = writeln!(s, "| pswpin | {} |", info.pswpin);
    let _ = writeln!(s, "| pswpout | {} |", info.pswpout);
    let _ = writeln!(s, "| pgfault | {} |", info.pgfault);
    let _ = writeln!(s, "| pgmajfault | {} |", info.pgmajfault);
    let _ = writeln!(s, "| pgfree | {} |", info.pgfree);
    let _ = writeln!(s, "| nr_free_pages | {} |", info.nr_free_pages);
    s
}

// ============================================================
// CPU Times
// ============================================================

pub fn cpu_times_text(info: &CpuTimes) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Cores: {}\n", info.per_core.len());
    let _ = writeln!(
        s,
        "{:<6} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "cpu", "user", "nice", "system", "idle", "iowait", "irq"
    );
    let t = &info.total;
    let _ = writeln!(
        s,
        "{:<6} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "all", t.user, t.nice, t.system, t.idle, t.iowait, t.irq
    );
    for c in &info.per_core {
        let _ = writeln!(
            s,
            "{:<6} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
            c.id, c.user, c.nice, c.system, c.idle, c.iowait, c.irq
        );
    }
    s
}

pub fn cpu_times_markdown(info: &CpuTimes) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("| CPU | user | nice | system | idle | iowait | irq | softirq |\n");
    s.push_str("|-----|------|------|--------|------|--------|-----|--------|\n");
    let _ = writeln!(
        s,
        "| all | {} | {} | {} | {} | {} | {} | {} |",
        info.total.user,
        info.total.nice,
        info.total.system,
        info.total.idle,
        info.total.iowait,
        info.total.irq,
        info.total.softirq
    );
    for c in &info.per_core {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            c.id, c.user, c.nice, c.system, c.idle, c.iowait, c.irq, c.softirq
        );
    }
    s
}

// ============================================================
// Users
// ============================================================
use pulse_platform::{EnvInfo, FsInfo, PackagesInfo, ServicesInfo, UsersInfo};

pub fn users_text(info: &UsersInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "Users: {}  |  Groups: {}\n",
        info.users.len(),
        info.groups.len()
    );
    let _ = writeln!(
        s,
        "{:>6} {:>6} {:<20} {:<28} shell",
        "uid", "gid", "name", "home"
    );
    for u in &info.users {
        let _ = writeln!(
            s,
            "{:>6} {:>6} {:<20} {:<28} {}",
            u.uid, u.gid, u.name, u.home, u.shell
        );
    }
    s.push('\n');
    let _ = writeln!(s, "[Groups]");
    for g in &info.groups {
        let members = if g.members.is_empty() {
            "-".to_string()
        } else {
            g.members.join(",")
        };
        let _ = writeln!(s, "  {:>6} {:<20} {}", g.gid, g.name, members);
    }
    s
}

pub fn users_markdown(info: &UsersInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "**Users:** {}  |  **Groups:** {}\n",
        info.users.len(),
        info.groups.len()
    );
    s.push_str("| UID | GID | Name | Home | Shell |\n|-----|-----|------|------|-------|\n");
    for u in &info.users {
        let _ = writeln!(
            s,
            "| {} | {} | `{}` | `{}` | `{}` |",
            u.uid, u.gid, u.name, u.home, u.shell
        );
    }
    s
}

// ============================================================
// Packages
// ============================================================

pub fn packages_text(info: &PackagesInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Manager: {}  |  Total: {}", info.manager, info.total);
    s.push('\n');
    for p in info.packages.iter().take(100) {
        let _ = writeln!(s, "{:<40} {}", p.name, p.version);
    }
    if info.packages.len() > 100 {
        let _ = writeln!(s, "... +{} more", info.packages.len() - 100);
    }
    s
}

pub fn packages_markdown(info: &PackagesInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "**Manager:** {}  |  **Total:** {}\n",
        info.manager, info.total
    );
    s.push_str("| Package | Version |\n|---------|---------|\n");
    for p in info.packages.iter().take(200) {
        let _ = writeln!(s, "| `{}` | {} |", p.name, p.version);
    }
    s
}

// ============================================================
// Services
// ============================================================

pub fn services_text(info: &ServicesInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Init: {}  |  Total: {}\n", info.init_system, info.total);
    for svc in &info.services {
        let state = match svc.enabled {
            Some(true) => "enabled",
            Some(false) => "disabled",
            None => "unknown",
        };
        let _ = writeln!(s, "  {:<40} {:<10} {}", svc.name, svc.kind, state);
    }
    s
}

pub fn services_markdown(info: &ServicesInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "**Init:** {}  |  **Total:** {}\n",
        info.init_system, info.total
    );
    s.push_str("| Service | Kind | State |\n|---------|------|-------|\n");
    for svc in &info.services {
        let state = match svc.enabled {
            Some(true) => "enabled",
            Some(false) => "disabled",
            None => "unknown",
        };
        let _ = writeln!(s, "| `{}` | {} | {} |", svc.name, svc.kind, state);
    }
    s
}

// ============================================================
// Filesystem
// ============================================================

pub fn fs_text(info: &FsInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Roots: {}\n", info.roots.len());
    let _ = writeln!(
        s,
        "{:<16} {:<12} {:>10} readable",
        "path", "kind", "entries"
    );
    for r in &info.roots {
        let _ = writeln!(
            s,
            "{:<16} {:<12} {:>10} {}",
            r.path,
            r.kind,
            r.entries,
            if r.readable { "yes" } else { "no" }
        );
    }
    s
}

pub fn fs_markdown(info: &FsInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Roots:** {}\n", info.roots.len());
    s.push_str("| Path | Kind | Entries | Readable |\n|------|------|---------|----------|\n");
    for r in &info.roots {
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} |",
            r.path,
            r.kind,
            r.entries,
            if r.readable { "yes" } else { "no" }
        );
    }
    s
}

// ============================================================
// Environment
// ============================================================

pub fn env_text(info: &EnvInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Variables: {}\n", info.total);
    for e in &info.entries {
        let v = if e.value.len() > 80 {
            format!("{}...", &e.value[..77])
        } else {
            e.value.clone()
        };
        let _ = writeln!(s, "{:<32} {}", e.key, v);
    }
    s
}

pub fn env_markdown(info: &EnvInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Variables:** {}\n", info.total);
    s.push_str("| Key | Value |\n|-----|-------|\n");
    for e in &info.entries {
        let v = e.value.replace('|', "\\|");
        let _ = writeln!(s, "| `{}` | `{}` |", e.key, v);
    }
    s
}

// ============================================================
// USB
// ============================================================
use pulse_platform::{BatteryInfo, DriversInfo, PciInfo, SensorsInfo, UsbInfo};

pub fn usb_text(info: &UsbInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "USB devices: {}\n", info.total);
    let _ = writeln!(
        s,
        "{:<16} {:<10} {:<10} {:<20} product",
        "name", "vendor", "product", "manufacturer"
    );
    for d in &info.devices {
        let _ = writeln!(
            s,
            "{:<16} {:<10} {:<10} {:<20} {}",
            d.name,
            d.id_vendor.as_deref().unwrap_or("-"),
            d.id_product.as_deref().unwrap_or("-"),
            d.manufacturer.as_deref().unwrap_or("-"),
            d.product.as_deref().unwrap_or("-")
        );
    }
    s
}

pub fn usb_markdown(info: &UsbInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**USB devices:** {}\n", info.total);
    s.push_str("| Name | VID | PID | Manufacturer | Product |\n|------|-----|-----|--------------|---------|\n");
    for d in &info.devices {
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} |",
            d.name,
            d.id_vendor.as_deref().unwrap_or("-"),
            d.id_product.as_deref().unwrap_or("-"),
            d.manufacturer.as_deref().unwrap_or("-"),
            d.product.as_deref().unwrap_or("-")
        );
    }
    s
}

// ============================================================
// PCI
// ============================================================

pub fn pci_text(info: &PciInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "PCI devices: {}\n", info.total);
    let _ = writeln!(
        s,
        "{:<16} {:<10} {:<10} {:<10} driver",
        "slot", "vendor", "device", "class"
    );
    for d in &info.devices {
        let _ = writeln!(
            s,
            "{:<16} {:<10} {:<10} {:<10} {}",
            d.slot,
            d.vendor.as_deref().unwrap_or("-"),
            d.device.as_deref().unwrap_or("-"),
            d.class.as_deref().unwrap_or("-"),
            d.driver.as_deref().unwrap_or("-")
        );
    }
    s
}

pub fn pci_markdown(info: &PciInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**PCI devices:** {}\n", info.total);
    s.push_str("| Slot | Vendor | Device | Class | Driver |\n|------|--------|--------|-------|--------|\n");
    for d in &info.devices {
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} |",
            d.slot,
            d.vendor.as_deref().unwrap_or("-"),
            d.device.as_deref().unwrap_or("-"),
            d.class.as_deref().unwrap_or("-"),
            d.driver.as_deref().unwrap_or("-")
        );
    }
    s
}

// ============================================================
// Battery
// ============================================================

pub fn battery_text(info: &BatteryInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Batteries: {}\n", info.total);
    for b in &info.batteries {
        let _ = writeln!(s, "[{}]", b.name);
        let _ = writeln!(
            s,
            "  Capacity    : {}%",
            b.capacity
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        );
        let _ = writeln!(s, "  Status      : {}", b.status.as_deref().unwrap_or("-"));
        let _ = writeln!(s, "  Health      : {}", b.health.as_deref().unwrap_or("-"));
        let _ = writeln!(
            s,
            "  Technology  : {}",
            b.technology.as_deref().unwrap_or("-")
        );
        if let Some(uv) = b.voltage_uv {
            let _ = writeln!(s, "  Voltage     : {:.3} V", uv as f64 / 1_000_000.0);
        }
        if let Some(ua) = b.current_ua {
            let _ = writeln!(s, "  Current     : {:.3} A", ua as f64 / 1_000_000.0);
        }
        if let Some(dc) = b.temp_dc {
            let _ = writeln!(s, "  Temperature : {:.1} C", dc as f64 / 10.0);
        }
        if let Some(c) = b.cycle_count {
            let _ = writeln!(s, "  Cycles      : {}", c);
        }
        s.push('\n');
    }
    s
}

pub fn battery_markdown(info: &BatteryInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Batteries:** {}\n", info.total);
    for b in &info.batteries {
        let _ = writeln!(s, "### {}\n", b.name);
        s.push_str("| Field | Value |\n|-------|-------|\n");
        let _ = writeln!(
            s,
            "| Capacity | {}% |",
            b.capacity
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        );
        let _ = writeln!(s, "| Status | {} |", b.status.as_deref().unwrap_or("-"));
        let _ = writeln!(s, "| Health | {} |", b.health.as_deref().unwrap_or("-"));
        let _ = writeln!(
            s,
            "| Technology | {} |",
            b.technology.as_deref().unwrap_or("-")
        );
        s.push('\n');
    }
    s
}

// ============================================================
// Sensors
// ============================================================

pub fn sensors_text(info: &SensorsInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Chips: {}\n", info.total);
    for chip in &info.chips {
        let _ = writeln!(s, "[{}]  ({})", chip.name, chip.path);
        if chip.temps.is_empty() {
            let _ = writeln!(s, "  (no temperature inputs)");
        } else {
            for t in &chip.temps {
                let label = t.label.as_deref().unwrap_or("-");
                let _ = writeln!(s, "  {:<24} {:>8.2} C", label, t.celsius);
            }
        }
        s.push('\n');
    }
    s
}

pub fn sensors_markdown(info: &SensorsInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Chips:** {}\n", info.total);
    for chip in &info.chips {
        let _ = writeln!(s, "### {} (`{}`)\n", chip.name, chip.path);
        if !chip.temps.is_empty() {
            s.push_str("| Sensor | Temp (C) |\n|--------|----------|\n");
            for t in &chip.temps {
                let _ = writeln!(
                    s,
                    "| {} | {:.2} |",
                    t.label.as_deref().unwrap_or("-"),
                    t.celsius
                );
            }
            s.push('\n');
        }
    }
    s
}

// ============================================================
// Drivers
// ============================================================

pub fn drivers_text(info: &DriversInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Kernel modules: {}\n", info.total);
    let _ = writeln!(s, "{:<32} {:>12} {:>6} deps", "name", "size (KB)", "refs");
    for m in &info.modules {
        let deps = if m.deps.is_empty() {
            "-".to_string()
        } else {
            m.deps.join(",")
        };
        let _ = writeln!(
            s,
            "{:<32} {:>12.1} {:>6} {}",
            m.name,
            m.size as f64 / 1024.0,
            m.refs,
            deps
        );
    }
    s
}

pub fn drivers_markdown(info: &DriversInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Kernel modules:** {}\n", info.total);
    s.push_str("| Module | Size (KB) | Refs | Deps |\n|--------|-----------|------|------|\n");
    for m in &info.modules {
        let deps = if m.deps.is_empty() {
            "-".to_string()
        } else {
            m.deps.join(", ")
        };
        let _ = writeln!(
            s,
            "| `{}` | {:.1} | {} | {} |",
            m.name,
            m.size as f64 / 1024.0,
            m.refs,
            deps
        );
    }
    s
}

// ============================================================
// Containers
// ============================================================
use pulse_platform::{BrowsersInfo, ContainersInfo, CronInfo, CryptoInfo, VmInfo};

pub fn containers_text(info: &ContainersInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Detected: {}", if info.detected { "yes" } else { "no" });
    let _ = writeln!(s, "Runtime : {}", info.runtime.as_deref().unwrap_or("none"));
    s.push('\n');
    if info.evidences.is_empty() {
        s.push_str("No container evidence found.\n");
    } else {
        s.push_str("Evidence:\n");
        for e in &info.evidences {
            let _ = writeln!(s, "  - {}", e);
        }
    }
    s
}

pub fn containers_markdown(info: &ContainersInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "**Detected:** {}",
        if info.detected { "yes" } else { "no" }
    );
    let _ = writeln!(
        s,
        "**Runtime:** {}",
        info.runtime.as_deref().unwrap_or("none")
    );
    s.push_str("\n| Evidence |\n|----------|\n");
    for e in &info.evidences {
        let _ = writeln!(s, "| {} |", e);
    }
    s
}

// ============================================================
// VM
// ============================================================

pub fn vm_text(info: &VmInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "Is Virtual Machine: {}",
        if info.is_vm { "yes" } else { "no" }
    );
    let _ = writeln!(
        s,
        "Hypervisor        : {}",
        info.hypervisor.as_deref().unwrap_or("none")
    );
    let _ = writeln!(
        s,
        "Product           : {}",
        info.product_name.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        s,
        "Vendor            : {}",
        info.sys_vendor.as_deref().unwrap_or("-")
    );
    s.push('\n');
    if info.evidences.is_empty() {
        s.push_str("No virtualization evidence found.\n");
    } else {
        s.push_str("Evidence:\n");
        for e in &info.evidences {
            let _ = writeln!(s, "  - {}", e);
        }
    }
    s
}

pub fn vm_markdown(info: &VmInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "| Field | Value |");
    let _ = writeln!(s, "|-------|-------|");
    let _ = writeln!(s, "| Is VM | {} |", if info.is_vm { "yes" } else { "no" });
    let _ = writeln!(
        s,
        "| Hypervisor | {} |",
        info.hypervisor.as_deref().unwrap_or("none")
    );
    let _ = writeln!(
        s,
        "| Product | {} |",
        info.product_name.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        s,
        "| Vendor | {} |",
        info.sys_vendor.as_deref().unwrap_or("-")
    );
    s
}

// ============================================================
// Browsers
// ============================================================

pub fn browsers_text(info: &BrowsersInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Detected: {}", info.total);
    s.push('\n');
    s.push_str("name                 kind       path\n");
    for b in &info.detected {
        let _ = writeln!(s, "{:<20} {:<10} {}", b.name, b.kind, b.path);
    }
    s
}

pub fn browsers_markdown(info: &BrowsersInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "**Detected:** {}\n", info.total);
    s.push_str("| Name | Kind | Path |\n|------|------|------|\n");
    for b in &info.detected {
        let _ = writeln!(s, "| {} | {} | `{}` |", b.name, b.kind, b.path);
    }
    s
}

// ============================================================
// Crypto
// ============================================================

pub fn crypto_text(info: &CryptoInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "SSL certs (count)  : {}", info.ssl_certs_count);
    let _ = writeln!(
        s,
        "GnuPG              : {}",
        if info.has_gnupg { "yes" } else { "no" }
    );
    let _ = writeln!(
        s,
        "GnuPG path         : {}",
        info.gnupg_path.as_deref().unwrap_or("-")
    );
    s.push('\n');
    let _ = writeln!(s, "System SSH keys ({})", info.system_ssh_keys.len());
    for k in &info.system_ssh_keys {
        let _ = writeln!(s, "  {}", k);
    }
    s.push('\n');
    let _ = writeln!(s, "User SSH keys ({})", info.user_ssh_keys.len());
    for k in &info.user_ssh_keys {
        let _ = writeln!(s, "  {}", k);
    }
    s
}

pub fn crypto_markdown(info: &CryptoInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "| Metric | Value |");
    let _ = writeln!(s, "|--------|-------|");
    let _ = writeln!(s, "| SSL certs | {} |", info.ssl_certs_count);
    let _ = writeln!(s, "| System SSH keys | {} |", info.system_ssh_keys.len());
    let _ = writeln!(s, "| User SSH keys | {} |", info.user_ssh_keys.len());
    let _ = writeln!(
        s,
        "| GnuPG | {} |",
        if info.has_gnupg { "yes" } else { "no" }
    );
    s
}

// ============================================================
// Cron
// ============================================================

pub fn cron_text(info: &CronInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "/etc/crontab      : {}",
        if info.has_etc_crontab { "yes" } else { "no" }
    );
    s.push('\n');
    let _ = writeln!(s, "System cron files ({})", info.system_files.len());
    for f in &info.system_files {
        let _ = writeln!(s, "  {}", f);
    }
    s.push('\n');
    let _ = writeln!(s, "System cron dirs ({})", info.system_dirs.len());
    for d in &info.system_dirs {
        let _ = writeln!(s, "  {}", d);
    }
    s.push('\n');
    let _ = writeln!(s, "User crontabs ({})", info.user_crontabs.len());
    for u in &info.user_crontabs {
        let _ = writeln!(s, "  {}", u);
    }
    s
}

pub fn cron_markdown(info: &CronInfo) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "| Metric | Value |");
    let _ = writeln!(s, "|--------|-------|");
    let _ = writeln!(
        s,
        "| /etc/crontab | {} |",
        if info.has_etc_crontab { "yes" } else { "no" }
    );
    let _ = writeln!(s, "| System cron files | {} |", info.system_files.len());
    let _ = writeln!(s, "| System cron dirs | {} |", info.system_dirs.len());
    let _ = writeln!(s, "| User crontabs | {} |", info.user_crontabs.len());
    s
}

// ============================================================
// HWID
// ============================================================
use pulse_platform::HwidInfo;

pub fn hwid_text(info: &HwidInfo, verbose: bool) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "=== PULSE HWID ===");
    s.push('\n');
    let _ = writeln!(s, "HWID     : {}", info.hash);
    let _ = writeln!(s, "Mode     : {}", info.mode);
    if let Some(ctx) = &info.context {
        let _ = writeln!(s, "Context  : {}", ctx);
    }
    let _ = writeln!(
        s,
        "Sources  : {} / {} active ({:.0}% confidence)",
        info.active_count,
        info.total_count,
        info.confidence * 100.0
    );
    if info.confidence < 0.5 {
        let _ = writeln!(s, "Warning  : Low confidence — HWID may vary across runs");
        let _ = writeln!(s, "           Run with root for stable HWID");
    }
    s.push('\n');
    if verbose {
        s.push_str("Source breakdown:\n");
        for src in &info.sources {
            let mark = if src.available { "+" } else { "-" };
            let val = src.value.as_deref().unwrap_or("(unavailable)");
            let _ = writeln!(
                s,
                "  [{}] {:<20} (w={:>2}) {}",
                mark, src.name, src.weight, val
            );
        }
        s.push('\n');
        s.push_str("Formula: SHA-256(VERSION_TAG + sources + context)\n");
        s.push_str("Stable across reinstall. Changes only on hardware change.\n");
    }
    s
}

pub fn hwid_markdown(info: &HwidInfo, verbose: bool) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# Pulse HWID\n\n");
    let _ = writeln!(s, "| Field | Value |");
    let _ = writeln!(s, "|-------|-------|");
    let _ = writeln!(s, "| HWID | `{}` |", info.hash);
    let _ = writeln!(s, "| Mode | {} |", info.mode);
    if let Some(ctx) = &info.context {
        let _ = writeln!(s, "| Context | {} |", ctx);
    }
    let _ = writeln!(
        s,
        "| Active sources | {} / {} |",
        info.active_count, info.total_count
    );
    let _ = writeln!(s, "| Confidence | {:.0}% |", info.confidence * 100.0);
    s.push('\n');
    if verbose {
        s.push_str("## Sources\n\n| Name | Weight | Available | Value |\n|------|--------|-----------|-------|\n");
        for src in &info.sources {
            let _ = writeln!(
                s,
                "| `{}` | {} | {} | `{}` |",
                src.name,
                src.weight,
                if src.available { "yes" } else { "no" },
                src.value.as_deref().unwrap_or("-")
            );
        }
    }
    s
}
