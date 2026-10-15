//! Data structures returned by platform introspection.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub hostname: String,
    pub uptime_seconds: u64,
    pub boot_time_unix: u64,
    pub architecture: String,
    pub pointer_width: u8,
    pub endianness: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub model: String,
    pub architecture: String,
    pub cores: u32,
    pub features: Vec<String>,
    pub per_core: Vec<CoreInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreInfo {
    pub id: u32,
    pub cur_freq_khz: Option<u64>,
    pub min_freq_khz: Option<u64>,
    pub max_freq_khz: Option<u64>,
    pub governor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_kb: u64,
    pub free_kb: u64,
    pub available_kb: u64,
    pub buffers_kb: u64,
    pub cached_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

// ------------------- Disk -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub mounts: Vec<MountInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub options: String,
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub use_percent: Option<f64>,
}

// ------------------- Network -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetInterface {
    pub name: String,
    pub mac: Option<String>,
    pub state: Option<String>,
    pub mtu: Option<u64>,
    pub kind: Option<String>,
}

// ------------------- Process -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub total: u32,
    pub processes: Vec<ProcessEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub state: String,
    pub threads: u32,
    pub rss_pages: u64,
}

// ------------------- Thermal -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermalInfo {
    pub zones: Vec<ThermalZone>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermalZone {
    pub name: String,
    pub temp_millicelsius: i64,
    pub temp_celsius: f64,
}

// ------------------- GPU -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub detected: Vec<GpuDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDevice {
    pub driver: String,
    pub path: String,
    pub kind: String,
}

// ------------------- Extended Memory -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDetail {
    // Core
    pub total_kb: u64,
    pub free_kb: u64,
    pub available_kb: u64,
    // Cache
    pub buffers_kb: u64,
    pub cached_kb: u64,
    pub swap_cached_kb: u64,
    pub shmem_kb: u64,
    // Active / Inactive
    pub active_kb: u64,
    pub inactive_kb: u64,
    pub active_anon_kb: u64,
    pub inactive_anon_kb: u64,
    pub active_file_kb: u64,
    pub inactive_file_kb: u64,
    // Unevictable
    pub unevictable_kb: u64,
    pub mlocked_kb: u64,
    // Kernel
    pub slab_kb: u64,
    pub sreclaimable_kb: u64,
    pub sunreclaim_kb: u64,
    pub kernel_stack_kb: u64,
    pub page_tables_kb: u64,
    pub k_reclaimable_kb: u64,
    // Anonymous / Mapped
    pub anon_pages_kb: u64,
    pub mapped_kb: u64,
    // Dirty
    pub dirty_kb: u64,
    pub writeback_kb: u64,
    // Commit
    pub commit_limit_kb: u64,
    pub committed_as_kb: u64,
    // Vmalloc
    pub vmalloc_total_kb: u64,
    pub vmalloc_used_kb: u64,
    pub vmalloc_chunk_kb: u64,
    // HugePages
    pub hugepages_total: u64,
    pub hugepages_free: u64,
    pub hugepagesize_kb: u64,
    // Swap
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

// ------------------- Load Average -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAvg {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub running_tasks: u32,
    pub total_tasks: u32,
    pub last_pid: u32,
    pub uptime_seconds: u64,
}

// ------------------- VMStat -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmStat {
    pub pgpgin: u64,
    pub pgpgout: u64,
    pub pswpin: u64,
    pub pswpout: u64,
    pub pgfault: u64,
    pub pgmajfault: u64,
    pub pgalloc_dma: u64,
    pub pgalloc_dma32: u64,
    pub pgalloc_normal: u64,
    pub pgalloc_movable: u64,
    pub pgfree: u64,
    pub pgactivate: u64,
    pub pgdeactivate: u64,
    pub pglazyfree: u64,
    pub pglazyfreed: u64,
    pub pgsteal_kswapd: u64,
    pub pgsteal_direct: u64,
    pub pgscan_kswapd: u64,
    pub pgscan_direct: u64,
    pub nr_free_pages: u64,
    pub nr_zone_inactive_anon: u64,
    pub nr_zone_active_anon: u64,
    pub nr_zone_inactive_file: u64,
    pub nr_zone_active_file: u64,
    pub nr_slab_reclaimable: u64,
    pub nr_slab_unreclaimable: u64,
    pub nr_dirty: u64,
    pub nr_writeback: u64,
    pub nr_shmem: u64,
    pub nr_kernel_misc_reclaimable: u64,
}

// ------------------- CPU Times (from /proc/stat) -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuTimes {
    pub per_core: Vec<CoreTimes>,
    pub total: CoreTimes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreTimes {
    pub id: i32, // -1 = "cpu" aggregate
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

// ------------------- Users -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersInfo {
    pub users: Vec<UserEntry>,
    pub groups: Vec<GroupEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

// ------------------- Packages -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackagesInfo {
    pub manager: String,
    pub total: u32,
    pub packages: Vec<PackageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    pub status: String,
}

// ------------------- Services -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesInfo {
    pub init_system: String,
    pub total: u32,
    pub services: Vec<ServiceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub kind: String,
    pub enabled: Option<bool>,
}

// ------------------- Filesystem -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsInfo {
    pub roots: Vec<FsNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsNode {
    pub path: String,
    pub kind: String,
    pub size_bytes: Option<u64>,
    pub entries: u32,
    pub readable: bool,
}

// ------------------- Environment -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvInfo {
    pub total: u32,
    pub entries: Vec<EnvEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvEntry {
    pub key: String,
    pub value: String,
}

// ------------------- USB -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbInfo {
    pub total: u32,
    pub devices: Vec<UsbDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub name: String,
    pub id_vendor: Option<String>,
    pub id_product: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub bclass: Option<String>,
}

// ------------------- PCI -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PciInfo {
    pub total: u32,
    pub devices: Vec<PciDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PciDevice {
    pub slot: String,
    pub vendor: Option<String>,
    pub device: Option<String>,
    pub class: Option<String>,
    pub driver: Option<String>,
}

// ------------------- Battery -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryInfo {
    pub total: u32,
    pub batteries: Vec<BatteryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatteryEntry {
    pub name: String,
    pub capacity: Option<u32>,
    pub status: Option<String>,
    pub health: Option<String>,
    pub technology: Option<String>,
    pub voltage_uv: Option<u64>,
    pub current_ua: Option<i64>,
    pub temp_dc: Option<i32>,
    pub cycle_count: Option<u32>,
}

// ------------------- Sensors (hwmon) -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorsInfo {
    pub total: u32,
    pub chips: Vec<SensorChip>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorChip {
    pub name: String,
    pub path: String,
    pub temps: Vec<SensorReading>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReading {
    pub label: Option<String>,
    pub celsius: f64,
}

// ------------------- Drivers (/proc/modules) -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriversInfo {
    pub total: u32,
    pub modules: Vec<DriverModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverModule {
    pub name: String,
    pub size: u64,
    pub refs: u32,
    pub deps: Vec<String>,
    pub state: String,
}

// ------------------- Containers -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainersInfo {
    pub detected: bool,
    pub runtime: Option<String>,
    pub evidences: Vec<String>,
}

// ------------------- Virtualization -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInfo {
    pub is_vm: bool,
    pub hypervisor: Option<String>,
    pub product_name: Option<String>,
    pub sys_vendor: Option<String>,
    pub evidences: Vec<String>,
}

// ------------------- Browsers -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowsersInfo {
    pub total: u32,
    pub detected: Vec<BrowserEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserEntry {
    pub name: String,
    pub kind: String,
    pub path: String,
}

// ------------------- Crypto -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoInfo {
    pub ssl_certs_count: u32,
    pub system_ssh_keys: Vec<String>,
    pub user_ssh_keys: Vec<String>,
    pub has_gnupg: bool,
    pub gnupg_path: Option<String>,
}

// ------------------- Cron -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronInfo {
    pub has_etc_crontab: bool,
    pub system_files: Vec<String>,
    pub system_dirs: Vec<String>,
    pub user_crontabs: Vec<String>,
}

// ------------------- HWID -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwidInfo {
    pub hash: String,
    pub mode: String,
    pub context: Option<String>,
    pub active_count: u32,
    pub total_count: u32,
    pub confidence: f32,
    pub sources: Vec<HwidSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HwidSource {
    pub name: String,
    pub value: Option<String>,
    pub available: bool,
    pub weight: u32,
}
