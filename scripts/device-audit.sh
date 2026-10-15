#!/usr/bin/env bash
# Android Device Identity Audit
# Read-only inventory. No installation, network access, or system changes.

set -u
export LC_ALL=C

if [ -t 1 ]; then
    BLUE='\033[1;34m'
    CYAN='\033[1;36m'
    GREEN='\033[1;32m'
    YELLOW='\033[1;33m'
    RESET='\033[0m'
else
    BLUE='' CYAN='' GREEN='' YELLOW='' RESET=''
fi

section() {
    printf '\n%b\n' "${BLUE}============================================================${RESET}"
    printf '%b\n' "${CYAN}$*${RESET}"
    printf '%b\n' "${BLUE}============================================================${RESET}"
}

read_value() {
    local label="$1" path="$2" value
    if [ -r "$path" ]; then
        value="$(cat "$path" 2>/dev/null)"
        value="${value:-empty}"
        value="$(printf '%s' "$value" | tr '\000' ' ' | head -c 400)"
    else
        value="unavailable"
    fi
    printf '%-30s : %s\n' "$label" "$value"
}

section "DEVICE AND ENVIRONMENT"
printf 'Timestamp: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
printf 'Hostname : %s\n' "$(hostname 2>/dev/null || echo unknown)"
printf 'Identity : %s\n' "$(id)"
printf 'PWD      : %s\n' "$PWD"
printf 'Shell    : %s\n' "${SHELL:-unknown}"

section "LINUX KERNEL"
printf 'Kernel       : %s\n' "$(uname -r)"
printf 'Architecture : %s\n' "$(uname -m)"
printf 'Kernel build : %s\n' "$(uname -v)"
read_value "Kernel version details" /proc/version
read_value "Device-tree model" /proc/device-tree/model
read_value "Device-tree compatible" /proc/device-tree/compatible

section "ANDROID DEVICE PROPERTIES"
if command -v getprop >/dev/null 2>&1; then
    for prop in \
        ro.product.manufacturer \
        ro.product.brand \
        ro.product.model \
        ro.product.marketname \
        ro.product.device \
        ro.product.name \
        ro.product.board \
        ro.board.platform \
        ro.hardware \
        ro.boot.hardware \
        ro.soc.manufacturer \
        ro.soc.model \
        ro.build.version.release \
        ro.build.version.sdk \
        ro.build.version.incremental \
        ro.build.id \
        ro.build.fingerprint \
        ro.boot.product.hardware.sku; do
        value="$(getprop "$prop" 2>/dev/null)"
        printf '%-36s : %s\n' "$prop" "${value:-unavailable}"
    done
else
    echo "getprop unavailable in this environment."
fi

section "CPU AND SOC"
read_value "CPU info" /proc/cpuinfo
read_value "Online CPUs" /sys/devices/system/cpu/online

for c in /sys/devices/system/cpu/cpu[0-9]*; do
    [ -d "$c" ] || continue
    cpu="${c##*/}"
    printf '\n[%s]\n' "$cpu"
    for f in scaling_cur_freq scaling_min_freq scaling_max_freq \
             cpuinfo_max_freq scaling_governor; do
        read_value "$f" "$c/cpufreq/$f"
    done
done

section "MEMORY AND ZRAM"
if [ -r /proc/meminfo ]; then
    grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|Shmem|SReclaimable|SwapTotal|SwapFree):' \
        /proc/meminfo
fi

if [ -r /proc/swaps ]; then
    printf '\n'
    cat /proc/swaps
fi

if [ -d /sys/block ]; then
    for z in /sys/block/zram*; do
        [ -e "$z" ] || continue
        printf '\n[%s]\n' "${z##*/}"
        read_value "Disk size" "$z/disksize"
        read_value "Compression algorithm" "$z/comp_algorithm"
        read_value "ZRAM mm_stat" "$z/mm_stat"
    done
fi

section "STORAGE"
df -hT / /data /storage/emulated/0 2>/dev/null || df -h 2>/dev/null

section "BATTERY AND POWER"
if [ -d /sys/class/power_supply ]; then
    for p in /sys/class/power_supply/*; do
        [ -e "$p" ] || continue
        printf '\n[%s]\n' "${p##*/}"
        for f in type present status capacity health technology \
                 voltage_now current_now temp charge_counter energy_now; do
            [ -r "$p/$f" ] && read_value "$f" "$p/$f"
        done
    done
else
    echo "Power-supply interfaces unavailable."
fi

section "SELINUX AND KERNEL SECURITY"
printf 'Process context: '
cat /proc/self/attr/current 2>/dev/null || echo unavailable

if command -v getenforce >/dev/null 2>&1; then
    printf 'SELinux mode   : '
    getenforce 2>&1
else
    echo "getenforce unavailable."
fi

read_value "SELinux enforce node" /sys/fs/selinux/enforce

for key in randomize_va_space kptr_restrict dmesg_restrict perf_event_paranoid; do
    read_value "kernel.$key" "/proc/sys/kernel/$key"
done

section "ANDROID AND CHROOT CLUES"
for var in PREFIX TERMUX_VERSION ANDROID_ROOT ANDROID_DATA EXTERNAL_STORAGE HOME USER; do
    eval 'value=${'"$var"'-}'
    printf '%-24s : %s\n' "$var" "${value:-unavailable}"
done

read_value "Mount namespace" /proc/self/ns/mnt
read_value "PID 1 command line" /proc/1/cmdline
read_value "Self cgroup" /proc/self/cgroup

section "AVAILABLE DIAGNOSTIC TOOLS"
for tool in getprop getenforce dumpsys toybox busybox termux-info adb fastboot; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf '%-18s : %s\n' "$tool" "$(command -v "$tool")"
    else
        printf '%-18s : unavailable\n' "$tool"
    fi
done

section "AUDIT COMPLETE"
printf '%b\n' "${GREEN}Read-only inventory finished.${RESET}"
printf '%b\n' "${YELLOW}Unavailable values are reported, not guessed.${RESET}"
