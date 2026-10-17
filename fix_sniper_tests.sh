#!/bin/bash
set -e

echo "=================================================="
echo "   FIXING SNIPER TESTS (Smart Environment Logic)  "
echo "=================================================="

TRUST_FILE="crates/pulse-core/src/trust.rs"

# 1. Remove the old sniper tests block (from the marker to EOF)
echo "[*] Removing old sniper tests..."
awk '/^\/\/ ============================================================================/{exit} {print}' "$TRUST_FILE" > "${TRUST_FILE}.tmp"
mv "${TRUST_FILE}.tmp" "$TRUST_FILE"

# 2. Inject the corrected sniper tests
echo "[*] Injecting smart sniper tests..."
cat << 'RUST_EOF' >> "$TRUST_FILE"

// ============================================================================
// SNIPER TESTS V2: Designed to kill missed mutants in trust.rs
// ============================================================================
#[cfg(test)]
mod sniper_tests {
    use super::*;
    use std::fs;

    #[test]
    fn sniper_read_i64_mutant() {
        let path = "/tmp/sniper_i64_test.txt";
        fs::write(path, "12345").unwrap();
        assert_eq!(read_i64(path), Some(12345));
        
        fs::write(path, "-999").unwrap();
        assert_eq!(read_i64(path), Some(-999));
        
        fs::write(path, "invalid").unwrap();
        assert_eq!(read_i64(path), None);
        
        assert_eq!(read_i64("/does/not/exist_123"), None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn sniper_is_android_kernel_mutant() {
        // Dynamically check the environment
        let is_actually_android = fs::read_to_string("/proc/version")
            .map(|v| v.to_lowercase().contains("android"))
            .unwrap_or(false);
        
        assert_eq!(is_android_kernel(), is_actually_android, "Kernel detection must match reality");
    }

    #[test]
    fn sniper_is_process_running_mutant() {
        // "init" is PID 1 on both Linux and Android, and its process name is "init"
        assert!(is_process_running("init"), "Process 'init' must be running");
        
        // A completely fake process name must not exist.
        assert!(!is_process_running("fake_process_name_xyz_123"), "Fake process must be false");
    }

    #[test]
    fn sniper_is_port_listening_mutant() {
        assert!(!is_port_listening(0), "Port 0 cannot be listening");
        assert!(!is_port_listening(1), "Port 1 should not be listening");
    }

    #[test]
    fn sniper_signal_uptime_logic() {
        let sig = signal_uptime();
        for e in &sig.evidence {
            if let Ok(num) = e.parse::<f64>() {
                assert!(num < 100000.0, "Uptime number is absurdly large (mutant caught)");
            }
        }
    }

    #[test]
    fn sniper_signal_cron_jobs_logic() {
        let sig = signal_cron_jobs();
        assert!(sig.detail.contains("cron source"), "Signal detail must be present");
    }

    #[test]
    fn sniper_signal_users_uid0_logic() {
        let sig = signal_users_uid0();
        // On any sane system, there is exactly 1 root user.
        assert_eq!(sig.state, SignalState::Good, "Should detect only root as UID 0");
    }

    #[test]
    fn sniper_signal_deleted_binaries_logic() {
        let sig = signal_deleted_binaries();
        assert!(sig.evidence.len() <= 3, "Evidence should be capped at 3");
    }

    #[test]
    fn sniper_render_text_mutants() {
        let report = build_trust_report();
        let text = report.render_text();
        
        // Catch the String::new() mutant
        assert!(!text.is_empty(), "Rendered text cannot be empty");
        
        // Catch formatting breakages (like table headers)
        assert!(text.contains("Score") || text.contains("Grade"), "Rendered text must contain Score or Grade");
    }
}
RUST_EOF

echo "[+] Smart sniper tests injected."

echo "[*] Formatting and running tests..."
cargo fmt
cargo test -p pulse-core sniper_tests -- --nocapture

echo -e "\n=================================================="
echo -e "\033[92m\033[1m   SNIPER TESTS FIXED AND PASSED!                \033[0m"
echo "=================================================="
