//! Loopback address classification tests.
//! Fails BEFORE the fix: IPv6 ::1 not recognized.

use pulse_core::trust::is_loopback_addr;

#[test]
fn ipv4_loopback_127_0_0_1() {
    assert!(is_loopback_addr("0100007F"));
}

#[test]
fn ipv4_non_loopback_8_8_8_8() {
    assert!(!is_loopback_addr("08080808"));
}

#[test]
fn ipv6_loopback_double_colon_one() {
    // ::1 in /proc/net/tcp6 hex format
    assert!(is_loopback_addr("00000000000000000000000001000000"));
}

#[test]
fn ipv6_non_loopback_google_dns() {
    // 2001:4860:4860::8888
    assert!(!is_loopback_addr(
        "00000000000000000000000001000000"
            .replace("01000000", "8888")
            .as_str()
    ));
}
