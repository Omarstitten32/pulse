//! Tests for `pulse-platform::error::PlatformError`.
//!
//! Every constructor, every `Display` arm, and the `source()` chain
//! is exercised. No mocks.

use pulse_platform::error::{PlatformError, Result};

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

#[test]
fn unsupported_constructor_stores_tag() {
    let e = PlatformError::unsupported("battery");
    match e {
        PlatformError::Unsupported(what) => assert_eq!(what, "battery"),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn io_constructor_stores_path_and_source() {
    let src = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
    let e = PlatformError::io("/tmp/foo", src);
    match e {
        PlatformError::Io { path, source } => {
            assert_eq!(path, "/tmp/foo");
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn io_constructor_accepts_string_and_str() {
    let _a = PlatformError::io("/x", std::io::Error::other("e"));
    let _b = PlatformError::io(String::from("/y"), std::io::Error::other("e"));
}

#[test]
fn parse_constructor_stores_path_and_reason() {
    let e = PlatformError::parse("/proc/stat", "bad cpu line");
    match e {
        PlatformError::Parse { path, reason } => {
            assert_eq!(path, "/proc/stat");
            assert_eq!(reason, "bad cpu line");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn parse_constructor_accepts_string() {
    let e = PlatformError::parse(String::from("/p"), String::from("r"));
    match e {
        PlatformError::Parse { path, reason } => {
            assert_eq!(path, "/p");
            assert_eq!(reason, "r");
        }
        _ => panic!("wrong variant"),
    }
}

// ---------------------------------------------------------------------------
// Display impl — all three arms
// ---------------------------------------------------------------------------

#[test]
fn display_unsupported_contains_tag() {
    let e = PlatformError::unsupported("sensors");
    let s = format!("{e}");
    assert!(s.contains("unsupported"));
    assert!(s.contains("sensors"));
}

#[test]
fn display_io_contains_path_and_message() {
    let src = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let e = PlatformError::io("/etc/shadow", src);
    let s = format!("{e}");
    assert!(s.contains("i/o error"));
    assert!(s.contains("/etc/shadow"));
    assert!(s.contains("denied"));
}

#[test]
fn display_parse_contains_path_and_reason() {
    let e = PlatformError::parse("/proc/meminfo", "missing MemTotal");
    let s = format!("{e}");
    assert!(s.contains("parse error"));
    assert!(s.contains("/proc/meminfo"));
    assert!(s.contains("missing MemTotal"));
}

// ---------------------------------------------------------------------------
// std::error::Error impl
// ---------------------------------------------------------------------------

#[test]
fn source_returns_some_for_io() {
    use std::error::Error;
    let src = std::io::Error::other("root");
    let e = PlatformError::io("/x", src);
    assert!(e.source().is_some());
    assert_eq!(e.source().unwrap().to_string(), "root");
}

#[test]
fn source_returns_none_for_unsupported() {
    use std::error::Error;
    let e = PlatformError::unsupported("x");
    assert!(e.source().is_none());
}

#[test]
fn source_returns_none_for_parse() {
    use std::error::Error;
    let e = PlatformError::parse("/p", "r");
    assert!(e.source().is_none());
}

#[test]
fn error_is_send_sync_static() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<PlatformError>();
}

// ---------------------------------------------------------------------------
// Result alias
// ---------------------------------------------------------------------------

#[test]
fn result_ok_variant() {
    let r: Result<u32> = Ok(42);
    assert!(r.is_ok());
}

#[test]
fn result_err_variant() {
    let r: Result<u32> = Err(PlatformError::unsupported("test"));
    assert!(r.is_err());
}

// ---------------------------------------------------------------------------
// Debug formatting
// ---------------------------------------------------------------------------

#[test]
fn debug_unsupported() {
    let e = PlatformError::unsupported("gpu");
    assert!(format!("{e:?}").contains("Unsupported"));
}

#[test]
fn debug_io() {
    let e = PlatformError::io("/p", std::io::Error::other("e"));
    let d = format!("{e:?}");
    assert!(d.contains("Io"));
    assert!(d.contains("/p"));
}

#[test]
fn debug_parse() {
    let e = PlatformError::parse("/p", "r");
    let d = format!("{e:?}");
    assert!(d.contains("Parse"));
    assert!(d.contains("/p"));
}
