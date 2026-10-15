//! Advanced analysis modules.
//!
//! Each module is self-contained: it reads from the platform layer
//! and produces a serializable report.

pub mod attack_surface;
pub mod audit;
pub mod ebpf;
pub mod firmware;
pub mod forensics;
pub mod hardening;
pub mod integrity;
pub mod iommu;
pub mod namespaces;
pub mod numa;
pub mod nvme;
pub mod rootkit;
pub mod seccomp;
pub mod tpm;
pub mod vulnerabilities;
