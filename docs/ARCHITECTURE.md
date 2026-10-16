# Pulse — Architecture

> Status: v1.9.0 · Last updated: 2026-10-13

This document describes the internal structure of Pulse. It is intended
for contributors and for anyone who needs to understand how the binary
is organized before reading the source.

## Overview

Pulse is a single static binary with no runtime dependencies. It reads
directly from `/proc` and `/sys`, aggregates the data through a small
set of analysis engines, and renders the result in three formats:
text, JSON, and Markdown.

The codebase is split into three Rust crates. The split is deliberate:
each crate has one responsibility, and the dependency direction is
strictly one-way.

    pulse-cli  →  pulse-core  →  pulse-platform
    (user I/O)   (analysis)      (kernel access)

## pulse-platform

**Responsibility:** read from the Linux kernel. Nothing else.

This crate knows about `/proc`, `/sys`, libc calls, and platform
detection. It does not know what a "trust score" is, what JSON looks
like, or how output is formatted.

### Modules

| File | Purpose |
|---|---|
| `linux.rs` | All kernel reads: `/proc/*`, `/sys/*`, `statvfs`, `uname` |
| `types.rs` | Data structures returned by readers: `SystemInfo`, `CpuInfo`, `MemoryInfo`, `HwidInfo`, ... |
| `hwid.rs` | Hardware identifier assembly (8 sources → SHA-256) |
| `sha256.rs` | Pure-Rust SHA-256 implementation (no external crate) |
| `error.rs` | `PlatformError` enum with context-friendly variants |
| `lib.rs` | Public re-exports and thin wrappers around the readers |

### Contract

Every public function returns `Result<T, PlatformError>`. There is no
`unwrap()` in the public API. Failures are explicit and carry context
(file path, syscall name, expected shape).

The crate compiles on Linux and Android. It does not compile on macOS
or Windows.

## pulse-core

**Responsibility:** analysis. Given platform data, produce reports.

This crate knows about security signals, statistical baselines,
Ed25519 signatures, and output formatting. It does not perform any
I/O against `/proc` or `/sys`.

### Modules

| File | Purpose |
|---|---|
| `trust.rs` | 18 security signals → 0–100 score with penalty breakdown |
| `anomaly.rs` | z-score baseline for 10 metrics; learn and check |
| `snapshot.rs` | Full state capture + structured diff between two snapshots |
| `timeline.rs` | Unified chronological event stream |
| `sign.rs` | Ed25519 signing and verification (HWID-derived keys) |
| `render.rs` | Text / JSON / Markdown formatters for every report type |
| `report.rs` | Top-level report that composes all module outputs |
| `analysis.rs` | Health analysis with findings and severity |
| `format.rs` | `Format` and `JsonStyle` enums |
| `output.rs` | `Target` enum: stdout or file |

### Contract

`pulse-core` never reads from `/proc` directly. It receives
`pulse_platform` types, transforms them, and returns report structs
that implement `Serialize`. The `pulse-cli` crate decides which
formatter to invoke.

`build_trust_report()` has no arguments. It calls into
`pulse_platform` internally. This keeps the CLI code small: one
command, one function call.

## pulse-cli

**Responsibility:** command-line interface. Parse arguments, dispatch
to the right function in `pulse-core` or `pulse-platform`, write the
result.

This crate contains no business logic. It is the thinnest layer of the
three.

### Structure of `main.rs`

    fn main() -> ExitCode
        parse_args()          — populates Cli struct
        match command         — dispatch table (~40 commands)
        write output          — via Target (stdout or file)

    fn parse_args(args)       — manual parser, no clap
    fn generate_*()           — one function per command
    fn render_help()          — usage text

### Design choices

- **No clap.** Argument parsing is 40 lines of manual code. This keeps
  the binary small and gives full control over passthrough options
  (`--since=`, `--source=`, `--pubkey=`).

- **One function per command.** `generate_cpu()`, `generate_trust()`,
  `generate_sign()`, etc. All follow the same signature shape: take
  `&Cli` and `&[&str]` positional args, return `Result<String, _>`.

- **Exit codes.** `0` on success, `1` on runtime error, `2` on
  unknown command. This matches POSIX shell conventions and allows
  `pulse ... || fallback` patterns in scripts.

## The 28 Modules

Pulse exposes 28 introspection modules organized in six categories.
Each module is a `generate_*()` function in `pulse-cli`, backed by
readers in `pulse-platform`.

### Core (4)
| Module | Source |
|---|---|
| `system` | `/proc/version`, `/proc/uptime`, `/etc/os-release` |
| `cpu` | `/proc/cpuinfo`, `/sys/devices/system/cpu/*` |
| `memory` | `/proc/meminfo` |
| `disk` | `statvfs` per mount point |

### Memory detail (4)
`mem-detail` (35 fields), `load` (`/proc/loadavg`), `vmstat`
(`/proc/vmstat`, 30 fields), `cputimes` (`/proc/stat`).

### Process & Network (2)
`process` (`/proc/[pid]/*`), `network` (`/proc/net/*`, `ip link`).

### Devices (7)
`thermal` (hwmon zones), `gpu` (`/sys/class/drm/*`), `usb`
(`/sys/bus/usb/devices/*`), `pci` (`/sys/bus/pci/devices/*`),
`battery` (`/sys/class/power_supply/*`), `sensors` (hwmon chips),
`drivers` (`/proc/modules`).

### Users & Software (5)
`users` (`/etc/passwd`, `/etc/group`), `packages` (dpkg / rpm / apk),
`services` (systemd / openrc units), `filesystem` (mounts overview),
`env` (process environment).

### Environment (4)
`containers` (cgroup, `/proc/1/comm`), `vm` (hypervisor detection),
`browsers` (installed binaries), `crypto` (SSL certs, SSH keys),
`cron` (`/etc/crontab`, `/etc/cron.d`).

## The 6 Rare Features

These are the features that distinguish Pulse from similar tools.

### 1. `hwid` — Stable hardware identifier
SHA-256 of 8 hardware sources. Deterministic across reboots,
hostnames, and reinstalls. Optional context makes the HWID private
for a given deployment.

### 2. `trust` — Security score (0–100)
18 signals in 6 categories. Each signal has a state (Good, Warn,
Bad, Unknown) and a weight. Unknown signals receive 40% of their
weight as penalty. If more than 50% of signals are unknown, an
additional 15-point penalty is applied.

### 3. `snapshot` + `diff` — Time machine for systems
Captures full state to JSON. Computes structured diff between two
snapshots, grouped by category (processes, modules, filesystem,
users, network).

### 4. `anomaly` — Statistical detection
z-score over 10 metrics with a floor at `max(stddev, epsilon)` to
prevent division by zero. Baseline stored at
`~/.config/pulse/baseline.json`. No daemon.

### 5. `timeline` — Unified event stream
Merges kernel boot, process starts, module loads, and file events
into one chronological view. Filters: `--since=<duration>`,
`--source=<name>`.

### 6. `sign` / `verify` — Ed25519 attestation
Signs a file with a key derived from the device HWID. Writes a JSON
envelope (`.sig`) next to the input. Verification recomputes the
sha256 and checks the signature. Optional `--pubkey=<hex>` asserts
the signer's identity.

## Data Flow

    ┌──────────────────────────────────────────────────┐
    │  pulse-cli: parse_args()                         │
    │    → Cli { command, format, output, ... }        │
    └────────────────────┬─────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────┐
    │  match command { "trust" => generate_trust(...) }│
    └────────────────────┬─────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────┐
    │  pulse-core: build_trust_report()                │
    │    → TrustReport { score, grade, signals }       │
    └────────────────────┬─────────────────────────────┘
                         │  calls into
                         ▼
    ┌──────────────────────────────────────────────────┐
    │  pulse-platform: read /proc, /sys                │
    │    → Result<T, PlatformError>                    │
    └────────────────────┬─────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────┐
    │  pulse-core::render: text / json / markdown      │
    │    → String                                      │
    └────────────────────┬─────────────────────────────┘
                         │
                         ▼
    ┌──────────────────────────────────────────────────┐
    │  Target: write to stdout or file                 │
    └──────────────────────────────────────────────────┘

## Adding a New Module

1. Add a reader in `pulse-platform/src/linux.rs` returning a
   `Result<T, PlatformError>` where `T` derives `Serialize`.
2. Add the type to `pulse-platform/src/types.rs` and re-export it
   from `lib.rs`.
3. Add `generate_<name>()` in `pulse-cli/src/main.rs`, following
   the existing pattern (return `Result<String, _>`).
4. Add a match arm in the dispatch table.
5. Add an entry in `render_help()`.
6. Write an integration test in `crates/pulse-cli/tests/`.

Rule: no `unwrap()` in new code. Failures must surface as errors
with context.

## Design Principles

- **No runtime dependencies.** The binary is statically linked with
  musl. It runs on any Linux or Android without installing libraries.
  Build-time crates (serde, ed25519-dalek) do not violate this — they
  are compiled into the binary, not loaded at runtime.

- **No daemon.** Every command is a one-shot process. There is no
  background service, no socket, no persistent state except what the
  user explicitly writes (`snapshot` files, `baseline.json`).

- **No network.** Pulse never opens a socket. It cannot phone home,
  cannot fetch updates, cannot leak data. This is a hard constraint.

- **No filesystem writes during read commands.** `trust`, `cpu`,
  `hwid`, etc. observe only. The only write commands are `sign` (writes
  `.sig`), `snapshot` (via `--output`), and `anomaly learn` (writes
  `baseline.json`).

- **Honest reporting.** When data is unavailable, the signal state is
  `Unknown` and the message says so. Pulse does not guess.

- **Reproducible builds.** `rust-toolchain.toml` pins the channel to
  `1.99.0`. `musl-gcc` is the linker. Verified: three builds in
  distinct paths produce identical sha256.

## Non-Goals

- **Not a monitoring agent.** Pulse is not falco, not osquery. It
  does not stream events. Use it for point-in-time introspection.

- **Not a package manager.** `packages` reads the system state. It
  does not install, remove, or upgrade anything.

- **Not a kernel module.** Pulse runs entirely in userspace. It
  cannot enforce policy, cannot intercept syscalls, cannot do anything
  that requires kernel privileges beyond what `/proc` and `/sys`
  already expose.

- **Not cross-platform.** Linux and Android only. The codebase
  assumes `/proc` and `/sys` exist and behave as documented by the
  kernel.
