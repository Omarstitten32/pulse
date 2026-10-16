# Pulse

> **Deep system introspection for every platform.**
> 28+ modules · 6 rare features · static binary · zero runtime dependencies.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.99.0-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20android-blue.svg)]()
[![Size](https://img.shields.io/badge/binary-1.05%20MB-green.svg)]()
[![Version](https://img.shields.io/badge/version-1.9.0-blueviolet.svg)]()
[![Static](https://img.shields.io/badge/linking-static-brightgreen.svg)]()
[![Reproducible](https://img.shields.io/badge/build-reproducible-brightgreen.svg)](docs/REPRODUCIBILITY.md)

---

## What is Pulse?

**Pulse** is a portable system introspection tool that reads directly
from the Linux kernel (`/proc`, `/sys`) — no simulation, no caching,
no external commands, no network, no daemon.

It aggregates **28+ modules**, **3 dedicated security engines**, and
**6 rare analysis features** into a single **~1 MB static binary**.
It runs on any Linux or Android/aarch64 without installing a single
runtime library.

Pulse is designed for engineers, auditors, and forensic analysts who
want **deterministic, verifiable, and reproducible** system state —
not a UI wrapper around shell commands.

---

## Key Highlights

- **Static musl binary** — one file, no glibc, no dependencies.
- **Reproducible builds** — byte-identical output across independent builds.
- **Ed25519 attestation** — sign and verify any file with a device-bound key.
- **Merkle root** — cryptographic digest of configuration state.
- **Zero network** — cannot phone home, cannot leak data.
- **No daemon** — every invocation is a one-shot process.
- **Fast** — every command completes in under a second on modern hardware.

---

## Quick Start

### Download (once a release is published)

    curl -L https://github.com/Omarstitten32/pulse/releases/download/v1.10.1/pulse-v1.10.1-aarch64-linux-static -o pulse
    chmod +x pulse

Verify the download against the reference `sha256`:

    sha256sum pulse
    # Reference hash is published in the release notes.

### Run

    ./pulse trust
    ./pulse hardening
    ./pulse attack-surface
    ./pulse all

**No installation. No dependencies. No daemon.**

---

## Root Requirements

Pulse works in two modes.

### Full mode (with root)

    sudo ./pulse all
    # On Termux/Android:
    tsu ./pulse all

### Restricted mode (no root)

    ./pulse all

Pulse honestly reports when data is unavailable. It never guesses.

### Command Root Requirements

| Command | Root required? |
|---------|:--------------:|
| platform, cpu, memory, gpu | No |
| system, timeline | Partial |
| thermal, battery, sensors, network, drivers | Yes |
| trust, hardening, attack-surface, vulns | Confidence varies |
| snapshot, diff, anomaly, sign, verify | Partial |

---

## Commands Reference

### Core

| Command | Description |
|---------|-------------|
| `version` | Print Pulse version |
| `help` | Show command reference |
| `platform` | Architecture, OS, family, endianness |
| `formats` | List supported output formats |

### System Introspection

| Command | Description |
|---------|-------------|
| `system` | OS, kernel, hostname, uptime, boot time |
| `cpu` | CPU model, cores, per-core frequencies, features |
| `memory` | RAM and swap summary |
| `disk` | Mounted filesystems with usage |
| `network` | Network interfaces |
| `process` | Running processes |
| `thermal` | Thermal zones (from `/sys/class/thermal`) |
| `gpu` | Detected GPU devices |
| `mem-detail` | Extended memory breakdown (~35 fields) |
| `load` | Load average and task counters |
| `vmstat` | Kernel VM statistics |
| `cputimes` | Per-core CPU time breakdown |

### Users, Packages, and Software

| Command | Description |
|---------|-------------|
| `users` | Local users and groups |
| `packages` | Installed packages (dpkg, apk) |
| `services` | Service units (systemd, sysvinit) |
| `filesystem` | Filesystem roots overview |
| `env` | Environment variables |
| `cron` | Scheduled tasks |
| `browsers` | Detected browsers |

### Devices and Hardware

| Command | Description |
|---------|-------------|
| `usb` | USB devices |
| `pci` | PCI devices |
| `battery` | Battery status |
| `sensors` | Hardware sensor chips (hwmon) |
| `drivers` | Loaded kernel modules |

### Environment Context

| Command | Description |
|---------|-------------|
| `containers` | Container runtime detection |
| `vm` | Virtualization detection |
| `crypto` | SSL certificates and SSH keys |

### Security Analysis

| Command | Description |
|---------|-------------|
| `trust` | Security trust score (0–100) |
| `hardening` | Kernel hardening audit (22 checks) |
| `attack-surface` | Attack surface enumeration |
| `vulns` | Configuration vulnerability scan |
| `hwid` | Stable hardware identifier |

### State, Diffing, and Attestation

| Command | Description |
|---------|-------------|
| `snapshot` | Full system state as JSON |
| `merkle-leaves` | Merkle leaf digests (diagnostic) |
| `diff` | Compare two snapshots |
| `anomaly learn` | Build a statistical baseline |
| `anomaly check` | Compare against baseline |
| `timeline` | Unified chronological event stream |
| `sign` | Ed25519-sign a file |
| `verify` | Verify a signed file |
| `all` | Run all modules, composite report |

---

## Output Formats

Every command supports three output formats.

    pulse cpu                    # text   (default, human-readable)
    pulse cpu --format=json      # json   (for automation)
    pulse cpu --format=markdown  # markdown (for reports)
    pulse cpu --json --compact   # compact JSON (single line)
    pulse all --output=/tmp/report.json

---

## The 3 Security Engines

### 1. `pulse hardening` — Kernel Hardening Audit

Runs **22 checks** against `/proc/sys/` and `/sys/kernel/`, with
weighted scoring and a letter grade (A–F).

    $ pulse hardening
    === KERNEL HARDENING AUDIT ===

    Score : 44/112  (Grade F)
    Checks: 22
    Issues: 13

    [CHECKS]
      [+] Kernel ASLR              OK       expected=2 actual=2
      [-] dmesg restricted to root FAIL     expected=1 actual=0
      [+] Kernel pointers hidden   OK       expected=2 actual=2
      ...

### 2. `pulse attack-surface` — Attack Surface Enumeration

Lists listening ports, SUID/SGID binaries, file capabilities,
world-writable files, SSH keys, and exposed secrets. Runs in under
one second.

    $ pulse attack-surface
    === ATTACK SURFACE ===

    Score: 62/100

    [LISTENING PORTS] (5)
      tcp 0.0.0.0:22 LISTEN
      ...
    [SUID BINARIES] (51)
      /bin/chfn
      /usr/bin/passwd
      ...

### 3. `pulse vulns` — Configuration Vulnerability Scan

Detects empty passwords, world-readable SSH keys, dangerous sudoers
rules, insecure mounts, and unsigned repositories.

    $ pulse vulns
    === VULNERABILITY REPORT ===

    Score: 95/100
    Findings: 1

    [HIGH] 1 NOPASSWD:ALL sudoers rule(s)
         evidence: /etc/sudoers.d/...:3: user ALL=(ALL:ALL) NOPASSWD: ALL

---

## The 6 Rare Features

### 1. hwid — Stable Hardware Identifier

    $ pulse hwid
    HWID     : 7be2fc58eab0fedc29743d5352a9a4a9e9f585df8dae92b93b12e83cf3f301f3
    Mode     : stable
    Sources  : 4 / 8 active (50% confidence)

SHA-256 hash from 8 hardware sources. Deterministic across reboots,
hostname changes, and reinstall. Optional context makes the HWID
private for a given deployment.

### 2. trust — Security Score (0–100)

    $ pulse trust
    Overall : 87/100  (Grade B)
    Signals : 18 total | 15 pass | 2 warn | 0 fail | 1 n/a

18 security signals in 6 categories (kernel, MAC, filesystem,
config, network, posture). Weighted penalty model. Distro-aware
thresholds (Kali, Parrot, BlackArch, Debian, Arch). Android and
KernelSU aware. See `docs/ARCHITECTURE.md` for the full signal list.

### 3. snapshot + diff — Time Machine for Systems

    $ pulse snapshot > before.json
    $ pulse snapshot > after.json
    $ pulse diff before.json after.json
    [PROCESS]
      + pid=23457 com.android.nfc
      - pid=23045 com.android.nfc

Captures full system state to JSON. Computes structured diff grouped
by category (processes, modules, filesystem, users, network).

### 4. anomaly — Statistical Anomaly Detection

    $ pulse anomaly learn    # build baseline (10 samples)
    $ pulse anomaly check    # compare against baseline

z-score over 10 metrics with a floor at `max(stddev, epsilon)`.
Baseline stored at `~/.config/pulse/baseline.json`. No daemon
required.

### 5. timeline — Unified Event Stream

    $ pulse timeline
    +00:00:00    kernel     boot     system boot
    +00:11:35    process    start    pid=12356 com.termux
    +00:36:53    process    start    pid=32033 zsh

Merges kernel boot, process starts, module loads, and file events
into one chronological view. Filters: `--since=<duration>`,
`--source=<name>`.

### 6. sign / verify — Ed25519 Attestation

    $ pulse sign /etc/hostname
    signed: /etc/hostname
    sig:    /etc/hostname.sig
    pubkey: 9de1512a598cc58181ca1b5cf9a34105c102069ce71594effb6987ebce6f8569
    sha256: a1fff0ffefb9eace7230c24e50731f0a91c62f9cefdfe77121c2f607125dffae

    $ pulse verify /etc/hostname
    VALID: /etc/hostname
      sha256: a1fff0ffefb9eace7230c24e50731f0a91c62f9cefdfe77121c2f607125dffae
      pubkey: 9de1512a598cc58181ca1b5cf9a34105c102069ce71594effb6987ebce6f8569

Signs a file with a key derived from the device HWID. Detached
Ed25519 signature over `sha256(file)`. Optional `--pubkey=<hex>`
asserts the signer's identity. See `docs/CRYPTO.md` for the full
design and threat model.

---

## Why Pulse? Comparison with Existing Tools

| Tool | Size | Static | Runtime deps | Coverage |
|------|-----:|:------:|:------------:|:--------:|
| neofetch | 90 KB | No | bash | system info |
| fastfetch | 800 KB | No | glibc | system info |
| inxi | 600 KB | No | perl | system info |
| Lynis | 1.5 MB | No | perl | audit |
| AIDE | ~1 MB | No | glibc | integrity only |
| rkhunter | 200 KB | No | perl | rootkits only |
| osquery | 40 MB | No | daemon | SQL queries |
| Falco | 50+ MB | No | eBPF | runtime security |
| **Pulse** | **1.05 MB** | **Yes** | **none** | **all of the above** |

- Zero runtime dependencies — no Python, no Perl, no Bash runtime
- Static binary — runs on any Linux/Android without installing libraries
- No network — cannot phone home, cannot leak data
- No daemon — every command is a one-shot process
- No filesystem writes on read commands — pure observation

---

## Architecture

Pulse is organized as a Rust workspace with three crates:

- **`pulse-platform`** — reads from `/proc` and `/sys`. No business logic.
- **`pulse-core`** — pure engines: analysis, trust, hardening, attack
  surface, vulnerabilities, anomaly, timeline, snapshot, Merkle,
  Ed25519 signing.
- **`pulse-cli`** — argument parsing and output routing.

Full details in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Security and Verification

- **Reproducible builds** — two independent builds produce the same
  `sha256`. See [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md).
- **Merkle root** — every snapshot carries a 32-byte Merkle root over
  stable configuration fields (system, users, modules, network, cron).
  Volatile fields (processes, memory, CPU frequency) are deliberately
  excluded. Two snapshots of the same system configuration produce
  the same root.
- **Ed25519 signatures** — detached signatures over `sha256(file)`.
- **No network calls** — verified by `strace`.

---

## Reproducible Builds

Two independent builds of the same tag produce byte-identical output.

    file:   ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped
    size:   ~1.05 MB
    sha256: a0155fd0d89ecf22659687cad8ed371a83a9aa2fa5d5af26ebc7289607cf4b51

Verify with:

    git checkout v1.10.1
    cargo build --release --target=aarch64-unknown-linux-musl
    sha256sum target/aarch64-unknown-linux-musl/release/pulse

Full procedure in [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md).

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — three crates, 28 modules, data flow
- [`docs/CRYPTO.md`](docs/CRYPTO.md) — Ed25519 design, key derivation, threat model
- [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) — how to verify a build
- [`CHANGELOG.md`](CHANGELOG.md) — version history since 0.1.0

---

## Build from Source

    git clone https://github.com/Omarstitten32/pulse
    cd pulse
    git checkout v1.10.1
    cargo build --release --target=aarch64-unknown-linux-musl
    ./target/aarch64-unknown-linux-musl/release/pulse --version

**Requirements:** Rust `1.99.0` (pinned in `rust-toolchain.toml`)
and `musl-tools`.

### Quality Gates

Pulse ships with a full local quality gate:

    ./check.sh

Runs, in order: `cargo fmt --check`, `cargo clippy -D warnings`,
debug build, full test suite, `cargo doc`, release (musl) build,
and binary sanity checks. All must pass before any commit is
accepted.

---

## Legal Notice and Responsible Use

Pulse is a **defensive introspection tool**. It only reads from
the kernel's public interfaces (`/proc`, `/sys`, `/etc`) and never
writes to the system during read commands.

- Pulse is intended for **authorized** system administration,
  security auditing, compliance verification, and forensic analysis.
- Users are responsible for ensuring their use of Pulse complies
  with all applicable laws, regulations, and organizational
  policies.
- Pulse outputs (reports, snapshots, signatures) become the
  property of the operator generating them. OMAR-DEV does not
  receive, transmit, or collect any output.
- Pulse carries **no telemetry, no analytics, and no network
  access** of any kind.
- Any redistribution of Pulse must preserve this README, the
  `LICENSE` file, and the original author attribution.

**Copyright © 2026 OMAR-DEV. All rights reserved under the MIT
License.**

---

## License

[MIT](LICENSE) © 2026 OMAR-DEV (Omarstitten32)
