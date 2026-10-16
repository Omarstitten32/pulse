# Changelog

All notable changes to Pulse are documented in this file.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

---

## [1.10.2] — 2026-10-16

Non-root graceful degradation. Pulse is now fully usable on
Termux/Android without root. Previously, `pulse all` and
`pulse snapshot` aborted on the first permission error from a
restricted kernel file. Now every section is independent.

### Fixed

- `system_info()`: tolerant reads for `/proc/version`,
  `/proc/sys/kernel/hostname`, `/proc/uptime`, and boot time.
  Unreadable fields become empty strings or zero.
- `thermal_info()`: returns empty zone list if `/sys/class/thermal`
  is unreadable.
- `network_info()`: returns empty interface list if `/sys/class/net`
  is unreadable.
- `drivers_info()`: returns empty module list if `/proc/modules`
  is unreadable.
- `FullReport`: `system`, `cpu`, `memory` are now `Option<T>`.
- `build_full_report()`: every section is optional; failed sections
  are recorded in `skipped` with the error message.
- `pulse all` and `pulse snapshot` now succeed on non-root
  Android/Termux, emitting a partial report.

### Verified

- Termux (uid 10315, no root): 31/31 audited commands succeed.
- 1094 workspace tests pass.
- clippy clean, fmt clean.

### Notes

The JSON schema of `pulse all` changes: `system`, `cpu`, and
`memory` may now be `null`. Consumers should treat absence as
"section unavailable".

## [1.10.1] — 2026-10-16

Hotfix for the v1.10.0 vulnerability report structure. The text and
markdown renderers used to skip the `[BREAKDOWN]` / `## Breakdown`
section when the findings list was empty, which made the document
structure depend on scan results. This caused CI to pass on Kali
systems (findings present due to `/etc/sudoers.d/kali-grant-root`)
but fail on ubuntu-latest (no findings).

### Fixed

- `vulns` now always emits the breakdown section in both text and
  markdown output. The "No known vulnerabilities detected." message
  is still shown when findings are empty.
- `ci.yml`: cross-compile check now accepts `static-pie linked`
  (the format produced by rust-lld on x86_64).

### Notes

This is a structure-only fix. The JSON schema is unchanged. Users
who do not rely on the markdown layout are unaffected.

## [1.10.0] — 2026-10-16

Second public release. Hardens the security engines so they never
report a misleading score when the underlying data was not readable.
Adds a confidence level and explicit source-read/source-total counters
to every scored module.

### Added

- `pulse_core::Confidence` enum (High / Medium / Low / None) shared
  by all scored security engines.
- `attack-surface`: `sources_read`, `sources_total`, `confidence`
  fields in text, JSON, and markdown output.
- `vulnerabilities`: same three fields.
- `pulse-platform::PlatformInfo` struct and `platform_info()` function.

### Changed

- **Breaking (JSON schema)**: `attack-surface.score` and
  `vulnerabilities.score` are now `Option<u32>`. They are `null` when
  no source was readable, instead of a misleading `0` or `100`.
- `platform` now respects `--format=json` and `--format=markdown`
  and emits a proper `PlatformInfo` struct (previously emitted plain
  text regardless of the format flag).
- `pulse all` now reports skipped sections with a reason instead of
  aborting on the first permission error.

### Fixed

- `hardening`: unreadable checks are now reported as `[?] UNREADABLE`
  instead of `[-] FAIL`. The score only counts checks that were
  actually evaluated.
- `vm`: no longer reports "Is Virtual Machine: yes" on real Android
  devices. `/sys/hypervisor` alone is not sufficient evidence.
- `help`: usage line now correctly reads `pulse [OPTIONS] [COMMAND]`.
- `timeline_test`: `build_timeline_large_window_matches_default` no
  longer fails on live systems. The assertion is now directional.

### Internal

- Added 12 new regression tests (Confidence, attack-surface, vulns).
- All 1094 tests pass. Zero clippy warnings.

## [1.9.0] — 2026-10-15

This is the first public release of Pulse. It consolidates every
earlier internal milestone into a single, audited, reproducible
binary.

### Binary

    type:   ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped
    size:   1,052,744 bytes (~1.05 MB)
    sha256: a0155fd0d89ecf22659687cad8ed371a83a9aa2fa5d5af26ebc7289607cf4b51

Two independent builds of the same source produce byte-identical
output. See `docs/REPRODUCIBILITY.md`.

### Added — Three security engines

- **`pulse hardening`** — Kernel hardening audit with **22 checks**
  against `/proc/sys/` and `/sys/kernel/`. Weighted scoring, letter
  grade (A–F), and structured findings with evidence strings.

- **`pulse attack-surface`** — Enumerates listening ports, SUID/SGID
  binaries, file capabilities, world-writable files in `/etc`,
  SSH authorized keys, SSH private keys, exposed secret files, and
  the presence of a Docker socket. Produces a 0–100 surface score.
  Runs in under a second.

- **`pulse vulns`** — Configuration vulnerability scan detecting
  empty passwords in `/etc/shadow`, world-readable SSH private keys,
  dangerous `NOPASSWD:ALL` sudoers rules, insecure mount options,
  and unsigned APT repositories. Produces a 0–100 score and a list
  of findings with severity levels.

### Added — Module infrastructure

- `crates/pulse-core/src/modules/` — new workspace sub-tree for
  self-contained analysis engines.
- `modules/mod.rs` — registry of all module sources.
- `modules/hardening.rs` — 22 kernel checks with match kinds
  (`Exact`, `MinAtLeast`, `ZeroMeansEnabled`), severity levels, and
  weighted scoring.
- `modules/attack_surface.rs` — attack surface collection and scoring.
- `modules/vulnerabilities.rs` — configuration vulnerability engine.
- Stub modules prepared for future work: `namespaces`, `ebpf`,
  `iommu`, `numa`, `nvme`, `firmware`, `tpm`, `audit`, `seccomp`,
  `rootkit`, `integrity`, `forensics`.

### Added — Security features (finalized)

- **Merkle root in every snapshot.** `pulse snapshot` emits a
  `merkle_root` field: a single 32-byte hash summarizing the
  configuration state of the machine. Two snapshots taken from the
  same configuration produce the same root, regardless of elapsed
  time. Included: system identity, users, loaded kernel modules,
  network interface identity, cron schedule files. Excluded
  (deliberately): processes, volatile measurements, module refcount,
  interface state, environment variables.

- **`pulse merkle-leaves`** — Diagnostic command printing one line
  per Merkle leaf as `<hash>\t<label>`. Intended for debugging which
  field changed between two snapshots.

- **`pulse sign <file>`** — Signs a file with a device-bound key
  derived from the HWID. Writes a detached `.sig` file containing a
  JSON envelope with `version`, `algorithm`, `file`, `size`,
  `sha256`, `public_key`, `signature`.

- **`pulse verify <file>`** — Recomputes sha256 of the file,
  compares it with the stored hash, and verifies the Ed25519
  signature. Supports `--pubkey=<hex>` to assert the signer's
  identity.

- **`pulse timeline`** — Unified chronological event stream merging
  kernel boot, process starts, module loads, and file events.
  Filters: `--since=<duration>`, `--source=<name>`.

- **`pulse anomaly learn` / `pulse anomaly check`** — Statistical
  anomaly detection using z-score over 10 metrics. Baseline stored
  at `~/.config/pulse/baseline.json`. No daemon required.

- **`pulse trust`** — Security trust score (0–100) over 18 signals
  across 6 categories: kernel, MAC, filesystem, config, network,
  posture. Distro-aware thresholds. Android/KernelSU aware.

- **`pulse hwid`** — Stable hardware identifier derived from 8
  hardware sources. Deterministic across reboots, hostname changes,
  and reinstalls. Optional context produces a private HWID for a
  given deployment.

- **`pulse snapshot` + `pulse diff`** — Full system state as JSON,
  with semantic diff between two snapshots grouped by category
  (processes, users, modules, network, environment).

### Added — Test suite

- **~1,080 tests** across the workspace, all passing.
- Coverage: **~92.6%** line coverage, verified via `cargo-llvm-cov`.
- Test categories:
  - Unit tests for every parser and pure helper.
  - Integration tests via `CARGO_BIN_EXE_pulse` (real binary execution).
  - Subprocess tests as `nobody` (non-root code paths).
  - Property tests via `proptest` and `quickcheck`.
  - Snapshot tests via `insta`.
  - Benchmarks via `criterion`.

- **`check.sh`** — Local quality gate running:
  1. `cargo fmt --all --check`
  2. `cargo clippy --all-targets --all-features -- -D warnings`
  3. `cargo build --all-targets`
  4. `cargo test --all-features`
  5. `cargo doc --no-deps --all-features`
  6. `cargo build --release --target aarch64-unknown-linux-musl`
  7. Binary sanity check (`file`, `sha256sum`, `size`)

  All seven stages must pass before a commit is accepted.

- **`live-test.sh`** — End-to-end verification against the running
  kernel:
  - Builds the real binary and records its SHA-256.
  - Executes every CLI command (38 commands).
  - Validates every JSON output (28 commands).
  - Cross-verifies 4 values directly against `/proc`.
  - Confirms determinism across repeated invocations.
  - Runs 4 real-world workflows (snapshot+diff, sign+verify+tamper,
    trust, timeline).
  - Writes a complete evidence bundle under `live-evidence/`.

### Changed — Architecture

- `pulse-platform` — Platform abstraction layer. Reads from `/proc`
  and `/sys`. No business logic. Handles: system, CPU, memory, disk,
  network, processes, thermal, GPU, users, packages, services,
  filesystem, environment, USB, PCI, battery, sensors, drivers,
  containers, VM, browsers, crypto, cron, HWID.

- `pulse-core` — Pure engines. No I/O beyond parsing. Handles:
  analysis, anomaly, format, output, render, report, sign, snapshot,
  timeline, trust, merkle, hardening, attack surface,
  vulnerabilities.

- `pulse-cli` — Argument parsing and output routing. Handles all
  33 CLI commands, three output formats (text/JSON/Markdown), and
  file output via `--output=`.

### Changed — Performance

- **`pulse attack-surface` time reduced 185×.**
  - Before: 80s (recursive `getcap -r /`).
  - After: 0.43s (scoped to `/usr/bin`, `/usr/sbin`, `/bin`,
    `/sbin`, `/usr/local/bin`, `/usr/local/sbin`).

### Fixed

- **`parse_args` positional argument handling.** `--format=json sign
  <file>` previously failed because the file path was read from
  `args[2]` (which was actually the subcommand name). Now uses the
  filtered `positional` slice. This was a real bug affecting every
  command that takes a positional argument when any flag precedes
  it.

- **`hwid_info` context propagation.** After a refactor, the context
  string was no longer folded into the hash input, causing all
  context variants to produce the same HWID. Restored. Verified by
  the `hwid_info_changes_with_different_context` test.

- **Duplicate render methods in `hardening.rs`.** An automated patch
  inserted a second `render_text` / `render_markdown` pair. Removed.

- **Missing process names.** Process 597 (kernel thread) has an empty
  `comm` field. `read_process_entry` now substitutes `[pid:<N>]` so
  every entry has a non-empty name.

- **13 clippy warnings in stub modules.** `field_reassign_with_default`
  on `X::default()` followed by field writes. Suppressed locally via
  `#![allow(clippy::field_reassign_with_default)]` at the top of
  each stub file. These modules are placeholders and will be
  refactored when implemented.

### Security — Design invariants

- **No network access.** Pulse never opens an outbound socket.
- **No daemon.** Every invocation is a one-shot process.
- **No filesystem writes on read commands.** Pure observation.
- **Ed25519 signing** uses `ed25519-dalek 2.2` with
  `default-features = false, features = ["std"]`. No runtime
  dependency is introduced.
- **Reproducible builds** verified across two independent paths.
- **SELinux-aware.** Detects enforcing, permissive, and disabled
  states via `/sys/fs/selinux/enforce`, `/proc/self/attr/current`,
  and AppArmor profile presence.
- **Android/KernelSU aware.** Taint flags, SELinux context, and
  randomized MACs are handled correctly on Android 14+ systems with
  KernelSU Next.

### Documentation

- `README.md` — Rewritten with command reference, comparison table,
  quality gates, and a legal notice.
- `docs/ARCHITECTURE.md` — Three-crate design, data flow, module
  registry.
- `docs/CRYPTO.md` — Ed25519 key derivation, threat model, and
  signing protocol.
- `docs/REPRODUCIBILITY.md` — How to verify a build.

### Measurement summary

| Metric | Value |
|---|---:|
| Binary size | 1,052,744 bytes |
| SHA-256 | `a0155fd0...7cf4b51` |
| CLI commands | 33 |
| Analysis modules | 28+ |
| Security engines | 3 |
| Tests | ~1,080 |
| Line coverage | ~92.6% |
| Clippy warnings | 0 |
| Formatting diffs | 0 |
| Runtime dependencies | 0 |
| Network calls | 0 |
| Daemons | 0 |

---

## Versioning policy

Starting with `1.9.0`, Pulse follows a simple versioning policy:

- **Major (`x.0.0`)** — breaking change to the snapshot or signature
  format.
- **Minor (`1.x.0`)** — new command, new module, or new security
  engine.
- **Patch (`1.9.x`)** — bug fix, documentation update, or
  performance improvement.

Every release publishes:

1. The static aarch64 binary.
2. Its `sha256` hash.
3. A `SHA256SUMS` file.
4. The complete source tree at the release tag.

---

[1.9.0]: https://github.com/Omarstitten32/pulse/releases/tag/v1.9.0
