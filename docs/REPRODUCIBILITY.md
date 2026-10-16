# Pulse — Reproducibility

> Status: v1.10.3 · Last updated: 2026-10-16

This document explains how to verify that a Pulse binary was built
from the source code published in the repository, and not from a
modified tree.

The build is **reproducible**: two independent builds of the same
tag produce byte-identical binaries. This is verified for
`aarch64-unknown-linux-musl` at v1.8.0.

## What "reproducible" means here

Given:

- the same tag (`v1.8.0`)
- the same toolchain (`rust-toolchain.toml` pins `1.99.0`)
- the same target (`aarch64-unknown-linux-musl`)
- the same linker (`musl-gcc`, per `.cargo/config.toml`)

...the resulting binary has the same sha256 regardless of the path
the source was cloned into, the hostname of the machine, or the
order of operations.

## Reference Hash for v1.10.3

    size:   1010920 bytes
    sha256: 36d94cb20a3ee2278f0d18ce4d6428b853cd17b81ff0120072b8ee3459dbf65a
    linker: rust-lld (self-contained)

Runtime OS detection: a static musl binary now reports `os: android`
when it runs on Android, instead of the compile-time `linux`.

## Reference Hash for v1.10.2

    size:   1010664 bytes
    sha256: 49d85aa775dad53780a359e803335bd0afcb5398edac2b0585776c34714c06cd
    linker: rust-lld (self-contained)

Non-root graceful degradation: `pulse all` and `pulse snapshot` no
longer abort on the first permission error.

## Reference Hash for v1.10.1

    size:   1011208 bytes
    sha256: bb27af96765546232e3ac95bbc16ff070a33677250b99fe61ab12578bf035728
    linker: rust-lld (self-contained)

Structure-only hotfix for v1.10.0: the vulnerability report now
emits the breakdown section unconditionally. JSON schema unchanged.

## Reference Hash for v1.10.0

    size:   1011144 bytes
    sha256: 2fb47047946c99b9f2976981fcc9165ee910949f7ddc1f8e1ca696cd7af4a6a1
    linker: rust-lld (self-contained)

This is the first release where the three scored security engines
report a confidence field and use Option<u32> for their score. See
CHANGELOG.md for the full list of changes.

## Reference Hash for v1.9.0

    size:   1002816 bytes
    sha256: f1302f6bbcc533c16060760aedf364120e4c0d94e2c781d33da89dfd1420da4b
    linker: rust-lld (self-contained, no external musl-gcc required)

This hash is reproducible on any Linux/Android host that uses the
pinned toolchain (1.99.0) with Rust's built-in self-contained linker
for `aarch64-unknown-linux-musl`.

## Reference Hash for v1.8.0

    size:   921,672 bytes
    sha256: fdb0b18d4155ab74db21027b5e8d96f80ebd25934c1313fa4e6f1095698c367e

Any aarch64 Linux/Android binary claiming to be v1.8.0 must match
this hash. If it does not, either:

- the binary was not built from v1.8.0 source
- or the build environment differs (see "Toolchain" below)
- or the binary was modified after the build

None of these are acceptable for a release artifact. Investigate
before using.

## Reference Hash for v1.7.0

    sha256: 6a2af682660e66ef75a040cc816c7c8e00d4feb457990a3982a301f94965e5d7

## Older tags

Reproducibility was not formally verified before v1.7.0. Binary
sizes are recorded in `CHANGELOG.md`. Verify older binaries by
comparing size only; sha256 comparison is not meaningful for
pre-1.7.0 tags because the build environment was not pinned.

## How to Verify the Build Yourself

### Prerequisites

- A Linux or Android/aarch64 machine
- Rust `1.99.0` (installed automatically if you use `rustup` and the
  repo's `rust-toolchain.toml`)
- `musl-tools` (provides `musl-gcc`)

On Debian/Kali/Ubuntu:

    sudo apt install musl-tools

### Steps

    # 1. Clone the repository at the exact tag
    git clone https://github.com/Omarstitten32/pulse
    cd pulse
    git checkout v1.8.0

    # 2. Build
    cargo build --release --target=aarch64-unknown-linux-musl

    # 3. Hash the result
    sha256sum target/aarch64-unknown-linux-musl/release/pulse

    # 4. Compare with the reference
    # Expected: fdb0b18d4155ab74db21027b5e8d96f80ebd25934c1313fa4e6f1095698c367e

If the hash matches, the binary is byte-identical to the published
release. If it does not, see "Troubleshooting" below.

## What Makes This Build Reproducible

Four properties are required. All four are enforced by the repository.

### 1. Pinned toolchain

`rust-toolchain.toml`:

    [toolchain]
    channel    = "1.99.0"
    components = ["rustfmt", "clippy", "rust-analyzer"]

A `stable` channel would drift over time. Pinning to an exact version
guarantees that rustc, cargo, and the standard library are identical
on every machine.

### 2. Pinned dependencies

`Cargo.lock` is committed. `cargo build --locked` uses the exact
crate versions recorded there.

### 3. Pinned linker

`.cargo/config.toml`:

    [target.aarch64-unknown-linux-musl]
    linker = "musl-gcc"
    rustflags = ["-C", "link-arg=-static"]

`release.yml` uses the same linker. An earlier version of the CI
used `aarch64-linux-gnu-gcc`, which produced a different binary.
This was fixed in v1.7.0.

### 4. No path embedding

The build is verified to not embed the source path into the binary.
Building in `/tmp/pH` and `/tmp/pI` yields identical sha256. If
paths were embedded, the hashes would differ.

## Troubleshooting

### Hash differs, but I did everything right

Possible causes, in order of likelihood:

1. **Wrong toolchain.** Run `rustc --version`. If it does not say
   `1.99.0`, force it: `rustup override set 1.99.0` inside the repo.

2. **Wrong linker.** Verify `which musl-gcc` returns a path. If not,
   install `musl-tools`.

3. **Modified working tree.** Run `git status`. If it shows
   modifications, `git stash` them and rebuild.

4. **Different `Cargo.lock`.** Run `git diff Cargo.lock`. If it
   changed, `git checkout Cargo.lock`.

5. **Old build in `target/`.** Run `cargo clean` and rebuild from
   scratch.

### Still differs

Open an issue with:

- `rustc --version`
- `cargo --version`
- `musl-gcc --version`
- `uname -a`
- The sha256 you obtained
- `git rev-parse HEAD`

## What This Guarantees

Reproducibility guarantees that the published binary matches the
published source. It does **not** guarantee that the source is free
of bugs, backdoors, or design flaws. For that, read the code.

The cryptographic signature in `docs/CRYPTO.md` provides an
independent layer: a signed release binary can be verified even if
the build environment is unknown.
