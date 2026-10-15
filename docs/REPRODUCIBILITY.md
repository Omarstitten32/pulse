# Pulse — Reproducibility

> Status: v1.8.0 · Last updated: 2026-10-13

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
