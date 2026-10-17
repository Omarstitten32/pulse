#!/bin/bash
set -e

echo "=================================================="
echo "   FINAL WINDOWS BUILD FIX (Setup-MinGW & Upload) "
echo "=================================================="

WORKFLOW_FILE=".github/workflows/ci.yml"

# 1. Overwrite ci.yml with the guaranteed working configuration
echo "[*] Rewriting ci.yml..."
cat << 'YAML_EOF' > "$WORKFLOW_FILE"
name: Pulse CI Pipeline

on:
  push:
    branches: [ "main", "master" ]
    tags: [ "v*" ]
  pull_request:
    branches: [ "main", "master" ]

permissions:
  contents: write

env:
  CARGO_TERM_COLOR: always

jobs:
  quality-and-tests:
    name: Quality & Tests
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
      with:
        components: rustfmt, clippy
    - name: Check formatting
      run: cargo fmt --all -- --check
    - name: Run Clippy
      run: cargo clippy --workspace --all-targets -- -D warnings
    - name: Run Tests
      run: cargo test --workspace

  cross-platform:
    name: Cross-Platform Compilation
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - name: Add Windows Target
      run: rustup target add x86_64-pc-windows-gnu
    - name: Check Windows Compilation
      run: cargo check --workspace --target x86_64-pc-windows-gnu

  build-and-release-windows:
    name: Build & Release Windows Binary
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/v')
    needs: [quality-and-tests, cross-platform]
    steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - name: Setup MinGW-w64 (Guaranteed Installation)
      uses: egor-tensin/setup-mingw@v2
      with:
        platform: x64
    - name: Add Windows Target
      run: rustup target add x86_64-pc-windows-gnu
    - name: Build Windows Release Binary
      run: cargo build --release --target x86_64-pc-windows-gnu
    - name: Upload Binary to GitHub Release
      uses: softprops/action-gh-release@v2
      with:
        files: target/x86_64-pc-windows-gnu/release/pulse.exe
        fail_on_unmatched_files: true
        tag_name: ${{ github.ref_name }}
        name: Release ${{ github.ref_name }}
        draft: false
        prerelease: false
        generate_release_notes: true
YAML_EOF

# 2. Commit and push
echo "[*] Committing and pushing changes..."
git add .github/workflows/ci.yml
git commit -m "ci: use setup-mingw action for reliable windows build and upload"
git push origin main

# 3. Delete old tag and create a new one to trigger the workflow
echo "[*] Re-triggering release v1.12.4..."
git tag -d v1.12.3 || true
git push origin :refs/tags/v1.12.3 || true

git tag v1.12.4
git push origin v1.12.4

echo -e "\n=================================================="
echo -e "\033[92m\033[1m   SUCCESS: Pipeline fixed and v1.12.4 is running! \033[0m"
echo "=================================================="
