#!/bin/bash
# Pulse — Full quality gate
# Runs every check the project must pass before a release.

set -euo pipefail
cd "$(dirname "$0")"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

step() { echo -e "\n${CYAN}==> $1${NC}"; }
fail() { echo -e "${RED}FAILED: $1${NC}"; exit 1; }
pass() { echo -e "${GREEN}OK: $1${NC}"; }

step "1. Formatting check"
cargo fmt --all -- --check || fail "cargo fmt"

step "2. Clippy (zero warnings)"
cargo clippy --all-targets --all-features -- -D warnings || fail "clippy"

step "3. Build (debug)"
cargo build --all-targets || fail "cargo build"

step "4. Unit + integration tests"
cargo test --all-features || fail "cargo test"

step "5. Documentation build"
cargo doc --no-deps --all-features || fail "cargo doc"

step "6. Release build (musl static)"
rustup target add aarch64-unknown-linux-musl 2>/dev/null || true
cargo build --release --target aarch64-unknown-linux-musl || fail "release build"

step "7. Binary sanity"
BIN="target/aarch64-unknown-linux-musl/release/pulse"
if [ -f "$BIN" ]; then
    file "$BIN"
    sha256sum "$BIN"
    size "$BIN"
else
    fail "binary not produced"
fi

pass "All checks passed."
