#!/bin/bash
set -e

echo "=================================================="
echo "   PULSE: AIR-TO-GROUND RECON & WINDOWS PURGE     "
echo "=================================================="

# 1. Clean up all temporary shell scripts and junk files
echo "[*] Removing temporary scripts and junk files..."
rm -f add_windows_release.sh grand_finale_fix.sh final_windows_ci_fix.sh
rm -f fix_ci_triggers.sh fix_sniper_tests.sh fix_windows_build_final.sh
rm -rf mutants.out mutants.out.old
rm -rf .cargo # Removes the LLD config we added

# Keep only essential scripts: check.sh, live-test.sh

# 2. Remove Windows Directory from the codebase
echo "[*] Deleting the Windows platform module..."
rm -rf crates/pulse-platform/src/windows

# 3. Purge Windows dependencies from Cargo.toml
echo "[*] Removing Windows dependencies from Cargo.toml..."
python3 - << 'PY_EOF'
import re
filepath = "crates/pulse-platform/Cargo.toml"
with open(filepath, "r") as f:
    content = f.read()

# Remove the entire [target.'cfg(windows)'.dependencies] block
content = re.sub(r"\[target\.'cfg\(windows\)'\.dependencies\].*?(?=\n\[|\Z)", "", content, flags=re.DOTALL)

with open(filepath, "w") as f:
    f.write(content.strip() + "\n")
print("[+] Cargo.toml cleaned.")
PY_EOF

# 4. Purge Windows routing from lib.rs
echo "[*] Purging Windows routing from lib.rs..."
python3 - << 'PY_EOF'
import re
filepath = "crates/pulse-platform/src/lib.rs"
with open(filepath, "r") as f:
    content = f.read()

# Remove the windows module declaration
content = re.sub(r"#\[cfg\(target_os = \"windows\"\)\]\npub mod windows;\n", "", content)

# Remove windows from return branches (e.g., return windows::...;)
content = re.sub(r"#\[cfg\(target_os = \"windows\"\)\]\n\s*return windows::[a-zA-Z0-9_]+\([^)]*\);\n", "", content)

# Fix host_os function to remove windows
content = re.sub(r"#\[cfg\(target_os = \"windows\"\)\]\n\s*\{\s*\"windows\"\s*\}", "", content)
content = content.replace('target_os = "windows", ', '')
content = content.replace(', target_os = "windows"', '')

with open(filepath, "w") as f:
    f.write(content)
print("[+] lib.rs cleaned.")
PY_EOF

# 5. Streamline GitHub Actions (Remove Windows Jobs)
echo "[*] Simplifying GitHub Actions CI (Linux Only)..."
cat << 'YAML_EOF' > .github/workflows/ci.yml
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
    name: Quality & Tests (Linux)
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
YAML_EOF

# 6. Commit and push the purification
echo "[*] Committing and pushing the purge..."
git add -A
git commit -m "refactor: purge windows support, remove temporary scripts, and streamline CI"

git push origin main

# 7. Delete old windows tags
git tag -d v1.12.2 v1.12.3 v1.12.4 v1.12.5 v1.12.6 2>/dev/null || true
git push origin --delete v1.12.2 v1.12.3 v1.12.4 v1.12.5 v1.12.6 2>/dev/null || true

echo -e "\n=================================================="
echo -e "\033[92m\033[1m   SUCCESS: Base Purged & Project is Clean!       \033[0m"
echo "=================================================="
