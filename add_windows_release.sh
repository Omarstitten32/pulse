#!/bin/bash
set -e

echo "=================================================="
echo "   ADDING WINDOWS RELEASE TO GITHUB ACTIONS       "
echo "=================================================="

WORKFLOW_FILE=".github/workflows/ci.yml"

# 1. Add the Windows build & release job to ci.yml
echo "[*] Updating CI workflow with Windows release job..."

# Remove the old cross-platform job if it exists, we'll replace it with a more complete one
python3 - << 'PY_EOF'
import re

filepath = ".github/workflows/ci.yml"
with open(filepath, "r") as f:
    content = f.read()

# Find the cross-platform job and replace it
pattern = r"  cross-platform:\n(?:    .*\n)*"
new_job = """  cross-platform:
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
    - name: Add Windows Target
      run: rustup target add x86_64-pc-windows-gnu
    - name: Build Windows Release Binary
      run: cargo build --release --target x86_64-pc-windows-gnu
    - name: Upload Binary to GitHub Release
      uses: softprops/action-gh-release@v2
      with:
        files: target/x86_64-pc-windows-gnu/release/pulse.exe
        tag_name: ${{ github.ref_name }}
        name: Release ${{ github.ref_name }}
        draft: false
        prerelease: false
        generate_release_notes: true
"""

content = re.sub(pattern, new_job, content)

with open(filepath, "w") as f:
    f.write(content)
print("[+] ci.yml updated with Windows release job.")
PY_EOF

# 2. Update README to reflect Windows core support
echo "[*] Updating README Windows note..."
python3 - << 'PY_EOF'
filepath = "README.md"
with open(filepath, "r") as f:
    content = f.read()

old_note = "> **Note**: Windows support is currently in active development (Core APIs implemented, advanced modules pending)."
new_note = "> **Note**: Core system modules (system, cpu, memory) are now supported on Windows. Advanced modules are under active development."

content = content.replace(old_note, new_note)
with open(filepath, "w") as f:
    f.write(content)
print("[+] README.md updated.")
PY_EOF

echo "[*] Committing and pushing changes..."
git add .github/workflows/ci.yml README.md
git commit -m "ci: add automated Windows release build and update README"
git push origin main

echo -e "\n=================================================="
echo -e "\033[92m\033[1m   SUCCESS: Windows Release Pipeline Added!       \033[0m"
echo "=================================================="
