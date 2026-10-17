#!/bin/bash
set -e

echo "=================================================="
echo "   GRAND FINALE: Fixing Docs & Windows CI Build   "
echo "=================================================="

# 1. Fix the rustdoc warning
echo "[*] Fixing rustdoc warning in memory_forensics.rs..."
python3 - << 'PY_EOF'
filepath = "crates/pulse-core/src/modules/memory_forensics.rs"
with open(filepath, "r") as f:
    content = f.read()

# Replace the broken doc comment with the correct one
content = content.replace("/// Parse the content of `/proc/`[pid]`/maps`.", "/// Parse the content of `/proc/[pid]/maps`.")

with open(filepath, "w") as f:
    f.write(content)
print("[+] Doc warning fixed.")
PY_EOF

# 2. Create .cargo/config.toml to force LLD and correct linker
echo "[*] Creating .cargo/config.toml for Windows cross-compilation..."
mkdir -p .cargo
cat << 'TOML_EOF' > .cargo/config.toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
TOML_EOF
echo "[+] Cargo config created."

# 3. Update GitHub Actions to use Ubuntu 22.04 for the Windows job
echo "[*] Updating CI to use Ubuntu 22.04 (Stable for MinGW)..."
python3 - << 'PY_EOF'
filepath = ".github/workflows/ci.yml"
with open(filepath, "r") as f:
    content = f.read()

# Change runs-on for the windows build job
old_block = """  build-and-release-windows:
    name: Build & Release Windows Binary
    runs-on: ubuntu-latest"""
new_block = """  build-and-release-windows:
    name: Build & Release Windows Binary
    runs-on: ubuntu-22.04"""

content = content.replace(old_block, new_block)

with open(filepath, "w") as f:
    f.write(content)
print("[+] CI workflow updated to Ubuntu 22.04.")
PY_EOF

# 4. Commit, push, and tag
echo "[*] Committing, pushing, and tagging v1.12.6..."
git add .
git commit -m "fix(ci): resolve mingw linker issues, fix doc warning, and stabilize windows build"

git push origin main

git tag -d v1.12.5 || true
git push origin :refs/tags/v1.12.5 || true

git tag v1.12.6
git push origin v1.12.6

echo -e "\n=================================================="
echo -e "\033[92m\033[1m   SUCCESS: Fixes applied and v1.12.6 is running! \033[0m"
echo "=================================================="
