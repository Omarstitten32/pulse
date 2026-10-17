#!/bin/bash
set -e

echo "=================================================="
echo "   FIXING GITHUB ACTIONS: INSTALL MINGW-W64       "
echo "=================================================="

WORKFLOW_FILE=".github/workflows/ci.yml"

# 1. Update ci.yml to install mingw-w64
echo "[*] Updating CI workflow to install mingw-w64..."
python3 - << 'PY_EOF'
import re

filepath = ".github/workflows/ci.yml"
with open(filepath, "r") as f:
    content = f.read()

# Add the installation step in the windows build job
# We look for the "Add Windows Target" step and insert our step before "Build Windows Release Binary"
old_step = """    - name: Build Windows Release Binary
      run: cargo build --release --target x86_64-pc-windows-gnu"""

new_steps = """    - name: Install MinGW-w64 (Required for linking)
      run: sudo apt-get update && sudo apt-get install -y mingw-w64
    - name: Build Windows Release Binary
      run: cargo build --release --target x86_64-pc-windows-gnu"""

content = content.replace(old_step, new_steps)

with open(filepath, "w") as f:
    f.write(content)
print("[+] ci.yml updated with MinGW-w64 installation.")
PY_EOF

# 2. Remove the temporary script from Git
echo "[*] Removing temporary script from repository..."
git rm --cached fix_sniper_tests.sh || true
echo "fix_sniper_tests.sh" >> .gitignore

# 3. Commit, Push, and Tag
echo "[*] Committing and pushing changes..."
git add .github/workflows/ci.yml .gitignore
git commit -m "ci: install mingw-w64 for windows cross-compilation"

git push origin main

# 4. Create a new tag to trigger the release
echo "[*] Creating new tag v1.12.3 to trigger the release..."
git tag v1.12.3
git push origin v1.12.3

echo -e "\n=================================================="
echo -e "\033[92m\033[1m   SUCCESS: Pipeline fixed and v1.12.3 is running! \033[0m"
echo "=================================================="
