#!/bin/bash
set -e

echo "=================================================="
echo "   PHASE 1: DOCS CLEANUP, VERSION BUMP & STUBS    "
echo "=================================================="

# 1. Clean up temp scripts
echo "[*] Removing remaining temp scripts..."
rm -f purge_and_recon.sh recon_gap_analysis.sh

# 2. Fix README.md (Remove Windows badge and note)
echo "[*] Cleaning Windows references from README..."
sed -i 's/platform-linux%20%7C%20android%20%7C%20windows/platform-linux%20%7C%20android/g' README.md
# Remove the Windows note (Lines 12-14 roughly)
python3 - << 'PY_EOF'
filepath = "README.md"
with open(filepath, "r") as f:
    content = f.read()

content = content.replace(
    "> **Note**: Core system modules (system, cpu, memory) are now supported on Windows. Advanced modules are under active development.\n\n",
    ""
)
with open(filepath, "w") as f:
    f.write(content)
print("[+] README cleaned.")
PY_EOF

# 3. Bump Version to 1.13.0
echo "[*] Bumping workspace version to 1.13.0..."
sed -i 's/version      = "1.12.1"/version      = "1.13.0"/' Cargo.toml

# 4. Update CHANGELOG
echo "[*] Adding v1.13.0 to CHANGELOG..."
python3 - << 'PY_EOF'
filepath = "CHANGELOG.md"
with open(filepath, "r") as f:
    content = f.read()

new_entry = """## [1.13.0] — 2026-10-18

Major architectural cleanup and focus on Linux/Android stability.

### Removed
- **Windows Support:** Purged incomplete Windows cross-compilation pipelines to ensure 100% reliability on Linux and Android.
- Removed temporary CI scripts and LLD linker configurations.

### Changed
- Streamlined GitHub Actions CI to focus entirely on Linux quality gates.
- Updated README badges and documentation to reflect the Linux/Android focus.

---

"""
content = content.replace("---\n\n## [1.12.1]", "---\n\n" + new_entry + "## [1.12.1]")
with open(filepath, "w") as f:
    f.write(content)
print("[+] CHANGELOG updated.")
PY_EOF

# 5. Discover and print the Stub Modules
echo -e "\n\033[96m=== 5. THE STUB MODULES (TO BE IMPLEMENTED) ===\033[0m"
echo "Listing files under 1KB in modules directory:"
find crates/pulse-core/src/modules -type f -name "*.rs" -size -1k -exec ls -lh {} \; | awk '{print $9, "(" $5 ")"}'

echo -e "\nPrinting contents of a sample stub (e.g., iommu.rs):"
cat crates/pulse-core/src/modules/iommu.rs 2>/dev/null || echo "iommu.rs not found."

# 6. Commit and push
echo -e "\n[*] Committing and pushing Phase 1 changes..."
git add -A
git commit -m "docs: purge windows references, bump version to 1.13.0, and update changelog"
git push origin main

echo -e "\n=================================================="
echo -e "\033[92m\033[1m   PHASE 1 COMPLETE: Docs are clean, ready for Stubs! \033[0m"
echo "=================================================="
