#!/bin/bash
set -e

echo "=================================================="
echo "   FIXING CI TRIGGERS FOR RELEASES & PERMISSIONS  "
echo "=================================================="

WORKFLOW_FILE=".github/workflows/ci.yml"

# Overwrite the top part of ci.yml to include tags and permissions
python3 - << 'PY_EOF'
import re

filepath = ".github/workflows/ci.yml"
with open(filepath, "r") as f:
    content = f.read()

# Replace the trigger block
new_header = """name: Pulse CI Pipeline

on:
  push:
    branches: [ "main", "master" ]
    tags: [ "v*" ]
  pull_request:
    branches: [ "main", "master" ]

permissions:
  contents: write
"""

# Find the old trigger block and replace it
content = re.sub(r"name: Pulse CI Pipeline\n\non:\n(?:  .*\n)*", new_header, content)

with open(filepath, "w") as f:
    f.write(content)
print("[+] ci.yml triggers and permissions updated.")
PY_EOF

echo "[*] Committing and pushing the fix..."
git add .github/workflows/ci.yml
git commit -m "ci: fix triggers for tags and add write permissions for releases"
git push origin main

echo -e "\n=================================================="
echo -e "\033[92m\033[1m   SUCCESS: CI is now ready for Releases!        \033[0m"
echo "=================================================="
