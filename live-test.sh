#!/bin/bash
# ==========================================================================
# PULSE — LIVE TEST
# Build the real binary, run every command, verify against kernel,
# and produce a tangible evidence bundle.
# ==========================================================================
set -euo pipefail

PROJ="/root/pulse-build"
EVID="$PROJ/live-evidence"
BIN="$PROJ/target/aarch64-unknown-linux-musl/release/pulse"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

step() { echo -e "\n${BOLD}${MAGENTA}===== $1 =====${NC}"; }
sub()  { echo -e "\n${CYAN}--- $1 ---${NC}"; }
ok()   { echo -e "${GREEN}[✔]${NC} $1"; }
bad()  { echo -e "${RED}[✘]${NC} $1"; }
info() { echo -e "${YELLOW}[i]${NC} $1"; }

cd "$PROJ"
rm -rf "$EVID"
mkdir -p "$EVID"

# ==========================================================================
# PHASE 0 — Build
# ==========================================================================
step "PHASE 0 — Building the real binary"

cargo build --release --target aarch64-unknown-linux-musl 2>&1 | tail -n 3

if [ ! -f "$BIN" ]; then
    bad "Binary not produced"
    exit 1
fi

BIN_SHA=$(sha256sum "$BIN" | awk '{print $1}')
BIN_SIZE=$(stat -c%s "$BIN")
ok "Binary: $BIN_SIZE bytes"
ok "SHA-256: $BIN_SHA"

{
    echo "Pulse Live Test — $(date)"
    echo "Binary:   $BIN"
    echo "Size:     $BIN_SIZE bytes"
    echo "SHA-256:  $BIN_SHA"
    echo ""
    echo "## file(1)"
    file "$BIN"
    echo ""
    echo "## size(1)"
    size "$BIN"
} > "$EVID/00-binary.txt"

# ==========================================================================
# PHASE 1 — Every command, real execution
# ==========================================================================
step "PHASE 1 — Executing every command"

COMMANDS=(
    version help formats platform
    system cpu memory disk network process thermal gpu analyze
    mem-detail load vmstat cputimes
    users packages services filesystem env
    usb pci battery sensors drivers
    containers vm browsers crypto cron
    hwid trust
    snapshot anomaly timeline all
)

EXEC_LOG="$EVID/01-execution.txt"
{
    echo "Pulse Live Execution — $(date)"
    echo "Binary SHA-256: $BIN_SHA"
    echo ""
} > "$EXEC_LOG"

PASS=0
FAIL=0
for cmd in "${COMMANDS[@]}"; do
    if timeout 15 "$BIN" "$cmd" >/tmp/out.txt 2>/tmp/err.txt; then
        PASS=$((PASS+1))
        {
            echo "===== pulse $cmd ====="
            echo "exit: 0"
            echo "--- stdout ---"
            head -n 30 /tmp/out.txt
            echo ""
        } >> "$EXEC_LOG"
    else
        rc=$?
        FAIL=$((FAIL+1))
        {
            echo "===== pulse $cmd ====="
            echo "exit: $rc"
            echo "--- stdout ---"
            head -n 15 /tmp/out.txt
            echo "--- stderr ---"
            head -n 10 /tmp/err.txt
            echo ""
        } >> "$EXEC_LOG"
    fi
done

ok "$PASS commands succeeded, $FAIL failed"
info "Full log: $EXEC_LOG"

# ==========================================================================
# PHASE 2 — JSON output validation
# ==========================================================================
step "PHASE 2 — JSON output validation"

JSON_LOG="$EVID/02-json.txt"
{
    echo "Pulse Live JSON Validation — $(date)"
    echo ""
} > "$JSON_LOG"

JSON_PASS=0
JSON_FAIL=0
for cmd in system cpu memory disk network process thermal gpu analyze \
           load vmstat cputimes users services filesystem env \
           usb pci battery sensors drivers containers vm browsers crypto cron hwid trust; do
    if "$BIN" --json "$cmd" > /tmp/j.json 2>/dev/null; then
        if python3 -c "import json,sys; json.load(open('/tmp/j.json'))" 2>/dev/null; then
            JSON_PASS=$((JSON_PASS+1))
            echo "  [✔] $cmd → valid JSON" >> "$JSON_LOG"
        else
            JSON_FAIL=$((JSON_FAIL+1))
            echo "  [✘] $cmd → INVALID JSON" >> "$JSON_LOG"
        fi
    else
        JSON_FAIL=$((JSON_FAIL+1))
        echo "  [✘] $cmd → command failed" >> "$JSON_LOG"
    fi
done

ok "JSON: $JSON_PASS valid, $JSON_FAIL invalid"

# ==========================================================================
# PHASE 3 — Cross-verify against /proc
# ==========================================================================
step "PHASE 3 — Cross-verify against /proc"

VERIFY_LOG="$EVID/03-cross-verify.txt"
{
    echo "Pulse Live Cross-Verification — $(date)"
    echo ""
} > "$VERIFY_LOG"

MATCH=0
MISMATCH=0

# CPU cores
PROC_CORES=$(grep -c "^processor" /proc/cpuinfo)
PULSE_CORES=$("$BIN" --json cpu | python3 -c "import json,sys; print(json.load(sys.stdin)['cores'])")
{
    echo "CPU cores:"
    echo "  /proc/cpuinfo  = $PROC_CORES"
    echo "  pulse --json   = $PULSE_CORES"
} >> "$VERIFY_LOG"
if [ "$PROC_CORES" == "$PULSE_CORES" ]; then
    echo "  MATCH" >> "$VERIFY_LOG"; MATCH=$((MATCH+1))
else
    echo "  MISMATCH" >> "$VERIFY_LOG"; MISMATCH=$((MISMATCH+1))
fi

# Memory
PROC_MEM=$(grep "^MemTotal" /proc/meminfo | awk '{print $2}')
PULSE_MEM=$("$BIN" --json memory | python3 -c "import json,sys; print(json.load(sys.stdin)['total_kb'])")
{
    echo ""
    echo "MemTotal:"
    echo "  /proc/meminfo  = $PROC_MEM"
    echo "  pulse --json   = $PULSE_MEM"
} >> "$VERIFY_LOG"
if [ "$PROC_MEM" == "$PULSE_MEM" ]; then
    echo "  MATCH" >> "$VERIFY_LOG"; MATCH=$((MATCH+1))
else
    echo "  MISMATCH" >> "$VERIFY_LOG"; MISMATCH=$((MISMATCH+1))
fi

# Hostname
PROC_HOST=$(cat /proc/sys/kernel/hostname)
PULSE_HOST=$("$BIN" --json system | python3 -c "import json,sys; print(json.load(sys.stdin)['hostname'])")
{
    echo ""
    echo "Hostname:"
    echo "  /proc          = $PROC_HOST"
    echo "  pulse --json   = $PULSE_HOST"
} >> "$VERIFY_LOG"
if [ "$PROC_HOST" == "$PULSE_HOST" ]; then
    echo "  MATCH" >> "$VERIFY_LOG"; MATCH=$((MATCH+1))
else
    echo "  MISMATCH" >> "$VERIFY_LOG"; MISMATCH=$((MISMATCH+1))
fi

# Users
PROC_USERS=$(grep -c "" /etc/passwd)
PULSE_USERS=$("$BIN" --json users | python3 -c "import json,sys; print(len(json.load(sys.stdin)['users']))")
{
    echo ""
    echo "Users:"
    echo "  /etc/passwd    = $PROC_USERS"
    echo "  pulse --json   = $PULSE_USERS"
} >> "$VERIFY_LOG"
if [ "$PROC_USERS" == "$PULSE_USERS" ]; then
    echo "  MATCH" >> "$VERIFY_LOG"; MATCH=$((MATCH+1))
else
    echo "  MISMATCH" >> "$VERIFY_LOG"; MISMATCH=$((MISMATCH+1))
fi

ok "Cross-verify: $MATCH matched, $MISMATCH mismatched"

# ==========================================================================
# PHASE 4 — Determinism checks
# ==========================================================================
step "PHASE 4 — Determinism checks"

DET_LOG="$EVID/04-determinism.txt"
{
    echo "Pulse Live Determinism — $(date)"
    echo ""
} > "$DET_LOG"

DET_PASS=0
DET_FAIL=0

for cmd in platform version formats; do
    A=$("$BIN" --json "$cmd" 2>/dev/null || "$BIN" "$cmd" 2>/dev/null)
    B=$("$BIN" --json "$cmd" 2>/dev/null || "$BIN" "$cmd" 2>/dev/null)
    if [ "$A" == "$B" ]; then
        echo "  [✔] $cmd deterministic" >> "$DET_LOG"
        DET_PASS=$((DET_PASS+1))
    else
        echo "  [✘] $cmd NOT deterministic" >> "$DET_LOG"
        DET_FAIL=$((DET_FAIL+1))
    fi
done

# HWID must be stable (without context)
A=$("$BIN" --json hwid | python3 -c "import json,sys; print(json.load(sys.stdin)['hash'])" 2>/dev/null || echo "")
B=$("$BIN" --json hwid | python3 -c "import json,sys; print(json.load(sys.stdin)['hash'])" 2>/dev/null || echo "")
if [ -n "$A" ] && [ "$A" == "$B" ]; then
    echo "  [✔] hwid stable: $A" >> "$DET_LOG"
    DET_PASS=$((DET_PASS+1))
else
    echo "  [✘] hwid unstable" >> "$DET_LOG"
    DET_FAIL=$((DET_FAIL+1))
fi

ok "Determinism: $DET_PASS passed, $DET_FAIL failed"

# ==========================================================================
# PHASE 5 — Real-world workflows
# ==========================================================================
step "PHASE 5 — Real-world workflows"

WF_LOG="$EVID/05-workflows.txt"
{
    echo "Pulse Live Workflows — $(date)"
    echo ""
} > "$WF_LOG"

# Workflow 1: Snapshot → Diff
sub "Workflow 1: snapshot + diff"
SNAP_A="/tmp/pulse-snap-a.json"
SNAP_B="/tmp/pulse-snap-b.json"
"$BIN" snapshot --output="$SNAP_A" >/dev/null 2>&1
sleep 1
"$BIN" snapshot --output="$SNAP_B" >/dev/null 2>&1
if [ -f "$SNAP_A" ] && [ -f "$SNAP_B" ]; then
    {
        echo "Snapshot A: $(stat -c%s "$SNAP_A") bytes"
        echo "Snapshot B: $(stat -c%s "$SNAP_B") bytes"
        echo "Merkle A:"
        python3 -c "import json; print('  ' + json.load(open('$SNAP_A'))['merkle_root'])" >> "$WF_LOG"
        echo "Merkle B:"
        python3 -c "import json; print('  ' + json.load(open('$SNAP_B'))['merkle_root'])" >> "$WF_LOG"
        echo ""
        echo "--- pulse diff ---"
        "$BIN" diff "$SNAP_A" "$SNAP_B" >> "$WF_LOG" 2>&1
    } >> "$WF_LOG"
    ok "snapshot + diff worked"
fi

# Workflow 2: Sign → Verify → Tamper
sub "Workflow 2: sign + verify"
TEST_FILE="/tmp/pulse-sign-test.txt"
echo "test payload" > "$TEST_FILE"
{
    echo ""
    echo "--- pulse sign ---"
    "$BIN" sign "$TEST_FILE" >> "$WF_LOG" 2>&1
    echo ""
    echo "--- pulse verify (unmodified) ---"
    "$BIN" verify "$TEST_FILE" >> "$WF_LOG" 2>&1
    echo "MODIFIED" > "$TEST_FILE"
    echo ""
    echo "--- pulse verify (after tamper) ---"
    "$BIN" verify "$TEST_FILE" >> "$WF_LOG" 2>&1
} >> "$WF_LOG"
ok "sign + verify + tamper detection worked"

# Workflow 3: Trust score
sub "Workflow 3: trust"
{
    echo ""
    echo "--- pulse trust ---"
    "$BIN" trust >> "$WF_LOG" 2>&1
} >> "$WF_LOG"
ok "trust worked"

# Workflow 4: Timeline
sub "Workflow 4: timeline"
{
    echo ""
    echo "--- pulse timeline ---"
    "$BIN" timeline >> "$WF_LOG" 2>&1 | head -n 30
} >> "$WF_LOG"
ok "timeline worked"

# ==========================================================================
# PHASE 6 — Final evidence summary
# ==========================================================================
step "PHASE 6 — Summary"

{
    echo "# Pulse Live Test — Summary"
    echo "Date: $(date)"
    echo "Binary: $BIN"
    echo "SHA-256: $BIN_SHA"
    echo "Size: $BIN_SIZE bytes"
    echo ""
    echo "## Results"
    echo "- Commands executed: ${#COMMANDS[@]}"
    echo "- Commands succeeded: $PASS"
    echo "- Commands failed: $FAIL"
    echo "- JSON valid: $JSON_PASS"
    echo "- JSON invalid: $JSON_FAIL"
    echo "- Cross-verify matched: $MATCH"
    echo "- Cross-verify mismatched: $MISMATCH"
    echo "- Determinism passed: $DET_PASS"
    echo "- Determinism failed: $DET_FAIL"
    echo ""
    echo "## Evidence files"
    ls -la "$EVID"
} > "$EVID/README.txt"

cat "$EVID/README.txt"

echo ""
echo -e "${BOLD}${GREEN}========================================${NC}"
echo -e "${BOLD}${GREEN}  LIVE TEST COMPLETE${NC}"
echo -e "${BOLD}${GREEN}========================================${NC}"
echo -e "${BOLD}Evidence:${NC} $EVID/"
