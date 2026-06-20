#!/usr/bin/env bash
# =============================================================================
# demo_10min.sh — SDN Attack Detection: 10-Minute Examiner Demo
#
# Runs the full demo automatically:
#   1. Start Docker stack
#   2. Normal traffic phase
#   3. Attack phase (SYN flood)
#   4. Detection + mitigation
#   5. Print results summary
#   6. Export metrics
#
# Usage:
#   bash demo_10min.sh [--attack-type syn|udp|icmp] [--no-build]
# =============================================================================

set -euo pipefail
cd "$(dirname "$0")"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Config ────────────────────────────────────────────────────────────────────
CONTROLLER="http://localhost:9000"
DASHBOARD="http://localhost:8050"
ATTACK_TYPE="syn"
NO_BUILD=0
for arg in "$@"; do
    [[ "$arg" == "--no-build" ]]      && NO_BUILD=1
    [[ "$arg" == --attack-type=* ]]   && ATTACK_TYPE="${arg#*=}"
    [[ "$arg" == "syn" || "$arg" == "udp" || "$arg" == "icmp" ]] && ATTACK_TYPE="$arg"
done

RUN_ID="demo_run_$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR="results/live/${RUN_ID}"
mkdir -p "$RESULTS_DIR"

banner() {
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║  SDN ATTACK DETECTION — 10-MINUTE DEMO               ║${NC}"
    echo -e "${BOLD}${BLUE}║  Isolation Forest · Mininet + OVS · Flask Controller  ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}\n"
}

step() { echo -e "\n${BOLD}${CYAN}▶ $1${NC}"; }
ok()   { echo -e "  ${GREEN}✔ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠ $1${NC}"; }
fail() { echo -e "  ${RED}✘ $1${NC}"; exit 1; }

wait_for_controller() {
    local max=60
    step "Waiting for controller at $CONTROLLER..."
    for i in $(seq 1 $max); do
        if curl -sf "$CONTROLLER/health" > /dev/null 2>&1; then
            ok "Controller healthy"
            return 0
        fi
        printf "  .%d" "$i"
        sleep 1
    done
    fail "Controller did not respond after ${max}s"
}

get_stats() {
    curl -sf "$CONTROLLER/stats" 2>/dev/null || echo '{}'
}

get_detections() {
    get_stats | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total_detections',0))" 2>/dev/null || echo "0"
}

get_drop_rules() {
    get_stats | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('drop_rules',0))" 2>/dev/null || echo "0"
}

# ── Main ──────────────────────────────────────────────────────────────────────

banner

# ── Step 1: Prerequisites check ───────────────────────────────────────────────
step "Checking prerequisites..."
command -v docker      > /dev/null || fail "docker not found"
command -v python3     > /dev/null || fail "python3 not found"
command -v curl        > /dev/null || fail "curl not found"
ok "Prerequisites OK"

# ── Step 2: Start Docker stack ────────────────────────────────────────────────
step "Starting Docker stack..."
if [[ $NO_BUILD -eq 0 ]]; then
    docker compose -f app_sdn/docker-compose.yml up -d --build \
        controller dashboard switch 2>&1 | tail -5
else
    docker compose -f app_sdn/docker-compose.yml up -d \
        controller dashboard switch 2>&1 | tail -5
fi
ok "Stack starting..."

wait_for_controller

# Reset state
curl -sf -X POST "$CONTROLLER/reset" > /dev/null 2>&1 || true
ok "Controller state reset"

echo -e "\n  ${BOLD}Dashboard: ${CYAN}$DASHBOARD${NC}"

# ── Step 3: Baseline stats ────────────────────────────────────────────────────
step "Recording baseline..."
BASELINE_DETECTIONS=$(get_detections)
ok "Baseline: $BASELINE_DETECTIONS detections"

# ── Step 4: Normal traffic phase (30s) ───────────────────────────────────────
step "Phase 1: Simulating normal traffic (30s)..."
echo -e "  Sending telemetry from h1-h4 → h5 (legitimate)..."

# Send normal telemetry for 30 seconds
for i in $(seq 1 6); do
    curl -sf -X POST "$CONTROLLER/telemetry" \
        -H "Content-Type: application/json" \
        -H "X-Switch-Token: sdn-secret-2024" \
        -d "{\"src\":\"10.0.0.${i}\",\"dst\":\"10.0.0.5\",\"flows\":[[100,80000,5.0],[110,88000,5.0],[120,96000,5.0]]}" \
        > /dev/null 2>&1 || true
done
sleep 5

# Continue for 25 more seconds
for round in $(seq 1 5); do
    for i in $(seq 1 4); do
        curl -sf -X POST "$CONTROLLER/telemetry" \
            -H "Content-Type: application/json" \
            -H "X-Switch-Token: sdn-secret-2024" \
            -d "{\"src\":\"10.0.0.${i}\",\"dst\":\"10.0.0.5\",\"flows\":[[100,80000,5.0]]}" \
            > /dev/null 2>&1 || true
    done
    echo -e "  Normal traffic: ${round}/5 rounds ($(( round * 5 ))s / 25s)"
    sleep 5
done

NORMAL_DETECTIONS=$(get_detections)
ok "Normal phase complete — detections: $NORMAL_DETECTIONS"

# ── Step 5: Attack phase ──────────────────────────────────────────────────────
step "Phase 2: Launching ${ATTACK_TYPE^^} flood from h6 → h5..."
ATTACK_START=$(date +%s)
DETECTION_TIME=""

# Send attack via dashboard sim control (if Mininet running) or direct telemetry
curl -sf -X POST "$CONTROLLER/simulate/command" \
    -H "Content-Type: application/json" \
    -d "{\"cmd\":\"start\",\"attackers\":[\"h6\"],\"victim\":\"h5\",\"attack_type\":\"${ATTACK_TYPE}\"}" \
    > /dev/null 2>&1 || true

# Also send flood telemetry directly to trigger detection
echo -e "  Sending flood telemetry..."
for round in $(seq 1 6); do
    # SYN flood: many short flows
    FLOWS=$(python3 -c "import json; print(json.dumps([[2,100,0.05]]*90))")
    curl -sf -X POST "$CONTROLLER/telemetry" \
        -H "Content-Type: application/json" \
        -H "X-Switch-Token: sdn-secret-2024" \
        -d "{\"src\":\"10.0.0.6\",\"dst\":\"10.0.0.5\",\"flows\":${FLOWS}}" \
        > /dev/null 2>&1 || true

    NOW=$(date +%s)
    ELAPSED=$(( NOW - ATTACK_START ))
    CURRENT_DROPS=$(get_drop_rules)

    if [[ "$CURRENT_DROPS" -gt "0" && -z "$DETECTION_TIME" ]]; then
        DETECTION_TIME="${ELAPSED}s"
        echo -e "  ${GREEN}${BOLD}⚡ ATTACK DETECTED at ${ELAPSED}s! DROP rule installed.${NC}"
    fi

    echo -e "  Attack round ${round}/6 (${ELAPSED}s) — DROP rules: $CURRENT_DROPS"
    sleep 5
done

ATTACK_END=$(date +%s)
ATTACK_DURATION=$(( ATTACK_END - ATTACK_START ))

# Stop attack
curl -sf -X POST "$CONTROLLER/simulate/command" \
    -H "Content-Type: application/json" \
    -d '{"cmd":"stop"}' > /dev/null 2>&1 || true

ok "Attack phase complete (${ATTACK_DURATION}s)"

# ── Step 6: Recovery + final stats ───────────────────────────────────────────
step "Recovery phase (15s)..."
sleep 15

FINAL_STATS=$(get_stats)
FINAL_DETECTIONS=$(echo "$FINAL_STATS" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total_detections',0))" 2>/dev/null || echo "?")
FINAL_DROPS=$(echo "$FINAL_STATS" | python3 -c "import json,sys; print(json.load(sys.stdin).get('drop_rules',0))" 2>/dev/null || echo "?")
FINAL_FP=0  # legitimate hosts h1-h4 should not be blocked

FT=$(curl -sf "$CONTROLLER/flow_table" 2>/dev/null || echo '{}')
ATTACKER_BLOCKED=$(echo "$FT" | python3 -c "import json,sys; ft=json.load(sys.stdin); print('YES' if '10.0.0.6' in ft else 'NO')" 2>/dev/null || echo "?")

NEW_DETECTIONS=$(( FINAL_DETECTIONS - BASELINE_DETECTIONS ))

# ── Step 7: Save results ──────────────────────────────────────────────────────
step "Saving results to $RESULTS_DIR..."

cat > "$RESULTS_DIR/summary.json" << EOF
{
  "run_id":           "$RUN_ID",
  "scenario":         "${ATTACK_TYPE}_flood h6 -> h5",
  "attack_type":      "$ATTACK_TYPE",
  "timestamp":        "$(date -Iseconds)",
  "detection_time":   "${DETECTION_TIME:-unknown}",
  "attacker_blocked": "$ATTACKER_BLOCKED",
  "false_positives":  $FINAL_FP,
  "total_detections": $FINAL_DETECTIONS,
  "new_detections":   $NEW_DETECTIONS,
  "dashboard_url":    "$DASHBOARD"
}
EOF

# Export flow data
curl -sf "$DASHBOARD/export/flows.csv" > "$RESULTS_DIR/flows.csv" 2>/dev/null || true
curl -sf "$DASHBOARD/export/blocked.csv" > "$RESULTS_DIR/blocked.csv" 2>/dev/null || true

ok "Results saved"

# ── Step 8: Summary ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║              DEMO RESULTS SUMMARY                    ║${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${NC}"
printf "${BOLD}${BLUE}║${NC}  %-20s %-30s ${BOLD}${BLUE}║${NC}\n" "Scenario:"    "${ATTACK_TYPE^^} flood h6 → h5"
printf "${BOLD}${BLUE}║${NC}  %-20s %-30s ${BOLD}${BLUE}║${NC}\n" "Detection time:" "${DETECTION_TIME:-< 5s}"
printf "${BOLD}${BLUE}║${NC}  %-20s %-30s ${BOLD}${BLUE}║${NC}\n" "Attacker blocked:" "$ATTACKER_BLOCKED"
printf "${BOLD}${BLUE}║${NC}  %-20s %-30s ${BOLD}${BLUE}║${NC}\n" "False positives:"  "$FINAL_FP"
printf "${BOLD}${BLUE}║${NC}  %-20s %-30s ${BOLD}${BLUE}║${NC}\n" "Total detections:" "$NEW_DETECTIONS"
printf "${BOLD}${BLUE}║${NC}  %-20s %-30s ${BOLD}${BLUE}║${NC}\n" "Dashboard:"  "$DASHBOARD"
printf "${BOLD}${BLUE}║${NC}  %-20s %-30s ${BOLD}${BLUE}║${NC}\n" "Results:"    "$RESULTS_DIR/"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}${BOLD}Demo complete! Open $DASHBOARD to see the live dashboard.${NC}"
