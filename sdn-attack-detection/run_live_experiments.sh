#!/usr/bin/env bash
# =============================================================================
# run_live_experiments.sh — Automated live SDN experiment runner
#
# Runs all attack scenarios against the live controller and produces:
#   results/live/ddos_metrics.csv
#   results/live/scan_metrics.csv
#   results/live/exfiltration_metrics.csv
#   results/live/flow_exhaustion_metrics.csv
#   results/live/lateral_movement_metrics.csv
#   results/live/mitigation_latency.csv
#   results/live/false_positive_rate.csv
#   results/live/experiment_summary.csv
#
# Usage:
#   bash run_live_experiments.sh [--controller http://localhost:9000] [--duration 60]
# =============================================================================

set -euo pipefail
cd "$(dirname "$0")"

CONTROLLER="http://localhost:9000"
ADMIN_TOKEN="${ADMIN_API_KEY:-sdn-admin-2024}"
DURATION=60
for arg in "$@"; do
    [[ "$arg" == --controller=* ]] && CONTROLLER="${arg#*=}"
    [[ "$arg" == --duration=* ]]   && DURATION="${arg#*=}"
done

RESULTS="results/live"
mkdir -p "$RESULTS"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "======================================================================="
echo " SDN LIVE EXPERIMENT RUNNER — $(date)"
echo " Controller: $CONTROLLER | Duration per scenario: ${DURATION}s"
echo "======================================================================="

# ── Check controller reachability ────────────────────────────────────────────
echo ""
echo "[0/7] Checking controller at $CONTROLLER..."
if ! curl -sf "$CONTROLLER/health" > /dev/null 2>&1; then
    echo "ERROR: Controller not reachable at $CONTROLLER"
    echo "Start the stack first: docker compose -f app_sdn/docker-compose.yml up -d"
    exit 1
fi
echo "  ✔ Controller healthy"

run_scenario() {
    local name="$1"
    local script="$2"
    local out_csv="$3"

    echo ""
    echo "─────────────────────────────────────────────────────────────────────"
    echo "[?/?] Running scenario: $name (${DURATION}s)"
    echo "─────────────────────────────────────────────────────────────────────"

    # Reset controller state
    curl -sf -X POST "$CONTROLLER/reset" -H "X-Admin-Token: $ADMIN_TOKEN" > /dev/null 2>&1 || true
    sleep 2

    # Run scenario (scenarios save CSVs themselves to results/live/)
    python3 "$script" \
        --controller "$CONTROLLER" \
        --duration "$DURATION" \
        --standalone \
        2>&1 | grep -E "\[|RESULT|ERROR|SIM|SCAN|EXFIL|EXHAUST|LATERAL|ARP" || true

    if [[ -f "$out_csv" ]]; then
        echo "  ✔ Results: $out_csv"
    else
        echo "  ⚠ No output CSV (scenario may save under a different name)"
    fi
}

# ── DDoS / SYN Flood ─────────────────────────────────────────────────────────
echo ""
echo "[1/7] DDoS — SYN Flood"
curl -sf -X POST "$CONTROLLER/reset" -H "X-Admin-Token: $ADMIN_TOKEN" > /dev/null 2>&1 || true
sleep 2

python3 - <<PYEOF
import sys, time, json, csv, os, requests

controller = "${CONTROLLER}"
duration   = ${DURATION}
out_csv    = "${RESULTS}/ddos_metrics.csv"
headers    = {"X-Switch-Token": "sdn-secret-2024", "Content-Type": "application/json"}

rows = []
start = time.time()
detection_t = None

# Normal phase (first third)
normal_end = start + duration / 3
while time.time() < normal_end:
    for i in range(1, 5):
        try:
            requests.post(f"{controller}/telemetry", headers=headers, timeout=2,
                json={"src": f"10.0.0.{i}", "dst": "10.0.0.5",
                      "flows": [[100, 80000, 5.0], [110, 88000, 5.0]]})
        except: pass
    time.sleep(2)

# Attack phase (remaining two thirds)
attack_start = time.time()
while time.time() < start + duration:
    try:
        r = requests.post(f"{controller}/telemetry", headers=headers, timeout=2,
            json={"src": "10.0.0.6", "dst": "10.0.0.5",
                  "flows": [[2, 100, 0.05]] * 90})
        d = r.json()
        if d.get("verdict") == "Attack" and detection_t is None:
            detection_t = round(time.time() - attack_start, 2)
            print(f"[SIM] Attack detected at {detection_t}s")
    except: pass
    time.sleep(2)

try:
    ft  = requests.get(f"{controller}/flow_table", timeout=2).json()
    sts = requests.get(f"{controller}/stats", timeout=2).json()
except:
    ft, sts = {}, {}

rows.append({
    "scenario": "ddos_syn_flood",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "duration_s": duration,
    "detection_latency_s": detection_t or "none",
    "attacker_blocked": "10.0.0.6" in ft,
    "false_positives": sum(1 for ip in ["10.0.0.1","10.0.0.2","10.0.0.3","10.0.0.4"] if ip in ft),
    "total_detections": sts.get("total_detections", 0),
    "drop_rules": sts.get("drop_rules", 0),
})

with open(out_csv, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)
print(f"[RESULT] DDoS: detected={rows[0]['attacker_blocked']}, latency={detection_t}s, fp={rows[0]['false_positives']}")
PYEOF

# ── Port Scan ────────────────────────────────────────────────────────────────
echo ""
echo "[2/7] Port Scan / Reconnaissance"
if [[ -f "simulation/scenarios/port_scan.py" ]]; then
    run_scenario "Port Scan" "simulation/scenarios/port_scan.py" \
        "${RESULTS}/scan_metrics.csv"
else
    echo "  ⚠ simulation/scenarios/port_scan.py not found, skipping"
fi

# ── Data Exfiltration ────────────────────────────────────────────────────────
echo ""
echo "[3/7] Data Exfiltration"
if [[ -f "simulation/scenarios/data_exfiltration.py" ]]; then
    run_scenario "Data Exfiltration" "simulation/scenarios/data_exfiltration.py" \
        "${RESULTS}/exfiltration_metrics.csv"
else
    echo "  ⚠ simulation/scenarios/data_exfiltration.py not found, skipping"
fi

# ── Flow Table Exhaustion ─────────────────────────────────────────────────────
echo ""
echo "[4/7] Flow Table Exhaustion"
if [[ -f "simulation/scenarios/flow_exhaustion.py" ]]; then
    run_scenario "Flow Exhaustion" "simulation/scenarios/flow_exhaustion.py" \
        "${RESULTS}/flow_exhaustion_metrics.csv"
else
    echo "  ⚠ simulation/scenarios/flow_exhaustion.py not found, skipping"
fi

# ── Lateral Movement ─────────────────────────────────────────────────────────
echo ""
echo "[5/7] Lateral Movement"
if [[ -f "simulation/scenarios/lateral_movement.py" ]]; then
    run_scenario "Lateral Movement" "simulation/scenarios/lateral_movement.py" \
        "${RESULTS}/lateral_movement_metrics.csv"
else
    echo "  ⚠ simulation/scenarios/lateral_movement.py not found, skipping"
fi

# ── ARP Spoof / MITM ─────────────────────────────────────────────────────────
echo ""
echo "[6/8] ARP Spoof / MITM"
if [[ -f "simulation/scenarios/arp_spoof.py" ]]; then
    run_scenario "ARP Spoof" "simulation/scenarios/arp_spoof.py" \
        "${RESULTS}/arp_spoof_metrics.csv"
else
    echo "  ⚠ simulation/scenarios/arp_spoof.py not found, skipping"
fi

# ── Mitigation Latency (combined) ────────────────────────────────────────────
echo ""
echo "[7/8] Collecting mitigation latency metrics..."

python3 - <<PYEOF
import csv, os, glob, json

results_dir = "${RESULTS}"
out_csv = f"{results_dir}/mitigation_latency.csv"

rows = []
for f in glob.glob(f"{results_dir}/*_metrics.csv"):
    try:
        with open(f) as csvf:
            for row in csv.DictReader(csvf):
                if row.get("detection_latency_s") not in ("none", ""):
                    rows.append({
                        "scenario": row.get("scenario", os.path.basename(f)),
                        "detection_latency_s": row.get("detection_latency_s"),
                        "attacker_blocked": row.get("attacker_blocked"),
                        "false_positives": row.get("false_positives", 0),
                    })
    except Exception as e:
        print(f"  ⚠ Could not read {f}: {e}")

if rows:
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario","detection_latency_s","attacker_blocked","false_positives"])
        w.writeheader(); w.writerows(rows)
    print(f"[RESULT] Latency file: {out_csv} ({len(rows)} entries)")
else:
    print("  ⚠ No latency data collected")
PYEOF

# ── False Positive Rate ───────────────────────────────────────────────────────
echo ""
echo "[8/8] False Positive Rate Analysis..."

python3 - <<PYEOF
import csv, os, glob, json, requests, time

controller = "${CONTROLLER}"
results_dir = "${RESULTS}"
headers     = {"X-Switch-Token": "sdn-secret-2024", "Content-Type": "application/json"}

# Reset and send only legitimate traffic, check for false positives
try:
    requests.post(f"{controller}/reset",
                  headers={"X-Admin-Token": "sdn-admin-2024"}, timeout=2)
    time.sleep(1)

    for _ in range(10):
        for i in range(1, 5):
            requests.post(f"{controller}/telemetry", headers=headers, timeout=2,
                json={"src": f"10.0.0.{i}", "dst": "10.0.0.5",
                      "flows": [[100, 80000, 5.0], [110, 88000, 5.0]]})
        time.sleep(1)

    ft  = requests.get(f"{controller}/flow_table", timeout=2).json()
    legit_ips = [f"10.0.0.{i}" for i in range(1, 5)]
    fp_list   = [ip for ip in legit_ips if ip in ft]
    fp_rate   = len(fp_list) / len(legit_ips) * 100

    rows = [{"scenario": "legitimate_only",
             "total_legit_hosts": len(legit_ips),
             "false_positives": len(fp_list),
             "fp_rate_pct": round(fp_rate, 2),
             "fp_ips": str(fp_list)}]

    with open(f"{results_dir}/false_positive_rate.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)
    print(f"[RESULT] FP rate: {fp_rate:.1f}% ({len(fp_list)}/{len(legit_ips)} legit hosts blocked)")
except Exception as e:
    print(f"  ⚠ FP test failed: {e}")
PYEOF

# ── Aggregate summary ─────────────────────────────────────────────────────────
echo ""
echo "======================================================================="
echo " Aggregating experiment summary..."
echo "======================================================================="

python3 - <<PYEOF
import csv, os, glob

results_dir = "${RESULTS}"
summary_rows = []

for f in sorted(glob.glob(f"{results_dir}/*_metrics.csv")):
    try:
        with open(f) as csvf:
            for row in csv.DictReader(csvf):
                summary_rows.append(row)
    except: pass

if summary_rows:
    fieldnames = list(summary_rows[0].keys())
    with open(f"{results_dir}/experiment_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(summary_rows)
    print(f"[RESULT] Summary: {len(summary_rows)} experiments → {results_dir}/experiment_summary.csv")

print()
print("Generated files:")
import glob as g
for fn in sorted(g.glob(f"{results_dir}/*.csv")):
    size = os.path.getsize(fn)
    print(f"  {fn} ({size} bytes)")
PYEOF

echo ""
echo "======================================================================="
echo " EXPERIMENTS COMPLETE — Results in ${RESULTS}/"
echo "======================================================================="
echo " Run 'bash demo_10min.sh' for the interactive 10-minute demo"
echo "======================================================================="
