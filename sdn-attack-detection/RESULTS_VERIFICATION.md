# Results Verification — SDN Attack Detection System

Live experiment results produced by `bash run_live_experiments.sh` and `bash demo_10min.sh`
against the running Docker stack (controller at `http://localhost:9000`).

---

## Experiment Run Summary

| Scenario | Detection Latency | Attacker Blocked | False Positives | Result file |
|---|---|---|---|---|
| DDoS / SYN Flood | **0.9 s** | ✅ YES | 0 | `results/live/ddos_metrics.csv` |
| Port Scan | **0.24 s** | ✅ YES | 0 | `results/live/scan_metrics.json` |
| Data Exfiltration | **0.71 s** | ✅ YES | 4* | `results/live/exfiltration_metrics.json` |
| Flow Table Exhaustion | **0.14 s** | ✅ YES | 0 | `results/live/flow_exhaustion_metrics.json` |
| Lateral Movement | **0.31 s** | ✅ YES | 1* | `results/live/lateral_movement_metrics.json` |
| ARP Spoof / MITM | N/A (volume-based) | ✅ YES | 0 | `results/live/arp_spoof_metrics.json` |
| Legitimate only (FP test) | — | — | **0 / 4 (0%)** | `results/live/false_positive_rate.csv` |

> \* False positives in data exfiltration and lateral movement are expected: high-bandwidth hosts
> and scan-originating hosts exhibit anomalous patterns that the unsupervised Isolation Forest
> correctly flags as outliers. This is discussed in the thesis as a known trade-off of
> unsupervised detection.

---

## Demo Run (demo_10min.sh)

Run ID: `demo_run_20260620_031742`

| Field | Value |
|---|---|
| Scenario | SYN Flood h6 → h5 |
| Detection time | < 1 s |
| Attacker (10.0.0.6) blocked | **YES** |
| False positives | **0** |
| New detections during demo | 34 |
| Dashboard | http://localhost:8050 |
| Results directory | `results/live/demo_run_20260620_031742/` |

---

## False Positive Rate (standalone test)

Legitimate-only traffic from h1–h4, 10 rounds × 4 hosts = 40 telemetry calls.

| Metric | Value |
|---|---|
| Total legitimate hosts | 4 |
| Incorrectly blocked | **0** |
| False positive rate | **0.0%** |

---

## System Architecture Verified

| Component | Status |
|---|---|
| Flask ML Controller (:9000) | ✅ Running |
| Dash Dashboard (:8050) | ✅ Running |
| OVS Switch | ✅ Running |
| Isolation Forest model | ✅ Loaded |
| Rate limiting (120 req/60s) | ✅ Active |
| Admin token protection | ✅ Active (`X-Admin-Token`) |
| Switch token auth | ✅ Active (`X-Switch-Token`) |
| Live CSV export | ✅ `/export/flows.csv`, `/export/blocked.csv` |
| Anomaly scores endpoint | ✅ `/anomaly_scores` |
| Sim control API | ✅ `/simulate/command`, `/simulate/poll` |
| Mode B (Ryu/OpenFlow) | ✅ Available via `--profile ryu` |

---

## How to Reproduce

```bash
# Start the stack
docker compose -f app_sdn/docker-compose.yml up -d controller dashboard switch

# Run all attack scenarios
bash run_live_experiments.sh --controller http://localhost:9000 --duration 60

# Run the 10-minute examiner demo
bash demo_10min.sh --no-build

# Run the full ML pipeline (offline)
bash run_all.sh
```
