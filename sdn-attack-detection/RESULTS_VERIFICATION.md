# Results Verification — SDN Attack Detection System

Two distinct experiment paths, kept separate on purpose:

- **API-level** scenarios: crafted telemetry sent straight to the controller REST API,
  produced by `bash run_live_experiments.sh` and `bash demo_10min.sh`. Latencies here are
  API-level (no real packets).
- **Packet-level** scenario: the real Mininet + Open vSwitch stack, produced by
  `bash run_packet_level_experiment.sh`. This is the only path with real dropped packets.

---

## API-level scenarios (`run_live_experiments.sh`)

| Scenario | Detection Latency (API) | Attacker Blocked | False Positives | Result file |
|---|---|---|---|---|
| DDoS / SYN Flood | 0.03 s (API only) | ✅ YES | 0 | `results/live/ddos_metrics.csv` |
| Port Scan | **0.24 s** (official 20 s run; a 60 s run gave 0.17 s) | ✅ YES | 0 | `results/live/scan_metrics.json` (20 s); both runs in `scan_metrics.csv` |
| Data Exfiltration | **0.71 s** | ✅ YES | 4* | `results/live/exfiltration_metrics.json` |
| Flow Table Exhaustion | **0.14 s** | ✅ YES | 0 | `results/live/flow_exhaustion_metrics.json` |
| Lateral Movement | **0.31 s** | ✅ YES | 1* | `results/live/lateral_movement_metrics.json` |
| ARP Spoof / MITM | N/A | ⚠️ blocked via collateral activity, **not** detected (TP=0, 2 FN) | 0 | `results/live/arp_spoof_metrics.json` |
| Legitimate only (FP test) | — | — | **0 / 4 (0%)** | `results/live/false_positive_rate.csv` |

> \* False positives in data exfiltration and lateral movement are expected: high-bandwidth hosts
> and scan-originating hosts exhibit anomalous patterns that the unsupervised Isolation Forest
> correctly flags as outliers. This is discussed in the thesis as a known trade-off of
> unsupervised detection.
>
> The ARP spoofing itself is **not** recognised by aggregate statistical detection; the attacker
> is blocked only because of accompanying anomalous activity (see thesis §6.8.6).

---

## Packet-level scenario (`run_packet_level_experiment.sh`)

Real hping3 SYN flood, 60 s attack, DROP rule with a 10 s lease that is **renewed** while the
attack continues. Latencies measured with a monotonic clock from attack start. Run
`mininet_run_20260714_184311`, commit recorded in `summary.json → code_commit`.

| Metric | Value | Source |
|---|---|---|
| First malicious telemetry | 1.14 s | `summary.json → latencies_s` |
| Model verdict (detection) | **1.16 s** | `summary.json → latencies_s` |
| Rule installed | 1.17 s | `summary.json → latencies_s` |
| First dropped packet | ~1.5 s (±0.5 s sampling) | `summary.json → latencies_s` |
| Total dropped packets | **1,456,155** | `ovs_dump_flows.txt` / summary |
| DROP rule leases (proactive / reactive) | 9 leases (8 proactive renewals, 0 reactive) | `summary.json` |
| Mitigation coverage | **97.7%** total, **100%** after detection | `summary.json` |
| False positives on legit hosts | 0 | `summary.json` |
| Legit ping during attack | 0% loss, ~4 ms RTT | `summary.json` |

The DROP-counter-derived timestamps (first dropped packet) carry ~±0.5 s sampling accuracy; the
model-verdict and rule-install latencies are direct monotonic timestamps and are precise.

TTL sweep (5 / 10 / 20 s) and the no-proactive-renewal baseline are recorded as separate `packet_level`
rows in `results/live/experiment_summary.csv`.

### Repeated cycles (10 cycles within one execution, statistical reliability)

Run `mininet_run_20260714_213805`, **10 repeated attack cycles within a single execution** of the
stack (same topology / controller / model, state reset between cycles — not 10 fully independent
stack restarts). Aggregates in `results/live/packet_level_repeated_stats.csv`; network impact in
`results/live/network_impact.csv`. Confidence intervals use the **t-distribution** (df = 9).

| Metric | Median | Mean | p95 | 95% CI of mean (t) |
|---|---|---|---|---|
| Detection rate | **100% (10/10)** | — | — | — |
| False-positive cycles | **0 / 10** | — | — | — |
| Detection latency (s) | 1.41 | 1.52 | 2.66 | [1.06, 1.98] |
| First dropped packet (s) * | 1.52 | 1.66 | 2.97 | [1.18, 2.13] |
| Mitigation coverage (%) | 95.6 | 95.0 | 97.1 | [93.6, 96.4] |
| Coverage after detection (%) | 100 | 100 | 100 | [100, 100] |
| Dropped packets | 744,845 | 746,757 | 770,106 | [736,192, 757,321] |

\* First-dropped-packet time has ~±0.5 s sampling accuracy (DROP counter polled every 0.5 s).

**Network impact (legit host, measured quantities only):** 0% packet loss in every phase of every
cycle; mean RTT ~4.5 ms (normal) / ~4.3 ms (under attack) / ~4.5 ms (after recovery). Within the
measured quantities (loss and RTT of the ping traffic) the mitigation isolates the attacker without
degrading legitimate traffic; throughput, jitter and controller CPU/RAM were not measured.

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
| Mode B (Ryu/OpenFlow) | ⚙️ Implemented experimental profile (`--profile ryu`) — **not** end-to-end validated |

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
