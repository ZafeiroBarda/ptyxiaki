#!/usr/bin/env python3
"""
data_exfiltration.py — Data exfiltration scenario (sustained abnormal outbound transfer).

Attack model:
  h6 (10.0.0.6) has compromised internal data and begins sending a large, sustained
  high-bandwidth stream to an external IP (10.0.0.99, outside the SDN subnet).
  The traffic is characterised by very large flows with high bytes-per-packet ratio,
  consistent duration, and a single outbound destination.

Detection signal to Isolation Forest:
  - very high avg_bytes_per_flow  (large file chunks, 1400-byte MTU packets)
  - high avg_pkts_per_flow        (sustained, hundreds of packets per poll window)
  - low flow_count                (single destination — h6 only talks to one external IP)
  - low short_ratio               (all flows are long-running, not short)
  - distinctly different from background traffic: high bytes/packet ratio (~1400)

Architecture note:
  The exfiltration is sent as large-bytes telemetry from h6.
  Normal hosts send to internal IPs with small-to-medium flows.
  The anomaly detector sees h6's traffic as an outlier in the feature space.

Usage:
  python3 simulation/scenarios/data_exfiltration.py --standalone --controller http://127.0.0.1:9000
  python3 simulation/scenarios/data_exfiltration.py --standalone --duration 60
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any

import requests

CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "http://127.0.0.1:9000")
SWITCH_API_KEY = os.environ.get("SWITCH_API_KEY", "sdn-secret-2024")

ATTACKER_IP  = "10.0.0.6"
EXTERNAL_IP  = "10.0.0.99"   # simulated external C2 / exfil server
LEGIT_IPS    = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]

HEADERS = {"X-Switch-Token": SWITCH_API_KEY, "Content-Type": "application/json"}
RESULTS_DIR = Path(__file__).resolve().parents[2] / "results" / "live"


def _post_telemetry(controller: str, src: str, dst: str,
                    flows: list[list]) -> dict[str, Any]:
    try:
        r = requests.post(
            f"{controller}/telemetry",
            json={"src": src, "dst": dst, "flows": flows},
            headers=HEADERS,
            timeout=5,
        )
        return r.json()
    except Exception as exc:
        return {"error": str(exc), "verdict": "Unknown", "action": "FORWARD"}


def _get_stats(controller: str) -> dict[str, Any]:
    try:
        return requests.get(f"{controller}/stats", timeout=5).json()
    except Exception:
        return {}


def _get_flow_table(controller: str) -> dict[str, Any]:
    try:
        return requests.get(f"{controller}/flow_table", timeout=5).json()
    except Exception:
        return {}


def _reset_controller(controller: str) -> None:
    try:
        requests.post(f"{controller}/reset", timeout=5)
    except Exception:
        pass


# ── traffic generators ────────────────────────────────────────────────────────

def _normal_batch(controller: str) -> None:
    """Legitimate hosts: small-to-medium flows among internal IPs."""
    for src_ip in LEGIT_IPS:
        n_flows = random.randint(1, 4)
        flows   = []
        for _ in range(n_flows):
            pkts  = random.randint(10, 100)
            bsize = random.randint(200, 800)   # mix of text/small files
            dur   = random.uniform(1.0, 5.0)
            flows.append([pkts, pkts * bsize, dur])
        dst = random.choice([ip for ip in LEGIT_IPS if ip != src_ip])
        _post_telemetry(controller, src_ip, dst, flows)


def _exfil_batch(controller: str, bandwidth_mbps: float = 8.0,
                 poll_interval: float = 5.0) -> dict[str, Any]:
    """
    Simulate h6 exfiltrating data to an external IP.

    bandwidth_mbps: simulated transfer rate (default 8 Mbit/s = 1 MB/s)
    poll_interval:  duration of this telemetry window (seconds)

    The exfiltration is modelled as a single large flow per poll window:
      - Very high byte count (bandwidth * poll_interval)
      - MTU-sized packets (1400 bytes each)
      - Low short_ratio (long-running, not a probe)
    """
    total_bytes  = int(bandwidth_mbps * 1e6 / 8 * poll_interval)
    pkt_size     = random.randint(1300, 1460)    # near-MTU packets (full payload)
    total_pkts   = max(1, total_bytes // pkt_size)

    # Small jitter to avoid perfectly constant rate (evades naive rate detectors)
    jitter = random.uniform(0.9, 1.1)
    total_pkts  = int(total_pkts  * jitter)
    total_bytes = int(total_bytes * jitter)

    # Represented as one sustained flow for the entire poll window
    flows = [[total_pkts, total_bytes, poll_interval]]
    return _post_telemetry(controller, ATTACKER_IP, EXTERNAL_IP, flows)


# ── standalone scenario ───────────────────────────────────────────────────────

def run_standalone(controller: str, duration: int,
                   bandwidth_mbps: float = 8.0) -> dict[str, Any]:
    normal_duration = duration // 2
    attack_duration = duration - normal_duration
    poll_interval   = 5.0

    print(f"[EXFIL] Standalone | controller={controller}")
    print(f"[EXFIL] Normal: {normal_duration}s | Attack: {attack_duration}s")
    print(f"[EXFIL] Attacker: {ATTACKER_IP} → {EXTERNAL_IP} @ {bandwidth_mbps} Mbit/s")

    stats_before      = _get_stats(controller)
    detections_before = stats_before.get("total_detections", 0)

    detection_time: float | None = None
    attack_start: float | None   = None
    exfil_verdicts: list[str]    = []
    total_bytes_sent: int        = 0

    # ── Phase 1: normal ───────────────────────────────────────────────────────
    print(f"\n[EXFIL] === Phase 1: Normal traffic ({normal_duration}s) ===")
    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        _normal_batch(controller)
        remaining = phase1_end - time.time()
        print(f"[EXFIL] Phase 1 — {normal_duration - remaining:.0f}s/{normal_duration}s",
              flush=True)
        time.sleep(min(poll_interval, max(0.1, remaining)))

    print(f"[EXFIL] End Phase 1 — detections: {_get_stats(controller).get('total_detections', 0)}")

    # ── Phase 2: exfiltration ─────────────────────────────────────────────────
    print(f"\n[EXFIL] === Phase 2: Data exfiltration ({attack_duration}s) ===")
    phase2_end  = time.time() + attack_duration
    attack_start = time.time()

    while time.time() < phase2_end:
        # Background: legit hosts remain active
        _normal_batch(controller)

        # Attacker: sustained large outbound flow
        result  = _exfil_batch(controller, bandwidth_mbps, poll_interval)
        verdict = result.get("verdict", "Unknown")
        action  = result.get("action", "FORWARD")
        exfil_verdicts.append(verdict)

        batch_bytes = int(bandwidth_mbps * 1e6 / 8 * poll_interval)
        total_bytes_sent += batch_bytes
        elapsed = time.time() - attack_start

        print(f"[EXFIL] Phase 2 — {elapsed:.0f}s/{attack_duration}s | "
              f"verdict={verdict} action={action} "
              f"total_sent={total_bytes_sent // (1024*1024):.1f} MB", flush=True)

        if verdict == "Attack" and detection_time is None:
            detection_time = elapsed
            print(f"[EXFIL] *** DETECTED at t+{detection_time:.1f}s ***")

        remaining = phase2_end - time.time()
        time.sleep(min(poll_interval, max(0.1, remaining)))

    # ── Metrics ───────────────────────────────────────────────────────────────
    stats_after = _get_stats(controller)
    flow_table  = _get_flow_table(controller)

    new_detections = stats_after.get("total_detections", 0) - detections_before
    blocked_ips    = list(flow_table.keys())

    attack_detections = [v for v in exfil_verdicts if v == "Attack"]
    tp = len(attack_detections)
    fn = len(exfil_verdicts) - tp
    fp = sum(1 for ip in LEGIT_IPS if ip in flow_table)
    tn = len(LEGIT_IPS) - fp

    result_dict = {
        "scenario":              "data_exfiltration",
        "duration":              duration,
        "normal_phase_s":        normal_duration,
        "attack_phase_s":        attack_duration,
        "bandwidth_mbps":        bandwidth_mbps,
        "total_bytes_exfiltrated": total_bytes_sent,
        "total_mb_exfiltrated":  round(total_bytes_sent / (1024 * 1024), 2),
        "detections":            new_detections,
        "false_positives":       fp,
        "true_positives":        tp,
        "false_negatives":       fn,
        "true_negatives":        tn,
        "detection_latency_s":   round(detection_time, 2) if detection_time is not None else None,
        "blocked_ips":           blocked_ips,
        "attacker_blocked":      ATTACKER_IP in flow_table,
        "exfil_batches_sent":    len(exfil_verdicts),
        "success":               tp > 0 and fp == 0,
    }

    print("\n" + "=" * 60)
    print("[EXFIL] RESULTS")
    print("=" * 60)
    for k, v in result_dict.items():
        print(f"  {k:35s}: {v}")
    print("=" * 60)

    return result_dict


# ── Mininet mode ──────────────────────────────────────────────────────────────

def run_mininet(net, controller: str, duration: int) -> dict[str, Any]:  # type: ignore[type-arg]
    """
    Mininet mode: h6 runs iperf3 to an external IP to simulate exfiltration.
    Since 10.0.0.99 may not exist, we use h5 as a proxy target and iperf3 server.
    """
    hosts = {f"h{i}": net.get(f"h{i}") for i in range(1, 7)}
    h5 = hosts["h5"]
    h6 = hosts["h6"]

    normal_duration = duration // 2
    attack_duration = duration - normal_duration

    h5.cmd("iperf3 -s -D > /tmp/iperf_server.log 2>&1")
    time.sleep(1)

    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        for h in [hosts[f"h{i}"] for i in range(1, 5)]:
            h.cmd(f"ping -c 20 -i 0.5 -q {h5.IP()} > /dev/null 2>&1 &")
        time.sleep(5)

    attack_start = time.time()
    detection_time = None

    # iperf3 high-bandwidth transfer
    h6.cmd(
        f"iperf3 -c {h5.IP()} -t {attack_duration} -b 100M "
        f"> /tmp/exfil.log 2>&1 &"
    )

    deadline = time.time() + attack_duration
    while time.time() < deadline:
        ft = _get_flow_table(controller)
        if ATTACKER_IP in ft and detection_time is None:
            detection_time = time.time() - attack_start
        time.sleep(5)

    h6.cmd("pkill iperf3 2>/dev/null; true")
    h5.cmd("pkill iperf3 2>/dev/null; true")

    ft = _get_flow_table(controller)
    fp = sum(1 for ip in LEGIT_IPS if ip in ft)
    return {
        "scenario":            "data_exfiltration",
        "duration":            duration,
        "detections":          1 if ATTACKER_IP in ft else 0,
        "false_positives":     fp,
        "detection_latency_s": round(detection_time, 2) if detection_time else None,
        "blocked_ips":         list(ft.keys()),
        "success":             ATTACKER_IP in ft and fp == 0,
    }


# ── save results ──────────────────────────────────────────────────────────────

def save_results(result: dict[str, Any]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / "exfiltration_metrics.json"
    with open(out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"[EXFIL] Results saved to {out}")

    csv_path  = RESULTS_DIR / "exfiltration_metrics.csv"
    write_hdr = not csv_path.exists()
    flat = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
            for k, v in result.items()}
    with open(csv_path, "a") as fh:
        if write_hdr:
            fh.write(",".join(flat.keys()) + "\n")
        fh.write(",".join(str(v) for v in flat.values()) + "\n")
    return out


# ── uniform entry point ──────────────────────────────────────────────────────

def run(controller_url: str, duration: int = 60, standalone: bool = True,
        net=None) -> dict[str, Any]:
    """Uniform entry point: standalone (crafted telemetry) or Mininet mode."""
    if standalone or net is None:
        return run_standalone(controller_url, duration)
    return run_mininet(net, controller_url, duration)


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Data exfiltration scenario")
    parser.add_argument("--standalone",  action="store_true")
    parser.add_argument("--controller",  default=CONTROLLER_URL)
    parser.add_argument("--duration",    type=int,   default=60)
    parser.add_argument("--bandwidth",   type=float, default=8.0,
                        help="Simulated exfiltration bandwidth in Mbit/s (default 8)")
    parser.add_argument("--no-reset",    action="store_true")
    args = parser.parse_args()

    if not args.no_reset:
        print(f"[EXFIL] Resetting controller at {args.controller}...")
        _reset_controller(args.controller)
        time.sleep(1)

    if args.standalone:
        result = run_standalone(args.controller, args.duration, args.bandwidth)
    else:
        print("[EXFIL] Pass --standalone to run without Mininet.")
        sys.exit(1)

    save_results(result)
    sys.exit(0 if result.get("success") else 2)


if __name__ == "__main__":
    main()
