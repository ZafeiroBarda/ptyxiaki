#!/usr/bin/env python3
"""
port_scan.py — Port/network reconnaissance scenario (nmap-style SYN scan).

Attack model:
  h6 (10.0.0.6) performs a SYN scan against h5 (10.0.0.5), probing ports 1-1024.
  Each port probe is a unique flow with 1-3 packets and very few bytes.

Detection signal to Isolation Forest:
  - high flow_count  (many distinct destination ports → distinct flows)
  - very low avg_pkts_per_flow  (~1-2)
  - high short_ratio  (~1.0 — almost all flows are "short")
  - low avg_bytes_per_flow  (~60-80 bytes per probe, TCP SYN only)

Phases:
  Phase 1 (normal_duration s): h1-h4 normal traffic to h5, h6 idle
  Phase 2 (attack_duration s): h6 SYN-scans h5 while h1-h4 remain normal

Modes:
  STANDALONE (default): crafts telemetry JSON and POSTs to controller — no Mininet needed.
  MININET: uses real hping3 inside Mininet namespaces (requires privileged container).

Usage:
  python3 simulation/scenarios/port_scan.py --standalone --controller http://127.0.0.1:9000
  python3 simulation/scenarios/port_scan.py --standalone --duration 60 --controller http://127.0.0.1:9000
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

# ── defaults ─────────────────────────────────────────────────────────────────
CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "http://127.0.0.1:9000")
SWITCH_API_KEY = os.environ.get("SWITCH_API_KEY", "sdn-secret-2024")

VICTIM_IP   = "10.0.0.5"
ATTACKER_IP = "10.0.0.6"
LEGIT_IPS   = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

HEADERS = {"X-Switch-Token": SWITCH_API_KEY, "Content-Type": "application/json"}

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results" / "live"


# ── telemetry helpers ─────────────────────────────────────────────────────────

def _post_telemetry(controller: str, src: str, dst: str,
                    flows: list[list]) -> dict[str, Any]:
    """Send one telemetry batch to the controller and return the parsed response."""
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


# ── normal traffic generator ──────────────────────────────────────────────────

def _normal_telemetry_batch(controller: str) -> None:
    """
    Simulate one telemetry interval from h1-h4 doing normal traffic to h5.
    Characteristics: moderate packet rate, ~64-1400 byte avg pkt size, 1-4 flows each.
    """
    for src_ip in LEGIT_IPS:
        flow_count = random.randint(1, 4)
        flows = []
        for _ in range(flow_count):
            pkts  = random.randint(20, 120)
            bsize = random.randint(64, 1400)
            dur   = random.uniform(2.0, 5.0)
            flows.append([pkts, pkts * bsize, dur])
        _post_telemetry(controller, src_ip, VICTIM_IP, flows)


# ── port scan traffic generator ───────────────────────────────────────────────

def _scan_telemetry_batch(controller: str, ports_per_batch: int = 50) -> dict[str, Any]:
    """
    Simulate one telemetry poll window from h6 performing a SYN port scan.

    Each probed port = one flow with 1-2 packets (SYN + maybe SYN-ACK retransmit),
    ~60-80 bytes each (TCP header only, no payload).
    Sends `ports_per_batch` flows in one telemetry batch to mimic a 5-second OVS poll window.
    """
    flows = []
    for _ in range(ports_per_batch):
        pkts  = random.randint(1, 3)          # 1-3 packets per port probe
        bsize = random.randint(40, 80)         # TCP SYN only — very small
        dur   = random.uniform(0.01, 0.1)     # sub-second per probe
        flows.append([pkts, pkts * bsize, dur])

    return _post_telemetry(controller, ATTACKER_IP, VICTIM_IP, flows)


# ── standalone scenario runner ────────────────────────────────────────────────

def run_standalone(controller: str, duration: int) -> dict[str, Any]:
    """
    Standalone mode: drives the scenario purely via crafted telemetry POSTs.
    No Mininet / hping3 required.

    Timeline:
      0 .. duration/2   : Phase 1 — normal traffic only
      duration/2 .. end : Phase 2 — port scan from h6 + normal traffic
    """
    normal_duration = duration // 2
    attack_duration = duration - normal_duration

    poll_interval   = 5       # seconds between telemetry batches (mirrors OVS poll)
    ports_per_poll  = 80      # ~80 ports probed per 5-second window (realistic nmap rate)

    print(f"[PORT_SCAN] Standalone mode | controller={controller}")
    print(f"[PORT_SCAN] Phase 1 (normal): {normal_duration}s | Phase 2 (scan): {attack_duration}s")

    stats_before: dict[str, Any] = _get_stats(controller)
    detections_before = stats_before.get("total_detections", 0)

    detection_time: float | None = None
    attack_start: float | None   = None
    scan_verdicts: list[str]     = []

    # ── Phase 1: normal ───────────────────────────────────────────────────────
    print(f"\n[PORT_SCAN] === Phase 1: Normal traffic ({normal_duration}s) ===")
    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        _normal_telemetry_batch(controller)
        remaining = max(0, phase1_end - time.time())
        print(f"[PORT_SCAN] Phase 1 — {normal_duration - remaining:.0f}s/{normal_duration}s",
              flush=True)
        time.sleep(min(poll_interval, remaining + 0.01))

    stats_p1 = _get_stats(controller)
    print(f"[PORT_SCAN] End Phase 1 — detections so far: {stats_p1.get('total_detections', 0)}")

    # ── Phase 2: SYN scan from h6 ─────────────────────────────────────────────
    print(f"\n[PORT_SCAN] === Phase 2: SYN port scan h6 -> h5 ({attack_duration}s) ===")
    phase2_end = time.time() + attack_duration
    attack_start = time.time()

    while time.time() < phase2_end:
        # normal traffic still present (scanner operates alongside legit hosts)
        _normal_telemetry_batch(controller)

        result = _scan_telemetry_batch(controller, ports_per_poll)
        verdict = result.get("verdict", "Unknown")
        action  = result.get("action", "FORWARD")
        scan_verdicts.append(verdict)

        elapsed = time.time() - attack_start
        print(f"[PORT_SCAN] Phase 2 — {elapsed:.0f}s/{attack_duration}s | "
              f"verdict={verdict} action={action}", flush=True)

        if verdict == "Attack" and detection_time is None:
            detection_time = time.time() - attack_start
            print(f"[PORT_SCAN] *** DETECTED at t+{detection_time:.1f}s ***")

        remaining = max(0, phase2_end - time.time())
        time.sleep(min(poll_interval, remaining + 0.01))

    # ── Metrics ───────────────────────────────────────────────────────────────
    stats_after  = _get_stats(controller)
    flow_table   = _get_flow_table(controller)
    blocked_ips  = list(flow_table.keys())

    detections_total = stats_after.get("total_detections", 0)
    new_detections   = detections_total - detections_before

    attack_verdicts  = [v for v in scan_verdicts if v == "Attack"]
    normal_verdicts  = [v for v in scan_verdicts if v == "Normal"]

    # True positives: attack detected during scan phase
    tp = len(attack_verdicts)
    # False negatives: scan phases where model said Normal
    fn = len(normal_verdicts)
    # Phase 1 false positives: we check flow table for legit IPs being blocked
    fp = sum(1 for ip in LEGIT_IPS if ip in flow_table)
    # True negatives: legit hosts that were not blocked
    tn = len(LEGIT_IPS) - fp

    detection_latency = detection_time if detection_time is not None else float("nan")
    success = tp > 0 and fp == 0

    result_dict = {
        "scenario":           "port_scan",
        "duration":           duration,
        "normal_phase_s":     normal_duration,
        "attack_phase_s":     attack_duration,
        "detections":         new_detections,
        "false_positives":    fp,
        "true_positives":     tp,
        "false_negatives":    fn,
        "true_negatives":     tn,
        "detection_latency_s": round(detection_latency, 2) if not (detection_latency != detection_latency) else None,
        "blocked_ips":        blocked_ips,
        "attacker_blocked":   ATTACKER_IP in flow_table,
        "scan_batches_sent":  len(scan_verdicts),
        "success":            success,
    }

    print("\n" + "=" * 60)
    print("[PORT_SCAN] RESULTS")
    print("=" * 60)
    for k, v in result_dict.items():
        print(f"  {k:30s}: {v}")
    print("=" * 60)

    return result_dict


# ── Mininet mode ──────────────────────────────────────────────────────────────

def run_mininet(net, controller: str, duration: int) -> dict[str, Any]:  # type: ignore[type-arg]
    """
    Mininet mode: uses real hping3 inside Mininet host namespaces.
    net: a live mininet.net.Mininet instance with hosts h1-h6.
    """
    import threading

    hosts    = {f"h{i}": net.get(f"h{i}") for i in range(1, 7)}
    victim   = hosts["h5"]
    attacker = hosts["h6"]
    legit    = [hosts[f"h{i}"] for i in range(1, 5)]

    normal_duration = duration // 2
    attack_duration = duration - normal_duration

    print(f"[PORT_SCAN] Mininet mode | controller={controller}")

    # Phase 1
    print(f"[PORT_SCAN] Phase 1: normal traffic ({normal_duration}s)")
    deadline = time.time() + normal_duration
    while time.time() < deadline:
        for h in legit:
            h.cmd(f"ping -c 10 -i 0.5 -q {victim.IP()} > /dev/null 2>&1 &")
        time.sleep(5)

    # Phase 2: real SYN scan via hping3 (SYN scan, ports 1-1024)
    print(f"[PORT_SCAN] Phase 2: SYN scan via hping3 ({attack_duration}s)")
    attacker.cmd(
        f"hping3 -S -p ++1 --fast --count 1024 {victim.IP()} "
        f"> /tmp/scan_{ATTACKER_IP}.log 2>&1 &"
    )

    detection_time: float | None = None
    attack_start = time.time()
    deadline = time.time() + attack_duration

    while time.time() < deadline:
        for h in legit:
            h.cmd(f"ping -c 10 -i 0.5 -q {victim.IP()} > /dev/null 2>&1 &")
        time.sleep(5)
        ft = _get_flow_table(controller)
        if ATTACKER_IP in ft and detection_time is None:
            detection_time = time.time() - attack_start

    attacker.cmd("pkill hping3 2>/dev/null; true")

    ft = _get_flow_table(controller)
    fp = sum(1 for ip in LEGIT_IPS if ip in ft)
    tp = 1 if ATTACKER_IP in ft else 0

    return {
        "scenario":            "port_scan",
        "duration":            duration,
        "detections":          tp,
        "false_positives":     fp,
        "detection_latency_s": round(detection_time, 2) if detection_time else None,
        "blocked_ips":         list(ft.keys()),
        "attacker_blocked":    ATTACKER_IP in ft,
        "success":             tp > 0 and fp == 0,
    }


# ── save results ──────────────────────────────────────────────────────────────

def save_results(result: dict[str, Any]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / "scan_metrics.json"
    with open(out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"[PORT_SCAN] Results saved to {out}")

    # also write a one-row CSV for the bash runner
    csv_path = RESULTS_DIR / "scan_metrics.csv"
    write_header = not csv_path.exists()
    with open(csv_path, "a") as fh:
        if write_header:
            fh.write(",".join(str(k) for k in result.keys()) + "\n")
        fh.write(",".join(str(v) for v in result.values()) + "\n")
    return out


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Port scan attack scenario")
    parser.add_argument("--standalone", action="store_true",
                        help="Run without Mininet (craft telemetry directly)")
    parser.add_argument("--controller", default=CONTROLLER_URL,
                        help="Flask controller base URL")
    parser.add_argument("--duration", type=int, default=60,
                        help="Total scenario duration in seconds (default 60)")
    parser.add_argument("--no-reset", action="store_true",
                        help="Skip controller reset before running")
    args = parser.parse_args()

    if not args.no_reset:
        print(f"[PORT_SCAN] Resetting controller state at {args.controller}...")
        _reset_controller(args.controller)
        time.sleep(1)

    if args.standalone:
        result = run_standalone(args.controller, args.duration)
    else:
        print("[PORT_SCAN] ERROR: non-standalone mode requires a running Mininet instance.")
        print("            Pass --standalone to run without Mininet.")
        sys.exit(1)

    save_results(result)
    sys.exit(0 if result.get("success") else 2)


if __name__ == "__main__":
    main()
