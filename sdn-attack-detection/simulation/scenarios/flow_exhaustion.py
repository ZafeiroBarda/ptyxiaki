#!/usr/bin/env python3
"""
flow_exhaustion.py — Flow table exhaustion attack scenario.

Attack model:
  Compromised hosts h1-h4 (acting as a botnet) each generate hundreds of unique
  micro-flows targeted at h5.  Every flow has a unique (src_port, dst_port) pair
  so the switch cannot aggregate them into existing entries.  The goal is to
  fill the flow table and force it to evict legitimate rules.

Detection signal to Isolation Forest:
  - very high flow_count (1000+ per source per poll window)
  - avg_pkts_per_flow = 1  (each flow has exactly one packet)
  - short_ratio = 1.0  (every flow is a short flow by definition)
  - avg_bytes_per_flow = ~64-100 bytes (small, no payload)

Architecture note:
  This simulates the DATA PLANE symptom.  In the controller we model each
  "unique flow" as a separate entry in the flows list sent via POST /telemetry.
  The controller's Isolation Forest receives the aggregated feature vector and
  should flag the source as anomalous.

Usage:
  python3 simulation/scenarios/flow_exhaustion.py --standalone --controller http://127.0.0.1:9000
  python3 simulation/scenarios/flow_exhaustion.py --standalone --duration 60
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

VICTIM_IP     = "10.0.0.5"
ATTACKER_IPS  = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]  # compromised h1-h4

HEADERS = {"X-Switch-Token": SWITCH_API_KEY, "Content-Type": "application/json"}

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results" / "live"


# ── helpers ───────────────────────────────────────────────────────────────────

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


# ── normal traffic generator ──────────────────────────────────────────────────

def _normal_batch(controller: str, src_ip: str) -> None:
    """Simulate a legitimate polling window — moderate traffic, normal flow sizes."""
    flow_count = random.randint(2, 6)
    flows = [[random.randint(30, 150), random.randint(3000, 150000), random.uniform(2, 5)]
             for _ in range(flow_count)]
    _post_telemetry(controller, src_ip, VICTIM_IP, flows)


# ── exhaustion attack generator ───────────────────────────────────────────────

def _exhaustion_batch(controller: str, src_ip: str,
                      flows_per_batch: int = 300) -> dict[str, Any]:
    """
    Simulate one polling window from a compromised host creating many unique micro-flows.
    Each unique (src_port, dst_port) pair = one flow entry.
    flow characteristics: 1 packet, ~64-100 bytes, <10ms duration.
    """
    flows = []
    for _ in range(flows_per_batch):
        pkts  = 1                           # exactly one packet — maximum short_ratio
        bsize = random.randint(40, 100)     # no payload, headers only
        dur   = random.uniform(0.001, 0.01) # sub-millisecond TCP SYN-only
        flows.append([pkts, bsize, dur])

    return _post_telemetry(controller, src_ip, VICTIM_IP, flows)


# ── standalone scenario ───────────────────────────────────────────────────────

def run_standalone(controller: str, duration: int) -> dict[str, Any]:
    """
    Phase 1 (duration/2 s): h1-h4 in normal mode.
    Phase 2 (duration/2 s): h1-h4 switch to flow exhaustion mode simultaneously.
    """
    normal_duration = duration // 2
    attack_duration = duration - normal_duration
    poll_interval   = 5

    print(f"[FLOW_EXHAUST] Standalone | controller={controller}")
    print(f"[FLOW_EXHAUST] Normal: {normal_duration}s | Attack: {attack_duration}s")

    stats_before     = _get_stats(controller)
    detections_before = stats_before.get("total_detections", 0)

    detection_times: dict[str, float] = {}   # src_ip -> seconds-to-detect
    attack_start: float | None = None

    # ── Phase 1 ───────────────────────────────────────────────────────────────
    print(f"\n[FLOW_EXHAUST] === Phase 1: Normal traffic ({normal_duration}s) ===")
    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        for ip in ATTACKER_IPS:
            _normal_batch(controller, ip)
        remaining = phase1_end - time.time()
        print(f"[FLOW_EXHAUST] Phase 1 — {normal_duration - remaining:.0f}s/{normal_duration}s",
              flush=True)
        time.sleep(min(poll_interval, max(0.1, remaining)))

    stats_p1 = _get_stats(controller)
    print(f"[FLOW_EXHAUST] End Phase 1 — detections so far: {stats_p1.get('total_detections', 0)}")

    # ── Phase 2 ───────────────────────────────────────────────────────────────
    print(f"\n[FLOW_EXHAUST] === Phase 2: Flow exhaustion ({attack_duration}s) ===")
    phase2_end = time.time() + attack_duration
    attack_start = time.time()

    per_host_verdicts: dict[str, list[str]] = {ip: [] for ip in ATTACKER_IPS}

    while time.time() < phase2_end:
        for ip in ATTACKER_IPS:
            result = _exhaustion_batch(controller, ip, flows_per_batch=300)
            verdict = result.get("verdict", "Unknown")
            action  = result.get("action", "FORWARD")
            per_host_verdicts[ip].append(verdict)

            if verdict == "Attack" and ip not in detection_times:
                detection_times[ip] = time.time() - attack_start
                print(f"[FLOW_EXHAUST] *** {ip} DETECTED at t+{detection_times[ip]:.1f}s ***")

            print(f"[FLOW_EXHAUST]   {ip} -> verdict={verdict} action={action}", flush=True)

        elapsed = time.time() - attack_start
        print(f"[FLOW_EXHAUST] Phase 2 — {elapsed:.0f}s/{attack_duration}s", flush=True)
        remaining = phase2_end - time.time()
        time.sleep(min(poll_interval, max(0.1, remaining)))

    # ── Metrics ───────────────────────────────────────────────────────────────
    stats_after = _get_stats(controller)
    flow_table  = _get_flow_table(controller)

    new_detections = stats_after.get("total_detections", 0) - detections_before
    blocked_ips    = list(flow_table.keys())

    # All ATTACKER_IPS are "attackers" in phase 2 — true positives if blocked
    tp = sum(1 for ip in ATTACKER_IPS if ip in flow_table)
    fn = len(ATTACKER_IPS) - tp
    fp = 0   # no innocent bystander hosts in this scenario (all h1-h4 are attackers)
    tn = 0

    all_latencies = list(detection_times.values())
    avg_latency   = sum(all_latencies) / len(all_latencies) if all_latencies else None

    result_dict = {
        "scenario":              "flow_exhaustion",
        "duration":              duration,
        "normal_phase_s":        normal_duration,
        "attack_phase_s":        attack_duration,
        "detections":            new_detections,
        "false_positives":       fp,
        "true_positives":        tp,
        "false_negatives":       fn,
        "true_negatives":        tn,
        "detection_latency_s":   round(avg_latency, 2) if avg_latency else None,
        "per_host_detection_s":  {k: round(v, 2) for k, v in detection_times.items()},
        "blocked_ips":           blocked_ips,
        "flows_per_host_per_poll": 300,
        "success":               tp == len(ATTACKER_IPS) and fp == 0,
    }

    print("\n" + "=" * 60)
    print("[FLOW_EXHAUST] RESULTS")
    print("=" * 60)
    for k, v in result_dict.items():
        print(f"  {k:35s}: {v}")
    print("=" * 60)

    return result_dict


# ── Mininet mode ──────────────────────────────────────────────────────────────

def run_mininet(net, controller: str, duration: int) -> dict[str, Any]:  # type: ignore[type-arg]
    """
    Mininet mode: h1-h4 each run a parallel hping3 flood with unique src ports
    to generate thousands of unique flow table entries on the OVS switch.
    """
    import threading

    hosts  = {f"h{i}": net.get(f"h{i}") for i in range(1, 7)}
    victim = hosts["h5"]
    legit  = [hosts[f"h{i}"] for i in range(1, 5)]

    normal_duration = duration // 2
    attack_duration = duration - normal_duration

    print(f"[FLOW_EXHAUST] Phase 1: normal ({normal_duration}s)")
    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        for h in legit:
            h.cmd(f"ping -c 20 -i 0.5 -q {victim.IP()} > /dev/null 2>&1 &")
        time.sleep(5)

    print(f"[FLOW_EXHAUST] Phase 2: flow exhaustion via hping3 ({attack_duration}s)")
    for h in legit:
        # --rand-source randomises src port every packet → unique flows
        h.cmd(
            f"hping3 --syn --flood --rand-dest -p ++1 {victim.IP()} "
            f"> /tmp/exhaust_{h.IP()}.log 2>&1 &"
        )

    detection_times: dict[str, float] = {}
    attack_start = time.time()
    deadline = time.time() + attack_duration

    while time.time() < deadline:
        ft = _get_flow_table(controller)
        for h in legit:
            if h.IP() in ft and h.IP() not in detection_times:
                detection_times[h.IP()] = time.time() - attack_start
        time.sleep(5)

    for h in legit:
        h.cmd("pkill hping3 2>/dev/null; true")

    ft  = _get_flow_table(controller)
    tp  = sum(1 for h in legit if h.IP() in ft)
    return {
        "scenario":            "flow_exhaustion",
        "duration":            duration,
        "detections":          tp,
        "false_positives":     0,
        "detection_latency_s": round(min(detection_times.values()), 2) if detection_times else None,
        "blocked_ips":         list(ft.keys()),
        "success":             tp == len(legit),
    }


# ── save results ──────────────────────────────────────────────────────────────

def save_results(result: dict[str, Any]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / "flow_exhaustion_metrics.json"
    with open(out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"[FLOW_EXHAUST] Results saved to {out}")

    csv_path   = RESULTS_DIR / "flow_exhaustion_metrics.csv"
    write_hdr  = not csv_path.exists()
    flat = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
            for k, v in result.items()}
    with open(csv_path, "a") as fh:
        if write_hdr:
            fh.write(",".join(flat.keys()) + "\n")
        fh.write(",".join(str(v) for v in flat.values()) + "\n")
    return out


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Flow table exhaustion scenario")
    parser.add_argument("--standalone", action="store_true")
    parser.add_argument("--controller", default=CONTROLLER_URL)
    parser.add_argument("--duration",   type=int, default=60)
    parser.add_argument("--no-reset",   action="store_true")
    args = parser.parse_args()

    if not args.no_reset:
        print(f"[FLOW_EXHAUST] Resetting controller at {args.controller}...")
        _reset_controller(args.controller)
        time.sleep(1)

    if args.standalone:
        result = run_standalone(args.controller, args.duration)
    else:
        print("[FLOW_EXHAUST] Pass --standalone to run without Mininet.")
        sys.exit(1)

    save_results(result)
    sys.exit(0 if result.get("success") else 2)


if __name__ == "__main__":
    main()
