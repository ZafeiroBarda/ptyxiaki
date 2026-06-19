#!/usr/bin/env python3
"""
lateral_movement.py — Internal lateral movement / reconnaissance scenario.

Attack model:
  h3 (10.0.0.3) has been compromised.  It begins scanning all other internal
  hosts one by one, probing multiple ports on each target, then establishes a
  small data transfer to each discovered host (simulating credential harvest /
  payload delivery).

Detection signal to Isolation Forest:
  - Many unique destination IPs from a single source → high flow_count
  - Flow sizes are small-to-moderate (SYN probes) mixed with slightly larger
    data transfers
  - avg_pkts_per_flow is low-to-medium  (1-10 packets)
  - short_ratio moderately high (~0.6-0.8) — lots of refused connections
  - Sudden change from h3's previously quiet baseline

Timeline:
  Phase 1 (normal_duration s): all hosts behave normally (h3 included)
  Phase 2 (attack_duration s): h3 scans h1, h2, h4, h5 in turn, pausing
      between each target (internal host sweep pattern)

Usage:
  python3 simulation/scenarios/lateral_movement.py --standalone --controller http://127.0.0.1:9000
  python3 simulation/scenarios/lateral_movement.py --standalone --duration 60
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

ATTACKER_IP = "10.0.0.3"   # h3 — compromised
TARGETS     = ["10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5"]
ALL_IPS     = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"]
LEGIT_IPS   = [ip for ip in ALL_IPS if ip != ATTACKER_IP]

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


# ── normal traffic helper ─────────────────────────────────────────────────────

def _normal_batch(controller: str) -> None:
    """All hosts generate typical bidirectional traffic."""
    for src_ip in ALL_IPS:
        # Each host talks to 1-3 random peers
        n_flows = random.randint(1, 3)
        flows   = []
        for _ in range(n_flows):
            pkts  = random.randint(20, 200)
            bsize = random.randint(200, 1400)
            dur   = random.uniform(1.0, 5.0)
            flows.append([pkts, pkts * bsize, dur])
        dst = random.choice([ip for ip in ALL_IPS if ip != src_ip])
        _post_telemetry(controller, src_ip, dst, flows)


# ── lateral movement helpers ──────────────────────────────────────────────────

def _scan_target(controller: str, target_ip: str, n_ports: int = 30) -> dict[str, Any]:
    """
    Simulate h3 probing `n_ports` ports on `target_ip`.
    Most probes are 1-packet SYN (refused), a few succeed (2-5 packets).
    The entire scan against one host is sent as a single telemetry batch.
    """
    flows = []
    for _ in range(n_ports):
        if random.random() < 0.15:   # 15% of ports "open" — slightly larger exchange
            pkts  = random.randint(3, 8)
            bsize = random.randint(200, 800)
        else:                         # 85% refused — SYN only
            pkts  = 1
            bsize = random.randint(40, 80)
        dur = random.uniform(0.005, 0.2)
        flows.append([pkts, pkts * bsize, dur])

    return _post_telemetry(controller, ATTACKER_IP, target_ip, flows)


def _data_transfer(controller: str, target_ip: str) -> dict[str, Any]:
    """
    After scanning, h3 performs a small data transfer to the target
    (simulating payload/credential delivery over a discovered open service).
    """
    flows = []
    for _ in range(random.randint(3, 8)):
        pkts  = random.randint(50, 300)
        bsize = random.randint(800, 1400)
        dur   = random.uniform(1.0, 5.0)
        flows.append([pkts, pkts * bsize, dur])
    return _post_telemetry(controller, ATTACKER_IP, target_ip, flows)


# ── standalone scenario ───────────────────────────────────────────────────────

def run_standalone(controller: str, duration: int) -> dict[str, Any]:
    normal_duration = duration // 2
    attack_duration = duration - normal_duration
    poll_interval   = 5

    print(f"[LATERAL] Standalone | controller={controller}")
    print(f"[LATERAL] Normal: {normal_duration}s | Attack: {attack_duration}s")
    print(f"[LATERAL] Attacker: {ATTACKER_IP} (h3) | Targets: {TARGETS}")

    stats_before      = _get_stats(controller)
    detections_before = stats_before.get("total_detections", 0)

    detection_time: float | None = None
    attack_start: float | None   = None

    # ── Phase 1: normal ───────────────────────────────────────────────────────
    print(f"\n[LATERAL] === Phase 1: Normal traffic ({normal_duration}s) ===")
    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        _normal_batch(controller)
        remaining = phase1_end - time.time()
        print(f"[LATERAL] Phase 1 — {normal_duration - remaining:.0f}s/{normal_duration}s",
              flush=True)
        time.sleep(min(poll_interval, max(0.1, remaining)))

    print(f"[LATERAL] End Phase 1 — detections: {_get_stats(controller).get('total_detections', 0)}")

    # ── Phase 2: lateral sweep ────────────────────────────────────────────────
    print(f"\n[LATERAL] === Phase 2: Lateral movement ({attack_duration}s) ===")
    phase2_end  = time.time() + attack_duration
    attack_start = time.time()

    # Spread the target sweep evenly across the attack phase
    dwell_per_target = max(5, (attack_duration // len(TARGETS)))
    scan_verdicts: list[str] = []

    for target in TARGETS:
        if time.time() >= phase2_end:
            break

        print(f"[LATERAL] Scanning {target} ({dwell_per_target}s dwell)...")
        dwell_end = time.time() + dwell_per_target

        # Port sweep: send several probe batches within this dwell window
        while time.time() < dwell_end and time.time() < phase2_end:
            # Background: legit hosts continue normal traffic
            _normal_batch(controller)

            # Attacker: scan this target
            result  = _scan_target(controller, target, n_ports=40)
            verdict = result.get("verdict", "Unknown")
            scan_verdicts.append(verdict)
            elapsed = time.time() - attack_start

            print(f"[LATERAL]   {ATTACKER_IP} -> {target} | verdict={verdict} "
                  f"t+{elapsed:.0f}s", flush=True)

            if verdict == "Attack" and detection_time is None:
                detection_time = elapsed
                print(f"[LATERAL] *** DETECTED at t+{detection_time:.1f}s ***")

            remaining = dwell_end - time.time()
            time.sleep(min(poll_interval, max(0.1, remaining)))

        # Short data transfer to simulate post-scan activity
        if time.time() < phase2_end:
            _data_transfer(controller, target)

    # ── Metrics ───────────────────────────────────────────────────────────────
    stats_after  = _get_stats(controller)
    flow_table   = _get_flow_table(controller)

    new_detections = stats_after.get("total_detections", 0) - detections_before
    blocked_ips    = list(flow_table.keys())

    tp = 1 if ATTACKER_IP in flow_table else 0
    fn = 0 if tp else 1
    fp = sum(1 for ip in LEGIT_IPS if ip in flow_table)
    tn = len(LEGIT_IPS) - fp

    result_dict = {
        "scenario":            "lateral_movement",
        "duration":            duration,
        "normal_phase_s":      normal_duration,
        "attack_phase_s":      attack_duration,
        "attacker_ip":         ATTACKER_IP,
        "targets_scanned":     len(TARGETS),
        "detections":          new_detections,
        "false_positives":     fp,
        "true_positives":      tp,
        "false_negatives":     fn,
        "true_negatives":      tn,
        "detection_latency_s": round(detection_time, 2) if detection_time is not None else None,
        "blocked_ips":         blocked_ips,
        "attacker_blocked":    ATTACKER_IP in flow_table,
        "scan_batches_sent":   len(scan_verdicts),
        "success":             tp > 0 and fp == 0,
    }

    print("\n" + "=" * 60)
    print("[LATERAL] RESULTS")
    print("=" * 60)
    for k, v in result_dict.items():
        print(f"  {k:30s}: {v}")
    print("=" * 60)

    return result_dict


# ── Mininet mode ──────────────────────────────────────────────────────────────

def run_mininet(net, controller: str, duration: int) -> dict[str, Any]:  # type: ignore[type-arg]
    """
    Mininet mode: h3 uses nmap / hping3 to sweep internal hosts.
    Requires nmap installed in the container.
    """
    hosts   = {f"h{i}": net.get(f"h{i}") for i in range(1, 7)}
    h3      = hosts["h3"]
    legit   = [hosts[f"h{i}"] for i in range(1, 7) if i != 3]

    normal_duration = duration // 2
    attack_duration = duration - normal_duration

    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        for h in legit:
            h.cmd(f"ping -c 10 -i 0.5 -q {hosts['h5'].IP()} > /dev/null 2>&1 &")
        time.sleep(5)

    attack_start = time.time()
    detection_time = None

    for target_name in ["h1", "h2", "h4", "h5"]:
        target = hosts[target_name]
        h3.cmd(
            f"nmap -sS -p 1-256 --max-rtt-timeout 50ms "
            f"{target.IP()} > /tmp/lateral_{target.IP()}.log 2>&1 &"
        )
        time.sleep(max(1, (attack_duration // 4) - 2))
        ft = _get_flow_table(controller)
        if ATTACKER_IP in ft and detection_time is None:
            detection_time = time.time() - attack_start

    h3.cmd("pkill nmap 2>/dev/null; true")

    ft = _get_flow_table(controller)
    fp = sum(1 for h in legit if h.IP() in ft)
    return {
        "scenario":            "lateral_movement",
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
    out = RESULTS_DIR / "lateral_movement_metrics.json"
    with open(out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"[LATERAL] Results saved to {out}")

    csv_path = RESULTS_DIR / "lateral_movement_metrics.csv"
    write_hdr = not csv_path.exists()
    flat = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
            for k, v in result.items()}
    with open(csv_path, "a") as fh:
        if write_hdr:
            fh.write(",".join(flat.keys()) + "\n")
        fh.write(",".join(str(v) for v in flat.values()) + "\n")
    return out


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Lateral movement scenario")
    parser.add_argument("--standalone", action="store_true")
    parser.add_argument("--controller", default=CONTROLLER_URL)
    parser.add_argument("--duration",   type=int, default=60)
    parser.add_argument("--no-reset",   action="store_true")
    args = parser.parse_args()

    if not args.no_reset:
        print(f"[LATERAL] Resetting controller at {args.controller}...")
        _reset_controller(args.controller)
        time.sleep(1)

    if args.standalone:
        result = run_standalone(args.controller, args.duration)
    else:
        print("[LATERAL] Pass --standalone to run without Mininet.")
        sys.exit(1)

    save_results(result)
    sys.exit(0 if result.get("success") else 2)


if __name__ == "__main__":
    main()
