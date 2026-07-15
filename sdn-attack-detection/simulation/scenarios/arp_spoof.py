#!/usr/bin/env python3
"""
arp_spoof.py — ARP spoofing / Man-in-the-Middle scenario.

Attack model:
  h6 (10.0.0.6) poisons h5's ARP cache, impersonating h1 (10.0.0.1).
  After the ARP cache is poisoned, traffic that h5 believes goes to h1
  actually arrives at h6 first (MITM position).

  In Mininet mode: h6 runs `arpspoof -t {h5_ip} {h1_ip}` which sends
  continuous gratuitous ARPs claiming h1's IP maps to h6's MAC.

  In STANDALONE mode: we simulate the NETWORK-LEVEL symptoms that a switch
  or controller would observe:
    - Traffic appears from h1's IP (10.0.0.1) but is actually sourced from h6
      (same MAC mismatch would be detected by a proper ARP inspection system)
    - From the telemetry perspective: h6 sends telemetry with src=10.0.0.1
      (spoofed IP), which causes unusual traffic patterns for that IP
    - Additionally h6 shows abnormal traffic volume for a host that should be
      acting as a passive MITM relay

Detection signal to Isolation Forest:
  - Sudden burst of traffic from h1's IP (actually h6) — abnormal rate spike
  - h6 also shows relay traffic (receives then forwards at near-identical rates)
  - The combination of unusual traffic volumes for both IPs in the same window
    is the anomaly signal

STANDALONE simulation strategy:
  We submit telemetry in h6's name (10.0.0.6) showing it simultaneously
  receiving large amounts of traffic (relay) AND sending the same traffic
  back — creating a double-counting anomaly that spikes the feature vector.
  We also submit spoofed traffic as if from h1 at an abnormal rate.

Usage:
  python3 simulation/scenarios/arp_spoof.py --standalone --controller http://127.0.0.1:9000
  python3 simulation/scenarios/arp_spoof.py --standalone --duration 60
"""

from __future__ import annotations

import argparse
import csv
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

ATTACKER_IP      = "10.0.0.6"   # h6 — ARP spoofer
VICTIM_IP        = "10.0.0.5"   # h5 — ARP cache target
IMPERSONATED_IP  = "10.0.0.1"   # h1 — impersonated host
LEGIT_IPS        = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]

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
    """Standard background traffic — all hosts behave normally."""
    all_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"]
    for src_ip in all_ips:
        n_flows = random.randint(1, 3)
        flows   = []
        for _ in range(n_flows):
            pkts  = random.randint(10, 80)
            bsize = random.randint(100, 600)
            dur   = random.uniform(1.0, 4.0)
            flows.append([pkts, pkts * bsize, dur])
        dst = random.choice([ip for ip in all_ips if ip != src_ip])
        _post_telemetry(controller, src_ip, dst, flows)


def _arp_spoof_batch(controller: str, poll_interval: float = 5.0) -> dict[str, Any]:
    """
    Simulate the network effects of active ARP spoofing by h6.

    Two anomaly signals sent in the same poll window:

    1. Spoofed source: traffic appears from IMPERSONATED_IP (10.0.0.1) but at
       an abnormally high rate — h6 is replaying/relaying traffic from h5 back
       with h1's IP, causing a sudden spike in h1's apparent traffic volume.

    2. Attacker relay: h6 itself shows an unusual pattern — it receives traffic
       destined for h1 and re-sends it, so its own traffic doubles up in ways
       that don't match any normal host behavior profile.
    """
    # Signal 1: abnormal spike attributed to impersonated IP
    # Normal h1 traffic baseline: ~20-100 pkts/poll at ~400 bytes avg
    # Spoofed: burst of h5-destined traffic replayed from h1's IP
    relay_pkts  = random.randint(500, 1500)   # 10-30x normal
    relay_bytes = relay_pkts * random.randint(300, 800)
    spoofed_flows = [[relay_pkts, relay_bytes, poll_interval]]
    r1 = _post_telemetry(controller, IMPERSONATED_IP, VICTIM_IP, spoofed_flows)

    # Signal 2: h6 relay traffic — receives AND retransmits, looks like double-flow
    # This appears as an anomalous number of flows from a single host in one window
    n_relay_flows = random.randint(20, 60)
    relay_flows = []
    for _ in range(n_relay_flows):
        pkts  = random.randint(10, 50)
        bsize = random.randint(300, 900)
        dur   = poll_interval / n_relay_flows
        relay_flows.append([pkts, pkts * bsize, dur])
    r2 = _post_telemetry(controller, ATTACKER_IP, VICTIM_IP, relay_flows)

    # Return the verdict for the attacker's own traffic (more likely to be flagged)
    return r2


# ── standalone scenario ───────────────────────────────────────────────────────

def run_standalone(controller: str, duration: int) -> dict[str, Any]:
    normal_duration = duration // 2
    attack_duration = duration - normal_duration
    poll_interval   = 5.0

    print(f"[ARP_SPOOF] Standalone | controller={controller}")
    print(f"[ARP_SPOOF] Normal: {normal_duration}s | Attack: {attack_duration}s")
    print(f"[ARP_SPOOF] Attacker: {ATTACKER_IP} impersonating {IMPERSONATED_IP} → {VICTIM_IP}")

    stats_before      = _get_stats(controller)
    detections_before = stats_before.get("total_detections", 0)

    detection_time: float | None = None
    attack_start: float | None   = None
    attack_verdicts: list[str]   = []

    # ── Phase 1: normal ───────────────────────────────────────────────────────
    print(f"\n[ARP_SPOOF] === Phase 1: Normal traffic ({normal_duration}s) ===")
    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        _normal_batch(controller)
        remaining = phase1_end - time.time()
        print(f"[ARP_SPOOF] Phase 1 — {normal_duration - remaining:.0f}s/{normal_duration}s",
              flush=True)
        time.sleep(min(poll_interval, max(0.1, remaining)))

    print(f"[ARP_SPOOF] End Phase 1 — detections: {_get_stats(controller).get('total_detections', 0)}")

    # ── Phase 2: ARP spoofing active ──────────────────────────────────────────
    print(f"\n[ARP_SPOOF] === Phase 2: ARP spoofing active ({attack_duration}s) ===")
    phase2_end  = time.time() + attack_duration
    attack_start = time.time()

    while time.time() < phase2_end:
        # Background: remaining legit hosts still operate normally
        _normal_batch(controller)

        # ARP spoof traffic patterns
        result  = _arp_spoof_batch(controller, poll_interval)
        verdict = result.get("verdict", "Unknown")
        action  = result.get("action", "FORWARD")
        attack_verdicts.append(verdict)
        elapsed = time.time() - attack_start

        print(f"[ARP_SPOOF] Phase 2 — {elapsed:.0f}s/{attack_duration}s | "
              f"verdict={verdict} action={action}", flush=True)

        if verdict == "Attack" and detection_time is None:
            detection_time = elapsed
            print(f"[ARP_SPOOF] *** DETECTED at t+{detection_time:.1f}s ***")

        remaining = phase2_end - time.time()
        time.sleep(min(poll_interval, max(0.1, remaining)))

    # ── Metrics ───────────────────────────────────────────────────────────────
    stats_after = _get_stats(controller)
    flow_table  = _get_flow_table(controller)

    new_detections = stats_after.get("total_detections", 0) - detections_before
    blocked_ips    = list(flow_table.keys())

    tp = len([v for v in attack_verdicts if v == "Attack"])
    fn = len([v for v in attack_verdicts if v == "Normal"])

    # False positives: legit hosts (not h6, not h1 impersonated) that got blocked
    truly_legit = ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
    fp = sum(1 for ip in truly_legit if ip in flow_table)
    tn = len(truly_legit) - fp

    # Note: IMPERSONATED_IP (h1) getting blocked is a side-effect of spoofing,
    # not a true FP from the detection perspective — h6 caused that.
    impersonated_blocked = IMPERSONATED_IP in flow_table
    attacker_blocked     = ATTACKER_IP in flow_table

    result_dict = {
        "scenario":                "arp_spoof",
        "duration":                duration,
        "normal_phase_s":          normal_duration,
        "attack_phase_s":          attack_duration,
        "attacker_ip":             ATTACKER_IP,
        "victim_ip":               VICTIM_IP,
        "impersonated_ip":         IMPERSONATED_IP,
        "detections":              new_detections,
        "false_positives":         fp,
        "true_positives":          tp,
        "false_negatives":         fn,
        "true_negatives":          tn,
        "detection_latency_s":     round(detection_time, 2) if detection_time is not None else None,
        "attacker_blocked":        attacker_blocked,
        "impersonated_ip_blocked": impersonated_blocked,
        "blocked_ips":             blocked_ips,
        "attack_batches_sent":     len(attack_verdicts),
        # Success ΜΟΝΟ αν η ΙΔΙΑ η επίθεση ARP ανιχνεύθηκε (tp>0) χωρίς ψευδώς
        # θετικά. Ο έμμεσος αποκλεισμός του attacker από συνοδευτική ανωμαλία ΔΕΝ
        # συνιστά επιτυχία ανίχνευσης ARP spoofing.
        "success":                 tp > 0 and fp == 0,
    }

    print("\n" + "=" * 60)
    print("[ARP_SPOOF] RESULTS")
    print("=" * 60)
    for k, v in result_dict.items():
        print(f"  {k:35s}: {v}")
    print("=" * 60)

    return result_dict


# ── Mininet mode ──────────────────────────────────────────────────────────────

def run_mininet(net, controller: str, duration: int) -> dict[str, Any]:  # type: ignore[type-arg]
    """
    Mininet mode: h6 uses `arpspoof` to poison h5's ARP cache.
    arpspoof must be installed (dsniff package) in the container.
    """
    hosts  = {f"h{i}": net.get(f"h{i}") for i in range(1, 7)}
    h1     = hosts["h1"]
    h5     = hosts["h5"]
    h6     = hosts["h6"]
    legit  = [hosts[f"h{i}"] for i in range(1, 6)]

    normal_duration = duration // 2
    attack_duration = duration - normal_duration

    print(f"[ARP_SPOOF] Phase 1: normal ({normal_duration}s)")
    phase1_end = time.time() + normal_duration
    while time.time() < phase1_end:
        for h in legit:
            h.cmd(f"ping -c 10 -i 0.5 -q {h5.IP()} > /dev/null 2>&1 &")
        time.sleep(5)

    print(f"[ARP_SPOOF] Phase 2: arpspoof h6 impersonates h1 ({attack_duration}s)")
    # arpspoof -i <iface> -t <target> <host_to_impersonate>
    # This sends continuous ARPs: "10.0.0.1 is at <h6-mac>"
    h6.cmd(
        f"arpspoof -i h6-eth0 -t {h5.IP()} {h1.IP()} "
        f"> /tmp/arpspoof.log 2>&1 &"
    )

    attack_start   = time.time()
    detection_time = None
    deadline       = time.time() + attack_duration

    while time.time() < deadline:
        for h in [hosts[f"h{i}"] for i in range(2, 6)]:
            h.cmd(f"ping -c 10 -i 0.5 -q {h5.IP()} > /dev/null 2>&1 &")
        ft = _get_flow_table(controller)
        if ATTACKER_IP in ft and detection_time is None:
            detection_time = time.time() - attack_start
        time.sleep(5)

    h6.cmd("pkill arpspoof 2>/dev/null; true")

    ft = _get_flow_table(controller)
    fp = sum(1 for ip in ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
             if ip in ft)
    return {
        "scenario":            "arp_spoof",
        "duration":            duration,
        "detections":          1 if ATTACKER_IP in ft else 0,
        "false_positives":     fp,
        "detection_latency_s": round(detection_time, 2) if detection_time else None,
        "blocked_ips":         list(ft.keys()),
        "attacker_blocked":    ATTACKER_IP in ft,
        "success":             ATTACKER_IP in ft and fp == 0,
    }


# ── save results ──────────────────────────────────────────────────────────────

def save_results(result: dict[str, Any]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / "arp_spoof_metrics.json"
    with open(out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"[ARP_SPOOF] Results saved to {out}")

    csv_path  = RESULTS_DIR / "mitigation_latency.csv"
    write_hdr = not csv_path.exists()
    row = {
        "scenario":            result["scenario"],
        "detection_latency_s": result.get("detection_latency_s"),
        "false_positives":     result.get("false_positives"),
        "true_positives":      result.get("true_positives"),
        "blocked_ips":         json.dumps(result.get("blocked_ips", [])),
        "success":             result.get("success"),
    }
    flat = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
            for k, v in row.items()}
    with open(csv_path, "a", newline="") as fh:
        w = csv.writer(fh)
        if write_hdr:
            w.writerow(list(flat.keys()))
        w.writerow(list(flat.values()))
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
    parser = argparse.ArgumentParser(description="ARP spoofing / MITM scenario")
    parser.add_argument("--standalone", action="store_true")
    parser.add_argument("--controller", default=CONTROLLER_URL)
    parser.add_argument("--duration",   type=int, default=60)
    parser.add_argument("--no-reset",   action="store_true")
    args = parser.parse_args()

    if not args.no_reset:
        print(f"[ARP_SPOOF] Resetting controller at {args.controller}...")
        _reset_controller(args.controller)
        time.sleep(1)

    if args.standalone:
        result = run_standalone(args.controller, args.duration)
    else:
        print("[ARP_SPOOF] Pass --standalone to run without Mininet.")
        sys.exit(1)

    save_results(result)
    sys.exit(0 if result.get("success") else 2)


if __name__ == "__main__":
    main()
