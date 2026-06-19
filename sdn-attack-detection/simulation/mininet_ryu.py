#!/usr/bin/env python3
"""
mininet_ryu.py — Mode B: Mininet + Ryu/os-ken + OpenFlow 1.3 + Flask ML Controller

Architecture:
  Mininet hosts ─► OVS switch ─[OpenFlow 1.3]─► Ryu (ryu_bridge.py)
                                                    │
                                                    └─[REST]─► Flask ML Controller :9000
                                                                  │
                                                              Isolation Forest

Run (inside mininet container):
  python3 simulation/mininet_ryu.py

This is Mode B — the "real SDN" mode with a proper OpenFlow control plane.
Mode A (standalone OVS) is simulation/mininet_live.py.
"""

import os
import subprocess
import sys
import threading
import time

import requests

CONTROLLER_URL  = os.environ.get("CONTROLLER_URL",  "http://controller:9000")
SWITCH_API_KEY  = os.environ.get("SWITCH_API_KEY",  "sdn-secret-2024")
NORMAL_PHASE    = int(os.environ.get("NORMAL_PHASE",    "30"))
ATTACK_PHASE    = int(os.environ.get("ATTACK_PHASE",    "30"))
RECOVERY_PHASE  = int(os.environ.get("RECOVERY_PHASE",  "20"))
LOOP_CYCLES     = int(os.environ.get("LOOP_CYCLES",     "0"))
RYU_PORT        = int(os.environ.get("RYU_PORT",         "6653"))

_AUTH_HEADERS = {"X-Switch-Token": SWITCH_API_KEY, "Content-Type": "application/json"}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RYU_BRIDGE = os.path.join(SCRIPT_DIR, "ryu_bridge.py")


# ── Helpers ───────────────────────────────────────────────────────────────────

def wait_for_flask(timeout=90):
    print(f"[RYU-MODE] Waiting for Flask controller ({CONTROLLER_URL})...", flush=True)
    for i in range(timeout):
        try:
            r = requests.get(f"{CONTROLLER_URL}/health", timeout=2)
            if r.ok:
                info = r.json()
                print(f"[RYU-MODE] Controller OK — Defense Engine: "
                      f"{info.get('defense_engine', '?')}", flush=True)
                try:
                    requests.post(f"{CONTROLLER_URL}/reset", timeout=3)
                    print("[RYU-MODE] Controller state reset.", flush=True)
                except Exception:
                    pass
                return
        except Exception:
            pass
        if i % 10 == 9:
            print(f"[RYU-MODE]   ...still waiting ({i+1}s)", flush=True)
        time.sleep(1)
    raise RuntimeError(f"Flask controller not responding after {timeout}s")


def start_ryu():
    """Start ryu-manager or os-ken-manager with ryu_bridge.py."""
    for mgr in ("ryu-manager", "os-ken-manager"):
        try:
            proc = subprocess.Popen(
                [mgr, RYU_BRIDGE,
                 f"--ofp-tcp-listen-port={RYU_PORT}",
                 "--observe-links"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True,
            )
            # Wait a bit and check it started
            time.sleep(3)
            if proc.poll() is None:
                print(f"[RYU-MODE] {mgr} started (PID {proc.pid})", flush=True)
                # Pipe output to console in background
                def _pipe(p):
                    for line in p.stdout:
                        print(f"[RYU] {line.rstrip()}", flush=True)
                threading.Thread(target=_pipe, args=(proc,), daemon=True).start()
                return proc
        except FileNotFoundError:
            continue
    raise RuntimeError("Neither ryu-manager nor os-ken-manager found. "
                       "Install with: pip install ryu  OR  pip install os-ken")


def register_host(name, ip):
    try:
        requests.post(f"{CONTROLLER_URL}/register",
                      json={"node_id": name, "type": "host", "ip": ip},
                      headers=_AUTH_HEADERS, timeout=3)
    except Exception:
        pass


def get_stats():
    try:
        return requests.get(f"{CONTROLLER_URL}/stats", timeout=5).json()
    except Exception:
        return {"total_detections": "?", "drop_rules": "?"}


def get_flow_table():
    try:
        return requests.get(f"{CONTROLLER_URL}/flow_table", timeout=5).json()
    except Exception:
        return {}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.link import TCLink
    from mininet.log import setLogLevel

    setLogLevel("warning")

    # ── 1. Wait for Flask controller ─────────────────────────────────────────
    wait_for_flask()

    # ── 2. Start Ryu/os-ken OpenFlow controller ───────────────────────────────
    print("[RYU-MODE] Starting Ryu OpenFlow controller...", flush=True)
    ryu_proc = start_ryu()
    time.sleep(5)  # give Ryu time to bind OpenFlow port

    # ── 3. Build Mininet topology ─────────────────────────────────────────────
    print("[RYU-MODE] Building topology: 6 hosts + 1 OVS switch + Ryu controller",
          flush=True)

    # RemoteController points to Ryu (running on localhost, same container)
    ryu_ctrl = RemoteController("ryu", ip="127.0.0.1", port=RYU_PORT)
    net = Mininet(switch=OVSSwitch, link=TCLink, autoSetMacs=True,
                  controller=None)
    net.addController(ryu_ctrl)

    # OVS switch in OpenFlow 1.3 mode (NOT standalone — Ryu handles forwarding)
    s1 = net.addSwitch("s1", protocols="OpenFlow13", datapath="user")

    hosts = {}
    for i in range(1, 7):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        net.addLink(h, s1, bw=10, delay="1ms")
        hosts[f"h{i}"] = h

    net.start()
    time.sleep(5)

    # Connect OVS to Ryu via OpenFlow
    subprocess.run(
        ["ovs-vsctl", "set-controller", "s1",
         f"tcp:127.0.0.1:{RYU_PORT}"],
        capture_output=True,
    )
    subprocess.run(
        ["ovs-vsctl", "set", "bridge", "s1",
         "protocols=OpenFlow13"],
        capture_output=True,
    )

    victim_ip   = hosts["h5"].IP()
    attacker_ip = hosts["h6"].IP()
    legit       = [hosts[f"h{i}"] for i in range(1, 5)]

    print(f"[RYU-MODE] h1-h4 legit | h5={victim_ip} victim | "
          f"h6={attacker_ip} attacker", flush=True)
    print("[RYU-MODE] OpenFlow forwarding via Ryu ← ryu_bridge.py ← Flask ML",
          flush=True)

    # ── 4. Register hosts ─────────────────────────────────────────────────────
    for name, h in hosts.items():
        register_host(name, h.IP())
    print("[RYU-MODE] Hosts registered.\n", flush=True)

    # ── Demo cycle ────────────────────────────────────────────────────────────
    cycle = 0
    loop_label = f"{LOOP_CYCLES} cycle(s)" if LOOP_CYCLES else "∞ (Ctrl-C to stop)"
    print(f"[RYU-MODE] Mode B demo — {loop_label}\n", flush=True)
    print("[RYU-MODE] NOTE: Telemetry is sent automatically by Ryu via "
          "PACKET_IN events. No manual telemetry loop needed.", flush=True)

    try:
        while True:
            cycle += 1
            bar = "=" * 60

            # ── Phase 1: Normal ───────────────────────────────────────────────
            print(f"\n{bar}", flush=True)
            print(f"  CYCLE {cycle} — PHASE 1: Normal traffic ({NORMAL_PHASE}s) [Mode B/Ryu]",
                  flush=True)
            print(f"{bar}", flush=True)

            deadline = time.time() + NORMAL_PHASE
            while time.time() < deadline:
                for h in legit:
                    h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
                time.sleep(5)
                elapsed = int(time.time() - (deadline - NORMAL_PHASE))
                print(f"[RYU-MODE] C{cycle} Phase 1 — {elapsed}s/{NORMAL_PHASE}s",
                      flush=True)

            p1 = get_stats()
            print(f"\n[RYU-MODE] End Phase 1 — detections: {p1['total_detections']} | "
                  f"DROP: {p1['drop_rules']}\n", flush=True)

            # ── Phase 2: Attack ────────────────────────────────────────────────
            print(f"{bar}", flush=True)
            print(f"  CYCLE {cycle} — PHASE 2: SYN flood h6→h5 ({ATTACK_PHASE}s) [Mode B/Ryu]",
                  flush=True)
            print(f"{bar}", flush=True)

            hosts["h6"].cmd(
                f"hping3 --syn --flood -p 80 {victim_ip} > /tmp/attack_ryu.log 2>&1 &"
            )

            deadline = time.time() + ATTACK_PHASE
            while time.time() < deadline:
                for h in legit:
                    h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
                time.sleep(5)
                elapsed = int(time.time() - (deadline - ATTACK_PHASE))
                s = get_stats()
                print(f"[RYU-MODE] C{cycle} Phase 2 — {elapsed}s/{ATTACK_PHASE}s | "
                      f"detections: {s['total_detections']} | DROP: {s['drop_rules']}",
                      flush=True)

            hosts["h6"].cmd("pkill hping3 2>/dev/null; true")

            # ── Results ────────────────────────────────────────────────────────
            ft      = get_flow_table()
            blocked = attacker_ip in ft
            fp      = any(h.IP() in ft for h in legit)
            print(f"\n[RYU-MODE] C{cycle}: "
                  f"{'✅ attacker blocked' if blocked else '⚠️  NOT blocked'} | "
                  f"{'✅ no FP' if not fp else '⚠️  FP on legit host'}\n",
                  flush=True)

            if LOOP_CYCLES > 0 and cycle >= LOOP_CYCLES:
                break

            # ── Recovery ──────────────────────────────────────────────────────
            print(f"[RYU-MODE] Recovery ({RECOVERY_PHASE}s)...", flush=True)
            try:
                requests.post(f"{CONTROLLER_URL}/unblock", timeout=3)
            except Exception:
                pass
            time.sleep(RECOVERY_PHASE)

    except KeyboardInterrupt:
        print("\n[RYU-MODE] Interrupted.", flush=True)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    ryu_proc.terminate()
    net.stop()
    print("[RYU-MODE] Done.", flush=True)


if __name__ == "__main__":
    main()
