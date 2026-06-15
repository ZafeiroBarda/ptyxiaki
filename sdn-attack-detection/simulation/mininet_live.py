#!/usr/bin/env python3
"""
mininet_live.py — End-to-end live demo: Mininet + Flask controller.

Scenario (automated):
  1. Wait for Flask controller (http://controller:9000)
  2. Build Mininet topology: OVS switch (standalone mode) + 6 hosts
  3. Start background telemetry thread (polls ovs-ofctl every 5s)
  4. Phase 1 (30s): normal traffic — h1-h4 ping h5
  5. Phase 2 (30s): SYN flood from h6 → h5 (hping3)
  6. Print detection/mitigation results

No Ryu/OpenFlow controller required.
OVS runs in standalone (self-learning L2) mode.
Traffic stats polled via 'ovs-ofctl dump-ports'.
"""

import os
import re
import subprocess
import sys
import threading
import time

import requests

CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "http://controller:9000")
NORMAL_PHASE   = int(os.environ.get("NORMAL_PHASE", "30"))
ATTACK_PHASE   = int(os.environ.get("ATTACK_PHASE", "30"))
TELEM_INTERVAL = 2  # seconds between telemetry snapshots (lower = smoother chart)


# ──────────────────────────────────────────────────────────────────────────────
#  Flask controller helpers
# ──────────────────────────────────────────────────────────────────────────────

def wait_for_flask(timeout=90):
    print(f"[LIVE] Waiting for Flask controller ({CONTROLLER_URL})...", flush=True)
    for i in range(timeout):
        try:
            r = requests.get(f"{CONTROLLER_URL}/health", timeout=2)
            if r.ok:
                info = r.json()
                print(f"[LIVE] Controller OK — Defense Engine: "
                      f"{info.get('defense_engine', '?')}", flush=True)
                # Clear any state from previous runs
                try:
                    requests.post(f"{CONTROLLER_URL}/reset", timeout=3)
                    print("[LIVE] Controller state reset.", flush=True)
                except Exception:
                    pass
                return
        except Exception:
            pass
        if i % 10 == 9:
            print(f"[LIVE]   ...still waiting ({i+1}s)", flush=True)
        time.sleep(1)
    raise RuntimeError(f"Flask controller not responding after {timeout}s")


def register_host(name, ip):
    try:
        requests.post(f"{CONTROLLER_URL}/register",
                      json={"node_id": name, "type": "host", "ip": ip},
                      timeout=3)
    except Exception:
        pass


def get_stats():
    return requests.get(f"{CONTROLLER_URL}/stats", timeout=5).json()


def get_flow_table():
    return requests.get(f"{CONTROLLER_URL}/flow_table", timeout=5).json()


def get_topology():
    return requests.get(f"{CONTROLLER_URL}/topology", timeout=5).json()


# ──────────────────────────────────────────────────────────────────────────────
#  OVS stats helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_ovs_port_stats(bridge="s1"):
    """Return {port_number: {packets, bytes}} via ovs-ofctl dump-ports."""
    try:
        result = subprocess.run(
            ["ovs-ofctl", "dump-ports", bridge],
            capture_output=True, text=True, timeout=5,
        )
        stats = {}
        for line in result.stdout.splitlines():
            m = re.match(r"\s+port\s+(\d+):\s+rx pkts=(\d+),\s*bytes=(\d+)", line)
            if m:
                stats[int(m.group(1))] = {
                    "packets": int(m.group(2)),
                    "bytes":   int(m.group(3)),
                }
        return stats
    except Exception:
        return {}


def read_iface_rx(iface):
    """Fallback: read rx_packets + rx_bytes from /sys/class/net."""
    try:
        p = int(open(f"/sys/class/net/{iface}/statistics/rx_packets").read())
        b = int(open(f"/sys/class/net/{iface}/statistics/rx_bytes").read())
        return p, b
    except Exception:
        return 0, 0


def install_drop_flow(src_ip, bridge="s1"):
    """Inject a high-priority DROP flow directly into OVS (bypasses controller)."""
    r = subprocess.run(
        ["ovs-ofctl", "add-flow", bridge,
         f"priority=100,ip,nw_src={src_ip},actions=drop"],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        print(f"[OVS]  DROP flow installed: {src_ip}", flush=True)
    else:
        print(f"[OVS]  DROP failed for {src_ip}: {r.stderr.strip()}", flush=True)


# ──────────────────────────────────────────────────────────────────────────────
#  Background telemetry thread
# ──────────────────────────────────────────────────────────────────────────────

def telemetry_loop(port_to_ip, victim_ip, stop_event, interval=TELEM_INTERVAL):
    """
    Every <interval> seconds:
      1. Read per-port rx stats from OVS (or /sys/class/net as fallback)
      2. Compute delta packets/bytes since last reading
      3. POST to Flask /telemetry for each active source
      4. If verdict == 'Attack', install DROP flow in OVS
    """
    prev = {p: {"packets": 0, "bytes": 0} for p in port_to_ip}
    drop_installed = set()

    while not stop_event.is_set():
        stop_event.wait(timeout=interval)
        if stop_event.is_set():
            break

        curr = get_ovs_port_stats()

        # Fall back to /sys/class/net if ovs-ofctl returned nothing
        if not curr:
            for port in port_to_ip:
                p, b = read_iface_rx(f"s1-eth{port}")
                curr[port] = {"packets": p, "bytes": b}

        for port, src_ip in port_to_ip.items():
            if port not in curr:
                continue
            # Don't report the victim's own port — it generates RST/ICMP
            # responses to the flood which would cause a false-positive block
            if src_ip == victim_ip:
                prev[port] = curr[port]
                continue
            dpkts  = max(0, curr[port]["packets"] - prev[port]["packets"])
            dbytes = max(0, curr[port]["bytes"]   - prev[port]["bytes"])
            prev[port] = curr[port]

            # Skip micro-flows (< 4 pkts) to avoid false positives from
            # timing gaps where a ping cycle doesn't complete in the window
            if dpkts < 4:
                continue

            # POST telemetry to Flask
            try:
                resp = requests.post(
                    f"{CONTROLLER_URL}/telemetry",
                    json={"src": src_ip, "dst": victim_ip,
                          "flows": [[dpkts, dbytes, interval]]},
                    timeout=3,
                )
                result = resp.json()
            except Exception as e:
                print(f"[TELEM] Error ({src_ip}): {e}", flush=True)
                continue

            verdict = result.get("verdict", "Normal")
            action  = result.get("action", "FORWARD")
            print(f"[TELEM] {src_ip:12s}  pkts={dpkts:6d}  bytes={dbytes:8d}"
                  f"  verdict={verdict}  action={action}", flush=True)

            if verdict == "Attack" and src_ip not in drop_installed:
                drop_installed.add(src_ip)
                install_drop_flow(src_ip)


# ──────────────────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    from mininet.net import Mininet
    from mininet.node import OVSSwitch
    from mininet.link import TCLink
    from mininet.log import setLogLevel

    setLogLevel("warning")

    # ── 1. Flask controller ──────────────────────────────────────────────────
    wait_for_flask()

    # ── 2. Build topology ───────────────────────────────────────────────────
    print("[LIVE] Building Mininet topology (6 hosts, 1 OVS switch)...", flush=True)

    # controller=None → no remote controller needed
    net = Mininet(switch=OVSSwitch, link=TCLink, autoSetMacs=True, controller=None)

    # failMode='standalone': OVS learns MACs autonomously (no controller required)
    # datapath='user':       userspace OVS (works on WSL2 without kernel module)
    s1 = net.addSwitch("s1", failMode="standalone", datapath="user")

    hosts = {}
    for i in range(1, 7):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        net.addLink(h, s1, bw=10, delay="1ms")
        hosts[f"h{i}"] = h

    net.start()
    time.sleep(3)

    victim_ip   = hosts["h5"].IP()
    attacker_ip = hosts["h6"].IP()
    legit       = [hosts[f"h{i}"] for i in range(1, 5)]

    # Port numbers are assigned in insertion order (h1→port1, h2→port2, …)
    port_to_ip = {i: hosts[f"h{i}"].IP() for i in range(1, 7)}

    print(f"[LIVE] h1-h4 legit | h5={victim_ip} victim | "
          f"h6={attacker_ip} attacker", flush=True)

    # ── 3. Register hosts ───────────────────────────────────────────────────
    for name, h in hosts.items():
        register_host(name, h.IP())
    print("[LIVE] Hosts registered.\n", flush=True)

    # ── 4. Start telemetry thread ───────────────────────────────────────────
    stop_event = threading.Event()
    telem = threading.Thread(
        target=telemetry_loop,
        args=(port_to_ip, victim_ip, stop_event),
        daemon=True,
    )
    telem.start()

    # ── PHASE 1: Normal traffic ──────────────────────────────────────────────
    print("=" * 60, flush=True)
    print(f"  PHASE 1: Normal traffic ({NORMAL_PHASE}s)", flush=True)
    print("=" * 60, flush=True)

    deadline = time.time() + NORMAL_PHASE
    while time.time() < deadline:
        for h in legit:
            # -c 20 -i 0.2 → 20 pkts in 4s → pkts > SHORT_FLOW_PKT_THRESHOLD(3)
            # so short_ratio stays 0 and model sees Normal traffic
            h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
        time.sleep(5)
        elapsed = int(time.time() - (deadline - NORMAL_PHASE))
        print(f"[LIVE] Phase 1 — {elapsed}s/{NORMAL_PHASE}s", flush=True)

    time.sleep(3)
    p1 = get_stats()
    print(f"\n[LIVE] End Phase 1 — detections: {p1['total_detections']} | "
          f"DROP rules: {p1['drop_rules']}\n", flush=True)

    # ── PHASE 2: DDoS SYN flood ─────────────────────────────────────────────
    print("=" * 60, flush=True)
    print(f"  PHASE 2: SYN flood h6 → h5 ({ATTACK_PHASE}s)", flush=True)
    print("=" * 60, flush=True)

    # Real SYN flood using hping3; no --rand-source so the controller
    # can identify and block the specific attacker IP
    hosts["h6"].cmd(
        f"hping3 --syn --flood -p 80 {victim_ip} > /tmp/attack.log 2>&1 &"
    )

    deadline = time.time() + ATTACK_PHASE
    while time.time() < deadline:
        for h in legit:
            h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
        time.sleep(5)
        elapsed = int(time.time() - (deadline - ATTACK_PHASE))
        s_now = get_stats()
        print(f"[LIVE] Phase 2 — {elapsed}s/{ATTACK_PHASE}s | "
              f"detections: {s_now['total_detections']} | "
              f"DROP: {s_now['drop_rules']}", flush=True)

    hosts["h6"].cmd("pkill hping3 2>/dev/null; true")
    stop_event.set()
    telem.join(timeout=10)
    time.sleep(2)

    # ── Results ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60, flush=True)
    print("  RESULTS", flush=True)
    print("=" * 60, flush=True)

    stats = get_stats()
    ft    = get_flow_table()
    topo  = get_topology()

    print(f"  Nodes in Global Network View   : {stats['nodes']}", flush=True)
    print(f"  Total anomaly detections       : {stats['total_detections']}", flush=True)
    print(f"  Active DROP rules              : {list(ft.keys())}", flush=True)

    print("\n  Host status:", flush=True)
    for node in topo["nodes"]:
        if node["type"] == "host":
            status = node.get("status", "?")
            tag    = "BLOCKED" if status == "blocked" else "OK     "
            print(f"    [{tag}] {node['ip']}", flush=True)

    print("\n  Recent events:", flush=True)
    for ev in stats.get("recent_log", [])[-6:]:
        print(f"    {ev['msg']}", flush=True)

    blocked = attacker_ip in ft
    fp      = any(h.IP() in ft for h in legit)
    print()
    if blocked:
        print("[LIVE] SUCCESS — attacker blocked!", flush=True)
    else:
        print("[LIVE] WARNING — attacker NOT blocked (check logs).", flush=True)
    if fp:
        print("[LIVE] WARNING — false positive on a legit host!", flush=True)
    else:
        print("[LIVE] No false positives on legit hosts.", flush=True)

    # ── Cleanup ──────────────────────────────────────────────────────────────
    print("\n[LIVE] Stopping Mininet...", flush=True)
    net.stop()
    print("[LIVE] Done.", flush=True)


if __name__ == "__main__":
    main()
