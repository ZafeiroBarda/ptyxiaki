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

CONTROLLER_URL  = os.environ.get("CONTROLLER_URL",  "http://controller:9000")
SWITCH_API_KEY  = os.environ.get("SWITCH_API_KEY",  "sdn-secret-2024")
NORMAL_PHASE    = int(os.environ.get("NORMAL_PHASE",    "30"))
ATTACK_PHASE    = int(os.environ.get("ATTACK_PHASE",    "30"))
RECOVERY_PHASE  = int(os.environ.get("RECOVERY_PHASE",  "20"))
LOOP_CYCLES     = int(os.environ.get("LOOP_CYCLES",     "0"))   # 0 = infinite
TELEM_INTERVAL  = 2

_SWITCH_HEADERS = {"X-Switch-Token": SWITCH_API_KEY}
ADMIN_API_KEY   = os.environ.get("ADMIN_API_KEY", "sdn-admin-2024")
_ADMIN_HEADERS  = {"X-Admin-Token": ADMIN_API_KEY}


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
                    requests.post(f"{CONTROLLER_URL}/reset",
                                  headers=_ADMIN_HEADERS, timeout=3)
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
    try:
        return requests.get(f"{CONTROLLER_URL}/stats", timeout=5).json()
    except Exception:
        return {"total_detections": "?", "drop_rules": "?", "nodes": 0, "active_flows": 0, "recent_log": []}


def get_flow_table():
    try:
        return requests.get(f"{CONTROLLER_URL}/flow_table", timeout=5).json()
    except Exception:
        return {}


def get_topology():
    try:
        return requests.get(f"{CONTROLLER_URL}/topology", timeout=5).json()
    except Exception:
        return {"nodes": [], "edges": []}


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


def install_pair_flows(hosts, bridge="s1"):
    """Εγκαθιστά κανόνες ανά ζεύγος (nw_src, nw_dst) που προωθούν κανονικά.

    Σε λειτουργία standalone ο μεταγωγέας έχει έναν προεπιλεγμένο κανόνα NORMAL,
    οπότε το dump-flows δίνει έναν μόνο συγκεντρωτικό μετρητή. Προσθέτοντας
    κανόνες υψηλότερης προτεραιότητας ανά ζεύγος IP (με ενέργεια NORMAL, ώστε η
    προώθηση να μη μεταβάλλεται), ο πίνακας ροών αποκτά ΞΕΧΩΡΙΣΤΗ καταχώρηση ανά
    ζεύγος, καθεμία με δικούς της μετρητές n_packets/n_bytes/duration. Έτσι η
    τηλεμετρία διαβάζει πραγματικές per-flow στατιστικές (OpenFlow flow stats),
    αντί για μία διαφορά μετρητή θύρας.
    """
    ips = [h.IP() for h in hosts.values()]
    n = 0
    for s in ips:
        for d in ips:
            if s == d:
                continue
            r = subprocess.run(
                ["ovs-ofctl", "add-flow", bridge,
                 f"priority=10,ip,nw_src={s},nw_dst={d},actions=normal"],
                capture_output=True, text=True,
            )
            if r.returncode == 0:
                n += 1
    print(f"[OVS]  Εγκαταστάθηκαν {n} κανόνες ροής ανά ζεύγος (per-flow stats)", flush=True)


def get_ovs_flow_stats(bridge="s1"):
    """Επιστρέφει την ακατέργαστη έξοδο του ovs-ofctl dump-flows (per-flow)."""
    try:
        r = subprocess.run(["ovs-ofctl", "dump-flows", bridge],
                           capture_output=True, text=True, timeout=5)
        return r.stdout
    except Exception:
        return ""


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

def sim_control_loop(hosts, stop_event):
    """
    Background thread — polls /simulate/poll for manual attack commands
    sent from the dashboard. Allows victim/attacker selection at runtime.
    """
    active_attackers: set = set()

    while not stop_event.is_set():
        stop_event.wait(timeout=3)
        if stop_event.is_set():
            break
        try:
            cmd = requests.get(f"{CONTROLLER_URL}/simulate/poll",
                               headers=_SWITCH_HEADERS, timeout=2).json()
        except Exception:
            continue
        if not cmd or "cmd" not in cmd:
            continue

        if cmd["cmd"] == "start":
            # Stop any existing manual attack first
            for a in active_attackers:
                hosts[a].cmd("pkill hping3 2>/dev/null; true")
            active_attackers.clear()

            victim      = cmd.get("victim", "h5")
            attackers   = cmd.get("attackers", [])
            attack_type = cmd.get("attack_type", "syn")

            _attack_flags = {
                "syn":  "--syn  --flood -p 80",
                "udp":  "--udp  --flood -p 53",
                "icmp": "--icmp --flood",
            }
            flags = _attack_flags.get(attack_type, "--syn --flood -p 80")

            if victim not in hosts:
                print(f"[SIM] Unknown victim: {victim}", flush=True)
                continue
            victim_ip_manual = hosts[victim].IP()
            for a in attackers:
                if a not in hosts or a == victim:
                    continue
                hosts[a].cmd(
                    f"hping3 {flags} {victim_ip_manual} "
                    f"> /tmp/attack_{a}.log 2>&1 &"
                )
                active_attackers.add(a)
                print(f"[SIM] Manual {attack_type} attack: {a}({hosts[a].IP()}) → "
                      f"{victim}({victim_ip_manual})", flush=True)

        elif cmd["cmd"] == "stop":
            for a in active_attackers:
                hosts[a].cmd("pkill hping3 2>/dev/null; true")
            print(f"[SIM] Manual attack stopped ({', '.join(active_attackers)})", flush=True)
            active_attackers.clear()


def _submit_telemetry(src_ip, victim_ip, flows, drop_state):
    """Στέλνει μία λίστα ροών μιας πηγής στον controller και εφαρμόζει DROP."""
    try:
        resp = requests.post(
            f"{CONTROLLER_URL}/telemetry",
            json={"src": src_ip, "dst": victim_ip, "flows": flows},
            headers=_SWITCH_HEADERS, timeout=3,
        )
        result = resp.json()
    except Exception as e:
        print(f"[TELEM] Error ({src_ip}): {e}", flush=True)
        return
    verdict = result.get("verdict", "Normal")
    action  = result.get("action", "FORWARD")
    total_pkts = sum(f[0] for f in flows)
    print(f"[TELEM] {src_ip:12s}  flows={len(flows):3d}  pkts={total_pkts:6d}"
          f"  verdict={verdict}  action={action}", flush=True)
    if verdict == "Attack" and src_ip not in drop_state["installed"]:
        drop_state["installed"].add(src_ip)
        install_drop_flow(src_ip)


def telemetry_loop(port_to_ip, victim_ip, stop_event, drop_state,
                   interval=TELEM_INTERVAL):
    """
    Background thread — runs across all cycles until stop_event is set.
    drop_state is a shared mutable dict {"installed": set()} so the main
    thread can clear it between cycles without restarting the thread.

    ΠΡΩΤΕΥΟΝ ΜΟΝΟΠΑΤΙ: per-flow στατιστικά από τον πίνακα ροών (dump-flows),
    ώστε κάθε πηγή να στέλνει ΠΟΛΛΑΠΛΕΣ πραγματικές ροές (flow_count > 1) με
    δικές τους διάρκειες. ΕΦΕΔΡΙΚΟ: αν ο πίνακας ροών δεν έχει ακόμη per-flow
    καταχωρήσεις (π.χ. πριν εγκατασταθούν οι κανόνες ζεύγους), χρησιμοποιείται
    η παλαιότερη προσέγγιση διαφοράς μετρητή θύρας.
    """
    import flow_telemetry as ft

    prev_flows = {}   # (nw_src, nw_dst) -> {"packets","bytes"} για per-flow deltas
    prev_port = {p: {"packets": 0, "bytes": 0} for p in port_to_ip}

    while not stop_event.is_set():
        stop_event.wait(timeout=interval)
        if stop_event.is_set():
            break

        # ── Πρωτεύον: per-flow τηλεμετρία ────────────────────────────────────
        dump = get_ovs_flow_stats()
        parsed = ft.parse_ofctl_flows(dump) if dump else []
        if parsed:
            per_source, prev_flows = ft.window_deltas(parsed, prev_flows)
            for src_ip, flows in per_source.items():
                if src_ip == victim_ip:            # αγνόησε την κίνηση-απάντηση
                    continue
                if sum(f[0] for f in flows) < 4:    # αγνόησε micro-flows
                    continue
                _submit_telemetry(src_ip, victim_ip, flows, drop_state)
            continue

        # ── Εφεδρικό: διαφορά μετρητή θύρας (μία συγκεντρωτική ροή) ──────────
        curr = get_ovs_port_stats()
        if not curr:
            for port in port_to_ip:
                p, b = read_iface_rx(f"s1-eth{port}")
                curr[port] = {"packets": p, "bytes": b}

        for port, src_ip in port_to_ip.items():
            if port not in curr:
                continue
            if src_ip == victim_ip:
                prev_port[port] = curr[port]
                continue
            dpkts  = max(0, curr[port]["packets"] - prev_port[port]["packets"])
            dbytes = max(0, curr[port]["bytes"]   - prev_port[port]["bytes"])
            prev_port[port] = curr[port]
            if dpkts < 4:
                continue
            _submit_telemetry(src_ip, victim_ip, [[dpkts, dbytes, interval]], drop_state)


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

    # ── 3. Register hosts + εγκατάσταση κανόνων ροής ανά ζεύγος ──────────────
    for name, h in hosts.items():
        register_host(name, h.IP())
    install_pair_flows(hosts)   # ώστε το dump-flows να δίνει per-flow στατιστικά
    print("[LIVE] Hosts registered.\n", flush=True)

    # ── 4. Start telemetry + sim-control threads ────────────────────────────
    drop_state = {"installed": set()}
    stop_event = threading.Event()
    telem = threading.Thread(
        target=telemetry_loop,
        args=(port_to_ip, victim_ip, stop_event, drop_state),
        daemon=True,
    )
    telem.start()
    sim_ctrl = threading.Thread(
        target=sim_control_loop,
        args=(hosts, stop_event),
        daemon=True,
    )
    sim_ctrl.start()

    # ── Main demo loop ────────────────────────────────────────────────────────
    cycle = 0
    loop_label = f"{LOOP_CYCLES} cycle(s)" if LOOP_CYCLES else "∞ (Ctrl-C to stop)"
    print(f"[LIVE] Demo loop: {loop_label}\n", flush=True)

    try:
        while True:
            cycle += 1
            bar = "=" * 60

            # ── Phase 1: Normal traffic ──────────────────────────────────────
            print(f"{bar}", flush=True)
            print(f"  CYCLE {cycle} · PHASE 1: Normal traffic ({NORMAL_PHASE}s)",
                  flush=True)
            print(f"{bar}", flush=True)

            deadline = time.time() + NORMAL_PHASE
            while time.time() < deadline:
                for h in legit:
                    h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
                time.sleep(5)
                elapsed = int(time.time() - (deadline - NORMAL_PHASE))
                print(f"[LIVE] C{cycle} Phase 1 — {elapsed}s/{NORMAL_PHASE}s",
                      flush=True)

            p1 = get_stats()
            print(f"\n[LIVE] End Phase 1 — detections: {p1['total_detections']} | "
                  f"DROP: {p1['drop_rules']}\n", flush=True)

            # ── Phase 2: DDoS SYN flood ──────────────────────────────────────
            print(f"{bar}", flush=True)
            print(f"  CYCLE {cycle} · PHASE 2: SYN flood h6 → h5 ({ATTACK_PHASE}s)",
                  flush=True)
            print(f"{bar}", flush=True)

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
                print(f"[LIVE] C{cycle} Phase 2 — {elapsed}s/{ATTACK_PHASE}s | "
                      f"detections: {s_now['total_detections']} | "
                      f"DROP: {s_now['drop_rules']}", flush=True)

            hosts["h6"].cmd("pkill hping3 2>/dev/null; true")

            # ── Cycle results ────────────────────────────────────────────────
            ft = get_flow_table()
            blocked = attacker_ip in ft
            fp      = any(h.IP() in ft for h in legit)
            print(f"\n[LIVE] C{cycle} result: "
                  f"{'✅ attacker blocked' if blocked else '⚠️ NOT blocked'} | "
                  f"{'✅ no FP' if not fp else '⚠️ FP on legit host'}\n",
                  flush=True)

            # ── Check loop exit condition ────────────────────────────────────
            if LOOP_CYCLES > 0 and cycle >= LOOP_CYCLES:
                break

            # ── Recovery phase: unblock and wait before next cycle ───────────
            print(f"[LIVE] Recovery ({RECOVERY_PHASE}s) — "
                  f"clearing DROP rules for next cycle...", flush=True)
            try:
                requests.post(f"{CONTROLLER_URL}/unblock",
                              headers=_ADMIN_HEADERS, timeout=3)
            except Exception:
                pass
            # Remove ONLY the priority-100 DROP flow so the attacker can flood
            # again next cycle. --strict + priority keeps the priority-10
            # per-pair NORMAL flows intact (needed for per-flow telemetry).
            subprocess.run(
                ["ovs-ofctl", "--strict", "del-flows", "s1",
                 f"priority=100,ip,nw_src={attacker_ip}"],
                capture_output=True,
            )
            drop_state["installed"].clear()   # telemetry thread can re-detect

            deadline = time.time() + RECOVERY_PHASE
            while time.time() < deadline:
                for h in legit:
                    h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
                time.sleep(5)
                elapsed = int(time.time() - (deadline - RECOVERY_PHASE))
                print(f"[LIVE] Recovery — {elapsed}s/{RECOVERY_PHASE}s", flush=True)

    except KeyboardInterrupt:
        print("\n[LIVE] Interrupted by user.", flush=True)

    # ── Final results ─────────────────────────────────────────────────────────
    stop_event.set()
    telem.join(timeout=10)

    stats = get_stats()
    print(f"\n[LIVE] Total cycles: {cycle} | "
          f"Total detections: {stats['total_detections']}", flush=True)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    print("\n[LIVE] Stopping Mininet...", flush=True)
    net.stop()
    print("[LIVE] Done.", flush=True)


if __name__ == "__main__":
    main()
