#!/usr/bin/env python3
"""
mininet_live.py — End-to-end live demo με Mininet + Ryu + Flask controller.

Σενάριο (αυτόματο, χωρίς χειροκίνητη παρέμβαση):
  1. Αναμένει τον Flask controller (http://controller:9000)
  2. Ξεκινά τον Ryu bridge controller (ryu_bridge.py) στο background
  3. Δημιουργεί τοπολογία Mininet: s1 + h1-h4 (νόμιμοι) + h5 (θύμα) + h6 (επιτιθέμενος)
  4. Εγγράφει hosts στον Flask controller
  5. Φάση 1 (30s): φυσιολογική κίνηση — ping μεταξύ hosts
  6. Φάση 2 (30s): DDoS SYN flood από h6 → h5 (hping3)
  7. Εκτυπώνει αποτελέσματα ανίχνευσης + mitigation

Εκτέλεση (μέσα στο Docker):
  python3 simulation/mininet_live.py
  (ή: docker compose exec mininet python3 simulation/mininet_live.py)
"""

import os
import sys
import time
import subprocess
import requests

CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "http://controller:9000")
RYU_PORT       = int(os.environ.get("RYU_PORT", "6653"))
NORMAL_PHASE   = int(os.environ.get("NORMAL_PHASE", "30"))   # δευτερόλεπτα
ATTACK_PHASE   = int(os.environ.get("ATTACK_PHASE", "30"))


# ------------------------------------------------------------------ #
#  Βοηθητικές συναρτήσεις
# ------------------------------------------------------------------ #

def wait_for_flask(timeout=90):
    print(f"[LIVE] Αναμονή για Flask controller ({CONTROLLER_URL})...")
    for i in range(timeout):
        try:
            r = requests.get(f"{CONTROLLER_URL}/health", timeout=2)
            if r.ok:
                info = r.json()
                print(f"[LIVE] Controller OK — Defense Engine: {info.get('defense_engine', '?')}")
                return
        except Exception:
            pass
        if i % 10 == 9:
            print(f"[LIVE]   ...ακόμα αναμονή ({i+1}s)")
        time.sleep(1)
    raise RuntimeError(f"Flask controller δεν ανταποκρίνεται μετά από {timeout}s")


def start_ryu():
    print(f"[LIVE] Εκκίνηση Ryu bridge (port {RYU_PORT})...")
    bridge_script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "ryu_bridge.py")
    env = os.environ.copy()
    env["CONTROLLER_URL"] = CONTROLLER_URL

    for cmd in ["os-ken-manager", "ryu-manager"]:
        try:
            proc = subprocess.Popen(
                [cmd, "--ofp-tcp-listen-port", str(RYU_PORT), bridge_script],
                env=env,
                stdout=open("/tmp/ryu_bridge.log", "w"),
                stderr=subprocess.STDOUT,
            )
            time.sleep(4)
            if proc.poll() is None:
                print(f"[LIVE] Ryu εκκινήθηκε (PID {proc.pid}, cmd={cmd})")
                return proc
            else:
                print(f"[LIVE] {cmd} τερματίστηκε αμέσως, δοκιμάζω επόμενο...")
        except FileNotFoundError:
            continue
    raise RuntimeError("Δεν βρέθηκε os-ken-manager ή ryu-manager στο PATH")


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


# ------------------------------------------------------------------ #
#  Κύρια ροή
# ------------------------------------------------------------------ #

def main():
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.link import TCLink
    from mininet.log import setLogLevel

    setLogLevel("warning")

    # 1. Flask controller
    wait_for_flask()

    # 2. Ryu bridge
    ryu_proc = start_ryu()

    # 3. Τοπολογία
    print("[LIVE] Δημιουργία τοπολογίας Mininet (6 hosts, 1 OVS switch)...")
    net = Mininet(switch=OVSSwitch, link=TCLink, autoSetMacs=True, controller=None)
    net.addController("c0", controller=RemoteController,
                      ip="127.0.0.1", port=RYU_PORT)

    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    hosts = {}
    for i in range(1, 7):
        ip = f"10.0.0.{i}/24"
        h  = net.addHost(f"h{i}", ip=ip)
        net.addLink(h, s1, bw=10, delay="1ms")
        hosts[f"h{i}"] = h

    net.start()
    time.sleep(3)

    victim_ip   = hosts["h5"].IP()
    attacker_ip = hosts["h6"].IP()
    legit       = [hosts[f"h{i}"] for i in range(1, 5)]

    print(f"[LIVE] Τοπολογία: h1–h4 νόμιμοι | h5={victim_ip} θύμα | h6={attacker_ip} επιτιθέμενος")

    # 4. Εγγραφή hosts
    for name, h in hosts.items():
        register_host(name, h.IP())
    print("[LIVE] Hosts εγγεγραμμένοι στον Flask controller.\n")

    # ------------------------------------------------------------------ #
    #  ΦΑΣΗ 1 — Φυσιολογική κίνηση
    # ------------------------------------------------------------------ #
    print(f"{'='*60}")
    print(f"  ΦΑΣΗ 1: Φυσιολογική κίνηση ({NORMAL_PHASE}s)")
    print(f"{'='*60}")
    deadline = time.time() + NORMAL_PHASE
    tick = 0
    while time.time() < deadline:
        for h in legit:
            h.cmd(f"ping -c 3 -q {victim_ip} > /dev/null 2>&1 &")
        time.sleep(5)
        tick += 1
        elapsed = int(time.time() - (deadline - NORMAL_PHASE))
        print(f"[LIVE] Φάση 1 — {elapsed}s/{NORMAL_PHASE}s", flush=True)

    time.sleep(3)
    s1 = get_stats()
    print(f"\n[LIVE] Τέλος Φάσης 1 — ανιχνεύσεις: {s1['total_detections']} | "
          f"DROP rules: {s1['drop_rules']}\n")

    # ------------------------------------------------------------------ #
    #  ΦΑΣΗ 2 — DDoS flood
    # ------------------------------------------------------------------ #
    print(f"{'='*60}")
    print(f"  ΦΑΣΗ 2: DDoS SYN flood από h6 → h5 ({ATTACK_PHASE}s)")
    print(f"{'='*60}")

    # hping3 SYN flood από h6 (πραγματική IP, όχι spoofed)
    # χωρίς --rand-source ώστε ο controller να μπλοκάρει τη συγκεκριμένη IP
    hosts["h6"].cmd(f"hping3 --syn --flood -p 80 {victim_ip} "
                    f"> /tmp/attack_syn.log 2>&1 &")

    deadline = time.time() + ATTACK_PHASE
    while time.time() < deadline:
        # η νόμιμη κίνηση συνεχίζεται παράλληλα
        for h in legit[:2]:
            h.cmd(f"ping -c 2 -q {victim_ip} > /dev/null 2>&1 &")
        time.sleep(5)
        elapsed = int(time.time() - (deadline - ATTACK_PHASE))
        s_now = get_stats()
        print(f"[LIVE] Φάση 2 — {elapsed}s/{ATTACK_PHASE}s | "
              f"ανιχνεύσεις: {s_now['total_detections']} | "
              f"DROP: {s_now['drop_rules']}", flush=True)

    hosts["h6"].cmd("pkill hping3 2>/dev/null; true")
    time.sleep(3)

    # ------------------------------------------------------------------ #
    #  Αποτελέσματα
    # ------------------------------------------------------------------ #
    print(f"\n{'='*60}")
    print("  ΑΠΟΤΕΛΕΣΜΑΤΑ")
    print(f"{'='*60}")

    stats = get_stats()
    ft    = get_flow_table()
    topo  = get_topology()

    print(f"  Κόμβοι στο Global Network View : {stats['nodes']}")
    print(f"  Συνολικές ανιχνεύσεις ανωμαλίας: {stats['total_detections']}")
    print(f"  Ενεργοί κανόνες DROP            : {list(ft.keys())}")

    print("\n  Κατάσταση hosts:")
    for node in topo["nodes"]:
        if node["type"] == "host":
            status = node.get("status", "?")
            flag   = "🔴" if status == "blocked" else "🟢"
            print(f"    {flag} {node['ip']:12s}  →  {status}")

    print("\n  Τελευταία events:")
    for ev in stats.get("recent_log", [])[-6:]:
        print(f"    {ev['msg']}")

    blocked = attacker_ip in ft
    fp = any(h.IP() in ft for h in legit)
    print()
    print("✅  ΕΠΙΤΥΧΙΑ — επιτιθέμενος μπλοκαρίστηκε!" if blocked
          else "⚠️   Ο επιτιθέμενος ΔΕΝ μπλοκαρίστηκε (έλεγξε τα logs).")
    print("✅  Μηδέν false positives σε νόμιμους hosts." if not fp
          else "⚠️   Υπήρξε false positive σε νόμιμο host!")

    # ------------------------------------------------------------------ #
    #  Καθαρισμός
    # ------------------------------------------------------------------ #
    print("\n[LIVE] Καθαρισμός Mininet...")
    net.stop()
    ryu_proc.terminate()
    print("[LIVE] Ολοκληρώθηκε.")


if __name__ == "__main__":
    main()
