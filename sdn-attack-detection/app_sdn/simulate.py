#!/usr/bin/env python3
"""
simulate.py  (ολοκληρωμένη προσομοίωση application-level SDN)
------------------------------------------------------------
Τρέχει ΟΛΟΚΛΗΡΟ το σύστημα end-to-end, ΧΩΡΙΣ Docker/Mininet, για επίδειξη &
έλεγχο της αρχιτεκτονικής της διπλωματικής:

  Control Plane (Flask controller)  +  Data Plane (Switch)  +  Hosts (traffic)
  +  Intelligence/Defense Plane (Isolation Forest)

Σενάριο:
  1. Ξεκινά ο controller (σε background thread).
  2. Εγγράφεται ένας switch και κάποιοι hosts.
  3. Παράγεται ΦΥΣΙΟΛΟΓΙΚΗ κίνηση -> ο controller δεν μπλοκάρει κανέναν.
  4. Ένας host (10.0.0.6) γίνεται ΕΠΙΤΙΘΕΜΕΝΟΣ (DDoS flood) ->
     ο Defense Engine ανιχνεύει ανωμαλία και ο controller εγκαθιστά DROP rule.
  5. Εκτυπώνεται το flow table, τα stats και το ιστορικό συμβάντων.

Χρήση:
  python3 app_sdn/simulate.py
"""

import os
import sys
import time
import threading
import random
import requests

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "app_sdn"))

CONTROLLER_URL = "http://127.0.0.1:9000"


def start_controller():
    """Ξεκινά τον Flask controller σε background thread."""
    import controller as ctrl
    t = threading.Thread(
        target=lambda: ctrl.app.run(host="127.0.0.1", port=9000,
                                    threaded=True, use_reloader=False),
        daemon=True)
    t.start()
    # περίμενε να σηκωθεί
    for _ in range(30):
        try:
            if requests.get(f"{CONTROLLER_URL}/health", timeout=1).ok:
                return
        except Exception:
            time.sleep(0.3)
    raise RuntimeError("Ο controller δεν ξεκίνησε.")


def normal_packet(switch, src):
    """Μία φυσιολογική 'συνεδρία': αρκετά πακέτα λογικού μεγέθους (όχι σύντομη ροή)."""
    for _ in range(random.randint(8, 20)):
        switch.ingest(src, "10.0.0.5", random.randint(400, 1200))


def attack_burst(switch, src, n=200):
    """
    Flow Table Exhaustion / flood: πολλές ΜΙΚΡΟ-ροές προς πολλούς προορισμούς,
    με μικροσκοπικά πακέτα. Σκοπός: γέμισμα του flow table & κατανάλωση πόρων.
    Υπογραφή: μεγάλο flow_count + υψηλό short_ratio + μικρό avg_pkt_size.
    """
    for _ in range(n):
        dst = f"10.0.0.{random.randint(10, 250)}"   # πολλοί διαφορετικοί προορισμοί
        switch.ingest(src, dst, random.randint(40, 100))  # μικροσκοπικά πακέτα


def main():
    print("=" * 64)
    print(" ΠΡΟΣΟΜΟΙΩΣΗ APPLICATION-LEVEL SDN (Control+Data+Defense Plane)")
    print("=" * 64)

    start_controller()
    health = requests.get(f"{CONTROLLER_URL}/health").json()
    print(f"[OK] Controller ενεργός. Defense Engine: {health['defense_engine']}\n")

    from switch import Switch
    sw = Switch("s1", CONTROLLER_URL, poll_interval=2)
    sw.register()

    # εγγραφή hosts
    legit = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    attacker = "10.0.0.6"
    for ip in legit + [attacker, "10.0.0.5"]:
        requests.post(f"{CONTROLLER_URL}/register",
                      json={"node_id": f"host-{ip}", "type": "host", "ip": ip})

    sw.start_polling()

    # --- Φάση 1: μόνο φυσιολογική κίνηση ---
    print("--- ΦΑΣΗ 1: Φυσιολογική κίνηση (8s) ---")
    end = time.time() + 8
    while time.time() < end:
        for ip in legit:
            for _ in range(random.randint(1, 4)):
                normal_packet(sw, ip)
        time.sleep(0.4)
    time.sleep(2)
    stats = requests.get(f"{CONTROLLER_URL}/stats").json()
    print(f"    Ανιχνεύσεις μέχρι τώρα: {stats['total_detections']} "
          f"| DROP rules: {stats['drop_rules']}\n")

    # --- Φάση 2: ο 10.0.0.6 επιτίθεται ---
    print("--- ΦΑΣΗ 2: Ο 10.0.0.6 ξεκινά DDoS flood (8s) ---")
    end = time.time() + 8
    while time.time() < end:
        for ip in legit:                 # συνεχίζεται και η νόμιμη κίνηση
            normal_packet(sw, ip)
        attack_burst(sw, attacker, n=120)  # ο επιτιθέμενος πλημμυρίζει
        time.sleep(0.4)
    time.sleep(2)

    # --- Αποτελέσματα ---
    print()
    stats = requests.get(f"{CONTROLLER_URL}/stats").json()
    ft = requests.get(f"{CONTROLLER_URL}/flow_table").json()
    topo = requests.get(f"{CONTROLLER_URL}/topology").json()

    print("=" * 64)
    print(" ΑΠΟΤΕΛΕΣΜΑΤΑ")
    print("=" * 64)
    print(f"Κόμβοι στο Global Network View: {stats['nodes']}")
    print(f"Ενεργές ροές: {stats['active_flows']}")
    print(f"Συνολικές ανιχνεύσεις ανωμαλίας: {stats['total_detections']}")
    print(f"Ενεργοί κανόνες DROP: {list(ft.keys())}")
    print("\nΚατάσταση κόμβων:")
    for node in topo["nodes"]:
        if node["type"] == "host":
            print(f"  {node['ip']:12s} -> {node['status']}")

    print("\nΙστορικό συμβάντων (τελευταία):")
    for e in stats["recent_log"]:
        print(f"  {e['msg']}")

    # έλεγχος επιτυχίας
    blocked = attacker in ft
    print("\n" + ("✅ ΕΠΙΤΥΧΙΑ: ο επιτιθέμενος μπλοκαρίστηκε."
                  if blocked else "❌ Ο επιτιθέμενος ΔΕΝ μπλοκαρίστηκε."))
    fp = any(ip in ft for ip in legit)
    print("✅ Καμία λανθασμένη απόρριψη νόμιμου host." if not fp
          else "⚠️ Υπήρξε false positive σε νόμιμο host.")


if __name__ == "__main__":
    main()
