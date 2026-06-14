#!/usr/bin/env python3
"""
offline_replay.py  (ΜΕΘΟΔΟΣ A — προσομοίωση ΧΩΡΙΣ Mininet, τρέχει παντού)
------------------------------------------------------------------------
Προσομοιώνει τη ροή του live SDN controller σε καθαρή Python, ΧΩΡΙΣ να
χρειάζεται Mininet/Linux. Χρήσιμο για:
  - να δοκιμάσεις/δείξεις τη λογική ανίχνευσης+mitigation σε Windows/Mac,
  - να παράγεις ένα demo timeline για τη διπλωματική πριν στήσεις το VM.

Τι κάνει:
  - Σε κάθε "παράθυρο" δειγματοληψίας δημιουργεί flow-stats για πολλούς hosts.
  - Οι περισσότεροι hosts είναι νόμιμοι· σε ορισμένα παράθυρα ένας host γίνεται
    επιτιθέμενος (flood -> πολλές σύντομες ροές).
  - Τρέφει τα στατιστικά στην ΙΔΙΑ μηχανή ανίχνευσης (detection_engine).
  - Όταν ανιχνευτεί επίθεση -> "εγκαθιστά" εικονική drop-rule (mitigation) και
    σταματά να μετράει κίνηση από εκείνη την πηγή για κάποια παράθυρα.
  - Παράγει log + timeline γράφημα results/offline_replay_timeline.png.

Χρήση:
  python3 controller/offline_replay.py
  python3 controller/offline_replay.py --windows 40 --seed 7
"""

import os
import sys
import argparse
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config
import detection_engine as engine


def _normal_flows(rng):
    """Flow-stats μιας νόμιμης πηγής σε ένα παράθυρο."""
    n = max(1, int(rng.normal(4, 2)))
    flows = []
    for _ in range(n):
        pkts = max(1, int(rng.normal(40, 20)))
        byts = pkts * max(60, int(rng.normal(600, 200)))
        dur = max(0.1, rng.normal(8, 4))
        flows.append((pkts, byts, dur))
    return flows


def _attack_flows(rng):
    """Flow-stats μιας επιτιθέμενης πηγής (flood -> πολλές σύντομες ροές)."""
    n = max(10, int(rng.normal(120, 50)))
    flows = []
    for _ in range(n):
        pkts = max(1, int(rng.normal(2.5, 1.5)))
        byts = pkts * max(40, int(rng.normal(80, 30)))
        dur = max(0.01, rng.normal(0.5, 0.4))
        flows.append((pkts, byts, dur))
    return flows


def run(windows=30, seed=config.RANDOM_STATE, attacker_active=None):
    rng = np.random.default_rng(seed)
    model, scaler = engine.load_live_model()
    if model is not None:
        print("[*] Χρήση εκπαιδευμένου live μοντέλου.")
    else:
        print("[*] Δεν βρέθηκε μοντέλο — χρήση heuristic fallback. "
              "(Τρέξε controller/train_live_model.py για ML.)")

    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    attacker = "10.0.0.6"

    # σε ποια παράθυρα είναι ενεργή η επίθεση
    if attacker_active is None:
        attacker_active = set(range(int(windows * 0.4), int(windows * 0.75)))

    blocked_until = {}     # src -> παράθυρο λήξης μπλοκαρίσματος
    BLOCK_WINDOWS = 4

    timeline = []          # (window, attacker_present, detected, blocked)
    log_lines = []

    for w in range(windows):
        # καθάρισε λήξαντα μπλοκαρίσματα
        for ip in list(blocked_until):
            if w >= blocked_until[ip]:
                del blocked_until[ip]
                log_lines.append(f"[w{w:02d}] [MITIGATE] Άρση μπλοκαρίσματος {ip}")

        attacker_present = w in attacker_active
        detected_this_window = False

        # --- νόμιμοι hosts ---
        for h in hosts:
            if h in blocked_until:
                continue
            feats = engine.aggregate_features(_normal_flows(rng))
            verdict = engine.classify(feats, model, scaler)
            if verdict == "Attack":   # false positive
                log_lines.append(f"[w{w:02d}] [FP!] Λάθος ανίχνευση σε νόμιμο {h}")

        # --- επιτιθέμενος ---
        if attacker_present and attacker not in blocked_until:
            feats = engine.aggregate_features(_attack_flows(rng))
            verdict = engine.classify(feats, model, scaler)
            if verdict == "Attack":
                detected_this_window = True
                blocked_until[attacker] = w + BLOCK_WINDOWS
                log_lines.append(
                    f"[w{w:02d}] [DETECT] ΕΠΙΘΕΣΗ από {attacker} "
                    f"(flows={int(feats[0])}, short_ratio={feats[7]:.2f}) "
                    f"-> [MITIGATE] DROP-rule για {BLOCK_WINDOWS} παράθυρα")
            else:
                log_lines.append(f"[w{w:02d}] [MISS] Επίθεση ΔΕΝ ανιχνεύθηκε!")

        timeline.append((w, int(attacker_present),
                         int(detected_this_window),
                         int(attacker in blocked_until)))

    return timeline, log_lines


def plot_timeline(timeline, out_path):
    w = [t[0] for t in timeline]
    present = [t[1] for t in timeline]
    detected = [t[2] for t in timeline]
    blocked = [t[3] for t in timeline]

    plt.figure(figsize=(13, 4.5))
    plt.fill_between(w, present, step="mid", alpha=0.25, color="red",
                     label="Επίθεση ενεργή")
    plt.fill_between(w, blocked, step="mid", alpha=0.25, color="green",
                     label="Πηγή μπλοκαρισμένη (mitigation)")
    det_x = [w[i] for i in range(len(w)) if detected[i]]
    plt.scatter(det_x, [1.05] * len(det_x), marker="v", color="black",
                s=60, zorder=5, label="Στιγμή ανίχνευσης")
    plt.yticks([0, 1], ["", ""])
    plt.ylim(-0.1, 1.2)
    plt.xlabel("Παράθυρο δειγματοληψίας (κάθε %ds)" % config.POLL_INTERVAL)
    plt.title("Offline προσομοίωση: ανίχνευση & αντιμετώπιση επίθεσης σε πραγματικό χρόνο")
    plt.legend(loc="upper right", ncol=3, fontsize=9)
    plt.tight_layout(); plt.savefig(out_path, dpi=150); plt.close()
    print(f"[OK] {out_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows", type=int, default=30)
    parser.add_argument("--seed", type=int, default=config.RANDOM_STATE)
    args = parser.parse_args()

    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    timeline, log_lines = run(windows=args.windows, seed=args.seed)

    print("\n--- ΗΜΕΡΟΛΟΓΙΟ ΣΥΜΒΑΝΤΩΝ ---")
    for line in log_lines:
        print(line)

    # μετρικές demo
    total_attack_windows = sum(t[1] for t in timeline)
    detected_windows = sum(t[2] for t in timeline)
    print(f"\nΠαράθυρα με επίθεση: {total_attack_windows} | "
          f"Παράθυρα με ανίχνευση: {detected_windows}")

    plot_timeline(timeline, os.path.join(config.RESULTS_DIR, "offline_replay_timeline.png"))
    print("[ΟΛΟΚΛΗΡΩΘΗΚΕ] Offline demo στο results/.")


if __name__ == "__main__":
    main()
