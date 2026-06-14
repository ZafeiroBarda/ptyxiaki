#!/usr/bin/env python3
"""
train_live_model.py  (ΜΕΘΟΔΟΣ A — live σύστημα)
-----------------------------------------------
Εκπαιδεύει το ΕΛΑΦΡΥ μοντέλο που τρέχει live μέσα στον Ryu controller.

Γιατί ξεχωριστό μοντέλο;
  Ο controller, μέσω OpenFlow flow-stats, μπορεί να υπολογίσει μόνο aggregate
  χαρακτηριστικά ανά πηγή IP (config.LIVE_FEATURE_COLUMNS) — όχι τα 24 πλούσια
  CICFlowMeter features. Άρα το live μοντέλο εκπαιδεύεται ΑΚΡΙΒΩΣ στα features
  που ο controller μπορεί να εξάγει σε πραγματικό χρόνο.

Πηγή δεδομένων:
  (α) Συνθετικά aggregate δεδομένα (παρακάτω) — για άμεση λειτουργία.
  (β) Το δικό σου CSV από simulation/collect_flow_stats.py — βάλε --collected.

Έξοδος:
  models/live_model.pkl, models/live_scaler.pkl
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml_pipeline"))
import config


def _gen_live_synthetic(n=12000, seed=config.RANDOM_STATE):
    """
    Δημιουργεί συνθετικά aggregate δεδομένα ανά πηγή IP, με τη ΛΟΓΙΚΗ που θα
    υπολόγιζε ο controller:
      - Normal: λίγες ροές, πολλά πακέτα/ροή, μεγαλύτερη διάρκεια.
      - Attack: πολλές σύντομες ροές, λίγα πακέτα/ροή (flood/scan).
    """
    rng = np.random.default_rng(seed)
    rows = []
    half = n // 2

    # --- Normal ---
    for _ in range(half):
        flow_count = max(1, int(rng.normal(4, 2)))
        avg_pkts = max(1.0, rng.normal(40, 20))
        avg_bytes = max(60.0, rng.normal(40 * 600, 8000))
        avg_dur = max(0.1, rng.normal(8.0, 4.0))
        total_packets = flow_count * avg_pkts
        total_bytes = flow_count * avg_bytes
        avg_pkt_size = avg_bytes / avg_pkts
        short_ratio = np.clip(rng.normal(0.1, 0.08), 0, 1)
        rows.append([flow_count, total_packets, total_bytes, avg_pkts,
                     avg_bytes, avg_dur, avg_pkt_size, short_ratio, "Normal"])

    # --- Attack (DDoS/DoS/Probe flood-like) ---
    for _ in range(n - half):
        flow_count = max(10, int(rng.normal(120, 60)))     # ΠΟΛΛΕΣ ροές
        avg_pkts = max(1.0, rng.normal(2.5, 1.5))          # λίγα πακέτα/ροή
        avg_bytes = max(40.0, rng.normal(2.5 * 80, 60))
        avg_dur = max(0.01, rng.normal(0.5, 0.4))          # σύντομες
        total_packets = flow_count * avg_pkts
        total_bytes = flow_count * avg_bytes
        avg_pkt_size = avg_bytes / avg_pkts
        short_ratio = np.clip(rng.normal(0.85, 0.12), 0, 1)  # πολλές σύντομες
        rows.append([flow_count, total_packets, total_bytes, avg_pkts,
                     avg_bytes, avg_dur, avg_pkt_size, short_ratio, "Attack"])

    cols = config.LIVE_FEATURE_COLUMNS + ["Label"]
    df = pd.DataFrame(rows, columns=cols)
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main(use_collected=False):
    os.makedirs(config.MODELS_DIR, exist_ok=True)

    if use_collected:
        path = os.path.join(config.DATA_DIR, "collected_live_flows.csv")
        print(f"[*] Χρήση συλλεγμένων δεδομένων: {path}")
        df = pd.read_csv(path)
    else:
        print("[*] Δημιουργία συνθετικών aggregate δεδομένων για live μοντέλο...")
        df = _gen_live_synthetic()

    X = df[config.LIVE_FEATURE_COLUMNS].astype(float).values
    y = (df["Label"] == "Attack").astype(int).values  # 1 = Attack, 0 = Normal

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=config.TEST_SIZE, random_state=config.RANDOM_STATE, stratify=y)

    scaler = StandardScaler().fit(X_tr)
    X_tr, X_te = scaler.transform(X_tr), scaler.transform(X_te)

    model = RandomForestClassifier(n_estimators=80, random_state=config.RANDOM_STATE, n_jobs=-1)
    model.fit(X_tr, y_tr)

    print("\n[Αξιολόγηση live μοντέλου]")
    print(classification_report(y_te, model.predict(X_te),
                                target_names=["Normal", "Attack"], digits=4))

    joblib.dump(model, os.path.join(config.MODELS_DIR, "live_model.pkl"))
    joblib.dump(scaler, os.path.join(config.MODELS_DIR, "live_scaler.pkl"))
    print(f"[OK] Αποθηκεύτηκαν: models/live_model.pkl, models/live_scaler.pkl")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--collected", action="store_true",
                        help="Χρήση δικού σου CSV από collect_flow_stats.py")
    args = parser.parse_args()
    main(use_collected=args.collected)
