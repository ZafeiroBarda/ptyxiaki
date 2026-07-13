#!/usr/bin/env python3
"""
train_defense_engine.py  (Intelligence & Defense Plane — live)
--------------------------------------------------------------
Εκπαιδεύει το Isolation Forest που τρέχει ΖΩΝΤΑΝΑ μέσα στον Flask controller.

Σε αντίθεση με το offline isolation_forest_detector.py (που δουλεύει στα 24
πλήρη features), εδώ το μοντέλο εκπαιδεύεται στα 8 ΣΥΓΚΕΝΤΡΩΤΙΚΑ features ανά
πηγή IP (config.LIVE_FEATURE_COLUMNS) — αυτά ακριβώς που στέλνει το Data Plane
ως τηλεμετρία (packet rate, byte rate κ.λπ.).

ΚΡΙΣΙΜΟ (unsupervised): εκπαιδεύεται ΜΟΝΟ σε φυσιολογική κίνηση, χωρίς ετικέτες.

Έξοδος:
  models/isolation_forest_live.pkl
  models/isolation_forest_live_scaler.pkl
"""

import os
import sys
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
sys.path.append(os.path.join(BASE, "controller"))
import config


def gen_normal_aggregate(n=20000, seed=config.RANDOM_STATE):
    """Συγκεντρωτικά features ΜΟΝΟ φυσιολογικής κίνησης (όπως θα τα δει ο controller).

    Οι κατανομές αντικατοπτρίζουν ό,τι πραγματικά παράγει η per-flow τηλεμετρία
    (ovs-ofctl dump-flows / OFPFlowStats), όπως επιβεβαιώθηκε σε ζωντανή εκτέλεση:

      * Η νόμιμη κίνηση καλύπτει ΔΥΟ καθεστώτα και το μοντέλο πρέπει να δέχεται
        και τα δύο: (α) διαδραστική/ελέγχου (ping, DNS, ACK) με ΜΙΚΡΑ πακέτα
        (~60-200 bytes) και ΛΙΓΑ πακέτα ανά παράθυρο, και (β) μαζική μεταφορά
        (download/upload) με μεγάλα πακέτα και πολλά πακέτα.
      * Οι ροές μπορεί να είναι ΜΑΚΡΟΒΙΕΣ: η διάρκεια φράσσεται στα 60s στην
        τηλεμετρία (flow_telemetry.DURATION_CAP), οπότε εδώ καλύπτεται 0.5-60s.
        (Η προηγούμενη έκδοση κάλυπτε μόνο 0.5-15s και σήμαινε λανθασμένα κάθε
        μακρόβια ροή ping ως ανωμαλία — false positive που εντοπίστηκε live.)

    Οι επιθέσεις παραμένουν διακριτές μέσω ΑΛΛΩΝ χαρακτηριστικών, όχι της
    διάρκειας: ένα flood έχει ΤΕΡΑΣΤΙΟ πλήθος πακέτων ανά ροή (πολύ πάνω από
    κάθε νόμιμο παράθυρο), ενώ ένα scan έχει ΠΟΛΛΕΣ σύντομες ροές (υψηλό
    flow_count και short_flow_ratio).
    """
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        flow_count = int(rng.integers(1, 11))                  # 1..10 προορισμοί
        avg_pkts = float(rng.uniform(5, 1500))                 # λίγα (ping) έως μέτριος όγκος
        avg_pkt_size = float(rng.uniform(60, 1400))            # ΜΙΚΡΑ (ping/ACK ~60) έως μεγάλα
        avg_bytes = avg_pkts * avg_pkt_size
        avg_dur = float(rng.uniform(0.5, 60.0))                # ΕΩΣ 60s (μακρόβιες ροές)
        total_packets = flow_count * avg_pkts
        total_bytes = flow_count * avg_bytes
        short_ratio = float(np.clip(rng.normal(0.06, 0.06), 0, 0.3))  # ΛΙΓΕΣ σύντομες
        rows.append([flow_count, total_packets, total_bytes, avg_pkts,
                     avg_bytes, avg_dur, avg_pkt_size, short_ratio])
    return np.array(rows, dtype=float)


def main():
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    X_normal = gen_normal_aggregate()
    print(f"[*] Εκπαίδευση Isolation Forest (live) σε {len(X_normal)} φυσιολογικά δείγματα...")

    scaler = StandardScaler().fit(X_normal)
    Xs = scaler.transform(X_normal)

    # Βελτιστοποιημένες υπερπαράμετροι (από ml_pipeline/hyperparameter_tuning.py):
    # περισσότερα δέντρα & μεγαλύτερο max_samples για σταθερότερη εκτίμηση.
    # Χαμηλό contamination ώστε το live σύστημα να ΜΗΝ παράγει false positives.
    iso = IsolationForest(
        n_estimators=300,        # ↑ από 150 (πιο σταθερό anomaly score)
        max_samples=512,         # μεγαλύτερο δείγμα ανά δέντρο
        max_features=0.75,       # 6/8 features ανά δέντρο
        contamination=0.03,      # συντηρητικό κατώφλι -> λίγα false positives
        random_state=config.RANDOM_STATE, n_jobs=-1,
    )
    iso.fit(Xs)

    joblib.dump(iso, os.path.join(config.MODELS_DIR, "isolation_forest_live.pkl"))
    joblib.dump(scaler, os.path.join(config.MODELS_DIR, "isolation_forest_live_scaler.pkl"))
    print("[OK] models/isolation_forest_live.pkl, isolation_forest_live_scaler.pkl")

    # γρήγορος έλεγχος λογικής σε ένα attack-like δείγμα
    attack = np.array([[120, 300, 9600, 2.5, 80, 0.5, 32, 0.85]])
    normal = np.array([[4, 160, 96000, 40, 24000, 8, 600, 0.1]])
    for name, x in [("attack-like", attack), ("normal-like", normal)]:
        pred = iso.predict(scaler.transform(x))[0]
        print(f"    {name}: {'ΑΝΩΜΑΛΙΑ' if pred == -1 else 'φυσιολογικό'}")


if __name__ == "__main__":
    main()
