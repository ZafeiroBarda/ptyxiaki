#!/usr/bin/env python3
"""
isolation_forest_detector.py  (Intelligence & Defense Plane — Isolation Forest)
-------------------------------------------------------------------------------
Υλοποιεί την προσέγγιση ΜΗ ΕΠΙΒΛΕΠΟΜΕΝΗΣ ανίχνευσης ανωμαλιών με τον αλγόριθμο
**Isolation Forest**, όπως ορίζεται στην αρχιτεκτονική της διπλωματικής
(Intelligence & Defense Plane).

Βασική ιδέα (όπως στο PDF):
  - Το μοντέλο εκπαιδεύεται ΜΟΝΟ σε ΦΥΣΙΟΛΟΓΙΚΗ κίνηση, ΧΩΡΙΣ ετικέτες επιθέσεων.
  - Η συνάρτηση απόφασης f(x): όταν f(x) < 0 το δείγμα θεωρείται outlier (ύποπτο),
    γεγονός που ενεργοποιεί την αντιμετώπιση (drop) από τον Controller.
  - Έτσι δεν απαιτούνται προ-ταξινομημένα (labeled) δεδομένα επιθέσεων.

Γιατί ταιριάζει με το υπόλοιπο project:
  - Χρησιμοποιεί τα ΙΔΙΑ feature vectors (packet rate, byte rate κ.λπ.).
  - Συγκρίνεται με την επιβλεπόμενη προσέγγιση (Random Forest) ως baseline.

Χρήση:
  python3 ml_pipeline/isolation_forest_detector.py
  python3 ml_pipeline/isolation_forest_detector.py --insdn
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score, roc_auc_score,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess

sns.set_theme(style="whitegrid")


def load_binary(use_insdn=False):
    """
    Φορτώνει τα δεδομένα και τα μετατρέπει σε ΔΥΑΔΙΚΟ πρόβλημα:
      Normal (φυσιολογικό)  vs  Anomaly (οποιαδήποτε επίθεση).
    Επιστρέφει DataFrame με στήλη 'is_attack' (0=Normal, 1=Attack).
    """
    df = preprocess.load_insdn() if use_insdn else preprocess.load_synthetic()
    feature_columns = [c for c in config.FEATURE_COLUMNS if c in df.columns]
    X = df[feature_columns].astype(float).values
    y = (df[config.LABEL_COL] != "Normal").astype(int).values  # 1 = επίθεση
    return X, y, feature_columns


def log_transform(X):
    """Λογαριθμικός μετασχηματισμός για τα ασύμμετρα (log-normal) network features.

    ΚΡΙΣΙΜΟ για το Isolation Forest σε ΠΡΑΓΜΑΤΙΚΑ δεδομένα: ανεβάζει το ROC AUC
    από ~0.70 σε ~0.93, καθώς τα χαρακτηριστικά ροής (διάρκεια, bytes, ρυθμοί)
    εκτείνονται σε πολλές τάξεις μεγέθους.
    """
    return np.log1p(np.clip(X, 0, None))


def main(use_insdn=False):
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    os.makedirs(config.MODELS_DIR, exist_ok=True)

    X, y, feature_columns = load_binary(use_insdn)
    print(f"[*] Σύνολο δειγμάτων: {len(X)} | Φυσιολογικά: {(y==0).sum()} | "
          f"Επιθέσεις: {(y==1).sum()}")

    # --- ΚΡΙΣΙΜΟ: εκπαίδευση ΜΟΝΟ σε φυσιολογική κίνηση (unsupervised) ---
    X_normal = X[y == 0]
    # κρατάμε ένα μέρος της φυσιολογικής για εκπαίδευση, τα υπόλοιπα + επιθέσεις για test
    n_train = int(len(X_normal) * 0.6)
    rng = np.random.default_rng(config.RANDOM_STATE)
    perm = rng.permutation(len(X_normal))
    train_idx, test_normal_idx = perm[:n_train], perm[n_train:]

    X_train = X_normal[train_idx]
    # test set: υπόλοιπα φυσιολογικά + ΟΛΕΣ οι επιθέσεις
    X_test = np.vstack([X_normal[test_normal_idx], X[y == 1]])
    y_test = np.concatenate([np.zeros(len(test_normal_idx)), np.ones((y == 1).sum())])

    # ΛΟΓΑΡΙΘΜΙΚΟΣ μετασχηματισμός (κρίσιμος για ασύμμετρα network features)
    X_train = log_transform(X_train)
    X_test = log_transform(X_test)

    # κανονικοποίηση (fit μόνο στα φυσιολογικά train)
    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_test_s = scaler.transform(X_test)

    # Βελτιστοποιημένες υπερπαράμετροι (από hyperparameter_tuning.py: ROC AUC 0.9936)
    # contamination=0.05: ισορροπία μεταξύ recall επιθέσεων & λίγων false positives
    print("[*] Εκπαίδευση Isolation Forest ΜΟΝΟ σε φυσιολογική κίνηση (tuned params)...")
    iso = IsolationForest(
        n_estimators=300, max_samples=512, contamination=0.05, max_features=0.5,
        random_state=config.RANDOM_STATE, n_jobs=-1,
    )
    iso.fit(X_train_s)

    # --- Πρόβλεψη: f(x) < 0 => ανωμαλία (επίθεση) ---
    raw_pred = iso.predict(X_test_s)          # +1 = inlier, -1 = outlier
    y_pred = (raw_pred == -1).astype(int)     # 1 = επίθεση
    scores = -iso.decision_function(X_test_s)  # μεγαλύτερο = πιο ανώμαλο

    # --- Αξιολόγηση ---
    print("\n" + "=" * 60)
    print("ISOLATION FOREST — ΑΞΙΟΛΟΓΗΣΗ (Normal vs Attack)")
    print("=" * 60)
    print(classification_report(y_test, y_pred,
                                target_names=["Normal", "Attack"], digits=4))
    auc = roc_auc_score(y_test, scores)
    print(f"ROC AUC (decision function): {auc:.4f}")

    metrics = {
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "roc_auc": auc,
    }
    pd.DataFrame([metrics]).to_csv(
        os.path.join(config.RESULTS_DIR, "isolation_forest_metrics.csv"), index=False)

    # --- Γράφημα 1: confusion matrix ---
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6.5, 5.5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Oranges",
                xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"])
    plt.title("Isolation Forest — Confusion Matrix")
    plt.ylabel("Πραγματική"); plt.xlabel("Προβλεπόμενη")
    plt.tight_layout()
    plt.savefig(os.path.join(config.RESULTS_DIR, "isolation_forest_cm.png"), dpi=150)
    plt.close()
    print(f"[OK] results/isolation_forest_cm.png")

    # --- Γράφημα 2: κατανομή anomaly score ---
    plt.figure(figsize=(10, 5))
    plt.hist(scores[y_test == 0], bins=60, alpha=0.6, label="Φυσιολογική", color="green", density=True)
    plt.hist(scores[y_test == 1], bins=60, alpha=0.6, label="Επίθεση", color="red", density=True)
    plt.axvline(0, color="black", linestyle="--", label="Κατώφλι f(x)=0")
    plt.title("Κατανομή Anomaly Score (Isolation Forest)")
    plt.xlabel("Anomaly score (μεγαλύτερο = πιο ύποπτο)"); plt.ylabel("Πυκνότητα")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(config.RESULTS_DIR, "isolation_forest_scores.png"), dpi=150)
    plt.close()
    print(f"[OK] results/isolation_forest_scores.png")

    # --- Αποθήκευση μοντέλου (Defense Engine artifact) ---
    joblib.dump(iso, os.path.join(config.MODELS_DIR, "isolation_forest.pkl"))
    joblib.dump(scaler, os.path.join(config.MODELS_DIR, "isolation_forest_scaler.pkl"))
    print("[OK] models/isolation_forest.pkl, isolation_forest_scaler.pkl")
    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Isolation Forest (unsupervised) έτοιμο.")
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--insdn", action="store_true")
    args = parser.parse_args()
    main(use_insdn=args.insdn)
