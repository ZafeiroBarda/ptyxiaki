#!/usr/bin/env python3
"""
synthetic_mode_study.py — Σύγκριση των δύο εκδοχών του συνθετικού συνόλου.

Ο γεννήτορας παράγει δύο εκδοχές:
  * προεπιλεγμένη ("clean"): καθαρές, μη επικαλυπτόμενες υπογραφές ανά κλάση.
  * --hard: προσθήκη θορύβου και ελεγχόμενης επικάλυψης μεταξύ γειτονικών
    κλάσεων (π.χ. DoS και DDoS).

Τα επίσημα αποτελέσματα του κειμένου προέρχονται από την προεπιλεγμένη εκδοχή.
Το script αυτό μετρά ρητά πόσο αισιόδοξες είναι οι τιμές αυτές σε σχέση με την
απαιτητική εκδοχή, ώστε ο αναγνώστης να γνωρίζει το εύρος.

ΔΕΝ αντικαθιστά κανένα υπάρχον αρχείο του results/: γράφει μόνο το
results/synthetic_mode_comparison.csv (+ .png).

Χρήση:  python3 ml_pipeline/synthetic_mode_study.py
"""
import os
import sys

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import f1_score, accuracy_score

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess
import generate_synthetic_dataset as gen

MODELS = {
    "Random Forest": lambda: RandomForestClassifier(
        n_estimators=200, n_jobs=-1, random_state=config.RANDOM_STATE),
    "Decision Tree": lambda: DecisionTreeClassifier(
        max_depth=20, random_state=config.RANDOM_STATE),
    "KNN": lambda: KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
    "SVM (RBF)": lambda: SVC(kernel="rbf", C=10, random_state=config.RANDOM_STATE),
    "Logistic Regression": lambda: LogisticRegression(
        max_iter=1000, random_state=config.RANDOM_STATE),
}


def run_mode(hard):
    """Ίδιο πρωτόκολλο με το train.py: group split + επιλογή στο validation."""
    df = gen.generate(hard=hard)
    feats = [c for c in config.FEATURE_COLUMNS if c in df.columns]
    data = preprocess.prepare(df, scale=True, feature_columns=feats,
                              split=config.SPLIT_STRATEGY,
                              val_size=config.VAL_SIZE)
    mode = "hard" if hard else "clean"
    rows = []
    for name, factory in MODELS.items():
        m = factory().fit(data["X_train"], data["y_train"])
        val = f1_score(data["y_val"], m.predict(data["X_val"]), average="macro")
        pred = m.predict(data["X_test"])
        rows.append({
            "mode": mode,
            "model": name,
            "val_macro_f1": round(val, 4),
            "test_accuracy": round(accuracy_score(data["y_test"], pred), 4),
            "test_macro_f1": round(f1_score(data["y_test"], pred, average="macro"), 4),
        })
        print(f"    [{mode:5s}] {name:20s} test macro-F1 = {rows[-1]['test_macro_f1']:.4f}")
    return rows


def main():
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    print("=" * 68)
    print(" ΣΥΓΚΡΙΣΗ ΤΩΝ ΔΥΟ ΕΚΔΟΧΩΝ ΤΟΥ ΣΥΝΘΕΤΙΚΟΥ ΣΥΝΟΛΟΥ")
    print("=" * 68)
    print("\n--- clean (προεπιλογή, καθαρές υπογραφές) ---")
    rows = run_mode(False)
    print("\n--- hard (θόρυβος + επικάλυψη κλάσεων) ---")
    rows += run_mode(True)

    df = pd.DataFrame(rows)
    out = os.path.join(config.RESULTS_DIR, "synthetic_mode_comparison.csv")
    df.to_csv(out, index=False)
    print("\n" + df.to_string(index=False))
    print(f"\n[OK] {out}")

    piv = df.pivot(index="model", columns="mode", values="test_macro_f1")
    ax = piv.plot(kind="bar", figsize=(9, 5), rot=0, color=["#4C72B0", "#C44E52"])
    ax.set_ylabel("test macro-F1")
    ax.set_ylim(0, 1.05)
    ax.set_title("Συνθετικό σύνολο: καθαρές υπογραφές έναντι θορύβου/επικάλυψης")
    ax.legend(title="εκδοχή")
    for c in ax.containers:
        ax.bar_label(c, fmt="%.3f", fontsize=8)
    plt.tight_layout()
    png = os.path.join(config.RESULTS_DIR, "synthetic_mode_comparison.png")
    plt.savefig(png, dpi=150)
    plt.close()
    print(f"[OK] {png}")

    rf = df[df.model == "Random Forest"].set_index("mode")
    print("\n=== ΣΥΜΠΕΡΑΣΜΑ (Random Forest) ===")
    print(f"  clean : test macro-F1 = {rf.loc['clean','test_macro_f1']:.4f}")
    print(f"  hard  : test macro-F1 = {rf.loc['hard','test_macro_f1']:.4f}")
    print(f"  πτώση : {rf.loc['clean','test_macro_f1'] - rf.loc['hard','test_macro_f1']:+.4f}")


if __name__ == "__main__":
    main()
