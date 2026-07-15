#!/usr/bin/env python3
"""
leakage_study.py — Ποσοτικοποίηση της διαρροής μέσω διπλότυπων ροών.

Το InSDN περιέχει μεγάλο ποσοστό ακριβών διπλότυπων σε επίπεδο διανύσματος
χαρακτηριστικών, κάτι εγγενές στις επιθέσεις πλημμύρας: χιλιάδες πακέτα SYN
παράγουν ροές με πανομοιότυπα στατιστικά. Με τυχαίο διαχωρισμό, όμοια
διανύσματα καταλήγουν ΚΑΙ στο train ΚΑΙ στο test, οπότε το μοντέλο μπορεί να
απομνημονεύσει αντί να γενικεύσει.

Το script μετρά:
  1. Το ποσοστό διπλότυπων ανά κλάση.
  2. Πόσα διανύσματα του test set έχουν ακριβές αντίγραφο στο train set,
     για τυχαίο διαχωρισμό και για group-aware (leakage-resistant) διαχωρισμό.
  3. Την απόδοση των μοντέλων και στις δύο στρατηγικές, ώστε να φανεί πόσο από
     τη μετρούμενη ακρίβεια οφείλεται στη διαρροή.

Χρήση:  python3 ml_pipeline/leakage_study.py            # συνθετικό
        python3 ml_pipeline/leakage_study.py --insdn    # InSDN
Έξοδοι: results/leakage_duplicates.csv
        results/leakage_split_comparison.csv
        results/leakage_split_comparison.png
"""
import os
import sys
import argparse

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import f1_score, accuracy_score

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess

# Και τα έξι μοντέλα αξιολογούνται ΚΑΙ με τυχαίο ΚΑΙ με group-aware διαχωρισμό, ώστε
# η απάντηση στο RQ1 να μη μειγνύει πρωτόκολλα: για κάθε μοντέλο φαίνεται ξεχωριστά
# η τιμή στον τυχαίο διαχωρισμό (με διαρροή διπλότυπων) και στον group-aware.
# Το SVM (RBF) είναι O(n^2) στο InSDN (~230k δείγματα train)· παραλείπεται όταν
# οριστεί --no-svm, χωρίς να επηρεάζεται η κύρια σύγκριση (train.py --insdn).
def build_models(include_svm=True):
    m = {
        "Random Forest": lambda: RandomForestClassifier(
            n_estimators=200, n_jobs=-1, random_state=config.RANDOM_STATE),
        "Decision Tree": lambda: DecisionTreeClassifier(
            max_depth=20, random_state=config.RANDOM_STATE),
        "KNN": lambda: KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "MLP (Neural Net)": lambda: MLPClassifier(
            hidden_layer_sizes=(64, 32), max_iter=300,
            random_state=config.RANDOM_STATE),
        "Logistic Regression": lambda: LogisticRegression(
            max_iter=1000, random_state=config.RANDOM_STATE),
    }
    if include_svm:
        m["SVM (RBF)"] = lambda: SVC(
            kernel="rbf", C=10, gamma="scale", random_state=config.RANDOM_STATE)
    return m


MODELS = build_models()


def duplicate_report(df, feats):
    rows = []
    for cls, g in df.groupby(config.LABEL_COL):
        n = len(g)
        uniq = len(g[feats].drop_duplicates())
        rows.append({
            "class": cls,
            "samples": n,
            "unique_vectors": uniq,
            "duplicate_pct": round(100.0 * (n - uniq) / n, 1) if n else 0.0,
        })
    total = len(df)
    uniq_all = len(df[feats].drop_duplicates())
    rows.append({
        "class": "ΣΥΝΟΛΟ", "samples": total, "unique_vectors": uniq_all,
        "duplicate_pct": round(100.0 * (total - uniq_all) / total, 1),
    })
    return pd.DataFrame(rows).sort_values("samples", ascending=False)


def leaked_fraction(X_train, X_test):
    """Ποσοστό δειγμάτων του test που έχουν ΑΚΡΙΒΕΣ αντίγραφο στο train."""
    tr = set(preprocess.feature_hash_groups(X_train))
    te = preprocess.feature_hash_groups(X_test)
    return 100.0 * np.mean([h in tr for h in te])


def evaluate(df, feats, split):
    X = df[feats].astype(float).values
    y = LabelEncoder().fit_transform(df[config.LABEL_COL].values)

    if split == "group":
        tr, te, _ = preprocess.group_train_test_split(
            X, y, config.TEST_SIZE, config.RANDOM_STATE)
    else:
        from sklearn.model_selection import train_test_split
        idx = np.arange(len(y))
        tr, te = train_test_split(idx, test_size=config.TEST_SIZE,
                                  random_state=config.RANDOM_STATE, stratify=y)

    Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]
    leak = leaked_fraction(Xtr, Xte)

    sc = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = sc.transform(Xtr), sc.transform(Xte)

    out = []
    for name, factory in MODELS.items():
        m = factory().fit(Xtr_s, ytr)
        pred = m.predict(Xte_s)
        out.append({
            "split": split,
            "model": name,
            "accuracy": round(accuracy_score(yte, pred), 4),
            "macro_f1": round(f1_score(yte, pred, average="macro"), 4),
            "test_leaked_pct": round(leak, 1),
        })
        print(f"    [{split:6s}] {name:20s} acc={out[-1]['accuracy']:.4f} "
              f"macroF1={out[-1]['macro_f1']:.4f}")
    return out


def main(use_insdn=False):
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    df = preprocess.load_insdn() if use_insdn else preprocess.load_synthetic()
    feats = [c for c in config.FEATURE_COLUMNS if c in df.columns]
    tag = "InSDN" if use_insdn else "συνθετικό"

    print("=" * 68)
    print(f" ΜΕΛΕΤΗ ΔΙΑΡΡΟΗΣ ΜΕΣΩ ΔΙΠΛΟΤΥΠΩΝ — {tag} ({len(df)} ροές)")
    print("=" * 68)

    dup = duplicate_report(df, feats)
    print("\n--- Διπλότυπα ανά κλάση ---")
    print(dup.to_string(index=False))
    dup.to_csv(os.path.join(config.RESULTS_DIR, "leakage_duplicates.csv"), index=False)

    print("\n--- Απόδοση ανά στρατηγική διαχωρισμού ---")
    rows = evaluate(df, feats, "random") + evaluate(df, feats, "group")
    cmp = pd.DataFrame(rows)
    print("\n" + cmp.to_string(index=False))
    cmp.to_csv(os.path.join(config.RESULTS_DIR, "leakage_split_comparison.csv"),
               index=False)

    # Γράφημα σύγκρισης
    piv = cmp.pivot(index="model", columns="split", values="macro_f1")
    ax = piv.plot(kind="bar", figsize=(9, 5), rot=0,
                  color=["#C44E52", "#1B7A3D"])
    ax.set_ylabel("macro-F1 στο test set")
    ax.set_ylim(0, 1.05)
    ax.set_title(f"Επίδραση της διαρροής διπλότυπων ({tag})")
    ax.legend(title="διαχωρισμός")
    for c in ax.containers:
        ax.bar_label(c, fmt="%.3f", fontsize=8)
    plt.tight_layout()
    out = os.path.join(config.RESULTS_DIR, "leakage_split_comparison.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"\n[OK] {out}")

    r = cmp[cmp.model == "Random Forest"].set_index("split")
    print("\n=== ΣΥΜΠΕΡΑΣΜΑ (Random Forest) ===")
    print(f"  τυχαίος διαχωρισμός : macro-F1 = {r.loc['random','macro_f1']:.4f} "
          f"(διαρροή: {r.loc['random','test_leaked_pct']}% του test)")
    print(f"  group διαχωρισμός   : macro-F1 = {r.loc['group','macro_f1']:.4f} "
          f"(διαρροή: {r.loc['group','test_leaked_pct']}% του test)")
    print(f"  ΔΙΑΦΟΡΑ             : {r.loc['random','macro_f1'] - r.loc['group','macro_f1']:+.4f}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--insdn", action="store_true")
    args = ap.parse_args()
    main(use_insdn=args.insdn)
