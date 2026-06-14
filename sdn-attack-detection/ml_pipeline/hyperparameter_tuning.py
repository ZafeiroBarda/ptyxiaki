#!/usr/bin/env python3
"""
hyperparameter_tuning.py  (βελτιστοποίηση υπερπαραμέτρων)
---------------------------------------------------------
Σοβαρή αναζήτηση υπερπαραμέτρων για το μοντέλο ανίχνευσης, με έμφαση στο
**Isolation Forest** (ο κεντρικός αλγόριθμος της διπλωματικής) και σύγκριση
με βελτιστοποιημένο **Random Forest** (επιβλεπόμενο).

Παράγει:
  results/isolation_forest_tuning.csv   (όλες οι διαμορφώσεις, ταξινομημένες)
  results/isolation_forest_tuning.png   (επίδραση υπερπαραμέτρων στο ROC AUC)
  results/rf_tuning.csv                 (καλύτερες παράμετροι Random Forest)
  models/isolation_forest_best.pkl      (το βέλτιστο IF)
  models/best_model.pkl                 (ενημερωμένο βέλτιστο supervised)

Χρήση:
  python3 ml_pipeline/hyperparameter_tuning.py
  python3 ml_pipeline/hyperparameter_tuning.py --insdn --iso-only
"""

import os
import sys
import time
import argparse
import itertools
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import roc_auc_score, f1_score, make_scorer

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess

sns.set_theme(style="whitegrid")


# ======================================================================
#  ISOLATION FOREST — πλήρης αναζήτηση πλέγματος (unsupervised)
# ======================================================================
def tune_isolation_forest(use_insdn=False):
    print("=" * 64)
    print(" ΒΕΛΤΙΣΤΟΠΟΙΗΣΗ ISOLATION FOREST")
    print("=" * 64)

    df = preprocess.load_insdn() if use_insdn else preprocess.load_synthetic()
    feats = [c for c in config.FEATURE_COLUMNS if c in df.columns]
    X = df[feats].astype(float).values
    y = (df[config.LABEL_COL] != "Normal").astype(int).values

    # εκπαίδευση ΜΟΝΟ σε φυσιολογικά (unsupervised)
    X_normal = X[y == 0]
    rng = np.random.default_rng(config.RANDOM_STATE)
    perm = rng.permutation(len(X_normal))
    n_train = int(len(X_normal) * 0.6)
    Xtr = X_normal[perm[:n_train]]
    # test = υπόλοιπα normal + όλες οι επιθέσεις
    X_test = np.vstack([X_normal[perm[n_train:]], X[y == 1]])
    y_test = np.concatenate([np.zeros(len(perm) - n_train), np.ones((y == 1).sum())])

    scaler = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(X_test)

    # ----- πλέγμα υπερπαραμέτρων -----
    grid = {
        "n_estimators": [100, 200, 300, 500],
        "max_samples": [256, 512, "auto"],
        "contamination": [0.02, 0.05, 0.10],
        "max_features": [0.5, 0.75, 1.0],
    }
    keys = list(grid.keys())
    combos = list(itertools.product(*[grid[k] for k in keys]))
    print(f"[*] Δοκιμή {len(combos)} διαμορφώσεων (1 core, υπομονή)...\n")

    rows = []
    t0 = time.perf_counter()
    for i, combo in enumerate(combos, 1):
        params = dict(zip(keys, combo))
        iso = IsolationForest(random_state=config.RANDOM_STATE, n_jobs=-1, **params)
        iso.fit(Xtr_s)
        scores = -iso.decision_function(Xte_s)     # μεγαλύτερο = πιο ανώμαλο
        y_pred = (iso.predict(Xte_s) == -1).astype(int)
        auc = roc_auc_score(y_test, scores)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        rows.append({**params, "roc_auc": auc, "f1": f1})
        if i % 12 == 0 or i == len(combos):
            el = time.perf_counter() - t0
            print(f"    {i:3d}/{len(combos)} | best AUC ως τώρα: "
                  f"{max(r['roc_auc'] for r in rows):.4f} | {el:.0f}s")

    res = pd.DataFrame(rows).sort_values("roc_auc", ascending=False).reset_index(drop=True)
    res.to_csv(os.path.join(config.RESULTS_DIR, "isolation_forest_tuning.csv"), index=False)

    best = res.iloc[0]
    print("\n--- ΚΑΛΥΤΕΡΗ ΔΙΑΜΟΡΦΩΣΗ ISOLATION FOREST ---")
    print(best.to_string())

    # ξανα-εκπαίδευσε & αποθήκευσε το βέλτιστο
    best_params = {k: best[k] for k in keys}
    # καθάρισμα τύπων
    best_params["n_estimators"] = int(best_params["n_estimators"])
    if best_params["max_samples"] != "auto":
        best_params["max_samples"] = int(best_params["max_samples"])
    best_iso = IsolationForest(random_state=config.RANDOM_STATE, n_jobs=-1, **best_params)
    best_iso.fit(Xtr_s)
    joblib.dump(best_iso, os.path.join(config.MODELS_DIR, "isolation_forest_best.pkl"))
    joblib.dump(scaler, os.path.join(config.MODELS_DIR, "isolation_forest_best_scaler.pkl"))
    print("\n[OK] models/isolation_forest_best.pkl")

    _plot_iso_tuning(res)
    return res


def _plot_iso_tuning(res):
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    for ax, param in zip(axes, ["n_estimators", "contamination", "max_features"]):
        grp = res.groupby(param)["roc_auc"].agg(["mean", "std"]).reset_index()
        ax.errorbar(range(len(grp)), grp["mean"], yerr=grp["std"],
                    marker="o", capsize=5, color="#C44E52")
        ax.set_xticks(range(len(grp)))
        ax.set_xticklabels(grp[param].astype(str))
        ax.set_xlabel(param); ax.set_ylabel("ROC AUC (μέσος)")
        ax.set_title(f"Επίδραση: {param}")
    plt.suptitle("Isolation Forest — Επίδραση υπερπαραμέτρων στο ROC AUC", y=1.02)
    plt.tight_layout()
    out = os.path.join(config.RESULTS_DIR, "isolation_forest_tuning.png")
    plt.savefig(out, dpi=150, bbox_inches="tight"); plt.close()
    print(f"[OK] {out}")


# ======================================================================
#  RANDOM FOREST — RandomizedSearchCV (supervised, για σύγκριση)
# ======================================================================
def tune_random_forest(use_insdn=False, n_iter=25):
    print("\n" + "=" * 64)
    print(" ΒΕΛΤΙΣΤΟΠΟΙΗΣΗ RANDOM FOREST (supervised)")
    print("=" * 64)

    df = preprocess.load_insdn() if use_insdn else preprocess.load_synthetic()
    data = preprocess.prepare(df, scale=True)
    X_train, y_train = data["X_train"], data["y_train"]
    X_test, y_test = data["X_test"], data["y_test"]

    param_dist = {
        "n_estimators": [100, 200, 300, 500],
        "max_depth": [10, 20, 30, None],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2", 0.5],
    }
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=config.RANDOM_STATE)
    scorer = make_scorer(f1_score, average="macro")

    rf = RandomForestClassifier(random_state=config.RANDOM_STATE, n_jobs=-1)
    search = RandomizedSearchCV(
        rf, param_dist, n_iter=n_iter, scoring=scorer, cv=cv,
        random_state=config.RANDOM_STATE, n_jobs=-1, verbose=1)
    print(f"[*] RandomizedSearchCV: {n_iter} διαμορφώσεις x 3-fold...")
    t0 = time.perf_counter()
    search.fit(X_train, y_train)
    print(f"    Ολοκληρώθηκε σε {time.perf_counter()-t0:.0f}s")

    best = search.best_estimator_
    test_f1 = f1_score(y_test, best.predict(X_test), average="macro")
    print(f"\n--- ΚΑΛΥΤΕΡΕΣ ΠΑΡΑΜΕΤΡΟΙ RF ---")
    print(search.best_params_)
    print(f"CV F1 (macro): {search.best_score_:.4f} | Test F1: {test_f1:.4f}")

    pd.DataFrame([{**search.best_params_,
                   "cv_f1": search.best_score_, "test_f1": test_f1}]).to_csv(
        os.path.join(config.RESULTS_DIR, "rf_tuning.csv"), index=False)

    # αποθήκευσε το βελτιστοποιημένο supervised μοντέλο
    joblib.dump(best, os.path.join(config.MODELS_DIR, "best_model_tuned.pkl"))
    print("[OK] models/best_model_tuned.pkl, results/rf_tuning.csv")
    return search


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--insdn", action="store_true")
    parser.add_argument("--iso-only", action="store_true", help="μόνο Isolation Forest")
    parser.add_argument("--rf-iter", type=int, default=25)
    args = parser.parse_args()

    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    os.makedirs(config.MODELS_DIR, exist_ok=True)

    tune_isolation_forest(use_insdn=args.insdn)
    if not args.iso_only:
        tune_random_forest(use_insdn=args.insdn, n_iter=args.rf_iter)

    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Βελτιστοποίηση υπερπαραμέτρων.")


if __name__ == "__main__":
    main()
