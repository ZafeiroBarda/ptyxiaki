#!/usr/bin/env python3
"""
hyperparameter_tuning.py  (βελτιστοποίηση υπερπαραμέτρων)
---------------------------------------------------------
Σοβαρή αναζήτηση υπερπαραμέτρων για το μοντέλο ανίχνευσης, με έμφαση στο
**Isolation Forest** (ο κεντρικός αλγόριθμος της διπλωματικής) και σύγκριση
με βελτιστοποιημένο **Random Forest** (επιβλεπόμενο).

Παράγει (suffix _insdn μόνο με --insdn, ώστε να μη γράφονται πάνω στα synthetic):
  results/isolation_forest_tuning[_insdn].csv   (όλες οι διαμορφώσεις, ταξινομημένες)
  results/isolation_forest_tuning[_insdn].png   (επίδραση υπερπαραμέτρων στο ROC AUC)
  results/rf_tuning[_insdn].csv                 (καλύτερες παράμετροι Random Forest)
  models/isolation_forest_best[_insdn].pkl      (το βέλτιστο IF)
  models/best_model_tuned[_insdn].pkl           (το βελτιστοποιημένο supervised)

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
from sklearn.pipeline import Pipeline
from sklearn.model_selection import (RandomizedSearchCV, StratifiedKFold,
                                     StratifiedGroupKFold)
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

    # Ίδια σύμβαση ονομασίας με το train.py: suffix _insdn μόνο για το InSDN run.
    suffix = "_insdn" if use_insdn else ""

    df = preprocess.load_insdn() if use_insdn else preprocess.load_synthetic()
    feats = [c for c in config.FEATURE_COLUMNS if c in df.columns]
    X = df[feats].astype(float).values
    y = (df[config.LABEL_COL] != "Normal").astype(int).values

    # Εκπαίδευση ΜΟΝΟ σε φυσιολογική κίνηση (μη επιβλεπόμενο).
    #
    # ΔΙΟΡΘΩΣΗ ΜΕΘΟΔΟΛΟΓΙΑΣ: παλαιότερα και οι 108 διαμορφώσεις αξιολογούνταν στο
    # ΙΔΙΟ σύνολο, από το οποίο επιλεγόταν και η καλύτερη. Αυτό είναι
    # υπερπροσαρμογή των υπερπαραμέτρων στο test set. Εδώ χωρίζουμε σε δύο
    # ανεξάρτητα σύνολα: η επιλογή γίνεται στο VALIDATION και η τελική τιμή που
    # αναφέρεται μετριέται μία φορά στο TEST, το οποίο δεν συμμετέχει στην
    # αναζήτηση.
    X_normal = X[y == 0]
    X_attack = X[y == 1]

    rng = np.random.default_rng(config.RANDOM_STATE)
    permn = rng.permutation(len(X_normal))
    perma = rng.permutation(len(X_attack))

    n_tr = int(len(X_normal) * 0.60)                     # 60% normal -> εκπαίδευση
    n_va = int(len(X_normal) * 0.20)                     # 20% normal -> validation
    Xtr = X_normal[permn[:n_tr]]                         # (μόνο normal)
    norm_va = X_normal[permn[n_tr:n_tr + n_va]]
    norm_te = X_normal[permn[n_tr + n_va:]]

    a_half = len(X_attack) // 2                          # επιθέσεις: 50/50 val/test
    atk_va = X_attack[perma[:a_half]]
    atk_te = X_attack[perma[a_half:]]

    X_val = np.vstack([norm_va, atk_va])
    y_val = np.concatenate([np.zeros(len(norm_va)), np.ones(len(atk_va))])
    X_test = np.vstack([norm_te, atk_te])
    y_test = np.concatenate([np.zeros(len(norm_te)), np.ones(len(atk_te))])

    scaler = StandardScaler().fit(Xtr)
    Xtr_s = scaler.transform(Xtr)
    Xva_s = scaler.transform(X_val)
    Xte_s = scaler.transform(X_test)
    print(f"[*] train(normal)={len(Xtr)} | validation={len(y_val)} | test={len(y_test)}")

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
        # ΕΠΙΛΟΓΗ: αποκλειστικά στο validation set
        val_scores = -iso.decision_function(Xva_s)      # μεγαλύτερο = πιο ανώμαλο
        val_pred = (iso.predict(Xva_s) == -1).astype(int)
        rows.append({**params,
                     "val_roc_auc": roc_auc_score(y_val, val_scores),
                     "val_f1": f1_score(y_val, val_pred, zero_division=0)})
        if i % 12 == 0 or i == len(combos):
            el = time.perf_counter() - t0
            print(f"    {i:3d}/{len(combos)} | best val AUC ως τώρα: "
                  f"{max(r['val_roc_auc'] for r in rows):.4f} | {el:.0f}s")

    res = (pd.DataFrame(rows)
           # Το ROC-AUC είναι threshold-independent, άρα το contamination δεν το
           # μεταβάλλει. Σε ισοβαθμία ROC-AUC, σπάμε το ισόπαλο με το validation F1
           # (που εξαρτάται από το threshold/contamination), ώστε να μην επιλέγεται
           # αυθαίρετα μια διαμόρφωση με χαμηλότερο F1 λόγω απλής ισοβαθμίας.
           .sort_values(["val_roc_auc", "val_f1"], ascending=[False, False])
           .reset_index(drop=True))

    best = res.iloc[0]
    print("\n--- ΚΑΛΥΤΕΡΗ ΔΙΑΜΟΡΦΩΣΗ (κατά validation ROC-AUC) ---")
    print(best.to_string())

    # ΤΕΛΙΚΗ ΑΞΙΟΛΟΓΗΣΗ: μία και μοναδική φορά, στο ανεξάρτητο test set
    bp = {k: best[k] for k in keys}
    bp["n_estimators"] = int(bp["n_estimators"])
    if bp["max_samples"] != "auto":
        bp["max_samples"] = int(bp["max_samples"])
    final_iso = IsolationForest(random_state=config.RANDOM_STATE, n_jobs=-1, **bp).fit(Xtr_s)
    te_scores = -final_iso.decision_function(Xte_s)
    te_pred = (final_iso.predict(Xte_s) == -1).astype(int)
    test_auc = roc_auc_score(y_test, te_scores)
    test_f1 = f1_score(y_test, te_pred, zero_division=0)
    print(f"\n--- ΤΕΛΙΚΗ ΑΞΙΟΛΟΓΗΣΗ ΣΤΟ ΑΝΕΞΑΡΤΗΤΟ TEST SET ---")
    print(f"    ROC-AUC = {test_auc:.4f} | F1 = {test_f1:.4f}")
    print(f"    (validation ROC-AUC της ίδιας διαμόρφωσης: {best['val_roc_auc']:.4f})")

    # Η τελική τιμή του test αφορά ΜΟΝΟ τη βέλτιστη διαμόρφωση (πρώτη γραμμή)·
    # οι υπόλοιπες μένουν κενές. Χτίζουμε τις στήλες ως λίστες object ώστε να
    # αποφευχθεί το σφάλμα ανάθεσης float σε string column (pandas 3.x).
    res["test_roc_auc"] = [round(test_auc, 4)] + [None] * (len(res) - 1)
    res["test_f1"] = [round(test_f1, 4)] + [None] * (len(res) - 1)
    res.to_csv(os.path.join(config.RESULTS_DIR, f"isolation_forest_tuning{suffix}.csv"), index=False)

    # Αποθήκευση του μοντέλου της βέλτιστης (κατά validation) διαμόρφωσης
    best_iso = final_iso
    joblib.dump(best_iso, os.path.join(config.MODELS_DIR, f"isolation_forest_best{suffix}.pkl"))
    joblib.dump(scaler, os.path.join(config.MODELS_DIR, f"isolation_forest_best_scaler{suffix}.pkl"))
    print(f"\n[OK] models/isolation_forest_best{suffix}.pkl")

    _plot_iso_tuning(res, suffix)
    return res


def _plot_iso_tuning(res, suffix=""):
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    for ax, param in zip(axes, ["n_estimators", "contamination", "max_features"]):
        grp = res.groupby(param)["val_roc_auc"].agg(["mean", "std"]).reset_index()
        ax.errorbar(range(len(grp)), grp["mean"], yerr=grp["std"],
                    marker="o", capsize=5, color="#C44E52")
        ax.set_xticks(range(len(grp)))
        ax.set_xticklabels(grp[param].astype(str))
        ax.set_xlabel(param); ax.set_ylabel("validation ROC-AUC (μέσος)")
        ax.set_title(f"Επίδραση: {param}")
    plt.suptitle("Isolation Forest — Επίδραση υπερπαραμέτρων στο ROC AUC", y=1.02)
    plt.tight_layout()
    out = os.path.join(config.RESULTS_DIR, f"isolation_forest_tuning{suffix}.png")
    plt.savefig(out, dpi=150, bbox_inches="tight"); plt.close()
    print(f"[OK] {out}")


# ======================================================================
#  RANDOM FOREST — RandomizedSearchCV (supervised, για σύγκριση)
# ======================================================================
def tune_random_forest(use_insdn=False, n_iter=25):
    print("\n" + "=" * 64)
    print(" ΒΕΛΤΙΣΤΟΠΟΙΗΣΗ RANDOM FOREST (supervised)")
    print("=" * 64)

    # Ίδια σύμβαση ονομασίας με το train.py: suffix _insdn μόνο για το InSDN run.
    suffix = "_insdn" if use_insdn else ""

    # Group-aware, leakage-resistant tuning: δουλεύουμε στα ΑΚΑΤΕΡΓΑΣΤΑ
    # χαρακτηριστικά, με το scaling μέσα σε Pipeline (ανά fold) και group split
    # ώστε τα ακριβή διπλότυπα διανύσματα να μη μοιράζονται μεταξύ των CV folds.
    df = preprocess.load_insdn() if use_insdn else preprocess.load_synthetic()
    feats = [c for c in config.FEATURE_COLUMNS if c in df.columns]
    X_all = df[feats].astype(float).values
    from sklearn.preprocessing import LabelEncoder
    y_all = LabelEncoder().fit_transform(df[config.LABEL_COL].values)
    groups = preprocess.feature_hash_groups(X_all)

    # Ανεξάρτητος διαχωρισμός train/test με ομαδοποίηση διπλότυπων· η αναζήτηση
    # γίνεται με group-CV ΜΟΝΟ στο train, η τελική τιμή μετριέται στο test.
    tr_idx, te_idx, _ = preprocess.group_train_test_split(
        X_all, y_all, config.TEST_SIZE, config.RANDOM_STATE)
    X_train, y_train, g_train = X_all[tr_idx], y_all[tr_idx], groups[tr_idx]
    X_test, y_test = X_all[te_idx], y_all[te_idx]

    param_dist = {
        "model__n_estimators": [100, 200, 300, 500],
        "model__max_depth": [10, 20, 30, None],
        "model__min_samples_split": [2, 5, 10],
        "model__min_samples_leaf": [1, 2, 4],
        "model__max_features": ["sqrt", "log2", 0.5],
    }
    cv = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=config.RANDOM_STATE)
    scorer = make_scorer(f1_score, average="macro")

    pipe = Pipeline([("scaler", StandardScaler()),
                     ("model", RandomForestClassifier(
                         random_state=config.RANDOM_STATE, n_jobs=-1))])
    search = RandomizedSearchCV(
        pipe, param_dist, n_iter=n_iter, scoring=scorer, cv=cv,
        random_state=config.RANDOM_STATE, n_jobs=-1, verbose=1)
    print(f"[*] RandomizedSearchCV (StratifiedGroupKFold): {n_iter} διαμορφώσεις x 3-fold...")
    t0 = time.perf_counter()
    search.fit(X_train, y_train, groups=g_train)
    print(f"    Ολοκληρώθηκε σε {time.perf_counter()-t0:.0f}s")

    best = search.best_estimator_
    test_f1 = f1_score(y_test, best.predict(X_test), average="macro")
    print(f"\n--- ΚΑΛΥΤΕΡΕΣ ΠΑΡΑΜΕΤΡΟΙ RF ---")
    print(search.best_params_)
    print(f"CV F1 (macro): {search.best_score_:.4f} | Test F1: {test_f1:.4f}")

    clean_params = {k.replace("model__", ""): v for k, v in search.best_params_.items()}
    pd.DataFrame([{**clean_params,
                   "cv_f1": search.best_score_, "test_f1": test_f1}]).to_csv(
        os.path.join(config.RESULTS_DIR, f"rf_tuning{suffix}.csv"), index=False)

    # αποθήκευσε το βελτιστοποιημένο supervised μοντέλο
    joblib.dump(best, os.path.join(config.MODELS_DIR, f"best_model_tuned{suffix}.pkl"))
    print(f"[OK] models/best_model_tuned{suffix}.pkl, results/rf_tuning{suffix}.csv")
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
