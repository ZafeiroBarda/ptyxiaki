#!/usr/bin/env python3
"""
advanced_eval.py  (ΜΕΘΟΔΟΣ Β — προχωρημένη αξιολόγηση)
------------------------------------------------------
Δύο πράγματα που ανεβάζουν την ποιότητα της αξιολόγησης σε επίπεδο διπλωματικής:

  1. Stratified K-Fold Cross-Validation: αντί για ένα μόνο train/test split,
     αξιολογεί κάθε μοντέλο σε K διαφορετικά folds και δίνει μέση τιμή ± τυπική
     απόκλιση. Έτσι αποδεικνύεις ότι τα αποτελέσματα είναι σταθερά, όχι τυχαία.

  2. ROC καμπύλες (one-vs-rest) + AUC ανά κλάση και micro/macro average.

Παράγει:
  results/cross_validation.csv
  results/cross_validation.png
  results/roc_curves.png

Χρήση:
  python3 ml_pipeline/advanced_eval.py
  python3 ml_pipeline/advanced_eval.py --insdn
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import (StratifiedKFold, StratifiedGroupKFold,
                                     cross_val_score)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import label_binarize, StandardScaler
from sklearn.metrics import roc_curve, auc
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess

sns.set_theme(style="whitegrid")


def cv_models():
    return {
        "Random Forest": RandomForestClassifier(n_estimators=120, n_jobs=-1,
                                                 random_state=config.RANDOM_STATE),
        "Decision Tree": DecisionTreeClassifier(max_depth=20,
                                                random_state=config.RANDOM_STATE),
        "KNN": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "SVM (RBF)": SVC(kernel="rbf", C=10, probability=True,
                         random_state=config.RANDOM_STATE),
        "Logistic Regression": LogisticRegression(max_iter=1000,
                                                  random_state=config.RANDOM_STATE),
    }


def run_cross_validation(X, y, k=5, groups=None):
    """k-fold CV χωρίς διαρροή.

    Δύο διορθώσεις σε σχέση με την αφελή υλοποίηση:
    1) Το StandardScaler μπαίνει ΜΕΣΑ σε Pipeline, ώστε να προσαρμόζεται
       αποκλειστικά στο train fold κάθε επανάληψης. Αν το scaling γίνει μία φορά
       πριν το CV, τα στατιστικά όλου του συνόλου διαρρέουν σε κάθε fold.
    2) Χρησιμοποιείται StratifiedGroupKFold με ομάδες τα πανομοιότυπα διανύσματα
       χαρακτηριστικών, ώστε διπλότυπα να μην εμφανίζονται ταυτόχρονα σε train
       και validation fold.
    """
    if groups is not None:
        cv = StratifiedGroupKFold(n_splits=k, shuffle=True,
                                  random_state=config.RANDOM_STATE)
        split_args = {"groups": groups}
        print(f"[*] CV: StratifiedGroupKFold (group-aware, "
              f"{len(np.unique(groups))} μοναδικά διανύσματα)")
    else:
        cv = StratifiedKFold(n_splits=k, shuffle=True,
                             random_state=config.RANDOM_STATE)
        split_args = {}
        print("[*] CV: StratifiedKFold")

    rows = []
    for name, model in cv_models().items():
        print(f"[*] {k}-fold CV: {name}")
        pipe = Pipeline([("scaler", StandardScaler()), ("model", model)])
        scores = cross_val_score(pipe, X, y, cv=cv, scoring="f1_macro",
                                 n_jobs=-1, **split_args)
        rows.append({
            "model": name,
            "f1_mean": scores.mean(),
            "f1_std": scores.std(),
            "f1_min": scores.min(),
            "f1_max": scores.max(),
        })
        print(f"    F1 = {scores.mean():.4f} ± {scores.std():.4f}")
    return pd.DataFrame(rows).sort_values("f1_mean", ascending=False)


def plot_cv(cv_df, out_path):
    plt.figure(figsize=(10, 6))
    order = cv_df.sort_values("f1_mean")
    plt.barh(order["model"], order["f1_mean"], xerr=order["f1_std"],
             capsize=5, color=sns.color_palette("crest", len(order)))
    plt.xlabel("F1-score (macro), μέσος όρος ± τυπ. απόκλιση")
    plt.title("Stratified K-Fold Cross-Validation")
    plt.xlim(min(0.85, order["f1_mean"].min() - 0.05), 1.0)
    plt.tight_layout(); plt.savefig(out_path, dpi=150); plt.close()
    print(f"[OK] {out_path}")


def plot_roc(model, X_train, X_test, y_train, y_test, class_names, out_path):
    """ROC one-vs-rest με micro & macro average."""
    n_classes = len(class_names)
    y_test_bin = label_binarize(y_test, classes=list(range(n_classes)))
    model.fit(X_train, y_train)
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_test)
    else:
        y_score = model.decision_function(X_test)

    fpr, tpr, roc_auc = {}, {}, {}
    for i in range(n_classes):
        fpr[i], tpr[i], _ = roc_curve(y_test_bin[:, i], y_score[:, i])
        roc_auc[i] = auc(fpr[i], tpr[i])

    # micro-average
    fpr["micro"], tpr["micro"], _ = roc_curve(y_test_bin.ravel(), y_score.ravel())
    roc_auc["micro"] = auc(fpr["micro"], tpr["micro"])

    # macro-average
    all_fpr = np.unique(np.concatenate([fpr[i] for i in range(n_classes)]))
    mean_tpr = np.zeros_like(all_fpr)
    for i in range(n_classes):
        mean_tpr += np.interp(all_fpr, fpr[i], tpr[i])
    mean_tpr /= n_classes
    fpr["macro"], tpr["macro"] = all_fpr, mean_tpr
    roc_auc["macro"] = auc(all_fpr, mean_tpr)

    plt.figure(figsize=(9, 7))
    colors = sns.color_palette("husl", n_classes)
    for i, c in enumerate(colors):
        plt.plot(fpr[i], tpr[i], color=c, lw=1.8,
                 label=f"{class_names[i]} (AUC={roc_auc[i]:.3f})")
    plt.plot(fpr["micro"], tpr["micro"], "k--", lw=2,
             label=f"micro-avg (AUC={roc_auc['micro']:.3f})")
    plt.plot(fpr["macro"], tpr["macro"], "k:", lw=2,
             label=f"macro-avg (AUC={roc_auc['macro']:.3f})")
    plt.plot([0, 1], [0, 1], color="gray", lw=1, linestyle="-")
    plt.xlim([0, 1]); plt.ylim([0, 1.02])
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("ROC Curves (one-vs-rest) — Random Forest")
    plt.legend(loc="lower right", fontsize=9)
    plt.tight_layout(); plt.savefig(out_path, dpi=150); plt.close()
    print(f"[OK] {out_path}")


def main(use_insdn=False, k=5):
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    df = preprocess.load_insdn() if use_insdn else preprocess.load_synthetic()
    data = preprocess.prepare(df, scale=True,
                              split=config.SPLIT_STRATEGY,
                              val_size=config.VAL_SIZE)

    # Το CV τρέχει στα ΑΚΑΤΕΡΓΑΣΤΑ χαρακτηριστικά: το scaling γίνεται μέσα στο
    # Pipeline, ξεχωριστά για κάθε fold. (Παλαιότερα ενώνονταν τα ΗΔΗ
    # κανονικοποιημένα X_train/X_test, οπότε τα στατιστικά διέρρεαν στα folds.)
    feats = [c for c in config.FEATURE_COLUMNS if c in df.columns]
    X_all = df[feats].astype(float).values
    y_all = preprocess.LabelEncoder().fit_transform(df[config.LABEL_COL].values)
    groups = preprocess.feature_hash_groups(X_all)

    print("=== STRATIFIED GROUP K-FOLD CROSS-VALIDATION ===")
    cv_df = run_cross_validation(X_all, y_all, k=k, groups=groups)
    cv_df.to_csv(os.path.join(config.RESULTS_DIR, "cross_validation.csv"), index=False)
    print("\n", cv_df.to_string(index=False))
    plot_cv(cv_df, os.path.join(config.RESULTS_DIR, "cross_validation.png"))

    print("\n=== ROC CURVES ===")
    rf = RandomForestClassifier(n_estimators=120, n_jobs=-1,
                                random_state=config.RANDOM_STATE)
    plot_roc(rf, data["X_train"], data["X_test"], data["y_train"], data["y_test"],
             data["class_names"], os.path.join(config.RESULTS_DIR, "roc_curves.png"))
    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Προχωρημένη αξιολόγηση στο results/.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--insdn", action="store_true")
    parser.add_argument("--k", type=int, default=5)
    args = parser.parse_args()
    main(use_insdn=args.insdn, k=args.k)
