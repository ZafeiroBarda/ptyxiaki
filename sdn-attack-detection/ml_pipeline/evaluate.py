"""
evaluate.py
-----------
Παράγει τα γραφήματα & τις αναλυτικές μετρικές αξιολόγησης για τη διπλωματική:
  - Σύγκριση μοντέλων (bar chart accuracy/precision/recall/F1)
  - Confusion matrix του καλύτερου μοντέλου
  - Feature importance (αν το μοντέλο το υποστηρίζει)
  - Αναλυτικό classification report ανά κλάση

Όλα αποθηκεύονται στον φάκελο results/.

Χρήση:
  python3 ml_pipeline/evaluate.py
  python3 ml_pipeline/evaluate.py --insdn
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # χωρίς GUI
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import train as train_mod


sns.set_theme(style="whitegrid")


def plot_model_comparison(res_df, out_path):
    metrics = ["accuracy", "precision", "recall", "f1"]
    plot_df = res_df.melt(id_vars="model", value_vars=metrics,
                          var_name="Μετρική", value_name="Τιμή")
    plt.figure(figsize=(12, 6))
    ax = sns.barplot(data=plot_df, x="model", y="Τιμή", hue="Μετρική")
    ax.set_title("Σύγκριση Μοντέλων Μηχανικής Μάθησης για Ανίχνευση Επιθέσεων SDN")
    ax.set_xlabel("Μοντέλο")
    ax.set_ylabel("Τιμή Μετρικής")
    ax.set_ylim(min(0.9, plot_df["Τιμή"].min() - 0.02), 1.001)
    plt.xticks(rotation=20, ha="right")
    plt.legend(title="Μετρική", loc="lower right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[OK] {out_path}")


def plot_confusion(model, data, out_path, title):
    y_pred = model.predict(data["X_test"])
    cm = confusion_matrix(data["y_test"], y_pred)
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)
    plt.figure(figsize=(8, 6.5))
    sns.heatmap(cm_norm, annot=cm, fmt="d", cmap="Blues",
                xticklabels=data["class_names"], yticklabels=data["class_names"],
                cbar_kws={"label": "Ποσοστό (κανονικοποιημένο ανά γραμμή)"})
    plt.title(title)
    plt.ylabel("Πραγματική κλάση")
    plt.xlabel("Προβλεπόμενη κλάση")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[OK] {out_path}")


def plot_feature_importance(model, feature_columns, out_path):
    if not hasattr(model, "feature_importances_"):
        print("[i] Το μοντέλο δεν υποστηρίζει feature_importances_ — παράλειψη.")
        return
    importances = model.feature_importances_
    order = np.argsort(importances)[::-1]
    feats = np.array(feature_columns)[order]
    vals = importances[order]
    plt.figure(figsize=(10, 8))
    sns.barplot(x=vals[:20], y=feats[:20], palette="viridis", hue=feats[:20], legend=False)
    plt.title("Σημαντικότητα Χαρακτηριστικών (Top 20) — Random Forest")
    plt.xlabel("Σημαντικότητα")
    plt.ylabel("Χαρακτηριστικό")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[OK] {out_path}")


def save_classification_report(model, data, out_path):
    y_pred = model.predict(data["X_test"])
    report = classification_report(
        data["y_test"], y_pred, target_names=data["class_names"], digits=4, zero_division=0,
    )
    with open(out_path, "w") as f:
        f.write("ΑΝΑΛΥΤΙΚΟ CLASSIFICATION REPORT (καλύτερο μοντέλο)\n")
        f.write("=" * 60 + "\n\n")
        f.write(report)
    print(f"[OK] {out_path}")
    print("\n" + report)


def main(use_insdn=False):
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    # Εκπαίδευση & λήψη αντικειμένων
    out = train_mod.main(use_insdn=use_insdn)
    res_df, data = out["results_df"], out["data"]
    best_model, best_name = out["best_model"], out["best_name"]

    print("\n[*] Δημιουργία γραφημάτων αξιολόγησης...")
    plot_model_comparison(res_df, os.path.join(config.RESULTS_DIR, "model_comparison.png"))
    plot_confusion(best_model, data,
                   os.path.join(config.RESULTS_DIR, "confusion_matrix.png"),
                   f"Confusion Matrix — {best_name}")
    plot_feature_importance(best_model, data["feature_columns"],
                            os.path.join(config.RESULTS_DIR, "feature_importance.png"))
    save_classification_report(best_model, data,
                               os.path.join(config.RESULTS_DIR, "classification_report.txt"))
    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Όλα τα αποτελέσματα στον φάκελο results/.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--insdn", action="store_true")
    args = parser.parse_args()
    main(use_insdn=args.insdn)
