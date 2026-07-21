#!/usr/bin/env python3
"""
shap_analysis.py  — Ανάλυση Ερμηνευσιμότητας (Explainability) με SHAP
-----------------------------------------------------------------------
Χρησιμοποιεί το SHAP (SHapley Additive exPlanations) για να εξηγήσει
τις αποφάσεις του Random Forest μοντέλου ανίχνευσης επιθέσεων SDN.

Παράγει τρία γραφήματα + ένα CSV στο results/ (suffix _insdn μόνο με --insdn,
ώστε να μη γράφονται πάνω στα synthetic):
  1. shap_summary[_insdn].png       — Beeswarm plot: κατεύθυνση & μέγεθος επίδρασης ανά feature
  2. shap_bar[_insdn].png           — Ραβδόγραμμα: μέση |SHAP| τιμή ανά feature (global)
  3. shap_class_heatmap[_insdn].png — Heatmap: ποια features ανιχνεύουν ποια επίθεση
  4. shap_feature_importance[_insdn].csv

Στο synthetic (προεπιλογή) φορτώνεται το ήδη εκπαιδευμένο canonical
best_model.pkl (ίδιο με deployment). Στο --insdn ΔΕΝ υπάρχει αποθηκευμένο
canonical InSDN μοντέλο (το train.py δεν το σειριοποιεί για --insdn, βλ.
σχόλια εκεί) — εκπαιδεύεται φρέσκο Random Forest αποκλειστικά για τη SHAP
ανάλυση.

Χρήση:
  python3 ml_pipeline/shap_analysis.py
  python3 ml_pipeline/shap_analysis.py --insdn
"""

import os
import sys
import json
import argparse
import warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import shap
from sklearn.ensemble import RandomForestClassifier

warnings.filterwarnings("ignore")
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess

RESULTS_DIR = config.RESULTS_DIR
MODELS_DIR  = config.MODELS_DIR

# Ελληνικά ονόματα features για τα γραφήματα
FEATURE_LABELS = {
    "Flow_Duration":      "Διάρκεια Ροής",
    "Tot_Fwd_Pkts":       "Πακέτα Εμπρός",
    "Tot_Bwd_Pkts":       "Πακέτα Πίσω",
    "TotLen_Fwd_Pkts":    "Bytes Εμπρός",
    "TotLen_Bwd_Pkts":    "Bytes Πίσω",
    "Fwd_Pkt_Len_Mean":   "Μέσο Μήκος Εμπρός",
    "Bwd_Pkt_Len_Mean":   "Μέσο Μήκος Πίσω",
    "Flow_Byts_s":        "Bytes/s",
    "Flow_Pkts_s":        "Πακέτα/s",
    "Flow_IAT_Mean":      "Μέσο IAT",
    "Flow_IAT_Std":       "Τυπ. Απόκλιση IAT",
    "Fwd_IAT_Mean":       "IAT Εμπρός",
    "Bwd_IAT_Mean":       "IAT Πίσω",
    "SYN_Flag_Cnt":       "SYN Flags",
    "ACK_Flag_Cnt":       "ACK Flags",
    "FIN_Flag_Cnt":       "FIN Flags",
    "RST_Flag_Cnt":       "RST Flags",
    "Pkt_Len_Mean":       "Μέσο Μήκος Πακέτου",
    "Pkt_Len_Std":        "Τυπ. Απόκλιση Μήκους",
    "Down_Up_Ratio":      "Λόγος Down/Up",
    "Pkt_Size_Avg":       "Μέσο Μέγεθος Πακέτου",
    "Active_Mean":        "Μέσος Χρόνος Ενεργός",
    "Idle_Mean":          "Μέσος Χρόνος Αδράνειας",
    "Init_Fwd_Win_Byts":  "Παράθυρο TCP Εμπρός",
}


SUBSAMPLE_INSDN = 60_000


def load_artifacts():
    """Canonical synthetic artifacts (μόνο για το προεπιλεγμένο, μη-InSDN run)."""
    model  = joblib.load(os.path.join(MODELS_DIR, "best_model.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
    le     = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
    with open(os.path.join(MODELS_DIR, "feature_columns.json")) as f:
        feature_cols = json.load(f)
    return model, scaler, le, feature_cols


def get_model_and_data(use_insdn=False, sample=2000):
    """
    Επιστρέφει (model, X_sample, y_sample, class_names, feature_cols).

    synthetic: φορτώνει το ήδη εκπαιδευμένο canonical best_model.pkl.
    insdn:     εκπαιδεύει φρέσκο RF (δεν υπάρχει αποθηκευμένο InSDN canonical
               μοντέλο — βλ. σχόλια του train.py).
    """
    if use_insdn:
        df = preprocess.load_insdn()
        feature_cols = [c for c in config.FEATURE_COLUMNS if c in df.columns]
        data = preprocess.prepare(df, scale=True, feature_columns=feature_cols,
                                  subsample=SUBSAMPLE_INSDN)
        model = RandomForestClassifier(n_estimators=200, n_jobs=-1,
                                       random_state=config.RANDOM_STATE)
        model.fit(data["X_train"], data["y_train"])
    else:
        model, _scaler, _le, feature_cols = load_artifacts()
        df = preprocess.load_synthetic()
        data = preprocess.prepare(df, scale=True, feature_columns=feature_cols)

    X, y = data["X_test"], data["y_test"]
    rng  = np.random.default_rng(config.RANDOM_STATE)
    idx  = rng.choice(len(X), size=min(sample, len(X)), replace=False)
    return model, X[idx], y[idx], data["class_names"], feature_cols


def compute_shap(model, X):
    """Επιστρέφει shap_values: np.ndarray shape (n_samples, n_features, n_classes)."""
    explainer   = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)
    # Νέες εκδόσεις shap επιστρέφουν 3D array, παλιές λίστα arrays
    if isinstance(shap_values, list):
        shap_values = np.stack(shap_values, axis=2)
    return shap_values   # (n_samples, n_features, n_classes)


def plot_summary(shap_values, X, feature_cols, class_names, suffix=""):
    """Beeswarm plot για την κλάση DDoS (πιο αντιπροσωπευτική για κυβερνοασφάλεια)."""
    ddos_idx  = class_names.index("DDoS") if "DDoS" in class_names else 0
    sv_ddos   = shap_values[:, :, ddos_idx]
    feat_labs = [FEATURE_LABELS.get(f, f) for f in feature_cols]

    plt.figure(figsize=(10, 7))
    shap.summary_plot(
        sv_ddos, X,
        feature_names=feat_labs,
        plot_type="dot",
        show=False,
        max_display=len(feature_cols),
        color_bar_label="Τιμή feature (κανονικοποιημένη)",
    )
    plt.title("SHAP Beeswarm — Επίδραση Features στην Ανίχνευση DDoS",
              fontsize=13, pad=12)
    plt.xlabel("SHAP τιμή (αρνητική = μειώνει πιθανότητα DDoS, θετική = αυξάνει)")
    plt.tight_layout()
    out = os.path.join(RESULTS_DIR, f"shap_summary{suffix}.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")


def plot_bar(shap_values, feature_cols, suffix=""):
    """Ραβδόγραμμα: mean(|SHAP|) ανά feature — global importance."""
    mean_abs = np.mean(np.abs(shap_values).sum(axis=2), axis=0)
    feat_labs = [FEATURE_LABELS.get(f, f) for f in feature_cols]
    order     = np.argsort(mean_abs)

    fig, ax = plt.subplots(figsize=(9, 7))
    bars = ax.barh(
        [feat_labs[i] for i in order],
        [mean_abs[i] for i in order],
        color=plt.cm.RdYlGn(np.linspace(0.25, 0.85, len(order))),
        edgecolor="grey", linewidth=0.4,
    )
    ax.set_xlabel("Μέση Απόλυτη Τιμή SHAP (σημαντικότητα feature)", fontsize=11)
    ax.set_title("Global Feature Importance — SHAP\n"
                 "(Random Forest, σύνολο κλάσεων)", fontsize=12)
    ax.grid(axis="x", linestyle="--", alpha=0.4)
    plt.tight_layout()
    out = os.path.join(RESULTS_DIR, f"shap_bar{suffix}.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")

    # Αποθήκευση και σε CSV
    df_imp = pd.DataFrame({
        "feature":    feature_cols,
        "feature_el": feat_labs,
        "mean_abs_shap": mean_abs,
    }).sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)
    csv_out = os.path.join(RESULTS_DIR, f"shap_feature_importance{suffix}.csv")
    df_imp.to_csv(csv_out, index=False)
    print(f"[OK] {csv_out}")
    return df_imp


def plot_class_heatmap(shap_values, feature_cols, class_names, suffix=""):
    """Heatmap: μέση |SHAP| ανά (class, feature) — δείχνει τι ανιχνεύει κάθε επίθεση."""
    # matrix: (n_classes, n_features)
    mat = np.mean(np.abs(shap_values), axis=0).T
    feat_labs = [FEATURE_LABELS.get(f, f) for f in feature_cols]

    # Ταξινόμηση features κατά συνολική σημαντικότητα
    order = np.argsort(mat.sum(axis=0))[::-1][:16]  # top-16 features

    mat_sub  = mat[:, order]
    feat_sub = [feat_labs[i] for i in order]

    # Κανονικοποίηση ανά κλάση (για συγκρισιμότητα)
    mat_norm = mat_sub / (mat_sub.max(axis=1, keepdims=True) + 1e-9)

    fig, ax = plt.subplots(figsize=(12, 5))
    im = ax.imshow(mat_norm, aspect="auto", cmap="YlOrRd",
                   vmin=0, vmax=1, interpolation="nearest")
    ax.set_xticks(range(len(feat_sub)))
    ax.set_xticklabels(feat_sub, rotation=40, ha="right", fontsize=9)
    ax.set_yticks(range(len(class_names)))
    ax.set_yticklabels(class_names, fontsize=11)
    ax.set_title("SHAP Feature Importance ανά Κλάση Επίθεσης\n"
                 "(κανονικοποιημένη τιμή — ανοιχτόχρωμο = χαμηλή, σκοτεινό = υψηλή σημαντικότητα)",
                 fontsize=11)
    cb = fig.colorbar(im, ax=ax, fraction=0.02, pad=0.02)
    cb.set_label("Κανονικοποιημένη SHAP τιμή")

    # Αριθμητικές τιμές μέσα στα κελιά
    for r in range(len(class_names)):
        for c in range(len(feat_sub)):
            ax.text(c, r, f"{mat_norm[r, c]:.2f}",
                    ha="center", va="center", fontsize=7,
                    color="black" if mat_norm[r, c] < 0.7 else "white")

    plt.tight_layout()
    out = os.path.join(RESULTS_DIR, f"shap_class_heatmap{suffix}.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")


def print_findings(df_imp, class_names, shap_values, feature_cols):
    """Εκτυπώνει τα κυριότερα ευρήματα."""
    print("\n" + "=" * 60)
    print("  ΕΥΡΗΜΑΤΑ SHAP ΑΝΑΛΥΣΗΣ")
    print("=" * 60)
    print("\nTop-5 πιο σημαντικά features (global):")
    for _, row in df_imp.head(5).iterrows():
        print(f"  {row['feature_el']:30s}  mean|SHAP| = {row['mean_abs_shap']:.4f}")

    print("\nΚορυφαίο feature ανά κλάση επίθεσης:")
    mean_per_class = np.mean(np.abs(shap_values), axis=0).T
    for ci, cls in enumerate(class_names):
        top_feat_idx = np.argmax(mean_per_class[ci])
        feat_name    = FEATURE_LABELS.get(feature_cols[top_feat_idx], feature_cols[top_feat_idx])
        print(f"  {cls:8s}  ->  {feat_name}")


def main(use_insdn=False):
    suffix = "_insdn" if use_insdn else ""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("[*] Φόρτωση μοντέλου και δεδομένων...")
    model, X, y, class_names, feature_cols = get_model_and_data(use_insdn=use_insdn, sample=2000)

    print(f"[*] Υπολογισμός SHAP τιμών ({len(X)} δείγματα × {len(feature_cols)} features)...")
    shap_values = compute_shap(model, X)
    print(f"    Shape: {shap_values.shape}")

    plot_summary(shap_values, X, feature_cols, class_names, suffix)
    df_imp = plot_bar(shap_values, feature_cols, suffix)
    plot_class_heatmap(shap_values, feature_cols, class_names, suffix)
    print_findings(df_imp, class_names, shap_values, feature_cols)

    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Γραφήματα SHAP αποθηκεύτηκαν στο results/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--insdn", action="store_true")
    args = parser.parse_args()
    main(use_insdn=args.insdn)
