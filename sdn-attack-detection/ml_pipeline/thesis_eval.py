#!/usr/bin/env python3
"""
thesis_eval.py — Ενιαία αξιολόγηση για τη διπλωματική
-------------------------------------------------------
Τρέχει όλα τα μοντέλα στο InSDN dataset και παράγει:
  1. Συγκριτικός πίνακας: Isolation Forest vs supervised (Accuracy/Precision/Recall/F1)
  2. Confusion matrix ανά μοντέλο (RF + IF)
  3. ROC curves (supervised binary + IF)
  4. Classification report (RF — καλύτερο supervised)
  5. Feature importance (RF)
  6. Anomaly score distribution (IF)

Χρήση:
  python3 ml_pipeline/thesis_eval.py
"""

import os, sys, time, warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
    roc_auc_score, roc_curve,
)

warnings.filterwarnings("ignore")
sns.set_theme(style="whitegrid", font_scale=1.05)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

RESULTS = config.RESULTS_DIR
MODELS  = config.MODELS_DIR
os.makedirs(RESULTS, exist_ok=True)
os.makedirs(MODELS,  exist_ok=True)

# Subsample για να τρέξουν και τα αργά μοντέλα (KNN/SVM) σε λογικό χρόνο
# Stratified: διατηρεί την κατανομή κλάσεων
SUBSAMPLE = 60_000   # από 343k → 60k, ίδια κατανομή


# ── 1. Φόρτωση & προεπεξεργασία InSDN ────────────────────────────────────────

def load_insdn():
    df = pd.read_csv(config.INSDN_CSV)
    df.columns = [c.strip() for c in df.columns]
    label_map = {
        "Normal": "Normal", "BENIGN": "Normal",
        "DDoS": "DDoS", "DoS": "DoS",
        "Probe": "Probe", "Port Scan": "Probe",
        "BFA": "BFA", "Brute Force": "BFA",
    }
    df["Label"] = df["Label"].astype(str).str.strip().map(lambda x: label_map.get(x, x))
    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    return df


def prepare(df, subsample=SUBSAMPLE):
    feat_cols = [c for c in config.FEATURE_COLUMNS if c in df.columns]

    # Stratified subsample
    if subsample and subsample < len(df):
        frac = subsample / len(df)
        df = df.groupby("Label", group_keys=False).apply(
            lambda g: g.sample(frac=frac, random_state=config.RANDOM_STATE)
        ).reset_index(drop=True)

    X = df[feat_cols].astype(float).values
    le = LabelEncoder()
    y = le.fit_transform(df["Label"].values)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=config.RANDOM_STATE
    )
    scaler = StandardScaler().fit(X_tr)
    return {
        "X_train": scaler.transform(X_tr),
        "X_test":  scaler.transform(X_te),
        "X_train_raw": X_tr,
        "X_test_raw":  X_te,
        "y_train": y_tr, "y_test": y_te,
        "classes": list(le.classes_),
        "le": le, "scaler": scaler, "feat_cols": feat_cols,
    }


# ── 2. Supervised models ──────────────────────────────────────────────────────

SUPERVISED = {
    "Random Forest":      RandomForestClassifier(n_estimators=200, n_jobs=-1,  random_state=42),
    "Decision Tree":      DecisionTreeClassifier(max_depth=20,                 random_state=42),
    "KNN":                KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
    "Logistic Regression":LogisticRegression(max_iter=1000,                   random_state=42),
    "MLP":                MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=300, random_state=42),
}


def eval_supervised(data):
    rows = []
    trained = {}
    for name, clf in SUPERVISED.items():
        print(f"  [{name}] εκπαίδευση...", flush=True)
        t0 = time.perf_counter()
        clf.fit(data["X_train"], data["y_train"])
        t_train = time.perf_counter() - t0

        t0 = time.perf_counter()
        y_pred = clf.predict(data["X_test"])
        t_pred = time.perf_counter() - t0

        rows.append({
            "Μοντέλο":    name,
            "Accuracy":   round(accuracy_score(data["y_test"], y_pred), 4),
            "Precision":  round(precision_score(data["y_test"], y_pred, average="macro", zero_division=0), 4),
            "Recall":     round(recall_score(data["y_test"], y_pred,    average="macro", zero_division=0), 4),
            "F1":         round(f1_score(data["y_test"], y_pred,        average="macro", zero_division=0), 4),
            "Train (s)":  round(t_train, 2),
            "Predict (s)":round(t_pred,  4),
            "Τύπος":      "Επιβλεπόμενο",
        })
        trained[name] = (clf, y_pred)
        print(f"       Accuracy={rows[-1]['Accuracy']:.4f}  F1={rows[-1]['F1']:.4f}", flush=True)
    return rows, trained


# ── 3. Isolation Forest (unsupervised) ───────────────────────────────────────

def eval_isolation_forest(df):
    """
    Εκπαίδευση ΜΟΝΟ σε Normal κίνηση — αληθινά unsupervised.
    Test set: υπόλοιπα Normal + ΟΛΕΣ οι επιθέσεις.
    """
    feat_cols = [c for c in config.FEATURE_COLUMNS if c in df.columns]
    X = df[feat_cols].astype(float).values
    y_bin = (df["Label"] != "Normal").astype(int).values

    X_normal = X[y_bin == 0]
    X_attack = X[y_bin == 1]

    rng = np.random.default_rng(42)
    perm = rng.permutation(len(X_normal))
    n_train = int(len(X_normal) * 0.60)
    X_tr = X_normal[perm[:n_train]]
    X_te = np.vstack([X_normal[perm[n_train:]], X_attack])
    y_te = np.concatenate([np.zeros(len(perm) - n_train), np.ones(len(X_attack))])

    # log-transform (κρίσιμο για skewed network features)
    X_tr = np.log1p(np.clip(X_tr, 0, None))
    X_te = np.log1p(np.clip(X_te, 0, None))

    scaler = StandardScaler().fit(X_tr)
    X_tr_s = scaler.transform(X_tr)
    X_te_s = scaler.transform(X_te)

    print("  [Isolation Forest] εκπαίδευση (μόνο Normal)...", flush=True)
    t0 = time.perf_counter()
    iso = IsolationForest(n_estimators=300, max_samples=512,
                          contamination=0.05, max_features=0.5,
                          random_state=42, n_jobs=-1)
    iso.fit(X_tr_s)
    t_train = time.perf_counter() - t0

    t0 = time.perf_counter()
    raw = iso.predict(X_te_s)
    t_pred = time.perf_counter() - t0
    y_pred = (raw == -1).astype(int)
    scores = -iso.decision_function(X_te_s)

    auc = roc_auc_score(y_te, scores)
    row = {
        "Μοντέλο":    "Isolation Forest",
        "Accuracy":   round(accuracy_score(y_te, y_pred), 4),
        "Precision":  round(precision_score(y_te, y_pred, zero_division=0), 4),
        "Recall":     round(recall_score(y_te, y_pred,    zero_division=0), 4),
        "F1":         round(f1_score(y_te, y_pred,        zero_division=0), 4),
        "Train (s)":  round(t_train, 2),
        "Predict (s)":round(t_pred, 4),
        "Τύπος":      "Μη επιβλεπόμενο (IF)",
    }
    print(f"       Accuracy={row['Accuracy']:.4f}  F1={row['F1']:.4f}  ROC-AUC={auc:.4f}", flush=True)

    joblib.dump(iso,    os.path.join(MODELS, "isolation_forest_best.pkl"))
    joblib.dump(scaler, os.path.join(MODELS, "isolation_forest_best_scaler.pkl"))

    return row, {"iso": iso, "scaler": scaler,
                 "X_te_s": X_te_s, "y_te": y_te,
                 "y_pred": y_pred, "scores": scores, "auc": auc}


# ── 4. Plots ──────────────────────────────────────────────────────────────────

def plot_comparison(df_res):
    """Bar chart: Accuracy / Precision / Recall / F1 για κάθε μοντέλο."""
    metrics = ["Accuracy", "Precision", "Recall", "F1"]
    melt = df_res.melt(id_vars="Μοντέλο", value_vars=metrics,
                       var_name="Μετρική", value_name="Τιμή")
    fig, ax = plt.subplots(figsize=(13, 6))
    palette = sns.color_palette("Set2", len(metrics))
    sns.barplot(data=melt, x="Μοντέλο", y="Τιμή", hue="Μετρική",
                palette=palette, ax=ax)
    ax.set_title("Σύγκριση Μοντέλων ML — InSDN Dataset\n"
                 "(Isolation Forest: unsupervised binary | Supervised: multi-class macro-avg)",
                 fontsize=12)
    ax.set_ylim(min(0.80, melt["Τιμή"].min() - 0.03), 1.005)
    ax.set_xlabel(""); ax.set_ylabel("Τιμή Μετρικής")
    plt.xticks(rotation=20, ha="right")
    plt.legend(title="Μετρική", loc="lower right")
    plt.tight_layout()
    out = os.path.join(RESULTS, "thesis_model_comparison.png")
    plt.savefig(out, dpi=150); plt.close()
    print(f"[OK] {out}")


def plot_confusion_rf(clf, data):
    y_pred = clf.predict(data["X_test"])
    cm = confusion_matrix(data["y_test"], y_pred)
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(8, 6.5))
    sns.heatmap(cm_norm, annot=cm, fmt="d", cmap="Blues",
                xticklabels=data["classes"], yticklabels=data["classes"],
                cbar_kws={"label": "Ποσοστό (κανονικοπ. ανά γραμμή)"}, ax=ax)
    ax.set_title("Random Forest — Confusion Matrix (InSDN)")
    ax.set_ylabel("Πραγματική κλάση"); ax.set_xlabel("Προβλεπόμενη κλάση")
    plt.tight_layout()
    out = os.path.join(RESULTS, "thesis_rf_confusion.png")
    plt.savefig(out, dpi=150); plt.close()
    print(f"[OK] {out}")


def plot_confusion_if(if_res):
    cm = confusion_matrix(if_res["y_te"], if_res["y_pred"])
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Oranges",
                xticklabels=["Normal", "Attack"],
                yticklabels=["Normal", "Attack"], ax=ax)
    ax.set_title(f"Isolation Forest — Confusion Matrix (InSDN)\nROC AUC = {if_res['auc']:.4f}")
    ax.set_ylabel("Πραγματική"); ax.set_xlabel("Προβλεπόμενη")
    plt.tight_layout()
    out = os.path.join(RESULTS, "thesis_if_confusion.png")
    plt.savefig(out, dpi=150); plt.close()
    print(f"[OK] {out}")


def plot_roc_if(if_res):
    fpr, tpr, _ = roc_curve(if_res["y_te"], if_res["scores"])
    fig, ax = plt.subplots(figsize=(7, 5.5))
    ax.plot(fpr, tpr, color="#C44E52", lw=2,
            label=f"Isolation Forest (AUC = {if_res['auc']:.4f})")
    ax.plot([0,1],[0,1], "k--", lw=1)
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve — Isolation Forest (InSDN, Normal vs Attack)")
    ax.legend(loc="lower right")
    plt.tight_layout()
    out = os.path.join(RESULTS, "thesis_if_roc.png")
    plt.savefig(out, dpi=150); plt.close()
    print(f"[OK] {out}")


def plot_anomaly_scores(if_res):
    scores, y_te = if_res["scores"], if_res["y_te"]
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.hist(scores[y_te == 0], bins=80, alpha=0.6, color="#4C72B0",
            label="Φυσιολογική κίνηση", density=True)
    ax.hist(scores[y_te == 1], bins=80, alpha=0.6, color="#C44E52",
            label="Επίθεση", density=True)
    ax.axvline(0, color="black", linestyle="--", lw=1.5, label="Κατώφλι f(x)=0")
    ax.set_xlabel("Anomaly Score (μεγαλύτερο = πιο ανώμαλο)")
    ax.set_ylabel("Πυκνότητα")
    ax.set_title("Isolation Forest — Κατανομή Anomaly Score (InSDN)")
    ax.legend()
    plt.tight_layout()
    out = os.path.join(RESULTS, "thesis_if_scores.png")
    plt.savefig(out, dpi=150); plt.close()
    print(f"[OK] {out}")


def plot_feature_importance(clf, feat_cols):
    if not hasattr(clf, "feature_importances_"):
        return
    imp = clf.feature_importances_
    order = np.argsort(imp)[::-1][:15]
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.barplot(x=imp[order], y=np.array(feat_cols)[order],
                palette="viridis", hue=np.array(feat_cols)[order], legend=False, ax=ax)
    ax.set_title("Top-15 Σημαντικότητα Χαρακτηριστικών — Random Forest (InSDN)")
    ax.set_xlabel("Σημαντικότητα"); ax.set_ylabel("")
    plt.tight_layout()
    out = os.path.join(RESULTS, "thesis_feature_importance.png")
    plt.savefig(out, dpi=150); plt.close()
    print(f"[OK] {out}")


# ── 5. Main ───────────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print(" THESIS EVAL — InSDN dataset, IF + Supervised comparison")
    print("=" * 65)

    print("\n[1] Φόρτωση InSDN...", flush=True)
    df = load_insdn()
    print(f"    {len(df):,} εγγραφές | Κατανομή:\n{df['Label'].value_counts().to_string()}")

    print("\n[2] Προεπεξεργασία (subsample={:,})...".format(SUBSAMPLE), flush=True)
    data = prepare(df, subsample=SUBSAMPLE)
    print(f"    Train: {len(data['X_train']):,} | Test: {len(data['X_test']):,}")
    print(f"    Κλάσεις: {data['classes']}")

    print("\n[3] Supervised models...", flush=True)
    sup_rows, trained = eval_supervised(data)

    print("\n[4] Isolation Forest (unsupervised)...", flush=True)
    if_row, if_res = eval_isolation_forest(df)  # χρησιμοποιεί ΟΛΟ το df (no subsample)

    # Ενιαίος πίνακας
    all_rows = sup_rows + [if_row]
    df_res = pd.DataFrame(all_rows).sort_values("F1", ascending=False).reset_index(drop=True)

    print("\n" + "=" * 65)
    print("ΑΠΟΤΕΛΕΣΜΑΤΑ (ταξινόμηση κατά F1)")
    print("=" * 65)
    print(df_res[["Μοντέλο", "Accuracy", "Precision", "Recall", "F1", "Τύπος"]].to_string(index=False))

    csv_out = os.path.join(RESULTS, "thesis_comparison.csv")
    df_res.to_csv(csv_out, index=False)
    print(f"\n[OK] {csv_out}")

    print("\n[5] Αποθήκευση best supervised (RF)...", flush=True)
    rf_clf, _ = trained["Random Forest"]
    joblib.dump(rf_clf, os.path.join(MODELS, "best_model.pkl"))
    joblib.dump(data["scaler"], os.path.join(MODELS, "scaler.pkl"))
    joblib.dump(data["le"],     os.path.join(MODELS, "label_encoder.pkl"))

    # Classification report (RF)
    rf_pred = rf_clf.predict(data["X_test"])
    report = classification_report(data["y_test"], rf_pred,
                                   target_names=data["classes"], digits=4, zero_division=0)
    rep_out = os.path.join(RESULTS, "thesis_classification_report.txt")
    with open(rep_out, "w") as f:
        f.write("CLASSIFICATION REPORT — Random Forest (InSDN dataset)\n")
        f.write("=" * 60 + "\n\n")
        f.write(report)
    print(f"[OK] {rep_out}")
    print(report)

    print("\n[6] Γράφηματα...", flush=True)
    plot_comparison(df_res)
    plot_confusion_rf(rf_clf, data)
    plot_confusion_if(if_res)
    plot_roc_if(if_res)
    plot_anomaly_scores(if_res)
    plot_feature_importance(rf_clf, data["feat_cols"])

    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Όλα τα αρχεία στο results/")


if __name__ == "__main__":
    main()
