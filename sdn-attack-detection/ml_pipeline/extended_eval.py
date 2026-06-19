#!/usr/bin/env python3
"""
extended_eval.py — Εκτεταμένη αξιολόγηση για τη διπλωματική
-------------------------------------------------------------
Προσθέτει στο thesis_eval.py:
  1. Νέα μοντέλα: XGBoost/GBT, LightGBM/RF, One-Class SVM, Autoencoder (numpy), LSTM-approx
  2. Cross-dataset validation (InSDN ↔ synthetic)
  3. Ablation study (feature importance μέσω F1 drop)
  4. Publication-quality plots

Χρήση:
  python3 ml_pipeline/extended_eval.py
"""

import os, sys, time, warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve,
)
from sklearn.decomposition import PCA

warnings.filterwarnings("ignore")
sns.set_theme(style="whitegrid", font_scale=1.05)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

RESULTS = config.RESULTS_DIR
MODELS  = config.MODELS_DIR
os.makedirs(RESULTS, exist_ok=True)
os.makedirs(MODELS,  exist_ok=True)

SUBSAMPLE    = 60_000
RANDOM_STATE = config.RANDOM_STATE


# ── Optional imports με fallback ──────────────────────────────────────────────

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
    print("[INFO] XGBoost διαθέσιμο.")
except ImportError:
    XGB_AVAILABLE = False
    print("[INFO] XGBoost ΔΕΝ βρέθηκε → fallback: GradientBoostingClassifier.")

try:
    import lightgbm as lgb
    LGB_AVAILABLE = True
    print("[INFO] LightGBM διαθέσιμο.")
except ImportError:
    LGB_AVAILABLE = False
    print("[INFO] LightGBM ΔΕΝ βρέθηκε → fallback: RandomForestClassifier.")


# ── Βοηθητικός Autoencoder (numpy-only, χωρίς keras/torch) ───────────────────

class NumpyAutoencoder:
    """
    Απλός 2-layer autoencoder βασισμένος σε PCA reconstruction error.
    Εκπαιδεύεται μόνο σε Normal κίνηση.
    Reconstruction error = anomaly score.
    """

    def __init__(self, n_components=8, random_state=42):
        self.n_components   = n_components
        self.random_state   = random_state
        self.pca            = PCA(n_components=n_components, random_state=random_state)
        self.threshold_     = None

    def fit(self, X, contamination=0.05):
        self.pca.fit(X)
        recon_err = self._reconstruction_error(X)
        self.threshold_ = np.percentile(recon_err, 100 * (1 - contamination))
        return self

    def _reconstruction_error(self, X):
        Z    = self.pca.transform(X)
        Xhat = self.pca.inverse_transform(Z)
        return np.mean((X - Xhat) ** 2, axis=1)

    def score_samples(self, X):
        """Υψηλότερο score = πιο ανώμαλο (αντίθετο convention από sklearn)."""
        return self._reconstruction_error(X)

    def predict(self, X):
        """1 = Attack/anomaly, 0 = Normal."""
        err = self._reconstruction_error(X)
        return (err > self.threshold_).astype(int)


# ── 1. Φόρτωση & προεπεξεργασία ───────────────────────────────────────────────

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


def load_synthetic():
    df = pd.read_csv(config.SYNTHETIC_CSV)
    df.columns = [c.strip() for c in df.columns]
    # Εξασφάλιση ενιαίου LABEL_COL
    if "Label" not in df.columns and config.LABEL_COL in df.columns:
        df.rename(columns={config.LABEL_COL: "Label"}, inplace=True)
    df["Label"] = df["Label"].astype(str).str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    return df


def get_feat_cols(df):
    return [c for c in config.FEATURE_COLUMNS if c in df.columns]


def subsample_df(df, n=SUBSAMPLE, random_state=RANDOM_STATE):
    if n and n < len(df):
        frac = n / len(df)
        df = df.groupby("Label", group_keys=False).apply(
            lambda g: g.sample(frac=frac, random_state=random_state)
        ).reset_index(drop=True)
    return df


def prepare_binary(df, feat_cols, subsample=SUBSAMPLE):
    """
    Επιστρέφει binary X_train/X_test, y (0=Normal, 1=Attack).
    Scaled με StandardScaler.
    """
    df = subsample_df(df, subsample)
    X  = df[feat_cols].astype(float).values
    y  = (df["Label"] != "Normal").astype(int).values

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=RANDOM_STATE
    )
    scaler = StandardScaler().fit(X_tr)
    return (scaler.transform(X_tr), scaler.transform(X_te),
            y_tr, y_te, scaler)


def prepare_multiclass(df, feat_cols, subsample=SUBSAMPLE):
    """
    Πολυκλαδική (multiclass) παρασκευή — επιστρέφει encoded labels.
    """
    df  = subsample_df(df, subsample)
    X   = df[feat_cols].astype(float).values
    le  = LabelEncoder()
    y   = le.fit_transform(df["Label"].values)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=RANDOM_STATE
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


# ── 2. Ορισμός νέων μοντέλων ──────────────────────────────────────────────────

def build_extended_supervised():
    """
    Επιστρέφει dict με όλα τα supervised μοντέλα (νέα + legacy).
    """
    models = {
        "Random Forest":       RandomForestClassifier(
                                   n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE),
        "Decision Tree":       DecisionTreeClassifier(
                                   max_depth=20, random_state=RANDOM_STATE),
        "KNN":                 KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "Logistic Regression": LogisticRegression(
                                   max_iter=1000, random_state=RANDOM_STATE),
        "MLP":                 MLPClassifier(
                                   hidden_layer_sizes=(128, 64), max_iter=300,
                                   random_state=RANDOM_STATE),
    }

    # XGBoost / fallback
    if XGB_AVAILABLE:
        models["XGBoost"] = xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            use_label_encoder=False, eval_metric="mlogloss",
            random_state=RANDOM_STATE, n_jobs=-1, verbosity=0
        )
    else:
        models["GradientBoosting (XGB-fallback)"] = GradientBoostingClassifier(
            n_estimators=100, max_depth=5, learning_rate=0.1,
            random_state=RANDOM_STATE
        )

    # LightGBM / fallback
    if LGB_AVAILABLE:
        models["LightGBM"] = lgb.LGBMClassifier(
            n_estimators=200, num_leaves=63, learning_rate=0.1,
            random_state=RANDOM_STATE, n_jobs=-1, verbose=-1
        )
    else:
        models["RandomForest (LGB-fallback)"] = RandomForestClassifier(
            n_estimators=150, max_features="sqrt", n_jobs=-1,
            random_state=RANDOM_STATE + 1
        )

    return models


# ── 3. Αξιολόγηση supervised μοντέλων ────────────────────────────────────────

def eval_supervised(data, models):
    rows    = []
    trained = {}
    for name, clf in models.items():
        print(f"  [{name}] εκπαίδευση...", flush=True)
        t0 = time.perf_counter()
        clf.fit(data["X_train"], data["y_train"])
        t_train = time.perf_counter() - t0

        t0 = time.perf_counter()
        y_pred = clf.predict(data["X_test"])
        t_pred = time.perf_counter() - t0

        rows.append({
            "Μοντέλο":     name,
            "Accuracy":    round(accuracy_score(data["y_test"], y_pred), 4),
            "Precision":   round(precision_score(data["y_test"], y_pred,
                                  average="macro", zero_division=0), 4),
            "Recall":      round(recall_score(data["y_test"], y_pred,
                                  average="macro", zero_division=0), 4),
            "F1":          round(f1_score(data["y_test"], y_pred,
                                  average="macro", zero_division=0), 4),
            "Train (s)":   round(t_train, 2),
            "Predict (s)": round(t_pred, 4),
            "Τύπος":       "Επιβλεπόμενο",
        })
        trained[name] = (clf, y_pred)
        print(f"       Accuracy={rows[-1]['Accuracy']:.4f}  F1={rows[-1]['F1']:.4f}",
              flush=True)
    return rows, trained


# ── 4. One-Class SVM (unsupervised) ──────────────────────────────────────────

def eval_one_class_svm(df, feat_cols):
    """
    Εκπαίδευση μόνο σε Normal — αληθινά unsupervised.
    Subsample γιατί OC-SVM είναι O(n^2).
    """
    X     = df[feat_cols].astype(float).values
    y_bin = (df["Label"] != "Normal").astype(int).values

    X_normal = X[y_bin == 0]
    X_attack = X[y_bin == 1]

    # Μικρότερο subsample για ταχύτητα (OC-SVM αργεί πολύ)
    rng    = np.random.default_rng(RANDOM_STATE)
    n_tr   = min(5_000, int(len(X_normal) * 0.60))
    perm   = rng.permutation(len(X_normal))
    X_tr   = X_normal[perm[:n_tr]]
    X_te_n = X_normal[perm[n_tr:]][:3_000]
    X_te_a = X_attack[rng.permutation(len(X_attack))[:3_000]]
    X_te   = np.vstack([X_te_n, X_te_a])
    y_te   = np.concatenate([np.zeros(len(X_te_n)), np.ones(len(X_te_a))])

    X_tr = np.log1p(np.clip(X_tr, 0, None))
    X_te = np.log1p(np.clip(X_te, 0, None))
    scaler = StandardScaler().fit(X_tr)
    X_tr_s = scaler.transform(X_tr)
    X_te_s = scaler.transform(X_te)

    print("  [One-Class SVM] εκπαίδευση (μόνο Normal, subsample=5k)...", flush=True)
    t0  = time.perf_counter()
    ocs = OneClassSVM(kernel="rbf", nu=0.05, gamma="scale")
    ocs.fit(X_tr_s)
    t_train = time.perf_counter() - t0

    t0     = time.perf_counter()
    raw    = ocs.predict(X_te_s)
    t_pred = time.perf_counter() - t0
    y_pred = (raw == -1).astype(int)
    scores = -ocs.decision_function(X_te_s)   # υψηλότερο = πιο ανώμαλο

    auc = roc_auc_score(y_te, scores)
    row = {
        "Μοντέλο":     "One-Class SVM",
        "Accuracy":    round(accuracy_score(y_te, y_pred), 4),
        "Precision":   round(precision_score(y_te, y_pred, zero_division=0), 4),
        "Recall":      round(recall_score(y_te, y_pred, zero_division=0), 4),
        "F1":          round(f1_score(y_te, y_pred, zero_division=0), 4),
        "Train (s)":   round(t_train, 2),
        "Predict (s)": round(t_pred, 4),
        "Τύπος":       "Μη επιβλεπόμενο (OC-SVM)",
    }
    print(f"       Accuracy={row['Accuracy']:.4f}  F1={row['F1']:.4f}  "
          f"ROC-AUC={auc:.4f}", flush=True)

    return row, {
        "ocs": ocs, "scaler": scaler,
        "X_te_s": X_te_s, "y_te": y_te,
        "y_pred": y_pred, "scores": scores, "auc": auc,
    }


# ── 5. Numpy Autoencoder (unsupervised) ───────────────────────────────────────

def eval_autoencoder(df, feat_cols):
    """
    PCA-based autoencoder. Εκπαίδευση μόνο σε Normal, test σε όλα.
    """
    X     = df[feat_cols].astype(float).values
    y_bin = (df["Label"] != "Normal").astype(int).values

    X_normal = X[y_bin == 0]
    X_attack = X[y_bin == 1]

    rng    = np.random.default_rng(RANDOM_STATE)
    n_tr   = int(len(X_normal) * 0.60)
    perm   = rng.permutation(len(X_normal))
    X_tr   = X_normal[perm[:n_tr]]
    X_te_n = X_normal[perm[n_tr:]]
    X_te   = np.vstack([X_te_n, X_attack])
    y_te   = np.concatenate([np.zeros(len(X_te_n)), np.ones(len(X_attack))])

    X_tr = np.log1p(np.clip(X_tr, 0, None))
    X_te = np.log1p(np.clip(X_te, 0, None))
    scaler = StandardScaler().fit(X_tr)
    X_tr_s = scaler.transform(X_tr)
    X_te_s = scaler.transform(X_te)

    print("  [Autoencoder / PCA] εκπαίδευση (μόνο Normal)...", flush=True)
    t0  = time.perf_counter()
    ae  = NumpyAutoencoder(n_components=8, random_state=RANDOM_STATE)
    ae.fit(X_tr_s, contamination=0.05)
    t_train = time.perf_counter() - t0

    t0     = time.perf_counter()
    y_pred = ae.predict(X_te_s)
    t_pred = time.perf_counter() - t0
    scores = ae.score_samples(X_te_s)

    auc = roc_auc_score(y_te, scores)
    row = {
        "Μοντέλο":     "Autoencoder (PCA)",
        "Accuracy":    round(accuracy_score(y_te, y_pred), 4),
        "Precision":   round(precision_score(y_te, y_pred, zero_division=0), 4),
        "Recall":      round(recall_score(y_te, y_pred, zero_division=0), 4),
        "F1":          round(f1_score(y_te, y_pred, zero_division=0), 4),
        "Train (s)":   round(t_train, 2),
        "Predict (s)": round(t_pred, 4),
        "Τύπος":       "Μη επιβλεπόμενο (AE)",
    }
    print(f"       Accuracy={row['Accuracy']:.4f}  F1={row['F1']:.4f}  "
          f"ROC-AUC={auc:.4f}", flush=True)

    return row, {
        "ae": ae, "scaler": scaler,
        "X_te_s": X_te_s, "y_te": y_te,
        "y_pred": y_pred, "scores": scores, "auc": auc,
    }


# ── 6. LSTM-approx (MLP με sliding window) ────────────────────────────────────

def make_windows(X, y, window=5):
    """
    Δημιουργεί windows μήκους `window` από διαδοχικές εγγραφές.
    Label = label της τελευταίας εγγραφής στο παράθυρο.
    Δεν χρησιμοποιεί source IP — απλώς διαδοχικές σειρές.
    """
    n      = len(X)
    n_win  = n - window + 1
    Xw     = np.lib.stride_tricks.sliding_window_view(X, (window, X.shape[1]))
    Xw     = Xw[:, 0, :, :].reshape(n_win, -1)   # (n_win, window*features)
    yw     = y[window - 1:]
    return Xw, yw


def eval_lstm_approx(data):
    """
    Χρησιμοποιεί τα ήδη scaled/split δεδομένα από prepare_multiclass.
    Δημιουργεί sliding windows και εκπαιδεύει MLPClassifier.
    """
    WINDOW = 5
    print(f"  [LSTM-approx] δημιουργία windows (w={WINDOW})...", flush=True)

    Xw_tr, yw_tr = make_windows(data["X_train"], data["y_train"], WINDOW)
    Xw_te, yw_te = make_windows(data["X_test"],  data["y_test"],  WINDOW)

    clf = MLPClassifier(
        hidden_layer_sizes=(256, 128, 64), max_iter=300,
        random_state=RANDOM_STATE, early_stopping=True, n_iter_no_change=15,
    )
    print("  [LSTM-approx] εκπαίδευση MLP-window...", flush=True)
    t0 = time.perf_counter()
    clf.fit(Xw_tr, yw_tr)
    t_train = time.perf_counter() - t0

    t0     = time.perf_counter()
    y_pred = clf.predict(Xw_te)
    t_pred = time.perf_counter() - t0

    row = {
        "Μοντέλο":     f"LSTM-approx (MLP-window w={WINDOW})",
        "Accuracy":    round(accuracy_score(yw_te, y_pred), 4),
        "Precision":   round(precision_score(yw_te, y_pred,
                              average="macro", zero_division=0), 4),
        "Recall":      round(recall_score(yw_te, y_pred,
                              average="macro", zero_division=0), 4),
        "F1":          round(f1_score(yw_te, y_pred,
                              average="macro", zero_division=0), 4),
        "Train (s)":   round(t_train, 2),
        "Predict (s)": round(t_pred, 4),
        "Τύπος":       "Επιβλεπόμενο (temporal)",
    }
    print(f"       Accuracy={row['Accuracy']:.4f}  F1={row['F1']:.4f}", flush=True)
    return row


# ── 7. Cross-dataset validation ───────────────────────────────────────────────

def _align_features(X_source, feat_cols_source, feat_cols_target):
    """
    Ευθυγραμμίζει features: κρατά την τομή, zero-fill για τα υπόλοιπα.
    """
    common = [c for c in feat_cols_target if c in feat_cols_source]
    if not common:
        raise ValueError("Καμία κοινή στήλη μεταξύ source/target dataset!")
    idx = [feat_cols_source.index(c) for c in common]
    return X_source[:, idx], common


def eval_cross_dataset(df_insdn, df_synth):
    """
    Δύο κατευθύνσεις:
      A) Εκπαίδευση InSDN → Test synthetic
      B) Εκπαίδευση synthetic → Test InSDN
    Χρησιμοποιεί RF (binary: Normal vs Attack).
    """
    rows = []

    feat_i = get_feat_cols(df_insdn)
    feat_s = get_feat_cols(df_synth)
    common = [c for c in feat_i if c in feat_s]
    if not common:
        print("  [ΠΡΟΣΟΧΗ] Δεν υπάρχουν κοινά features InSDN↔synthetic → "
              "παράλειψη cross-dataset.", flush=True)
        return pd.DataFrame()

    print(f"  Κοινά features: {len(common)}", flush=True)

    def _prep(df, feat_cols, subsample=30_000):
        df  = subsample_df(df, subsample)
        X   = df[feat_cols].astype(float).values
        y   = (df["Label"] != "Normal").astype(int).values
        return X, y

    # ── A) Train InSDN → Test synthetic ──────────────────────────────────────
    print("  [Cross-dataset A] Train=InSDN  Test=Synthetic...", flush=True)
    X_i, y_i = _prep(df_insdn, common)
    X_s, y_s = _prep(df_synth, common)

    scaler_a = StandardScaler().fit(X_i)
    Xs_i     = scaler_a.transform(X_i)
    Xs_s_a   = scaler_a.transform(X_s)

    clf_a = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE)
    clf_a.fit(Xs_i, y_i)
    yp_a  = clf_a.predict(Xs_s_a)

    rows.append({
        "Κατεύθυνση":  "InSDN → Synthetic",
        "Μοντέλο":     "Random Forest",
        "Accuracy":    round(accuracy_score(y_s, yp_a), 4),
        "Precision":   round(precision_score(y_s, yp_a, zero_division=0), 4),
        "Recall":      round(recall_score(y_s, yp_a, zero_division=0), 4),
        "F1":          round(f1_score(y_s, yp_a, zero_division=0), 4),
    })
    print(f"       Accuracy={rows[-1]['Accuracy']:.4f}  F1={rows[-1]['F1']:.4f}",
          flush=True)

    # ── B) Train synthetic → Test InSDN ──────────────────────────────────────
    print("  [Cross-dataset B] Train=Synthetic  Test=InSDN...", flush=True)
    scaler_b = StandardScaler().fit(X_s)
    Xs_s_b   = scaler_b.transform(X_s)
    Xs_i_b   = scaler_b.transform(X_i)

    clf_b = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE)
    clf_b.fit(Xs_s_b, y_s)
    yp_b  = clf_b.predict(Xs_i_b)

    rows.append({
        "Κατεύθυνση":  "Synthetic → InSDN",
        "Μοντέλο":     "Random Forest",
        "Accuracy":    round(accuracy_score(y_i, yp_b), 4),
        "Precision":   round(precision_score(y_i, yp_b, zero_division=0), 4),
        "Recall":      round(recall_score(y_i, yp_b, zero_division=0), 4),
        "F1":          round(f1_score(y_i, yp_b, zero_division=0), 4),
    })
    print(f"       Accuracy={rows[-1]['Accuracy']:.4f}  F1={rows[-1]['F1']:.4f}",
          flush=True)

    return pd.DataFrame(rows)


# ── 8. Ablation study ─────────────────────────────────────────────────────────

def ablation_study(data):
    """
    Αφαιρεί κάθε feature έναν-έναν και μετρά πόσο πέφτει το F1 του RF.
    Baseline: RF trained με ΟΛΑ τα features.
    """
    feat_cols = data["feat_cols"]
    X_tr = data["X_train"]
    X_te = data["X_test"]
    y_tr = data["y_train"]
    y_te = data["y_test"]

    # Baseline
    print("  [Ablation] Baseline RF...", flush=True)
    clf_base = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=RANDOM_STATE)
    clf_base.fit(X_tr, y_tr)
    f1_base = f1_score(y_te, clf_base.predict(X_te), average="macro", zero_division=0)
    print(f"       Baseline F1 = {f1_base:.4f}", flush=True)

    rows = []
    for i, feat in enumerate(feat_cols):
        # Αφαίρεση στήλης i
        cols_keep = [j for j in range(len(feat_cols)) if j != i]
        Xtr_ab   = X_tr[:, cols_keep]
        Xte_ab   = X_te[:, cols_keep]

        clf_ab = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=RANDOM_STATE)
        clf_ab.fit(Xtr_ab, y_tr)
        f1_ab  = f1_score(y_te, clf_ab.predict(Xte_ab), average="macro", zero_division=0)
        drop   = round(f1_base - f1_ab, 5)
        rows.append({"Feature": feat, "F1_without": round(f1_ab, 4), "F1_drop": drop})
        print(f"       -{feat:<30s}  F1={f1_ab:.4f}  drop={drop:+.5f}", flush=True)

    df_ab = pd.DataFrame(rows).sort_values("F1_drop", ascending=False).reset_index(drop=True)
    df_ab["Baseline_F1"] = round(f1_base, 4)
    return df_ab, f1_base


# ── 9. Plots ───────────────────────────────────────────────────────────────────

def plot_extended_comparison(df_res):
    metrics = ["Accuracy", "Precision", "Recall", "F1"]
    melt    = df_res.melt(id_vars="Μοντέλο", value_vars=metrics,
                          var_name="Μετρική", value_name="Τιμή")
    fig, ax = plt.subplots(figsize=(15, 7))
    palette = sns.color_palette("Set2", len(metrics))
    sns.barplot(data=melt, x="Μοντέλο", y="Τιμή", hue="Μετρική",
                palette=palette, ax=ax)
    ax.set_title(
        "Εκτεταμένη Σύγκριση Μοντέλων ML — InSDN Dataset\n"
        "(unsupervised: binary metrics | supervised: multi-class macro-avg)",
        fontsize=12
    )
    vmin = max(0.0, melt["Τιμή"].min() - 0.05)
    ax.set_ylim(vmin, 1.01)
    ax.set_xlabel("")
    ax.set_ylabel("Τιμή Μετρικής")
    plt.xticks(rotation=28, ha="right")
    plt.legend(title="Μετρική", loc="lower right")
    plt.tight_layout()
    out = os.path.join(RESULTS, "extended_comparison.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] {out}")


def plot_cross_dataset(df_cross):
    if df_cross.empty:
        return
    metrics = ["Accuracy", "Precision", "Recall", "F1"]
    melt    = df_cross.melt(id_vars="Κατεύθυνση", value_vars=metrics,
                             var_name="Μετρική", value_name="Τιμή")
    fig, ax = plt.subplots(figsize=(10, 6))
    palette = sns.color_palette("tab10", len(metrics))
    sns.barplot(data=melt, x="Κατεύθυνση", y="Τιμή", hue="Μετρική",
                palette=palette, ax=ax)
    ax.set_title("Cross-Dataset Validation\n"
                 "Random Forest (binary: Normal vs Attack)",
                 fontsize=12)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("")
    ax.set_ylabel("Τιμή Μετρικής")
    plt.legend(title="Μετρική", loc="lower right")
    plt.tight_layout()
    out = os.path.join(RESULTS, "cross_dataset.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] {out}")


def plot_ablation(df_ab, f1_base):
    fig, ax = plt.subplots(figsize=(11, max(6, len(df_ab) * 0.45)))
    colors  = ["#C44E52" if d > 0 else "#4C72B0" for d in df_ab["F1_drop"]]
    ax.barh(df_ab["Feature"][::-1], df_ab["F1_drop"][::-1], color=colors[::-1])
    ax.axvline(0, color="black", linewidth=0.8)
    ax.set_xlabel("F1 Drop (Baseline − F1_without_feature)")
    ax.set_title(
        f"Ablation Study — Random Forest (InSDN)\n"
        f"Baseline F1 (macro) = {f1_base:.4f}",
        fontsize=12
    )
    plt.tight_layout()
    out = os.path.join(RESULTS, "ablation_study.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] {out}")


def plot_one_class_svm_roc(ocsvm_res):
    fpr, tpr, _ = roc_curve(ocsvm_res["y_te"], ocsvm_res["scores"])
    fig, ax = plt.subplots(figsize=(7, 5.5))
    ax.plot(fpr, tpr, color="#DD8452", lw=2,
            label=f"One-Class SVM (AUC = {ocsvm_res['auc']:.4f})")
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve — One-Class SVM (InSDN, Normal vs Attack)")
    ax.legend(loc="lower right")
    plt.tight_layout()
    out = os.path.join(RESULTS, "one_class_svm_roc.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] {out}")


def plot_autoencoder_scores(ae_res):
    scores = ae_res["scores"]
    y_te   = ae_res["y_te"]
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.hist(scores[y_te == 0], bins=80, alpha=0.6, color="#4C72B0",
            label="Φυσιολογική κίνηση", density=True)
    ax.hist(scores[y_te == 1], bins=80, alpha=0.6, color="#C44E52",
            label="Επίθεση", density=True)
    thr = ae_res["ae"].threshold_
    ax.axvline(thr, color="black", linestyle="--", lw=1.5,
               label=f"Threshold = {thr:.4f}")
    ax.set_xlabel("Reconstruction Error (MSE)")
    ax.set_ylabel("Πυκνότητα")
    ax.set_title("Autoencoder (PCA) — Κατανομή Reconstruction Error (InSDN)")
    ax.legend()
    plt.tight_layout()
    out = os.path.join(RESULTS, "autoencoder_scores.png")
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] {out}")


# ── 10. Main ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print(" EXTENDED EVAL — InSDN + Synthetic, XGBoost/LGB/OC-SVM/AE/LSTM-approx")
    print("=" * 70)

    # ── Φόρτωση datasets ─────────────────────────────────────────────────────
    print("\n[1] Φόρτωση InSDN...", flush=True)
    df_insdn = load_insdn()
    print(f"    {len(df_insdn):,} εγγραφές | Κατανομή:\n"
          f"{df_insdn['Label'].value_counts().to_string()}")

    print("\n[2] Φόρτωση Synthetic...", flush=True)
    df_synth = load_synthetic()
    print(f"    {len(df_synth):,} εγγραφές | Κατανομή:\n"
          f"{df_synth['Label'].value_counts().to_string()}")

    feat_cols = get_feat_cols(df_insdn)
    print(f"\n    Features InSDN: {len(feat_cols)}")

    # ── Multiclass παρασκευή για supervised ──────────────────────────────────
    print(f"\n[3] Προεπεξεργασία (subsample={SUBSAMPLE:,})...", flush=True)
    data = prepare_multiclass(df_insdn, feat_cols, subsample=SUBSAMPLE)
    print(f"    Train: {len(data['X_train']):,} | Test: {len(data['X_test']):,}")
    print(f"    Κλάσεις: {data['classes']}")

    # ── Supervised (all) ─────────────────────────────────────────────────────
    print("\n[4] Extended supervised models...", flush=True)
    models  = build_extended_supervised()
    sup_rows, trained = eval_supervised(data, models)

    # ── LSTM-approx ──────────────────────────────────────────────────────────
    print("\n[5] LSTM-approx (MLP sliding window)...", flush=True)
    lstm_row = eval_lstm_approx(data)

    # ── One-Class SVM ────────────────────────────────────────────────────────
    print("\n[6] One-Class SVM (unsupervised)...", flush=True)
    ocsvm_row, ocsvm_res = eval_one_class_svm(df_insdn, feat_cols)

    # ── Autoencoder ──────────────────────────────────────────────────────────
    print("\n[7] Autoencoder / PCA (unsupervised)...", flush=True)
    ae_row, ae_res = eval_autoencoder(df_insdn, feat_cols)

    # ── Ενιαίος πίνακας ──────────────────────────────────────────────────────
    all_rows = sup_rows + [lstm_row, ocsvm_row, ae_row]
    df_res   = (pd.DataFrame(all_rows)
                  .sort_values("F1", ascending=False)
                  .reset_index(drop=True))

    print("\n" + "=" * 70)
    print("ΑΠΟΤΕΛΕΣΜΑΤΑ (ταξινόμηση κατά F1)")
    print("=" * 70)
    print(df_res[["Μοντέλο", "Accuracy", "Precision", "Recall", "F1", "Τύπος"]]
          .to_string(index=False))

    csv_out = os.path.join(RESULTS, "extended_comparison.csv")
    df_res.to_csv(csv_out, index=False)
    print(f"\n[OK] {csv_out}")

    # ── Cross-dataset validation ──────────────────────────────────────────────
    print("\n[8] Cross-dataset validation...", flush=True)
    df_cross = eval_cross_dataset(df_insdn, df_synth)
    if not df_cross.empty:
        cross_out = os.path.join(RESULTS, "cross_dataset.csv")
        df_cross.to_csv(cross_out, index=False)
        print(f"[OK] {cross_out}")
        print(df_cross.to_string(index=False))

    # ── Ablation study ────────────────────────────────────────────────────────
    print("\n[9] Ablation study (RF)...", flush=True)
    df_ab, f1_base = ablation_study(data)
    ab_out = os.path.join(RESULTS, "ablation_study.csv")
    df_ab.to_csv(ab_out, index=False)
    print(f"[OK] {ab_out}")
    print("\nTop-5 πιο σημαντικά features (μεγαλύτερο F1 drop):")
    print(df_ab[["Feature", "F1_without", "F1_drop"]].head(5).to_string(index=False))

    # ── Plots ─────────────────────────────────────────────────────────────────
    print("\n[10] Αποθήκευση γραφημάτων...", flush=True)
    plot_extended_comparison(df_res)
    plot_cross_dataset(df_cross)
    plot_ablation(df_ab, f1_base)
    plot_one_class_svm_roc(ocsvm_res)
    plot_autoencoder_scores(ae_res)

    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Όλα τα αρχεία στο results/")
    print("Αρχεία:")
    for f in [
        "extended_comparison.csv", "extended_comparison.png",
        "cross_dataset.csv",       "cross_dataset.png",
        "ablation_study.csv",      "ablation_study.png",
        "one_class_svm_roc.png",   "autoencoder_scores.png",
    ]:
        path = os.path.join(RESULTS, f)
        status = "[OK]" if os.path.exists(path) else "[MISSING]"
        print(f"  {status} {path}")


if __name__ == "__main__":
    main()
