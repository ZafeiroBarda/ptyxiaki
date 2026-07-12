# -*- coding: utf-8 -*-
"""Adversarial training: Original RF vs Robust RF (mimicry evasion vs epsilon).

Εκτέλεση:  python3 ml_pipeline/adversarial_training.py
Έξοδοι:    results/adv_robust_comparison.csv, adv_robust_clean.csv,
           adv_robust_mcnemar.txt, adv_robust_evasion.png
           models/robust_rf.pkl (+ robust_rf_scaler.pkl)

Σημειώσεις μεθοδολογίας:
- Οι ετικέτες κωδικοποιούνται με τον ΑΠΟΘΗΚΕΥΜΕΝΟ label_encoder.pkl (ίδια
  αντιστοίχιση κλάσεων με τα υπόλοιπα μοντέλα του project).
- Το "κέντρο" της φυσιολογικής κίνησης (normal mean) που χρησιμοποιεί ο
  επιτιθέμενος υπολογίζεται ΜΟΝΟ από το training set — ο επιτιθέμενος δεν
  έχει πρόσβαση στα στατιστικά του συνόλου ελέγχου.
"""
import math
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

BASE   = Path(__file__).resolve().parents[1]
RES    = BASE / "results"
MODELS = BASE / "models"
DATA   = BASE / "data"
RES.mkdir(exist_ok=True)

FEATS = json.load(open(MODELS / "feature_columns.json"))
LABEL = "Label"
NORMAL = "Normal"
EPSILONS = [0.0, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.65, 0.80, 1.0]
AUG_EPS  = [0.10, 0.20, 0.30]     # ε για adversarial augmentation στο training
RNG = 42

# --- data ---
df = pd.read_csv(DATA / "sdn_flows_synthetic.csv")
df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATS + [LABEL])
X = df[FEATS].astype(float).values

# Κωδικοποίηση με τον αποθηκευμένο encoder (κοινός με train.py)
le = joblib.load(MODELS / "label_encoder.pkl")
y = le.transform(df[LABEL].values)
classes = list(le.classes_)
NIDX = classes.index(NORMAL)
print("rows:", len(y), "| classes:", classes, "| Normal idx:", NIDX)

Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.30, stratify=y, random_state=RNG)
scaler = StandardScaler().fit(Xtr)
Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)

# Normal mean ΜΟΝΟ από το training set (γνώση του επιτιθέμενου)
norm_mean_tr = Xtr[ytr == NIDX].mean(axis=0)


def mimic(Xa, normal_mean, eps):
    Xadv = Xa + eps * (normal_mean - Xa)
    return np.clip(Xadv, 0, None)


def evasion(model, Xa_orig, normal_mean, eps):
    Xadv = mimic(Xa_orig, normal_mean, eps)
    pred = model.predict(scaler.transform(Xadv))
    return 100.0 * np.mean(pred == NIDX)


# --- Original RF (clean) ---
rf0 = RandomForestClassifier(n_estimators=200, random_state=RNG, n_jobs=-1).fit(Xtr_s, ytr)

# --- Robust RF (clean + adversarially perturbed attack samples) ---
atk_mask_tr = ytr != NIDX
Xa_tr, ya_tr = Xtr[atk_mask_tr], ytr[atk_mask_tr]
aug_X, aug_y = [Xtr], [ytr]
for e in AUG_EPS:
    aug_X.append(mimic(Xa_tr, norm_mean_tr, e))   # perturbed attacks
    aug_y.append(ya_tr)                            # ΚΡΑΤΟΥΝ την ετικέτα επίθεσης
Xaug, yaug = np.vstack(aug_X), np.concatenate(aug_y)
rf1 = RandomForestClassifier(n_estimators=200, random_state=RNG, n_jobs=-1).fit(
    scaler.transform(Xaug), yaug)

# Αποθήκευση του θωρακισμένου μοντέλου
joblib.dump(rf1, MODELS / "robust_rf.pkl")
joblib.dump(scaler, MODELS / "robust_rf_scaler.pkl")
print("saved: models/robust_rf.pkl, models/robust_rf_scaler.pkl")

# --- evasion vs epsilon (test attack samples, attacker knowledge = train stats) ---
Xa_te = Xte[yte != NIDX]
rows = []
for e in EPSILONS:
    ev0 = evasion(rf0, Xa_te, norm_mean_tr, e)
    ev1 = evasion(rf1, Xa_te, norm_mean_tr, e)
    rows.append((e, round(ev0, 1), round(ev1, 1)))
    print(f"eps={e:.2f}  evasion original={ev0:5.1f}%  robust={ev1:5.1f}%")
pd.DataFrame(rows, columns=["epsilon", "evasion_original_pct", "evasion_robust_pct"]).to_csv(
    RES / "adv_robust_comparison.csv", index=False)

# --- clean-data performance (full test set) ---
p0, p1 = rf0.predict(Xte_s), rf1.predict(Xte_s)
acc0, f10 = accuracy_score(yte, p0), f1_score(yte, p0, average="macro")
acc1, f11 = accuracy_score(yte, p1), f1_score(yte, p1, average="macro")

# --- McNemar (Original vs Robust) στο clean test set ---
c0, c1 = (p0 == yte), (p1 == yte)
b = int(np.sum(c0 & ~c1))
c = int(np.sum(~c0 & c1))
if b + c > 0:
    stat = (abs(b - c) - 1) ** 2 / (b + c)
    pval = math.erfc(math.sqrt(stat / 2.0))   # chi2 df=1 survival
else:
    stat, pval = 0.0, 1.0
print(f"\nCLEAN  original: acc={acc0:.4f} F1={f10:.4f} | robust: acc={acc1:.4f} F1={f11:.4f}")
print(f"McNemar: b={b} c={c} stat={stat:.3f} p={pval:.4f}")

pd.DataFrame([
    ["Original RF", round(acc0, 4), round(f10, 4)],
    ["Robust RF",   round(acc1, 4), round(f11, 4)],
], columns=["model", "clean_accuracy", "clean_macro_f1"]).to_csv(
    RES / "adv_robust_clean.csv", index=False)
(RES / "adv_robust_mcnemar.txt").write_text(
    f"McNemar Original vs Robust (clean test): b={b}, c={c}, "
    f"statistic={stat:.3f}, p={pval:.4f}\n")

# --- plot ---
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams["font.family"] = "DejaVu Sans"
eps = [r[0] for r in rows]
e0 = [r[1] for r in rows]
e1 = [r[2] for r in rows]
fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(eps, e0, "o-", color="#b3261e", lw=2, label="Original RF")
ax.plot(eps, e1, "s-", color="#1b7a3d", lw=2, label="Robust RF (adv. training)")
ax.axvspan(0.15, 0.22, color="#ffd54f", alpha=0.25, label="cliff περιοχή (original)")
ax.set_xlabel("Διαταραχη ε (mimicry)")
ax.set_ylabel("Ρυθμος αποφυγης (%)")
ax.set_title("Evasion rate vs ε: Original vs Robust RF")
ax.set_ylim(-3, 103)
ax.grid(alpha=.3)
ax.legend()
plt.tight_layout()
plt.savefig(RES / "adv_robust_evasion.png", dpi=150)
print("saved: results/adv_robust_evasion.png, adv_robust_comparison.csv, adv_robust_clean.csv")
