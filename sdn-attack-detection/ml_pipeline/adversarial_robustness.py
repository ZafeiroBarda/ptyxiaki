#!/usr/bin/env python3
"""
adversarial_robustness.py  — Ανάλυση Ανθεκτικότητας σε Αντίπαλες Επιθέσεις
============================================================================
Αξιολογεί κατά πόσο ένας επιτιθέμενος που ΓΝΩΡΙΖΕΙ το μοντέλο ML μπορεί
να τροποποιήσει σκόπιμα την κίνησή του για να αποφύγει την ανίχνευση.

Τρεις στρατηγικές αποφυγής (evasion strategies):
──────────────────────────────────────────────────
Α. MIMICRY ATTACK (εποπτευόμενο μοντέλο — Random Forest)
   Ο επιτιθέμενος μετακινεί τα στατιστικά της κίνησής του
   προς τη "μέση τιμή" της κανονικής κίνησης (Normal class mean).
   Παράμετρος ε ∈ [0,1]: ε=0 = χωρίς αλλαγή, ε=1 = πλήρης μίμηση κανονικής.

Β. ΣΤΟΧΕΥΜΕΝΗ ΑΛΛΑΓΗ ΧΑΡΑΚΤΗΡΙΣΤΙΚΩΝ (RF — feature-targeted)
   Αλλάζει μόνο τα N πιο σημαντικά features (κατά SHAP) με προσαύξηση ε.
   Πιο ρεαλιστικό: ο επιτιθέμενος ελέγχει συγκεκριμένες παραμέτρους.

Γ. ΦΥΣΙΚΕΣ ΣΤΡΑΤΗΓΙΚΕΣ ΑΠΟΦΥΓΗΣ (live μοντέλο — aggregate features)
   • Slow-rate: λιγότερες ροές/παράθυρο (μειωμένη ένταση)
   • Pulse: εναλλαγή επίθεσης/παύσης (1 παράθυρο on, 2 off)
   • Multi-source: κατανομή σε πολλές IPs (χαμηλό flow_count/IP)

Βασική ερώτηση:
   Πόσο πρέπει να αλλοιώσει ο επιτιθέμενος την κίνησή του
   ώστε να ξεφύγει; Και πόσο αποδυναμώνεται η επίθεσή του;

Παράγει:
  results/adv_mimicry_evasion.png      — ρυθμός αποφυγής vs ε (ανά κλάση)
  results/adv_feature_sensitivity.png  — ευαισθησία ανά feature
  results/adv_live_evasion.png         — φυσικές στρατηγικές (live μοντέλο)
  results/adv_tradeoff.png             — αντίθεση αποφυγής vs αποτελεσματικότητας
  results/adv_stats.csv                — αριθμητικά αποτελέσματα

Χρήση:
  python3 ml_pipeline/adversarial_robustness.py
"""

import os
import sys
import json
import warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.lines as mlines

warnings.filterwarnings("ignore")
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess
import detection_engine as engine

RESULTS_DIR = config.RESULTS_DIR
MODELS_DIR  = config.MODELS_DIR

# Εντάσεις εποπτευόμενης διαταραχής
EPSILONS = [0.0, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.65, 0.80, 1.0]

# Χρώματα ανά κλάση επίθεσης
CLASS_COLORS = {
    "DDoS":  "#e74c3c",
    "DoS":   "#e67e22",
    "Probe": "#9b59b6",
    "BFA":   "#2980b9",
}


# ══════════════════════════════════════════════════════════════════
#  ΦΟΡΤΩΣΗ ΜΟΝΤΕΛΟΥ ΚΑΙ ΔΕΔΟΜΕΝΩΝ
# ══════════════════════════════════════════════════════════════════
def load_artifacts():
    model  = joblib.load(os.path.join(MODELS_DIR, "best_model.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
    le     = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
    with open(os.path.join(MODELS_DIR, "feature_columns.json")) as f:
        feat_cols = json.load(f)
    return model, scaler, le, feat_cols


def load_data(feat_cols, scaler, le):
    """
    Φορτώνει δεδομένα και κωδικοποιεί με τον TRAINED label encoder
    (ώστε τα class indices να συμφωνούν απόλυτα με το μοντέλο).
    """
    df    = preprocess.load_synthetic()
    X_all = df[feat_cols].astype(float).values
    y_raw = df[config.LABEL_COL].values
    known = np.isin(y_raw, le.classes_)
    X_all = X_all[known]
    y_raw = y_raw[known]
    y     = le.transform(y_raw)        # TRAINED le → consistent indices

    normal_idx  = list(le.classes_).index("Normal")
    mask_attack = y != normal_idx
    mask_normal = y == normal_idx
    return (X_all[mask_attack], y[mask_attack],
            X_all[mask_normal],
            list(le.classes_), normal_idx)


# ══════════════════════════════════════════════════════════════════
#  Α. MIMICRY ATTACK — εποπτευόμενο μοντέλο
# ══════════════════════════════════════════════════════════════════
def mimicry_perturb(X_attack, X_normal, epsilon, feat_mask=None):
    """
    Mimicry: μετακίνηση X_attack προς μέσο φυσιολογικής κίνησης.
    feat_mask: αν δοθεί, αλλάζει μόνο τα επιλεγμένα features.
    Επιστρέφει X_adv στο original feature space (non-negative).
    """
    normal_mean = X_normal.mean(axis=0)
    direction   = normal_mean - X_attack   # διάνυσμα προς κανονική κίνηση
    if feat_mask is not None:
        mask = np.zeros(X_attack.shape[1], dtype=bool)
        mask[feat_mask] = True
        direction = direction * mask       # μόνο επιλεγμένα features
    X_adv = X_attack + epsilon * direction
    return np.clip(X_adv, 0, None)        # μη αρνητικές τιμές (physical constraint)


def evasion_rate(X_adv, y_true, model, scaler, normal_idx):
    """% attack samples που ταξινομήθηκαν ως Normal (successful evasion)."""
    X_scaled = scaler.transform(X_adv)
    y_pred   = model.predict(X_scaled)
    evaded   = np.sum(y_pred == normal_idx)
    return evaded / len(y_true) * 100


def attack_potency(epsilon, feature_weights=None):
    """
    Εκτίμηση: τι % της αρχικής ισχύος επίθεσης διατηρείται.
    Παραδοχή: όσο πιο πολύ αλλάζει ο επιτιθέμενος τα features
    (flow_pkts_s, IAT κλπ), τόσο λιγότερο αποτελεσματική η επίθεση.
    Γραμμικό μοντέλο: potency = 1 - ε (simplified, αρκετά για θεωρητική ανάλυση).
    """
    return max(0.0, 1.0 - epsilon) * 100


def run_mimicry_analysis(model, scaler, le, X_attack, y_attack,
                         X_normal, class_names, normal_idx):
    """Εκτελεί mimicry attack για κάθε epsilon και κλάση."""
    results = []
    for eps in EPSILONS:
        # Global (όλες οι κλάσεις)
        X_adv  = mimicry_perturb(X_attack, X_normal, eps)
        ev_all = evasion_rate(X_adv, y_attack, model, scaler, normal_idx)
        pot    = attack_potency(eps)
        results.append({
            "epsilon": eps, "class": "Όλες",
            "evasion_rate_pct": ev_all,
            "potency_pct": pot,
            "effective_attack": ev_all * pot / 100,
        })
        # Ανά κλάση
        for ci, cls in enumerate(class_names):
            if cls == "Normal":
                continue
            mask = y_attack == ci
            if mask.sum() == 0:
                continue
            X_adv_cls = mimicry_perturb(X_attack[mask], X_normal, eps)
            ev_cls    = evasion_rate(X_adv_cls, y_attack[mask], model, scaler, normal_idx)
            results.append({
                "epsilon": eps, "class": cls,
                "evasion_rate_pct": ev_cls,
                "potency_pct": pot,
                "effective_attack": ev_cls * pot / 100,
            })
    return pd.DataFrame(results)


# ══════════════════════════════════════════════════════════════════
#  Β. ΣΤΟΧΕΥΜΕΝΗ ΑΛΛΑΓΗ ΧΑΡΑΚΤΗΡΙΣΤΙΚΩΝ
# ══════════════════════════════════════════════════════════════════
def run_feature_sensitivity(model, scaler, le, X_attack, y_attack,
                             X_normal, class_names, normal_idx, feat_cols):
    """
    Για κάθε feature ξεχωριστά: εφαρμόζει mimicry μόνο σε αυτό το feature
    (ε=0.5) και μετρά πόσο αυξάνεται ο ρυθμός αποφυγής.
    Δείχνει ποια features είναι πιο "επικίνδυνα" για το μοντέλο.
    """
    SHAP_CSV = os.path.join(RESULTS_DIR, "shap_feature_importance.csv")
    if os.path.exists(SHAP_CSV):
        shap_df = pd.read_csv(SHAP_CSV)
        top_features = shap_df["feature"].tolist()[:12]
    else:
        top_features = feat_cols[:12]

    EPS_FIXED = 0.5
    baseline  = evasion_rate(X_attack, y_attack, model, scaler, normal_idx)
    rows      = []
    for feat in top_features:
        if feat not in feat_cols:
            continue
        fidx  = feat_cols.index(feat)
        X_adv = mimicry_perturb(X_attack, X_normal, EPS_FIXED, feat_mask=[fidx])
        ev    = evasion_rate(X_adv, y_attack, model, scaler, normal_idx)
        delta = ev - baseline
        rows.append({"feature": feat, "evasion_rate_pct": ev,
                     "delta_vs_baseline": delta})
    return pd.DataFrame(rows).sort_values("delta_vs_baseline", ascending=False)


# ══════════════════════════════════════════════════════════════════
#  Γ. ΦΥΣΙΚΕΣ ΣΤΡΑΤΗΓΙΚΕΣ — live μοντέλο
# ══════════════════════════════════════════════════════════════════
def _normal_flows(rng, n=4):
    n = max(1, int(rng.normal(n, 2)))
    return [(max(1, int(rng.normal(40, 20))),
             max(60, int(rng.normal(600, 200))) * max(1, int(rng.normal(40, 20))),
             max(0.1, rng.normal(8, 4))) for _ in range(n)]


def _attack_flows(rng, n):
    """Flood ροές με n ροές."""
    n = max(1, int(rng.normal(n, n * 0.15)))
    return [(max(1, int(rng.normal(2.5, 1.5))),
             max(40, int(rng.normal(80, 30))) * max(1, int(rng.normal(2, 1))),
             max(0.01, rng.normal(0.5, 0.3))) for _ in range(n)]


def simulate_evasion_strategy(model_live, scaler_live, strategy, rng,
                               n_windows=60, attack_start=10):
    """
    Προσομοιώνει μία στρατηγική αποφυγής στο live μοντέλο.
    Επιστρέφει (detection_rate, timeline).
    """
    HOSTS    = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    ATTACKER = "10.0.0.6"
    detected = 0
    total_attack_windows = 0
    timeline = []

    for w in range(n_windows):
        is_attack = w >= attack_start

        # — εφαρμογή στρατηγικής —
        if strategy["name"] == "slow_rate":
            attack_n = strategy["flow_count"]
            attack_active = is_attack
        elif strategy["name"] == "pulse":
            period = strategy["on"] + strategy["off"]
            attack_active = is_attack and (w - attack_start) % period < strategy["on"]
            attack_n = 120
        elif strategy["name"] == "multi_source":
            attack_active = is_attack
            attack_n = strategy["flows_per_ip"]  # ανά "IP"
        else:
            attack_active = is_attack
            attack_n = 120

        # — νόμιμοι hosts —
        for h in HOSTS:
            feats   = engine.aggregate_features(_normal_flows(rng))
            verdict = engine.classify(feats, model_live, scaler_live)

        # — επιτιθέμενος —
        att_detected_this = False
        if attack_active:
            total_attack_windows += 1
            if strategy["name"] == "multi_source":
                # Χωρίζει την επίθεση σε N IPs
                n_ips = strategy["n_ips"]
                for ip_i in range(n_ips):
                    flows = _attack_flows(rng, attack_n)
                    feats = engine.aggregate_features(flows)
                    if engine.classify(feats, model_live, scaler_live) == "Attack":
                        att_detected_this = True
            else:
                flows = _attack_flows(rng, attack_n)
                feats = engine.aggregate_features(flows)
                if engine.classify(feats, model_live, scaler_live) == "Attack":
                    att_detected_this = True

            if att_detected_this:
                detected += 1

        timeline.append({
            "w": w, "is_attack": int(is_attack),
            "attack_active": int(attack_active),
            "detected": int(att_detected_this),
        })

    det_rate = (detected / total_attack_windows * 100
                if total_attack_windows > 0 else 0)
    return det_rate, pd.DataFrame(timeline)


EVASION_STRATEGIES = [
    {"name": "baseline",      "label": "Baseline (120 ροές/παράθυρο)",     "flow_count": 120},
    {"name": "slow_rate",     "label": "Slow-rate (40 ροές/παράθυρο)",     "flow_count": 40},
    {"name": "slow_rate",     "label": "Slow-rate (20 ροές/παράθυρο)",     "flow_count": 20},
    {"name": "slow_rate",     "label": "Slow-rate (10 ροές/παράθυρο)",     "flow_count": 10},
    {"name": "pulse",         "label": "Pulse (1 on / 2 off παράθυρα)",    "on": 1, "off": 2},
    {"name": "pulse",         "label": "Pulse (1 on / 4 off παράθυρα)",    "on": 1, "off": 4},
    {"name": "multi_source",  "label": "Multi-source (5 IPs × 24 ροές)",   "n_ips": 5,  "flows_per_ip": 24},
    {"name": "multi_source",  "label": "Multi-source (10 IPs × 12 ροές)",  "n_ips": 10, "flows_per_ip": 12},
]


def run_live_evasion(model_live, scaler_live, n_trials=20):
    rng  = np.random.default_rng(config.RANDOM_STATE)
    rows = []
    for strat in EVASION_STRATEGIES:
        rates = []
        for trial in range(n_trials):
            rng_t = np.random.default_rng(trial * 100 + hash(strat["label"]) % 1000)
            rate, _ = simulate_evasion_strategy(model_live, scaler_live, strat, rng_t)
            rates.append(rate)
        rows.append({
            "strategy": strat["label"],
            "detection_rate_pct": np.mean(rates),
            "std": np.std(rates),
            "evasion_rate_pct": 100 - np.mean(rates),
        })
        print(f"  {strat['label']:45s} → Ανίχνευση: {np.mean(rates):.1f}%  "
              f"(Αποφυγή: {100 - np.mean(rates):.1f}%)")
    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════════
#  ΓΡΑΦΗΜΑΤΑ
# ══════════════════════════════════════════════════════════════════
def plot_mimicry(df_mimicry, out_path):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    # --- Ρυθμός αποφυγής ανά κλάση ---
    for cls, color in CLASS_COLORS.items():
        sub = df_mimicry[df_mimicry["class"] == cls]
        if sub.empty:
            continue
        ax1.plot(sub["epsilon"], sub["evasion_rate_pct"],
                 "o-", color=color, lw=2, markersize=6, label=cls)
    sub_all = df_mimicry[df_mimicry["class"] == "Όλες"]
    ax1.plot(sub_all["epsilon"], sub_all["evasion_rate_pct"],
             "k--", lw=2.5, markersize=7, label="Μέσος όρος", zorder=5)

    ax1.set_xlabel("ε (ένταση διαταραχής mimicry)", fontsize=11)
    ax1.set_ylabel("Ρυθμός Αποφυγής (%)", fontsize=11)
    ax1.set_title("Mimicry Attack: Αποφυγή Ανίχνευσης\n"
                  "(Random Forest — εποπτευόμενο μοντέλο)", fontsize=11)
    ax1.set_xlim(-0.02, 1.02)
    ax1.set_ylim(-3, 105)
    ax1.axhline(50, color="grey", lw=0.8, linestyle=":", alpha=0.7,
                label="50% (αδύναμη ανίχνευση)")
    ax1.grid(linestyle="--", alpha=0.3)
    ax1.legend(fontsize=9)

    # --- Αντίθεση αποφυγής vs αποτελεσματικότητας ---
    sub_all = df_mimicry[df_mimicry["class"] == "Όλες"].copy()
    sc = ax2.scatter(sub_all["evasion_rate_pct"], sub_all["potency_pct"],
                     c=sub_all["epsilon"], cmap="RdYlGn_r",
                     s=100, zorder=5, edgecolors="black", linewidths=0.5)
    cb = fig.colorbar(sc, ax=ax2, label="ε (ένταση διαταραχής)")
    for _, row in sub_all.iterrows():
        ax2.annotate(f"ε={row['epsilon']:.2f}",
                     (row["evasion_rate_pct"], row["potency_pct"]),
                     textcoords="offset points", xytext=(4, 4), fontsize=7)
    ax2.set_xlabel("Ρυθμός Αποφυγής (%)", fontsize=11)
    ax2.set_ylabel("Ισχύς Επίθεσης που Διατηρείται (%)", fontsize=11)
    ax2.set_title("Trade-off: Αποφυγή vs Ισχύς Επίθεσης\n"
                  "(ιδανικό για τον επιτιθέμενο: πάνω-δεξιά γωνία)", fontsize=11)
    ax2.set_xlim(-3, 103)
    ax2.set_ylim(-3, 103)
    ax2.axvline(50, color="red", lw=1, linestyle=":", alpha=0.5)
    ax2.axhline(50, color="red", lw=1, linestyle=":", alpha=0.5)
    ax2.fill_between([50, 100], [50, 50], [100, 100],
                     alpha=0.07, color="red", label="«Επιτυχής» εισβολέας")
    ax2.legend(fontsize=9)
    ax2.grid(linestyle="--", alpha=0.3)

    fig.suptitle(
        "Ανάλυση Ανθεκτικότητας: Mimicry Attack κατά Εποπτευόμενου Μοντέλου (RF)\n"
        "Ο επιτιθέμενος μετακινεί τα features της κίνησής του προς τον μέσο της κανονικής",
        fontsize=12, y=1.02,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out_path}")


def plot_feature_sensitivity(df_feat, feat_cols, out_path):
    SHAP_CSV = os.path.join(RESULTS_DIR, "shap_feature_importance.csv")
    feat_labels = {}
    if os.path.exists(SHAP_CSV):
        shap_df = pd.read_csv(SHAP_CSV)
        feat_labels = dict(zip(shap_df["feature"], shap_df["feature_el"]))

    df_feat = df_feat.copy()
    df_feat["label"] = df_feat["feature"].map(lambda f: feat_labels.get(f, f))

    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ["#e74c3c" if d > 5 else "#e67e22" if d > 1 else "#3498db"
              for d in df_feat["delta_vs_baseline"]]
    bars = ax.barh(df_feat["label"], df_feat["delta_vs_baseline"],
                   color=colors, edgecolor="grey", linewidth=0.4)
    ax.axvline(0, color="black", lw=1)
    ax.set_xlabel("Αύξηση ρυθμού αποφυγής vs baseline (% points, ε=0.5)", fontsize=11)
    ax.set_title(
        "Ευαισθησία Μοντέλου ανά Feature (Targeted Mimicry, ε=0.5)\n"
        "Μεγαλύτερη μπάρα = το feature είναι «αδύνατο σημείο» αν αλλαχθεί",
        fontsize=11,
    )
    ax.grid(axis="x", linestyle="--", alpha=0.4)

    legend_patches = [
        plt.Rectangle((0, 0), 1, 1, fc="#e74c3c", alpha=0.8, label="Υψηλή ευαισθησία (>5%)"),
        plt.Rectangle((0, 0), 1, 1, fc="#e67e22", alpha=0.8, label="Μέτρια (1–5%)"),
        plt.Rectangle((0, 0), 1, 1, fc="#3498db", alpha=0.8, label="Χαμηλή (<1%)"),
    ]
    ax.legend(handles=legend_patches, fontsize=9, loc="lower right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out_path}")


def plot_live_evasion(df_live, out_path):
    fig, ax = plt.subplots(figsize=(11, 5.5))
    strategies  = df_live["strategy"].tolist()
    det_rates   = df_live["detection_rate_pct"].tolist()
    stds        = df_live["std"].tolist()
    ev_rates    = df_live["evasion_rate_pct"].tolist()

    # Χρώματα κατά τύπο στρατηγικής
    bar_colors = []
    for s in strategies:
        if "Baseline" in s:
            bar_colors.append("#e74c3c")
        elif "Slow" in s:
            bar_colors.append("#e67e22")
        elif "Pulse" in s:
            bar_colors.append("#9b59b6")
        else:
            bar_colors.append("#2980b9")

    bars = ax.barh(range(len(strategies)), det_rates,
                   xerr=stds, color=bar_colors, alpha=0.85,
                   edgecolor="grey", linewidth=0.5,
                   error_kw=dict(elinewidth=1.2, capsize=4))

    # Annotation ρυθμού αποφυγής
    for i, (det, ev) in enumerate(zip(det_rates, ev_rates)):
        ax.text(det + 1, i, f"{det:.1f}%  (αποφυγή: {ev:.1f}%)",
                va="center", fontsize=8.5)

    ax.set_yticks(range(len(strategies)))
    ax.set_yticklabels(strategies, fontsize=9)
    ax.set_xlabel("Ρυθμός Ανίχνευσης (%)", fontsize=11)
    ax.set_xlim(0, 125)
    ax.set_title(
        "Φυσικές Στρατηγικές Αποφυγής — Live ML Μοντέλο\n"
        f"(Aggregate features, {20} δοκιμές ανά στρατηγική)",
        fontsize=11,
    )
    ax.axvline(50, color="red", lw=1.2, linestyle="--", alpha=0.5,
               label="50% threshold (αναποτελεσματικό IDS)")
    ax.grid(axis="x", linestyle="--", alpha=0.3)

    from matplotlib.patches import Patch
    legend_handles = [
        Patch(facecolor="#e74c3c", alpha=0.85, label="Baseline (χωρίς αποφυγή)"),
        Patch(facecolor="#e67e22", alpha=0.85, label="Slow-rate"),
        Patch(facecolor="#9b59b6", alpha=0.85, label="Pulse"),
        Patch(facecolor="#2980b9", alpha=0.85, label="Multi-source"),
    ]
    ax.legend(handles=legend_handles, fontsize=9, loc="lower right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out_path}")


# ══════════════════════════════════════════════════════════════════
#  ΑΠΟΘΗΚΕΥΣΗ & ΕΚΤΥΠΩΣΗ
# ══════════════════════════════════════════════════════════════════
def save_csv(df_mimicry, df_feat, df_live):
    df_mimicry.to_csv(os.path.join(RESULTS_DIR, "adv_mimicry.csv"), index=False)
    df_feat.to_csv(os.path.join(RESULTS_DIR, "adv_feature_sensitivity.csv"), index=False)
    df_live.to_csv(os.path.join(RESULTS_DIR, "adv_live_evasion.csv"), index=False)
    print(f"[OK] {os.path.join(RESULTS_DIR, 'adv_*.csv')}")


def print_summary(df_mimicry, df_feat, df_live):
    print("\n" + "=" * 65)
    print("  ΑΠΟΤΕΛΕΣΜΑΤΑ ΑΝΑΛΥΣΗΣ ΑΝΘΕΚΤΙΚΟΤΗΤΑΣ")
    print("=" * 65)

    print("\n[Α. Mimicry Attack — Random Forest]")
    sub = df_mimicry[df_mimicry["class"] == "Όλες"]
    for _, r in sub.iterrows():
        print(f"  ε={r['epsilon']:.2f}  →  Αποφυγή: {r['evasion_rate_pct']:5.1f}%  "
              f"| Ισχύς επίθεσης: {r['potency_pct']:5.1f}%")

    # Βρίσκουμε το κρίσιμο epsilon (>50% evasion)
    cross = sub[sub["evasion_rate_pct"] >= 50]
    if not cross.empty:
        eps_50 = cross.iloc[0]["epsilon"]
        print(f"\n  → Χρειάζεται ε≥{eps_50:.2f} για >50% αποφυγή")
        print(f"    Αλλά σε αυτό το ε, ισχύς επίθεσης = {attack_potency(eps_50):.0f}%")
        print(f"    ΔΗΛ.: ο επιτιθέμενος αποδυναμώνει σημαντικά την επίθεσή του")

    print("\n[Β. Ευαισθησία ανά Feature (top-3)]")
    for _, r in df_feat.head(3).iterrows():
        print(f"  {r['feature']:22s}  +{r['delta_vs_baseline']:.1f}% αποφυγή")

    print("\n[Γ. Φυσικές Στρατηγικές — Live Μοντέλο]")
    for _, r in df_live.iterrows():
        print(f"  {r['strategy']:45s}  Αποφυγή: {r['evasion_rate_pct']:.1f}%")


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("[*] Ανάλυση Ανθεκτικότητας σε Αντίπαλες Επιθέσεις\n")

    # --- Φόρτωση μοντέλων ---
    print("[1/4] Φόρτωση εποπτευόμενου μοντέλου...")
    model, scaler, le, feat_cols = load_artifacts()
    X_attack, y_attack, X_normal, class_names, normal_idx = load_data(
        feat_cols, scaler, le)
    print(f"      Attack samples: {len(X_attack)} | "
          f"Normal samples: {len(X_normal)} | "
          f"Features: {len(feat_cols)}")

    print("\n[2/4] Α. Mimicry Attack (εποπτευόμενο μοντέλο RF)...")
    df_mimicry = run_mimicry_analysis(
        model, scaler, le, X_attack, y_attack,
        X_normal, class_names, normal_idx)

    print("\n[3/4] Β. Ευαισθησία ανά Feature...")
    df_feat = run_feature_sensitivity(
        model, scaler, le, X_attack, y_attack,
        X_normal, class_names, normal_idx, feat_cols)

    print("\n[4/4] Γ. Φυσικές Στρατηγικές (live μοντέλο)...")
    model_live, scaler_live = engine.load_live_model()
    df_live = run_live_evasion(model_live, scaler_live)

    print_summary(df_mimicry, df_feat, df_live)

    plot_mimicry(df_mimicry,
                 os.path.join(RESULTS_DIR, "adv_mimicry_evasion.png"))
    plot_feature_sensitivity(df_feat, feat_cols,
                              os.path.join(RESULTS_DIR, "adv_feature_sensitivity.png"))
    plot_live_evasion(df_live,
                      os.path.join(RESULTS_DIR, "adv_live_evasion.png"))
    save_csv(df_mimicry, df_feat, df_live)

    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Αποτελέσματα adversarial analysis στο results/")


if __name__ == "__main__":
    main()
