#!/usr/bin/env python3
"""
mitigation_analysis.py  — Ανάλυση Αποτελεσματικότητας Αντιμετώπισης (Mitigation)
----------------------------------------------------------------------------------
Αξιολογεί πόσο αποτελεσματικό είναι το αυτόματο μπλοκάρισμα (drop-rule)
μετά την ανίχνευση επίθεσης.

Μετρικές:
  1. True Positive Rate  (TPR) — ποσοστό παραθύρων επίθεσης που ανιχνεύθηκαν
  2. False Positive Rate (FPR) — ποσοστό παραθύρων νόμιμης κίνησης που μπλοκαρίστηκαν
  3. Mitigation Coverage       — ποσοστό παραθύρων επίθεσης που ήταν υπό μπλοκάρισμα
  4. Traffic Reduction         — μείωση κακόβουλης κίνησης μετά το mitigation
  5. Time-to-Detect (TTD)     — χρόνος από έναρξη επίθεσης έως 1η ανίχνευση (s)
  6. Re-detection Rate        — αν η επίθεση επαναληφθεί μετά λήξη block, ξανα-ανιχνεύεται;

Σενάριο:
  - Φάση 1: Μόνο νόμιμη κίνηση  (παράθυρα 0-9)
  - Φάση 2: Επίθεση ξεκινά       (παράθυρα 10-25)
  - Φάση 3: Επίθεση επαναλαμβάνεται μετά τη λήξη block (παράθυρα 30-40)

Παράγει:
  results/mitigation_effectiveness.png  — πολυπίνακας με όλες τις μετρικές
  results/mitigation_stats.csv          — λεπτομερής πίνακας ανά δοκιμή
  results/mitigation_timeline.png       — χρονολόγιο ενός τυπικού σεναρίου

Χρήση:
  python3 ml_pipeline/mitigation_analysis.py
"""

import os
import sys
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

warnings.filterwarnings("ignore")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config
import detection_engine as engine

# --- Παράμετροι ---
N_TRIALS        = 50
N_WINDOWS       = 50
PHASE1_END      = 10   # παράθυρα 0-9:  μόνο νόμιμη κίνηση
PHASE2_START    = 10   # παράθυρα 10-24: επίθεση
PHASE2_END      = 25
PHASE3_START    = 30   # παράθυρα 30-45: επανάληψη επίθεσης
PHASE3_END      = 46
ATTACK_MEAN     = 120  # ροές/παράθυρο (υψηλή ένταση)
BLOCK_WINDOWS   = 4
POLL_S          = config.POLL_INTERVAL
NORMAL_HOSTS    = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
ATTACKER        = "10.0.0.6"


def _normal_flows(rng):
    n = max(1, int(rng.normal(4, 2)))
    return [(max(1, int(rng.normal(40, 20))),
             max(60, int(rng.normal(600, 200))) * max(1, int(rng.normal(40, 20))),
             max(0.1, rng.normal(8, 4)))
            for _ in range(n)]


def _attack_flows(rng, n_mean=ATTACK_MEAN):
    n = max(5, int(rng.normal(n_mean, n_mean * 0.15)))
    return [(max(1, int(rng.normal(2.5, 1.5))),
             max(40, int(rng.normal(80, 30))) * max(1, int(rng.normal(2, 1))),
             max(0.01, rng.normal(0.5, 0.3)))
            for _ in range(n)]


def run_trial(model, scaler, seed):
    """
    Εκτελεί ένα πλήρες σενάριο 3 φάσεων.
    Επιστρέφει λεπτομερή μετρικά και timeline.
    """
    rng           = np.random.default_rng(seed)
    blocked_until = {}
    timeline      = []  # (w, phase, attacker_active, detected, blocked, fp)

    attack_windows       = set(range(PHASE2_START, PHASE2_END)) | \
                           set(range(PHASE3_START, PHASE3_END))
    first_detection_w    = None
    detections_p2        = 0
    detections_p3        = 0
    fp_events            = 0
    blocked_attack_w     = 0
    total_attack_flows   = 0
    blocked_attack_flows = 0

    for w in range(N_WINDOWS):
        # λήξη μπλοκαρίσματος
        for ip in list(blocked_until):
            if w >= blocked_until[ip]:
                del blocked_until[ip]

        attacker_active = w in attack_windows
        phase = (1 if w < PHASE2_START
                 else 2 if w < PHASE2_END
                 else 3 if w >= PHASE3_START
                 else 0)  # 0 = "rest" μεταξύ φάσεων

        detected_this = False
        fp_this       = False

        # νόμιμοι hosts
        for h in NORMAL_HOSTS:
            feats   = engine.aggregate_features(_normal_flows(rng))
            verdict = engine.classify(feats, model, scaler)
            if verdict == "Attack":
                fp_events += 1
                fp_this    = True

        # επιτιθέμενος
        if attacker_active:
            aflows = _attack_flows(rng)
            total_attack_flows += len(aflows)
            if ATTACKER in blocked_until:
                # κίνηση μπλοκαρισμένη — δεν φτάνει στο σύστημα
                blocked_attack_flows += len(aflows)
                blocked_attack_w += 1
            else:
                feats   = engine.aggregate_features(aflows)
                verdict = engine.classify(feats, model, scaler)
                if verdict == "Attack":
                    detected_this = True
                    blocked_until[ATTACKER] = w + BLOCK_WINDOWS
                    if first_detection_w is None:
                        first_detection_w = w
                    if phase == 2:
                        detections_p2 += 1
                    elif phase == 3:
                        detections_p3 += 1

        timeline.append({
            "window": w, "phase": phase,
            "attacker_active": int(attacker_active),
            "detected": int(detected_this),
            "blocked": int(ATTACKER in blocked_until),
            "fp": int(fp_this),
        })

    # --- Μετρικές ---
    tl_df = pd.DataFrame(timeline)

    attack_w_total  = len(attack_windows.intersection(range(N_WINDOWS)))
    detected_w      = tl_df[tl_df["attacker_active"] == 1]["detected"].sum()
    tpr             = detected_w / attack_w_total if attack_w_total else 0
    mit_coverage    = blocked_attack_w / attack_w_total if attack_w_total else 0

    normal_w_total  = len(tl_df[tl_df["attacker_active"] == 0])
    fp_windows      = tl_df[tl_df["attacker_active"] == 0]["fp"].sum()
    fpr             = fp_windows / (normal_w_total * len(NORMAL_HOSTS)) if normal_w_total else 0

    traffic_red     = (blocked_attack_flows / total_attack_flows
                       if total_attack_flows else 0)
    ttd_s           = ((first_detection_w - PHASE2_START) * POLL_S
                       if first_detection_w is not None else np.nan)

    p3_attack_w = len(set(range(PHASE3_START, min(PHASE3_END, N_WINDOWS))))
    redet_rate  = detections_p3 / p3_attack_w if p3_attack_w > 0 else 0

    return {
        "tpr":          tpr,
        "fpr":          fpr,
        "mit_coverage": mit_coverage,
        "traffic_red":  traffic_red,
        "ttd_s":        ttd_s,
        "redet_rate":   redet_rate,
        "fp_events":    fp_events,
        "timeline":     tl_df,
    }


def plot_effectiveness(all_metrics):
    """Πολυπίνακας: κατανομές των 5 κύριων μετρικών σε violin plots."""
    metrics = {
        "TPR (%)": [m["tpr"] * 100 for m in all_metrics],
        "FPR (%)": [m["fpr"] * 100 for m in all_metrics],
        "Mitigation\nCoverage (%)": [m["mit_coverage"] * 100 for m in all_metrics],
        "Traffic\nReduction (%)": [m["traffic_red"] * 100 for m in all_metrics],
        "Re-detection\nRate (%)": [m["redet_rate"] * 100 for m in all_metrics],
    }
    ttd_vals = [m["ttd_s"] for m in all_metrics if not np.isnan(m["ttd_s"])]

    fig, axes = plt.subplots(1, len(metrics) + 1, figsize=(16, 5.5))

    colors = ["#2ecc71", "#e74c3c", "#3498db", "#9b59b6", "#f39c12"]
    for ax, (label, vals), color in zip(axes[:-1], metrics.items(), colors):
        vp = ax.violinplot(vals, positions=[0], showmedians=True,
                           showextrema=True, widths=0.6)
        for pc in vp["bodies"]:
            pc.set_facecolor(color)
            pc.set_alpha(0.7)
        vp["cmedians"].set_color("black")
        vp["cmedians"].set_linewidth(2)
        ax.scatter([0], [np.mean(vals)], color="white", edgecolors="black",
                   s=40, zorder=5)
        ax.set_xticks([])
        ax.set_ylabel(label, fontsize=10)
        ax.set_ylim(-5, 110)
        ax.axhline(100, color="grey", linestyle="--", linewidth=0.8, alpha=0.5)
        ax.axhline(0,   color="grey", linestyle="--", linewidth=0.8, alpha=0.5)
        ax.grid(axis="y", linestyle="--", alpha=0.3)
        ax.set_title(f"μ={np.mean(vals):.1f}%\nσ={np.std(vals):.1f}%",
                     fontsize=9, pad=4)

    # TTD σε ξεχωριστό subplot (σε δευτερόλεπτα)
    ax_ttd = axes[-1]
    if ttd_vals:
        ax_ttd.violinplot(ttd_vals, positions=[0], showmedians=True,
                          showextrema=True, widths=0.6)
        ax_ttd.scatter([0], [np.mean(ttd_vals)], color="white",
                       edgecolors="black", s=40, zorder=5)
        ax_ttd.set_title(f"μ={np.mean(ttd_vals):.1f}s\nσ={np.std(ttd_vals):.1f}s",
                         fontsize=9, pad=4)
    ax_ttd.set_xticks([])
    ax_ttd.set_ylabel("Time-to-Detect (s)", fontsize=10)
    ax_ttd.grid(axis="y", linestyle="--", alpha=0.3)

    fig.suptitle(
        f"Αποτελεσματικότητα Συστήματος Ανίχνευσης & Αντιμετώπισης Επιθέσεων SDN\n"
        f"({N_TRIALS} ανεξάρτητες δοκιμές, ένταση={ATTACK_MEAN} ροές/παράθυρο, "
        f"παράθυρο={POLL_S}s)",
        fontsize=12, y=1.02,
    )
    plt.tight_layout()
    out = os.path.join(config.RESULTS_DIR, "mitigation_effectiveness.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")


def plot_timeline_example(timeline_df):
    """Χρονολόγιο ενός τυπικού σεναρίου — ιδανικό για την πτυχιακή."""
    tl = timeline_df
    w  = tl["window"].values

    fig, axes = plt.subplots(3, 1, figsize=(13, 7), sharex=True)

    # --- Κατάσταση επιτιθέμενου ---
    ax = axes[0]
    ax.fill_between(w, tl["attacker_active"], step="post",
                    color="#e74c3c", alpha=0.35, label="Επίθεση ενεργή")
    ax.fill_between(w, tl["blocked"], step="post",
                    color="#2ecc71", alpha=0.4, label="Πηγή μπλοκαρισμένη")
    det_w = w[tl["detected"] == 1]
    ax.scatter(det_w, [1.05] * len(det_w), marker="v", color="black",
               s=70, zorder=5, label="Ανίχνευση")
    ax.set_ylim(-0.1, 1.3)
    ax.set_yticks([])
    ax.legend(loc="upper right", ncol=3, fontsize=9)
    ax.set_title("Κατάσταση Επίθεσης & Mitigation", fontsize=11)

    # Φάσεις
    for ax_ in axes:
        ax_.axvspan(0, PHASE2_START, color="#3498db", alpha=0.05, label="Φάση 1 (κανονική)")
        ax_.axvspan(PHASE2_START, PHASE2_END, color="#e74c3c", alpha=0.07)
        ax_.axvspan(PHASE3_START, PHASE3_END, color="#e74c3c", alpha=0.07)
        ax_.axvline(PHASE2_START, color="red", linewidth=0.8, linestyle="--")
        ax_.axvline(PHASE3_START, color="red", linewidth=0.8, linestyle="--")

    # --- False positives ---
    ax2 = axes[1]
    ax2.bar(w, tl["fp"], color="#e67e22", alpha=0.7, width=0.8, label="False Positive")
    ax2.set_ylabel("FP", fontsize=10)
    ax2.set_ylim(-0.1, 1.5)
    ax2.legend(loc="upper right", fontsize=9)
    ax2.set_title("Λανθασμένες Ανιχνεύσεις σε Νόμιμη Κίνηση (False Positives)", fontsize=11)

    # --- Φάσεις χρονολογίου ---
    ax3 = axes[2]
    phase_colors = {1: "#3498db", 2: "#e74c3c", 3: "#e74c3c", 0: "#95a5a6"}
    prev_phase   = tl["phase"].iloc[0]
    start_w      = 0
    phase_labels = {1: "Κανονική κίνηση", 2: "Επίθεση (Φάση 1)",
                    3: "Επίθεση (Φάση 2)", 0: "Ανάπαυλα"}
    for i, row in tl.iterrows():
        if row["phase"] != prev_phase or i == len(tl) - 1:
            ax3.barh(0, i - start_w, left=start_w, height=0.6,
                     color=phase_colors.get(prev_phase, "grey"), alpha=0.7,
                     label=phase_labels.get(prev_phase, ""))
            start_w    = i
            prev_phase = row["phase"]
    ax3.set_yticks([])
    ax3.set_xlabel(f"Παράθυρο δειγματοληψίας (× {POLL_S}s)", fontsize=11)
    ax3.set_title("Φάσεις Σεναρίου", fontsize=11)

    # Legend μοναδικά
    handles, labels = [], []
    for a in axes:
        h, l = a.get_legend_handles_labels()
        for hh, ll in zip(h, l):
            if ll not in labels:
                handles.append(hh); labels.append(ll)

    fig.suptitle("Χρονολόγιο Τυπικού Σεναρίου: Ανίχνευση & Αντιμετώπιση Επίθεσης SDN",
                 fontsize=13, y=1.01)
    plt.tight_layout()
    out = os.path.join(config.RESULTS_DIR, "mitigation_timeline.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")


def save_csv(all_metrics):
    rows = []
    for i, m in enumerate(all_metrics):
        rows.append({
            "trial":            i + 1,
            "tpr_pct":          round(m["tpr"] * 100, 1),
            "fpr_pct":          round(m["fpr"] * 100, 2),
            "mitigation_coverage_pct": round(m["mit_coverage"] * 100, 1),
            "traffic_reduction_pct":   round(m["traffic_red"] * 100, 1),
            "ttd_seconds":      round(m["ttd_s"], 1) if not np.isnan(m["ttd_s"]) else "N/A",
            "redetection_rate_pct": round(m["redet_rate"] * 100, 1),
            "fp_events":        m["fp_events"],
        })
    df = pd.DataFrame(rows)
    out = os.path.join(config.RESULTS_DIR, "mitigation_stats.csv")
    df.to_csv(out, index=False)
    print(f"[OK] {out}")
    return df


def print_summary(all_metrics):
    print("\n" + "=" * 60)
    print("  ΑΠΟΤΕΛΕΣΜΑΤΑ ΑΠΟΤΕΛΕΣΜΑΤΙΚΟΤΗΤΑΣ ΑΝΤΙΜΕΤΩΠΙΣΗΣ")
    print("=" * 60)

    tpr  = [m["tpr"] * 100 for m in all_metrics]
    fpr  = [m["fpr"] * 100 for m in all_metrics]
    cov  = [m["mit_coverage"] * 100 for m in all_metrics]
    tred = [m["traffic_red"] * 100 for m in all_metrics]
    ttd  = [m["ttd_s"] for m in all_metrics if not np.isnan(m["ttd_s"])]
    rdt  = [m["redet_rate"] * 100 for m in all_metrics]

    def fmt(vals, unit="%"):
        return f"{np.mean(vals):.1f}{unit} ± {np.std(vals):.1f}{unit}"

    print(f"  True Positive Rate:         {fmt(tpr)}")
    print(f"  False Positive Rate:        {fmt(fpr)}")
    print(f"  Mitigation Coverage:        {fmt(cov)}")
    print(f"  Traffic Reduction:          {fmt(tred)}")
    print(f"  Time-to-Detect:             {fmt(ttd, 's')}")
    print(f"  Re-detection Rate:          {fmt(rdt)}")
    print(f"\n  Δοκιμές: {N_TRIALS} | Παράθυρα/δοκιμή: {N_WINDOWS} | "
          f"Ένταση: {ATTACK_MEAN} ροές/παράθυρο")


def main():
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    print("[*] Ανάλυση Αποτελεσματικότητας Αντιμετώπισης Επιθέσεων SDN")
    print(f"    {N_TRIALS} δοκιμές × {N_WINDOWS} παράθυρα × {POLL_S}s/παράθυρο\n")

    model, scaler = engine.load_live_model()
    if model is None:
        print("[!] Δεν βρέθηκε live μοντέλο — χρήση heuristic.")

    all_metrics  = []
    example_tl   = None
    for seed in range(N_TRIALS):
        result = run_trial(model, scaler, seed)
        all_metrics.append(result)
        if seed == 0:
            example_tl = result["timeline"]  # αποθήκευση 1ης δοκιμής για το timeline plot

    print_summary(all_metrics)
    plot_effectiveness(all_metrics)
    plot_timeline_example(example_tl)
    save_csv(all_metrics)
    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Ανάλυση mitigation αποθηκεύτηκε στο results/")


if __name__ == "__main__":
    main()
