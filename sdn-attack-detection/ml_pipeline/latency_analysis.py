#!/usr/bin/env python3
"""
latency_analysis.py  — Ανάλυση Καθυστέρησης Ανίχνευσης (Detection Latency)
---------------------------------------------------------------------------
Μετρά πόσο γρήγορα ανιχνεύει η μηχανή μια επίθεση ανάλογα με την ένταση
της επίθεσης (αριθμός κακόβουλων ροών ανά παράθυρο δειγματοληψίας).

Μεθοδολογία:
  - Για κάθε επίπεδο έντασης (10 έως 200 ροές/παράθυρο):
      * Εκτελεί N=30 προσομοιώσεις με διαφορετικό random seed.
      * Μετρά την "καθυστέρηση ανίχνευσης" = (1ο παράθυρο ανίχνευσης)
        - (1ο παράθυρο επίθεσης).
      * Αρνητική τιμή: αδύνατη ανίχνευση (false negative για όλα τα παράθυρα).
  - Αποτέλεσμα: πόση κίνηση (σε παράθυρα και δευτερόλεπτα) χρειάζεται
    για αξιόπιστη ανίχνευση.

Παράγει:
  results/latency_vs_intensity.png  — box plot καθυστέρησης ανά ένταση
  results/latency_stats.csv         — λεπτομερής πίνακας στατιστικών

Χρήση:
  python3 ml_pipeline/latency_analysis.py
"""

import os
import sys
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config
import detection_engine as engine


# --- Παράμετροι πειράματος ---
ATTACK_INTENSITIES = [10, 20, 40, 60, 80, 100, 120, 150, 200]  # ροές/παράθυρο
N_TRIALS           = 30   # επαναλήψεις ανά ένταση (διαφορετικά seeds)
N_WINDOWS          = 40   # παράθυρα ανά προσομοίωση
POLL_INTERVAL_S    = config.POLL_INTERVAL  # δευτερόλεπτα ανά παράθυρο (5s)


def _normal_flows(rng, n_mean=4):
    n = max(1, int(rng.normal(n_mean, 2)))
    return [(max(1, int(rng.normal(40, 20))),
             max(60, int(rng.normal(600, 200))) * max(1, int(rng.normal(40, 20))),
             max(0.1, rng.normal(8, 4)))
            for _ in range(n)]


def _attack_flows(rng, n_mean):
    """Flood ροές με συγκεκριμένη μέση ένταση."""
    n = max(3, int(rng.normal(n_mean, n_mean * 0.2)))
    return [(max(1, int(rng.normal(2.5, 1.5))),
             max(40, int(rng.normal(80, 30))) * max(1, int(rng.normal(2, 1))),
             max(0.01, rng.normal(0.5, 0.3)))
            for _ in range(n)]


def run_single(model, scaler, rng, n_windows, attack_mean, attacker_start):
    """
    Μία προσομοίωση. Επιστρέφει:
      - detection_lag_windows: παράθυρα από έναρξη επίθεσης έως 1η ανίχνευση
        (None αν δεν ανιχνεύθηκε ποτέ)
      - fp_count: λανθασμένες ανιχνεύσεις σε νόμιμη κίνηση
    """
    hosts    = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    attacker = "10.0.0.6"

    first_detection = None
    fp_count        = 0
    blocked_until   = {}
    BLOCK_WINDOWS   = 4

    for w in range(n_windows):
        # λήξη μπλοκαρίσματος
        for ip in list(blocked_until):
            if w >= blocked_until[ip]:
                del blocked_until[ip]

        # νόμιμοι hosts
        for h in hosts:
            feats   = engine.aggregate_features(_normal_flows(rng))
            verdict = engine.classify(feats, model, scaler)
            if verdict == "Attack":
                fp_count += 1

        # επιτιθέμενος
        if w >= attacker_start and attacker not in blocked_until:
            feats   = engine.aggregate_features(_attack_flows(rng, attack_mean))
            verdict = engine.classify(feats, model, scaler)
            if verdict == "Attack":
                if first_detection is None:
                    first_detection = w
                blocked_until[attacker] = w + BLOCK_WINDOWS

    lag = (first_detection - attacker_start) if first_detection is not None else None
    return lag, fp_count


def run_experiment():
    model, scaler = engine.load_live_model()
    if model is None:
        print("[!] Δεν βρέθηκε live μοντέλο. Χρήση heuristic.")

    attacker_start = int(N_WINDOWS * 0.35)
    all_results    = []

    for intensity in ATTACK_INTENSITIES:
        lags   = []
        fp_tot = 0
        misses = 0

        for trial in range(N_TRIALS):
            rng = np.random.default_rng(trial * 1000 + intensity)
            lag, fp = run_single(model, scaler, rng, N_WINDOWS, intensity, attacker_start)
            fp_tot += fp
            if lag is None:
                misses += 1
            else:
                lags.append(lag)

        detection_rate = (N_TRIALS - misses) / N_TRIALS * 100
        mean_lag       = np.mean(lags) if lags else float("nan")
        median_lag     = np.median(lags) if lags else float("nan")
        p75_lag        = np.percentile(lags, 75) if lags else float("nan")
        mean_lag_s     = mean_lag * POLL_INTERVAL_S

        all_results.append({
            "intensity":       intensity,
            "detection_rate%": detection_rate,
            "mean_lag_windows": mean_lag,
            "median_lag_windows": median_lag,
            "p75_lag_windows": p75_lag,
            "mean_lag_seconds": mean_lag_s,
            "misses":          misses,
            "fp_per_trial":    fp_tot / N_TRIALS,
            "lags":            lags,
        })
        print(f"  Ένταση={intensity:3d} ροές/παράθυρο | "
              f"Ανίχνευση={detection_rate:5.1f}% | "
              f"Μέση καθυστέρηση={mean_lag:.2f} παράθυρα "
              f"({mean_lag_s:.1f}s)")

    return all_results


def plot_latency(results):
    intensities = [r["intensity"] for r in results]
    all_lags    = [r["lags"] for r in results]
    mean_lags_s = [r["mean_lag_seconds"] for r in results]
    det_rates   = [r["detection_rate%"] for r in results]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # --- Box plot καθυστέρησης σε παράθυρα ---
    bp = ax1.boxplot(
        all_lags,
        positions=range(len(intensities)),
        patch_artist=True,
        widths=0.55,
        showfliers=True,
        medianprops=dict(color="black", linewidth=2),
    )
    colors = plt.cm.RdYlGn(np.linspace(0.2, 0.8, len(intensities)))
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.8)

    ax1.set_xticks(range(len(intensities)))
    ax1.set_xticklabels(intensities, fontsize=9)
    ax1.set_xlabel("Ένταση Επίθεσης (ροές / παράθυρο)", fontsize=11)
    ax1.set_ylabel(f"Καθυστέρηση Ανίχνευσης (παράθυρα × {POLL_INTERVAL_S}s)", fontsize=11)
    ax1.set_title("Κατανομή Καθυστέρησης Ανίχνευσης\nανά Επίπεδο Έντασης Επίθεσης",
                  fontsize=12)
    ax1.grid(axis="y", linestyle="--", alpha=0.4)
    ax1.axhline(1, color="red", linestyle=":", linewidth=1, label="1 παράθυρο (ιδανικό)")
    ax1.legend(fontsize=9)

    # --- Ρυθμός ανίχνευσης ανά ένταση ---
    ax2.plot(intensities, det_rates, "o-", color="steelblue",
             linewidth=2, markersize=7, markerfacecolor="white", markeredgewidth=2)
    ax2.fill_between(intensities, det_rates, alpha=0.1, color="steelblue")
    ax2.set_xlabel("Ένταση Επίθεσης (ροές / παράθυρο)", fontsize=11)
    ax2.set_ylabel("Ρυθμός Ανίχνευσης (%)", fontsize=11)
    ax2.set_title("Ρυθμός Ανίχνευσης ανά Ένταση Επίθεσης\n"
                  f"({N_TRIALS} δοκιμές ανά επίπεδο)", fontsize=12)
    ax2.set_ylim(0, 105)
    ax2.axhline(100, color="green", linestyle="--", linewidth=1, alpha=0.5)
    ax2.grid(linestyle="--", alpha=0.4)

    # Annotation για threshold ανίχνευσης
    for x, r in zip(intensities, det_rates):
        ax2.annotate(f"{r:.0f}%", (x, r), textcoords="offset points",
                     xytext=(0, 6), ha="center", fontsize=8)

    plt.suptitle(
        "Ανάλυση Καθυστέρησης Ανίχνευσης Επίθεσης σε SDN\n"
        f"(Live ML μοντέλο, {POLL_INTERVAL_S}s ανά παράθυρο δειγματοληψίας)",
        fontsize=13, y=1.02,
    )
    plt.tight_layout()
    out = os.path.join(config.RESULTS_DIR, "latency_vs_intensity.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out}")


def save_csv(results):
    rows = []
    for r in results:
        rows.append({
            "intensity_flows_per_window": r["intensity"],
            "detection_rate_pct":         round(r["detection_rate%"], 1),
            "mean_lag_windows":           round(r["mean_lag_windows"], 2) if not np.isnan(r["mean_lag_windows"]) else "N/A",
            "median_lag_windows":         round(r["median_lag_windows"], 2) if not np.isnan(r["median_lag_windows"]) else "N/A",
            "mean_lag_seconds":           round(r["mean_lag_seconds"], 1) if not np.isnan(r["mean_lag_seconds"]) else "N/A",
            "misses_out_of_30":           r["misses"],
            "fp_per_trial":               round(r["fp_per_trial"], 2),
        })
    df = pd.DataFrame(rows)
    out = os.path.join(config.RESULTS_DIR, "latency_stats.csv")
    df.to_csv(out, index=False)
    print(f"[OK] {out}")
    return df


def print_summary(df):
    print("\n" + "=" * 65)
    print("  ΑΠΟΤΕΛΕΣΜΑΤΑ ΑΝΑΛΥΣΗΣ ΚΑΘΥΣΤΕΡΗΣΗΣ ΑΝΙΧΝΕΥΣΗΣ")
    print("=" * 65)
    print(df.to_string(index=False))

    # Εύρεση threshold 100% ανίχνευσης
    full_det = df[df["detection_rate_pct"] == 100.0]
    if not full_det.empty:
        thresh = full_det.iloc[0]["intensity_flows_per_window"]
        lag_s  = full_det.iloc[0]["mean_lag_seconds"]
        print(f"\n  Threshold 100% ανίχνευσης: {thresh} ροές/παράθυρο")
        print(f"  Μέση καθυστέρηση στο threshold: {lag_s}s")

    min_lag_row = df[df["mean_lag_seconds"] != "N/A"].copy()
    if not min_lag_row.empty:
        min_lag_row["mean_lag_seconds"] = min_lag_row["mean_lag_seconds"].astype(float)
        best = min_lag_row.loc[min_lag_row["mean_lag_seconds"].idxmin()]
        print(f"  Ταχύτερη ανίχνευση: {best['mean_lag_seconds']}s "
              f"(ένταση {best['intensity_flows_per_window']} ροές/παράθυρο)")


def main():
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    print("[*] Ανάλυση Καθυστέρησης Ανίχνευσης")
    print(f"    Εντάσεις: {ATTACK_INTENSITIES}")
    print(f"    Δοκιμές ανά ένταση: {N_TRIALS}")
    print(f"    Παράθυρο δειγματοληψίας: {POLL_INTERVAL_S}s\n")

    results = run_experiment()
    plot_latency(results)
    df = save_csv(results)
    print_summary(df)
    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Ανάλυση καθυστέρησης αποθηκεύτηκε στο results/")


if __name__ == "__main__":
    main()
