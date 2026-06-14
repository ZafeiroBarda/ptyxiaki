#!/usr/bin/env python3
"""
final_comparison.py  (ΜΕΘΟΔΟΣ Β — τελική συγκεντρωτική σύγκριση)
---------------------------------------------------------------
Ενώνει τα αποτελέσματα ΟΛΩΝ των μοντέλων (6 κλασικά ML + 2 Deep Learning)
σε έναν ενιαίο πίνακα και ένα συγκεντρωτικό γράφημα — ιδανικό για το κεφάλαιο
"Πειράματα & Αποτελέσματα" της διπλωματικής.

Διαβάζει:
  results/model_comparison.csv   (από train.py / evaluate.py)
  results/dl_comparison.csv      (από deep_learning.py)
Αν λείπουν, τα παράγει τρέχοντας τα αντίστοιχα modules.

Παράγει:
  results/final_comparison.png
  results/final_comparison.csv
"""

import os
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

sns.set_theme(style="whitegrid")


def ensure_results(use_insdn=False):
    mc = os.path.join(config.RESULTS_DIR, "model_comparison.csv")
    dl = os.path.join(config.RESULTS_DIR, "dl_comparison.csv")
    if not os.path.exists(mc):
        print("[*] Λείπει model_comparison.csv — τρέχω train.py...")
        import train
        train.main(use_insdn=use_insdn)
    if not os.path.exists(dl):
        print("[*] Λείπει dl_comparison.csv — τρέχω deep_learning.py...")
        import deep_learning
        deep_learning.main(use_insdn=use_insdn, epochs=30)
    return mc, dl


def main(use_insdn=False):
    mc_path, dl_path = ensure_results(use_insdn)
    classical = pd.read_csv(mc_path)
    deep = pd.read_csv(dl_path)

    classical["type"] = "Κλασικό ML"
    deep["type"] = "Deep Learning"

    cols = ["model", "accuracy", "precision", "recall", "f1", "type"]
    merged = pd.concat([classical[cols], deep[cols]], ignore_index=True)
    merged = merged.sort_values("f1", ascending=False).reset_index(drop=True)

    print("\n" + "=" * 78)
    print("ΤΕΛΙΚΗ ΣΥΓΚΡΙΣΗ — ΟΛΑ ΤΑ ΜΟΝΤΕΛΑ (ταξινόμηση κατά F1)")
    print("=" * 78)
    print(merged.to_string(index=False))

    out_csv = os.path.join(config.RESULTS_DIR, "final_comparison.csv")
    merged.to_csv(out_csv, index=False)
    print(f"\n[OK] {out_csv}")

    # --- γράφημα ---
    plt.figure(figsize=(13, 6.5))
    order = merged.sort_values("f1", ascending=False)
    palette = {"Κλασικό ML": "#4C72B0", "Deep Learning": "#C44E52"}
    bars = sns.barplot(data=order, x="model", y="f1", hue="type",
                       palette=palette, dodge=False)
    bars.set_title("Τελική σύγκριση μοντέλων (F1-score, macro) — Ανίχνευση Επιθέσεων SDN")
    bars.set_xlabel("Μοντέλο"); bars.set_ylabel("F1-score (macro)")
    bars.set_ylim(min(0.9, order["f1"].min() - 0.03), 1.005)
    for p in bars.patches:
        if p.get_height() > 0:
            bars.annotate(f"{p.get_height():.3f}",
                          (p.get_x() + p.get_width() / 2, p.get_height()),
                          ha="center", va="bottom", fontsize=8)
    plt.xticks(rotation=25, ha="right")
    plt.legend(title="Κατηγορία", loc="lower right")
    plt.ylim(min(0.9, order["f1"].min() - 0.03), 1.005)  # zoom μετά το annotate
    plt.tight_layout()
    out_png = os.path.join(config.RESULTS_DIR, "final_comparison.png")
    plt.savefig(out_png, dpi=150); plt.close()
    print(f"[OK] {out_png}")
    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Τελική σύγκριση στο results/.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--insdn", action="store_true")
    args = parser.parse_args()
    main(use_insdn=args.insdn)
