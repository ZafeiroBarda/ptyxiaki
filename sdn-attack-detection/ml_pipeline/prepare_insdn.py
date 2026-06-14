#!/usr/bin/env python3
"""
prepare_insdn.py  (προετοιμασία πραγματικού InSDN dataset)
----------------------------------------------------------
Ενώνει τα 3 αρχεία του InSDN (Normal_data.csv, OVS.csv, metasploitable-2.csv),
κανονικοποιεί τα ονόματα στηλών ώστε να ταιριάζουν με το config μας, φιλτράρει
στις 5 βασικές κλάσεις και αποθηκεύει ένα έτοιμο data/InSDN_dataset.csv.

Χρήση:
  python3 ml_pipeline/prepare_insdn.py --src /path/to/InSDN_DatasetCSV
"""

import os
import sys
import argparse
import pandas as pd
import numpy as np

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config


def normalize_col(c):
    """π.χ. 'Flow Byts/s' -> 'Flow_Byts_s', 'Down/Up Ratio' -> 'Down_Up_Ratio'."""
    return c.strip().replace("/", "_").replace(" ", "_")


# Αντιστοίχιση ετικετών InSDN -> δικές μας κλάσεις (CLASSES)
LABEL_MAP = {
    "Normal": "Normal",
    "DDoS": "DDoS",
    "DoS": "DoS",
    "Probe": "Probe",
    "BFA": "BFA",
    # σπάνιες κατηγορίες — εξαιρούνται από το 5-class setup
    # "Web-Attack", "BOTNET", "U2R" -> None (αγνοούνται)
}


def main(src_dir):
    files = ["Normal_data.csv", "OVS.csv", "metasploitable-2.csv"]
    frames = []
    for f in files:
        path = os.path.join(src_dir, f)
        if not os.path.exists(path):
            print(f"[!] Δεν βρέθηκε {path} — παράλειψη.")
            continue
        print(f"[*] Φόρτωση {f} ...")
        df = pd.read_csv(path, low_memory=False)
        df.columns = [normalize_col(c) for c in df.columns]
        frames.append(df)

    if not frames:
        raise SystemExit("Δεν φορτώθηκε κανένα αρχείο InSDN.")

    full = pd.concat(frames, ignore_index=True)
    print(f"[*] Συνολικές γραμμές πριν το φιλτράρισμα: {len(full)}")

    # καθάρισε & αντιστοίχισε ετικέτες
    full[config.LABEL_COL] = full[config.LABEL_COL].astype(str).str.strip()
    full["__mapped"] = full[config.LABEL_COL].map(lambda x: LABEL_MAP.get(x, None))
    before = len(full)
    full = full[full["__mapped"].notna()].copy()
    full[config.LABEL_COL] = full["__mapped"]
    full.drop(columns="__mapped", inplace=True)
    print(f"[*] Εξαιρέθηκαν {before - len(full)} γραμμές σπάνιων κλάσεων "
          f"(Web-Attack/BOTNET/U2R).")

    # κράτα μόνο τα 24 features + Label
    missing = [c for c in config.FEATURE_COLUMNS if c not in full.columns]
    if missing:
        print(f"[!] ΠΡΟΣΟΧΗ: λείπουν στήλες: {missing}")
    keep = [c for c in config.FEATURE_COLUMNS if c in full.columns] + [config.LABEL_COL]
    full = full[keep]

    # καθάρισε inf/nan
    full = full.replace([np.inf, -np.inf], np.nan).dropna()
    print(f"[*] Τελικές γραμμές μετά τον καθαρισμό: {len(full)}")
    print("\nΚατανομή κλάσεων:")
    print(full[config.LABEL_COL].value_counts())

    os.makedirs(config.DATA_DIR, exist_ok=True)
    full.to_csv(config.INSDN_CSV, index=False)
    print(f"\n[OK] Αποθηκεύτηκε: {config.INSDN_CSV}  (σχήμα {full.shape})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default="/home/claude/insdn_raw/InSDN_DatasetCSV",
                        help="Φάκελος με τα 3 CSV του InSDN")
    args = parser.parse_args()
    main(args.src)
