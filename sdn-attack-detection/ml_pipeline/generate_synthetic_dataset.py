"""
generate_synthetic_dataset.py
------------------------------
Δημιουργεί ένα ΡΕΑΛΙΣΤΙΚΟ συνθετικό dataset ροών SDN με την ίδια δομή
χαρακτηριστικών με το InSDN (CICFlowMeter-style).

Σκοπός: να μπορεί όλο το pipeline (preprocess -> train -> evaluate) να τρέχει
end-to-end ΑΜΕΣΩΣ, χωρίς να χρειάζεται να κατεβάσεις πρώτα το πραγματικό dataset.
Όταν αποκτήσεις το πραγματικό InSDN, αλλάζεις απλώς την πηγή στο train.py.

ΠΡΟΣΟΧΗ (για τη διπλωματική): δήλωσε ξεκάθαρα ότι αυτά είναι συνθετικά δεδομένα
που χρησιμοποιήθηκαν για την ΑΝΑΠΤΥΞΗ του pipeline. Τα τελικά αποτελέσματα της
εργασίας πρέπει να παραχθούν είτε με το πραγματικό InSDN (μέθοδος Β) είτε με
δεδομένα από τη δική σου προσομοίωση Mininet (μέθοδος Α).

Κάθε κλάση έχει διαφορετική "στατιστική υπογραφή", βασισμένη στη συμπεριφορά
που περιγράφεται στη βιβλιογραφία:
  - Normal : ισορροπημένη αμφίδρομη κίνηση, λογικά IAT, ποικιλία μεγεθών.
  - DDoS   : τεράστιος ρυθμός πακέτων, μικρά πακέτα, πολλά SYN, μικρό IAT.
  - DoS    : υψηλός ρυθμός από λιγότερες πηγές, half-open συνδέσεις (SYN flood).
  - Probe  : port/網 scanning -> πολλές μικρές ροές, RST, ελάχιστα bytes.
  - BFA    : brute force (π.χ. SSH) -> επαναλαμβανόμενες όμοιες συνδέσεις.
"""

import numpy as np
import pandas as pd

import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config


def _clip_nonneg(arr):
    """Δεν υπάρχουν αρνητικές μετρήσεις σε ροές."""
    return np.clip(arr, 0, None)


def _gen_normal(n, rng):
    d = {}
    dur = _clip_nonneg(rng.lognormal(mean=12.0, sigma=1.2, size=n))            # ευρεία διάρκεια
    fwd = _clip_nonneg(rng.normal(20, 12, n)).astype(int) + 1
    bwd = _clip_nonneg(rng.normal(18, 11, n)).astype(int) + 1
    fwd_len_mean = _clip_nonneg(rng.normal(550, 250, n))
    bwd_len_mean = _clip_nonneg(rng.normal(600, 280, n))
    d["Flow_Duration"] = dur
    d["Tot_Fwd_Pkts"] = fwd
    d["Tot_Bwd_Pkts"] = bwd
    d["TotLen_Fwd_Pkts"] = fwd * fwd_len_mean
    d["TotLen_Bwd_Pkts"] = bwd * bwd_len_mean
    d["Fwd_Pkt_Len_Mean"] = fwd_len_mean
    d["Bwd_Pkt_Len_Mean"] = bwd_len_mean
    total_bytes = d["TotLen_Fwd_Pkts"] + d["TotLen_Bwd_Pkts"]
    total_pkts = fwd + bwd
    d["Flow_Byts_s"] = total_bytes / (dur / 1e6 + 1e-3)
    d["Flow_Pkts_s"] = total_pkts / (dur / 1e6 + 1e-3)
    d["Flow_IAT_Mean"] = _clip_nonneg(rng.normal(40000, 20000, n))
    d["Flow_IAT_Std"] = _clip_nonneg(rng.normal(25000, 12000, n))
    d["Fwd_IAT_Mean"] = _clip_nonneg(rng.normal(45000, 20000, n))
    d["Bwd_IAT_Mean"] = _clip_nonneg(rng.normal(42000, 20000, n))
    d["SYN_Flag_Cnt"] = rng.integers(0, 3, n)
    d["ACK_Flag_Cnt"] = _clip_nonneg(rng.normal(15, 8, n)).astype(int)
    d["FIN_Flag_Cnt"] = rng.integers(0, 3, n)
    d["RST_Flag_Cnt"] = rng.integers(0, 2, n)
    d["Pkt_Len_Mean"] = (fwd_len_mean + bwd_len_mean) / 2
    d["Pkt_Len_Std"] = _clip_nonneg(rng.normal(180, 60, n))
    d["Down_Up_Ratio"] = _clip_nonneg(rng.normal(1.1, 0.4, n))
    d["Pkt_Size_Avg"] = d["Pkt_Len_Mean"] * rng.normal(1.0, 0.05, n)
    d["Active_Mean"] = _clip_nonneg(rng.normal(120000, 60000, n))
    d["Idle_Mean"] = _clip_nonneg(rng.normal(2_000_000, 1_000_000, n))
    d["Init_Fwd_Win_Byts"] = rng.integers(2048, 65535, n)
    return d


def _gen_ddos(n, rng):
    d = {}
    dur = _clip_nonneg(rng.lognormal(mean=8.0, sigma=1.0, size=n))             # σύντομες ροές
    fwd = _clip_nonneg(rng.normal(4, 3, n)).astype(int) + 1
    bwd = _clip_nonneg(rng.normal(1, 1, n)).astype(int)                        # σχεδόν χωρίς απάντηση
    fwd_len_mean = _clip_nonneg(rng.normal(80, 30, n))                         # μικρά πακέτα
    bwd_len_mean = _clip_nonneg(rng.normal(40, 25, n))
    d["Flow_Duration"] = dur
    d["Tot_Fwd_Pkts"] = fwd
    d["Tot_Bwd_Pkts"] = bwd
    d["TotLen_Fwd_Pkts"] = fwd * fwd_len_mean
    d["TotLen_Bwd_Pkts"] = bwd * bwd_len_mean
    d["Fwd_Pkt_Len_Mean"] = fwd_len_mean
    d["Bwd_Pkt_Len_Mean"] = bwd_len_mean
    total_bytes = d["TotLen_Fwd_Pkts"] + d["TotLen_Bwd_Pkts"]
    total_pkts = fwd + bwd
    d["Flow_Byts_s"] = total_bytes / (dur / 1e6 + 1e-5)
    d["Flow_Pkts_s"] = _clip_nonneg(rng.normal(50000, 25000, n))              # ΤΕΡΑΣΤΙΟΣ ρυθμός
    d["Flow_IAT_Mean"] = _clip_nonneg(rng.normal(50, 40, n))                   # ελάχιστο IAT
    d["Flow_IAT_Std"] = _clip_nonneg(rng.normal(30, 25, n))
    d["Fwd_IAT_Mean"] = _clip_nonneg(rng.normal(55, 40, n))
    d["Bwd_IAT_Mean"] = _clip_nonneg(rng.normal(60, 50, n))
    d["SYN_Flag_Cnt"] = _clip_nonneg(rng.normal(5, 3, n)).astype(int) + 1     # SYN flood
    d["ACK_Flag_Cnt"] = rng.integers(0, 2, n)
    d["FIN_Flag_Cnt"] = rng.integers(0, 1, n)
    d["RST_Flag_Cnt"] = rng.integers(0, 2, n)
    d["Pkt_Len_Mean"] = (fwd_len_mean + bwd_len_mean) / 2
    d["Pkt_Len_Std"] = _clip_nonneg(rng.normal(20, 10, n))
    d["Down_Up_Ratio"] = _clip_nonneg(rng.normal(0.1, 0.1, n))
    d["Pkt_Size_Avg"] = d["Pkt_Len_Mean"] * rng.normal(1.0, 0.05, n)
    d["Active_Mean"] = _clip_nonneg(rng.normal(5000, 3000, n))
    d["Idle_Mean"] = _clip_nonneg(rng.normal(1000, 800, n))
    d["Init_Fwd_Win_Byts"] = rng.integers(0, 1024, n)
    return d


def _gen_dos(n, rng):
    d = {}
    dur = _clip_nonneg(rng.lognormal(mean=9.5, sigma=1.1, size=n))
    fwd = _clip_nonneg(rng.normal(8, 5, n)).astype(int) + 1
    bwd = _clip_nonneg(rng.normal(2, 2, n)).astype(int)
    fwd_len_mean = _clip_nonneg(rng.normal(120, 50, n))
    bwd_len_mean = _clip_nonneg(rng.normal(60, 30, n))
    d["Flow_Duration"] = dur
    d["Tot_Fwd_Pkts"] = fwd
    d["Tot_Bwd_Pkts"] = bwd
    d["TotLen_Fwd_Pkts"] = fwd * fwd_len_mean
    d["TotLen_Bwd_Pkts"] = bwd * bwd_len_mean
    d["Fwd_Pkt_Len_Mean"] = fwd_len_mean
    d["Bwd_Pkt_Len_Mean"] = bwd_len_mean
    total_bytes = d["TotLen_Fwd_Pkts"] + d["TotLen_Bwd_Pkts"]
    total_pkts = fwd + bwd
    d["Flow_Byts_s"] = total_bytes / (dur / 1e6 + 1e-5)
    d["Flow_Pkts_s"] = _clip_nonneg(rng.normal(12000, 6000, n))              # υψηλός ρυθμός
    d["Flow_IAT_Mean"] = _clip_nonneg(rng.normal(400, 300, n))
    d["Flow_IAT_Std"] = _clip_nonneg(rng.normal(250, 180, n))
    d["Fwd_IAT_Mean"] = _clip_nonneg(rng.normal(420, 300, n))
    d["Bwd_IAT_Mean"] = _clip_nonneg(rng.normal(500, 350, n))
    d["SYN_Flag_Cnt"] = _clip_nonneg(rng.normal(8, 4, n)).astype(int) + 1     # half-open
    d["ACK_Flag_Cnt"] = rng.integers(0, 3, n)
    d["FIN_Flag_Cnt"] = rng.integers(0, 2, n)
    d["RST_Flag_Cnt"] = _clip_nonneg(rng.normal(2, 2, n)).astype(int)
    d["Pkt_Len_Mean"] = (fwd_len_mean + bwd_len_mean) / 2
    d["Pkt_Len_Std"] = _clip_nonneg(rng.normal(40, 20, n))
    d["Down_Up_Ratio"] = _clip_nonneg(rng.normal(0.2, 0.15, n))
    d["Pkt_Size_Avg"] = d["Pkt_Len_Mean"] * rng.normal(1.0, 0.05, n)
    d["Active_Mean"] = _clip_nonneg(rng.normal(15000, 8000, n))
    d["Idle_Mean"] = _clip_nonneg(rng.normal(8000, 5000, n))
    d["Init_Fwd_Win_Byts"] = rng.integers(0, 4096, n)
    return d


def _gen_probe(n, rng):
    d = {}
    dur = _clip_nonneg(rng.lognormal(mean=7.0, sigma=1.3, size=n))            # πολύ σύντομες
    fwd = _clip_nonneg(rng.normal(2, 1, n)).astype(int) + 1
    bwd = rng.integers(0, 2, n)
    fwd_len_mean = _clip_nonneg(rng.normal(45, 20, n))                        # ελάχιστα bytes
    bwd_len_mean = _clip_nonneg(rng.normal(40, 25, n))
    d["Flow_Duration"] = dur
    d["Tot_Fwd_Pkts"] = fwd
    d["Tot_Bwd_Pkts"] = bwd
    d["TotLen_Fwd_Pkts"] = fwd * fwd_len_mean
    d["TotLen_Bwd_Pkts"] = bwd * bwd_len_mean
    d["Fwd_Pkt_Len_Mean"] = fwd_len_mean
    d["Bwd_Pkt_Len_Mean"] = bwd_len_mean
    total_bytes = d["TotLen_Fwd_Pkts"] + d["TotLen_Bwd_Pkts"]
    total_pkts = fwd + bwd
    d["Flow_Byts_s"] = total_bytes / (dur / 1e6 + 1e-5)
    d["Flow_Pkts_s"] = _clip_nonneg(rng.normal(800, 600, n))
    d["Flow_IAT_Mean"] = _clip_nonneg(rng.normal(2000, 1500, n))
    d["Flow_IAT_Std"] = _clip_nonneg(rng.normal(1500, 1000, n))
    d["Fwd_IAT_Mean"] = _clip_nonneg(rng.normal(2100, 1500, n))
    d["Bwd_IAT_Mean"] = _clip_nonneg(rng.normal(2500, 1800, n))
    d["SYN_Flag_Cnt"] = _clip_nonneg(rng.normal(1.5, 1, n)).astype(int) + 1
    d["ACK_Flag_Cnt"] = rng.integers(0, 2, n)
    d["FIN_Flag_Cnt"] = rng.integers(0, 1, n)
    d["RST_Flag_Cnt"] = _clip_nonneg(rng.normal(2, 1.5, n)).astype(int) + 1   # πολλά RST (closed ports)
    d["Pkt_Len_Mean"] = (fwd_len_mean + bwd_len_mean) / 2
    d["Pkt_Len_Std"] = _clip_nonneg(rng.normal(15, 10, n))
    d["Down_Up_Ratio"] = _clip_nonneg(rng.normal(0.5, 0.4, n))
    d["Pkt_Size_Avg"] = d["Pkt_Len_Mean"] * rng.normal(1.0, 0.05, n)
    d["Active_Mean"] = _clip_nonneg(rng.normal(3000, 2000, n))
    d["Idle_Mean"] = _clip_nonneg(rng.normal(5000, 3000, n))
    d["Init_Fwd_Win_Byts"] = rng.integers(0, 8192, n)
    return d


def _gen_bfa(n, rng):
    d = {}
    dur = _clip_nonneg(rng.lognormal(mean=11.0, sigma=0.8, size=n))           # σταθερές, επαναλαμβανόμενες
    fwd = _clip_nonneg(rng.normal(15, 5, n)).astype(int) + 1
    bwd = _clip_nonneg(rng.normal(12, 4, n)).astype(int) + 1
    fwd_len_mean = _clip_nonneg(rng.normal(200, 40, n))                       # όμοιο μέγεθος (login attempts)
    bwd_len_mean = _clip_nonneg(rng.normal(180, 40, n))
    d["Flow_Duration"] = dur
    d["Tot_Fwd_Pkts"] = fwd
    d["Tot_Bwd_Pkts"] = bwd
    d["TotLen_Fwd_Pkts"] = fwd * fwd_len_mean
    d["TotLen_Bwd_Pkts"] = bwd * bwd_len_mean
    d["Fwd_Pkt_Len_Mean"] = fwd_len_mean
    d["Bwd_Pkt_Len_Mean"] = bwd_len_mean
    total_bytes = d["TotLen_Fwd_Pkts"] + d["TotLen_Bwd_Pkts"]
    total_pkts = fwd + bwd
    d["Flow_Byts_s"] = total_bytes / (dur / 1e6 + 1e-5)
    d["Flow_Pkts_s"] = _clip_nonneg(rng.normal(300, 150, n))
    d["Flow_IAT_Mean"] = _clip_nonneg(rng.normal(8000, 3000, n))
    d["Flow_IAT_Std"] = _clip_nonneg(rng.normal(2000, 800, n))               # χαμηλό std (κανονικότητα)
    d["Fwd_IAT_Mean"] = _clip_nonneg(rng.normal(8200, 3000, n))
    d["Bwd_IAT_Mean"] = _clip_nonneg(rng.normal(8500, 3200, n))
    d["SYN_Flag_Cnt"] = _clip_nonneg(rng.normal(2, 1, n)).astype(int) + 1
    d["ACK_Flag_Cnt"] = _clip_nonneg(rng.normal(20, 6, n)).astype(int)
    d["FIN_Flag_Cnt"] = _clip_nonneg(rng.normal(2, 1, n)).astype(int)
    d["RST_Flag_Cnt"] = _clip_nonneg(rng.normal(3, 2, n)).astype(int)        # απορρίψεις login
    d["Pkt_Len_Mean"] = (fwd_len_mean + bwd_len_mean) / 2
    d["Pkt_Len_Std"] = _clip_nonneg(rng.normal(25, 8, n))                    # χαμηλό std
    d["Down_Up_Ratio"] = _clip_nonneg(rng.normal(0.9, 0.2, n))
    d["Pkt_Size_Avg"] = d["Pkt_Len_Mean"] * rng.normal(1.0, 0.05, n)
    d["Active_Mean"] = _clip_nonneg(rng.normal(60000, 20000, n))
    d["Idle_Mean"] = _clip_nonneg(rng.normal(40000, 20000, n))
    d["Init_Fwd_Win_Byts"] = rng.integers(1024, 32768, n)
    return d


GENERATORS = {
    "Normal": _gen_normal,
    "DDoS": _gen_ddos,
    "DoS": _gen_dos,
    "Probe": _gen_probe,
    "BFA": _gen_bfa,
}


def _inject_realism(df, rng, noise_level=0.15, overlap_frac=0.08):
    """
    Κάνει τα δεδομένα πιο ρεαλιστικά (πιο δύσκολα για το ML):
      - Πολλαπλασιαστικός θόρυβος Gauss σε όλα τα features.
      - Επικάλυψη κλάσεων: ένα ποσοστό δειγμάτων DoS/DDoS "δανείζεται" τιμές
        από τη γειτονική κλάση, ώστε να μην είναι τέλεια διαχωρίσιμα.
    Αυτό ρίχνει το accuracy σε ρεαλιστικά επίπεδα (~0.90–0.97 αντί για ~1.0).
    """
    feats = config.FEATURE_COLUMNS
    # 1) πολλαπλασιαστικός θόρυβος
    noise = rng.normal(1.0, noise_level, size=df[feats].shape)
    df[feats] = np.clip(df[feats].values * noise, 0, None)

    # 2) επικάλυψη γειτονικών κλάσεων (συχνά συγχέονται στη βιβλιογραφία)
    for a, b in [("DoS", "DDoS"), ("Probe", "DoS"), ("BFA", "Normal")]:
        idx_a = df.index[df[config.LABEL_COL] == a]
        n_overlap = int(len(idx_a) * overlap_frac)
        if n_overlap == 0:
            continue
        chosen = rng.choice(idx_a, size=n_overlap, replace=False)
        donor_rows = df[df[config.LABEL_COL] == b][feats]
        if len(donor_rows) == 0:
            continue
        donor_sample = donor_rows.sample(n=n_overlap, replace=True,
                                         random_state=int(rng.integers(1_000_000)))
        # μίξη 50-50 ώστε να μπερδεύεται ο ταξινομητής
        df.loc[chosen, feats] = (
            0.5 * df.loc[chosen, feats].values + 0.5 * donor_sample.values)
    return df


def generate(n_per_class=None, seed=config.RANDOM_STATE, hard=False):
    """Παράγει το dataset. Ελαφρώς ανισόρροπο, όπως στην πραγματικότητα.

    hard=True -> προσθέτει θόρυβο & επικάλυψη κλάσεων (ρεαλιστικότερο).
    """
    if n_per_class is None:
        # ρεαλιστική ανισορροπία: πολλή normal, λιγότερες σπάνιες επιθέσεις
        n_per_class = {"Normal": 8000, "DDoS": 5000, "DoS": 3500, "Probe": 2500, "BFA": 1500}

    rng = np.random.default_rng(seed)
    frames = []
    for cls, gen in GENERATORS.items():
        n = n_per_class[cls]
        data = gen(n, rng)
        df = pd.DataFrame(data)
        df = df[config.FEATURE_COLUMNS]  # σταθερή σειρά στηλών
        df[config.LABEL_COL] = cls
        frames.append(df)

    full = pd.concat(frames, ignore_index=True)
    if hard:
        full = _inject_realism(full, rng)
    # ανακάτεμα
    full = full.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return full


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--hard", action="store_true",
                        help="Προσθήκη θορύβου & επικάλυψης κλάσεων (ρεαλιστικότερο)")
    args = parser.parse_args()

    os.makedirs(config.DATA_DIR, exist_ok=True)
    df = generate(hard=args.hard)
    df.to_csv(config.SYNTHETIC_CSV, index=False)
    mode = "HARD (με θόρυβο/επικάλυψη)" if args.hard else "EASY (καθαρές υπογραφές)"
    print(f"[OK] Δημιουργήθηκε synthetic dataset [{mode}]: {config.SYNTHETIC_CSV}")
    print(f"     Σχήμα (rows, cols): {df.shape}")
    print("\nΚατανομή κλάσεων:")
    print(df[config.LABEL_COL].value_counts())
    print("\nΠρώτες γραμμές:")
    print(df.head())
