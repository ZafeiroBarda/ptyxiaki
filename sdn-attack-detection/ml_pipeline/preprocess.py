"""
preprocess.py
-------------
Φόρτωση & προεπεξεργασία δεδομένων ροών SDN.

Δουλεύει με δύο πηγές:
  1) Συνθετικό dataset (data/sdn_flows_synthetic.csv) -> για ανάπτυξη του pipeline.
  2) Πραγματικό InSDN CSV (data/InSDN_dataset.csv)    -> για τα τελικά αποτελέσματα.

Το InSDN διανέμεται σε πολλαπλά CSV (Normal_data, OVS, metasploitable...).
Η συνάρτηση load_insdn() δείχνει πώς να τα ενώσεις και να καθαρίσεις τα ονόματα
στηλών (έχουν συχνά κενά/ειδικούς χαρακτήρες από το CICFlowMeter).
"""

import os
import hashlib

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder


def feature_hash_groups(X):
    """Ομάδα ανά ΜΟΝΑΔΙΚΟ διάνυσμα χαρακτηριστικών.

    Στο InSDN το 47,5% των εγγραφών είναι ακριβή διπλότυπα σε επίπεδο
    διανύσματος χαρακτηριστικών (98,8% στην κλάση DDoS), κάτι εγγενές στις
    επιθέσεις πλημμύρας. Με τυχαίο διαχωρισμό, όμοια διανύσματα καταλήγουν
    ΚΑΙ στο train ΚΑΙ στο test, οπότε το μοντέλο μπορεί να απομνημονεύσει
    αντί να γενικεύσει.

    Μέτρηση: results/leakage_duplicates_insdn.csv. Προσοχή στον ορισμό: το
    47,5% είναι τα πλεονάζοντα αντίγραφα (duplicated, keep=first). Αν αντί
    αυτού μετρηθούν όλες οι γραμμές που ανήκουν σε ομάδα διπλοτύπων, το
    ποσοστό βγαίνει 51,4%. Τα δύο νούμερα δεν συγκρούονται, μετρούν
    διαφορετικά πράγματα. Η εργασία αναφέρει το 47,5%.

    Αποδίδοντας το ίδιο group id σε κάθε πανομοιότυπο διάνυσμα και κάνοντας
    group-aware split, εξασφαλίζουμε ότι ΚΑΝΕΝΑ διάνυσμα του test δεν έχει
    ακριβές αντίγραφο στο train (leakage-resistant split).
    """
    Xr = np.round(np.asarray(X, dtype=float), 6)
    return np.array([hashlib.md5(row.tobytes()).hexdigest() for row in Xr])


def group_train_test_split(X, y, test_size, random_state):
    """Στρωματοποιημένος διαχωρισμός που ΔΕΝ σπάει ομάδες διπλότυπων."""
    groups = feature_hash_groups(X)
    n_splits = max(2, int(round(1.0 / test_size)))
    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True,
                                random_state=random_state)
    train_idx, test_idx = next(sgkf.split(X, y, groups=groups))
    return train_idx, test_idx, groups

import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config


def _clean_dataframe(df, dedup=True):
    """Κοινός καθαρισμός: inf -> nan, αφαίρεση nan, (προαιρετικά) αφαίρεση διπλότυπων.

    ΠΡΟΣΟΧΗ: στο InSDN τα flood (DDoS/DoS) παράγουν ΝΟΜΙΜΑ πανομοιότυπες ροές,
    οπότε η αφαίρεση διπλότυπων θα έσβηνε σχεδόν όλη την κλάση DDoS. Γι' αυτό
    για το InSDN καλούμε dedup=False.
    """
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    if dedup:
        df = df.drop_duplicates()
    return df.reset_index(drop=True)


def load_synthetic(path=None):
    """Φορτώνει το συνθετικό dataset."""
    path = path or config.SYNTHETIC_CSV
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Δεν βρέθηκε {path}. Τρέξε πρώτα: python3 ml_pipeline/generate_synthetic_dataset.py"
        )
    df = pd.read_csv(path)
    return _clean_dataframe(df)


def load_insdn(path=None):
    """
    Φορτώνει το πραγματικό InSDN dataset.

    Βήματα προσαρμογής (κάνε τα μία φορά όταν αποκτήσεις τα δεδομένα):
      1. Κατέβασε το InSDN (π.χ. από Kaggle: 'InSDN dataset') στον φάκελο data/.
      2. Αν έρχεται σε πολλά CSV, ένωσέ τα: pd.concat([...]).
      3. Καθάρισε τα ονόματα στηλών (.strip()).
      4. Βρες τη στήλη ετικέτας (συχνά 'Label') και αντιστοίχισε τις κατηγορίες
         στις δικές μας κλάσεις CLASSES, αν χρειάζεται (π.χ. 'DDoS '->'DDoS').
    """
    path = path or config.INSDN_CSV
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Δεν βρέθηκε {path}.\n"
            "Κατέβασε το InSDN dataset και βάλ' το στον φάκελο data/ ως 'InSDN_dataset.csv'.\n"
            "Πηγή: αναζήτησε 'InSDN dataset' σε Kaggle ή στο πανεπιστημιακό repository (TU Dublin)."
        )
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]  # καθάρισε κενά στα ονόματα

    # Παράδειγμα κανονικοποίησης ετικετών (προσάρμοσε στα πραγματικά ονόματα του InSDN):
    label_map = {
        "Normal": "Normal", "BENIGN": "Normal",
        "DDoS": "DDoS",
        "DoS": "DoS",
        "Probe": "Probe", "Port Scan": "Probe",
        "BFA": "BFA", "Brute Force": "BFA", "Web-Attack": "BFA",
    }
    if config.LABEL_COL in df.columns:
        df[config.LABEL_COL] = df[config.LABEL_COL].astype(str).str.strip()
        df[config.LABEL_COL] = df[config.LABEL_COL].map(lambda x: label_map.get(x, x))
    return _clean_dataframe(df, dedup=False)


def prepare(df, scale=True, feature_columns=None, subsample=None,
            split="random", val_size=0.0):
    """
    Χωρίζει σε X/y, κωδικοποιεί ετικέτες, κάνει train/(val)/test split και
    (προαιρετικά) κανονικοποίηση χαρακτηριστικών.

    subsample: αν δοθεί (π.χ. 60000), κάνει stratified υποδειγματοληψία ΠΡΙΝ το
    split — χρήσιμο για μεγάλα datasets (InSDN ~343k) ώστε αργά μοντέλα (SVM/KNN)
    να είναι εφικτά σε περιορισμένους πόρους.

    split:    "random" (κλασικός στρωματοποιημένος) ή "group" (leakage-resistant:
              τα πανομοιότυπα διανύσματα δεν μοιράζονται μεταξύ train και test).
    val_size: ποσοστό του ΣΥΝΟΛΟΥ που αποσπάται από το train ως validation set,
              για επιλογή μοντέλου χωρίς να «μολυνθεί» το test set.

    Επιστρέφει dict με όλα τα απαραίτητα για εκπαίδευση & αξιολόγηση.
    """
    feature_columns = feature_columns or [c for c in config.FEATURE_COLUMNS if c in df.columns]

    if subsample and subsample < len(df):
        frac = subsample / len(df)
        df = df.groupby(config.LABEL_COL, group_keys=False).sample(
            frac=frac, random_state=config.RANDOM_STATE).reset_index(drop=True)

    X = df[feature_columns].astype(float).values
    y_raw = df[config.LABEL_COL].values

    # Κωδικοποίηση ετικετών σε αριθμούς
    le = LabelEncoder()
    y = le.fit_transform(y_raw)

    # ── Διαχωρισμός train / test ────────────────────────────────────────────
    # split="group": τα πανομοιότυπα διανύσματα μένουν στην ΙΔΙΑ πλευρά, ώστε
    #                να μην υπάρχει διαρροή μέσω διπλότυπων (leakage-resistant).
    # split="random": ο κλασικός στρωματοποιημένος τυχαίος διαχωρισμός.
    if split == "group":
        tr_idx, te_idx, _ = group_train_test_split(
            X, y, config.TEST_SIZE, config.RANDOM_STATE)
        X_train, X_test = X[tr_idx], X[te_idx]
        y_train, y_test = y[tr_idx], y[te_idx]
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=config.TEST_SIZE,
            random_state=config.RANDOM_STATE,
            stratify=y,
        )

    # ── Προαιρετικό validation set, αποσπασμένο ΑΠΟ ΤΟ TRAIN ───────────────
    # Χρησιμεύει για επιλογή μοντέλου/υπερπαραμέτρων, ώστε το test set να
    # παραμένει εντελώς αόρατο μέχρι την τελική αξιολόγηση.
    X_val = y_val = None
    if val_size and val_size > 0:
        if split == "group":
            rel = val_size / (1.0 - config.TEST_SIZE)
            tr2, va2, _ = group_train_test_split(
                X_train, y_train, rel, config.RANDOM_STATE)
            X_train, X_val = X_train[tr2], X_train[va2]
            y_train, y_val = y_train[tr2], y_train[va2]
        else:
            rel = val_size / (1.0 - config.TEST_SIZE)
            X_train, X_val, y_train, y_val = train_test_split(
                X_train, y_train, test_size=rel,
                random_state=config.RANDOM_STATE, stratify=y_train)

    scaler = None
    if scale:
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)
        if X_val is not None:
            X_val = scaler.transform(X_val)

    return {
        "X_train": X_train, "X_test": X_test,
        "y_train": y_train, "y_test": y_test,
        "X_val": X_val, "y_val": y_val,
        "feature_columns": feature_columns,
        "label_encoder": le,
        "scaler": scaler,
        "class_names": list(le.classes_),
        "split": split,
    }


if __name__ == "__main__":
    df = load_synthetic()
    print(f"Φορτώθηκαν {len(df)} ροές, {len(df.columns)-1} χαρακτηριστικά.")
    data = prepare(df)
    print(f"Train: {data['X_train'].shape}, Test: {data['X_test'].shape}")
    print(f"Κλάσεις: {data['class_names']}")
