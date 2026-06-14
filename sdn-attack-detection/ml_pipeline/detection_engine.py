#!/usr/bin/env python3
"""
detection_engine.py  (κοινή μηχανή ανίχνευσης — χωρίς εξάρτηση από Ryu/POX)
---------------------------------------------------------------------------
Περιέχει την καθαρή λογική ανίχνευσης που μοιράζονται:
  - ο Ryu controller (detection_controller.py)
  - ο POX controller (pox_detection.py)
  - ο offline προσομοιωτής (offline_replay.py)

Έτσι η λογική feature-extraction + ταξινόμησης είναι ΜΙΑ και ΜΟΝΗ (DRY),
δοκιμασμένη ανεξάρτητα από το περιβάλλον SDN.
"""

import os
import sys
import joblib
import numpy as np

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config


def load_live_model():
    """Φορτώνει το live μοντέλο & scaler. Επιστρέφει (model, scaler) ή (None, None)."""
    try:
        model = joblib.load(os.path.join(config.MODELS_DIR, "live_model.pkl"))
        scaler = joblib.load(os.path.join(config.MODELS_DIR, "live_scaler.pkl"))
        return model, scaler
    except Exception:
        return None, None


def aggregate_features(flows):
    """
    flows: λίστα από tuples (packet_count, byte_count, duration) για μία πηγή IP.
    Επιστρέφει np.array με τα config.LIVE_FEATURE_COLUMNS (με σταθερή σειρά).
    """
    fc = len(flows)
    if fc == 0:
        return np.zeros(len(config.LIVE_FEATURE_COLUMNS))
    tp = sum(f[0] for f in flows)
    tb = sum(f[1] for f in flows)
    durs = [f[2] for f in flows]
    avg_p = tp / fc
    avg_b = tb / fc
    avg_d = sum(durs) / fc
    avg_ps = tb / tp if tp else 0
    short = sum(1 for f in flows if f[0] <= config.SHORT_FLOW_PKT_THRESHOLD)
    sr = short / fc
    return np.array([fc, tp, tb, avg_p, avg_b, avg_d, avg_ps, sr], dtype=float)


def classify(feats, model=None, scaler=None):
    """Επιστρέφει 'Attack' ή 'Normal'. Fallback σε heuristic χωρίς μοντέλο."""
    if model is not None and scaler is not None:
        X = scaler.transform(feats.reshape(1, -1))
        return "Attack" if int(model.predict(X)[0]) == 1 else "Normal"
    # heuristic: πολλές σύντομες ροές = flood
    flow_count, short_ratio = feats[0], feats[7]
    if flow_count > config.ATTACK_FLOW_THRESHOLD and short_ratio > 0.6:
        return "Attack"
    return "Normal"
