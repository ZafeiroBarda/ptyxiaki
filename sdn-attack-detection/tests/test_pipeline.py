#!/usr/bin/env python3
"""
test_pipeline.py  (έλεγχοι ορθότητας — pytest)
----------------------------------------------
Αυτοματοποιημένοι έλεγχοι που επιβεβαιώνουν ότι τα βασικά κομμάτια του
συστήματος δουλεύουν σωστά. Τρέξε με:

    pip install pytest
    pytest tests/ -v

Καλύπτει:
  - γεννήτορα συνθετικών δεδομένων (σχήμα, κλάσεις, καθαρότητα)
  - προεπεξεργασία (split, κανονικοποίηση, encoding)
  - μηχανή ανίχνευσης (feature extraction & ταξινόμηση)
"""

import os
import sys
import numpy as np
import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))

import config
import generate_synthetic_dataset as gen
import preprocess
import detection_engine as engine


# ----------------------------- Δεδομένα ----------------------------- #
def test_synthetic_shape_and_classes():
    df = gen.generate(n_per_class={c: 100 for c in config.CLASSES})
    # σωστός αριθμός στηλών (features + label)
    assert df.shape[1] == len(config.FEATURE_COLUMNS) + 1
    # όλες οι κλάσεις παρούσες
    assert set(df[config.LABEL_COL].unique()) == set(config.CLASSES)
    # σωστό πλήθος γραμμών
    assert len(df) == 100 * len(config.CLASSES)


def test_synthetic_no_negatives_or_nans():
    df = gen.generate(n_per_class={c: 80 for c in config.CLASSES})
    feats = df[config.FEATURE_COLUMNS].values
    assert not np.isnan(feats).any(), "Υπάρχουν NaN στα features"
    assert (feats >= 0).all(), "Υπάρχουν αρνητικές τιμές σε μετρήσεις ροών"


def test_hard_mode_changes_data():
    easy = gen.generate(n_per_class={c: 200 for c in config.CLASSES}, hard=False)
    hard = gen.generate(n_per_class={c: 200 for c in config.CLASSES}, hard=True)
    # ο θόρυβος αλλάζει τις τιμές
    assert not np.allclose(easy[config.FEATURE_COLUMNS].values,
                           hard[config.FEATURE_COLUMNS].values)


# --------------------------- Προεπεξεργασία -------------------------- #
def test_prepare_split_and_scaling():
    df = gen.generate(n_per_class={c: 150 for c in config.CLASSES})
    data = preprocess.prepare(df, scale=True)
    n_total = len(df)
    n_test = len(data["X_test"])
    # σωστό ποσοστό test
    assert abs(n_test / n_total - config.TEST_SIZE) < 0.02
    # μετά την κανονικοποίηση: μέση τιμή train ~0
    assert abs(data["X_train"].mean()) < 0.1
    # σωστός αριθμός κλάσεων
    assert len(data["class_names"]) == len(config.CLASSES)


def test_clean_removes_inf():
    import pandas as pd
    df = gen.generate(n_per_class={c: 50 for c in config.CLASSES})
    df.loc[0, config.FEATURE_COLUMNS[0]] = np.inf
    cleaned = preprocess._clean_dataframe(df)
    assert np.isfinite(cleaned[config.FEATURE_COLUMNS].values).all()


# ------------------------- Μηχανή ανίχνευσης ------------------------- #
def test_aggregate_features_length():
    flows = [(10, 6000, 5.0), (2, 120, 0.3)]
    feats = engine.aggregate_features(flows)
    assert len(feats) == len(config.LIVE_FEATURE_COLUMNS)


def test_aggregate_features_values():
    flows = [(10, 1000, 2.0), (10, 1000, 4.0)]
    feats = engine.aggregate_features(flows)
    # flow_count=2, total_packets=20, total_bytes=2000
    assert feats[0] == 2
    assert feats[1] == 20
    assert feats[2] == 2000
    assert feats[3] == 10        # avg packets/flow
    assert feats[5] == 3.0       # avg duration


def test_empty_flows_safe():
    feats = engine.aggregate_features([])
    assert len(feats) == len(config.LIVE_FEATURE_COLUMNS)
    assert (feats == 0).all()


def test_classify_heuristic_detects_flood():
    # χωρίς μοντέλο -> heuristic: πολλές σύντομες ροές = Attack
    attack_flows = [(1, 60, 0.1) for _ in range(100)]
    feats = engine.aggregate_features(attack_flows)
    assert engine.classify(feats, None, None) == "Attack"


def test_classify_heuristic_passes_normal():
    normal_flows = [(50, 30000, 8.0) for _ in range(3)]
    feats = engine.aggregate_features(normal_flows)
    assert engine.classify(feats, None, None) == "Normal"


def test_classify_with_model_if_available():
    model, scaler = engine.load_live_model()
    if model is None:
        pytest.skip("Δεν υπάρχει εκπαιδευμένο live μοντέλο — παράλειψη.")
    attack_flows = [(2, 100, 0.2) for _ in range(120)]
    feats = engine.aggregate_features(attack_flows)
    assert engine.classify(feats, model, scaler) == "Attack"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
