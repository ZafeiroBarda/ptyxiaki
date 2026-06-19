#!/usr/bin/env python3
"""
test_model_regression.py — ML model regression tests.
Run: pytest tests/test_model_regression.py -v
"""
import os, sys, time
import numpy as np
import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "ml_pipeline"))
sys.path.insert(0, os.path.join(BASE, "app_sdn"))

import config

MODELS_DIR = config.MODELS_DIR

_iso, _scaler, _live_model, _live_scaler = None, None, None, None

def _load_models():
    global _iso, _scaler, _live_model, _live_scaler
    if _iso is not None:
        return
    try:
        import joblib
        _iso    = joblib.load(os.path.join(MODELS_DIR, "isolation_forest_live.pkl"))
        _scaler = joblib.load(os.path.join(MODELS_DIR, "isolation_forest_live_scaler.pkl"))
    except Exception as e:
        pytest.skip(f"Models not found: {e}")
    try:
        import detection_engine as engine
        _live_model, _live_scaler = engine.load_live_model()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def load_models():
    _load_models()


# ── Isolation Forest live model ───────────────────────────────────────────────

def test_model_files_exist():
    assert os.path.exists(os.path.join(MODELS_DIR, "isolation_forest_live.pkl"))
    assert os.path.exists(os.path.join(MODELS_DIR, "isolation_forest_live_scaler.pkl"))


def test_model_loads_correctly():
    assert _iso is not None
    assert _scaler is not None
    assert hasattr(_iso, "predict")
    assert hasattr(_scaler, "transform")


def test_feature_count():
    # Model expects 8 aggregate features
    n_features = _iso.n_features_in_ if hasattr(_iso, "n_features_in_") else \
                 _scaler.n_features_in_
    assert n_features == len(config.LIVE_FEATURE_COLUMNS), \
        f"Expected {len(config.LIVE_FEATURE_COLUMNS)} features, got {n_features}"


def test_normal_traffic_classified_normal():
    import detection_engine as engine
    # Normal: 3 steady flows, many packets, normal size
    normal_flows = [(120, 120 * 800, 6.0) for _ in range(3)]
    feats = engine.aggregate_features(normal_flows)
    X = _scaler.transform(feats.reshape(1, -1))
    pred = _iso.predict(X)[0]
    # IF: +1 = normal, -1 = anomaly
    assert pred == 1, f"Normal traffic misclassified as anomaly (pred={pred})"


def test_attack_traffic_classified_attack():
    import detection_engine as engine
    # SYN flood: 90 very short flows, 2 packets each
    attack_flows = [(2, 100, 0.05) for _ in range(90)]
    feats = engine.aggregate_features(attack_flows)
    X = _scaler.transform(feats.reshape(1, -1))
    pred = _iso.predict(X)[0]
    assert pred == -1, f"Attack traffic not detected as anomaly (pred={pred})"


def test_inference_time_under_100ms():
    import detection_engine as engine
    flows = [(50, 40000, 5.0) for _ in range(5)]
    feats = engine.aggregate_features(flows)
    X = _scaler.transform(feats.reshape(1, -1))
    t0 = time.perf_counter()
    for _ in range(100):
        _iso.predict(X)
    elapsed_per_call = (time.perf_counter() - t0) / 100 * 1000  # ms
    assert elapsed_per_call < 100, f"Inference took {elapsed_per_call:.1f}ms (>100ms)"


def test_scaler_no_nan_inf():
    import detection_engine as engine
    flows = [(10, 8000, 1.0) for _ in range(5)]
    feats = engine.aggregate_features(flows)
    X = _scaler.transform(feats.reshape(1, -1))
    assert not np.any(np.isnan(X)), "Scaler output contains NaN"
    assert not np.any(np.isinf(X)), "Scaler output contains Inf"


def test_anomaly_score_returned():
    import detection_engine as engine
    attack_flows = [(2, 100, 0.05) for _ in range(90)]
    feats = engine.aggregate_features(attack_flows)
    X = _scaler.transform(feats.reshape(1, -1))
    score = _iso.score_samples(X)[0]
    assert isinstance(score, float)
    # Attack should have lower (more negative) score than normal
    normal_flows = [(120, 96000, 6.0) for _ in range(3)]
    feats_n = engine.aggregate_features(normal_flows)
    Xn = _scaler.transform(feats_n.reshape(1, -1))
    score_n = _iso.score_samples(Xn)[0]
    assert score < score_n, \
        f"Attack score ({score:.3f}) not lower than normal ({score_n:.3f})"


# ── Feature engineering ────────────────────────────────────────────────────────

def test_aggregate_features_shape():
    import detection_engine as engine
    flows = [(10, 8000, 1.0)]
    feats = engine.aggregate_features(flows)
    assert feats.shape[0] == len(config.LIVE_FEATURE_COLUMNS)


def test_aggregate_features_no_nan():
    import detection_engine as engine
    flows = [(10, 8000, 1.0), (5, 4000, 0.5), (1, 50, 0.1)]
    feats = engine.aggregate_features(flows)
    assert not np.any(np.isnan(feats))
    assert not np.any(np.isinf(feats))
