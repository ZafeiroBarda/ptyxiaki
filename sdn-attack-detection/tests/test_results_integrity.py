#!/usr/bin/env python3
"""
test_results_integrity.py — Ακεραιότητα των παραγόμενων αρχείων αποτελεσμάτων.

Αφορμή: τα αρχεία του results/live/ γράφονταν με σχήμα που διέφερε ανά σενάριο,
με αποτέλεσμα γραμμές με λάθος πλήθος πεδίων (μη αναγνώσιμο CSV) και σύνοψη που
περιείχε ένα μόνο σενάριο. Τα tests αυτά αποτρέπουν την επανεμφάνιση.

Run: pytest tests/test_results_integrity.py -v
"""
import json
import os
import glob

import pytest

pd = pytest.importorskip("pandas")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(BASE, "results")
LIVE = os.path.join(RESULTS, "live")

SUMMARY_SCHEMA = [
    "scenario", "experiment_type", "duration_s", "detection_latency_s",
    "true_positives", "false_positives", "true_negatives", "false_negatives",
    "attacker_blocked", "blocked_ips", "detections", "success",
]


def _csvs(folder):
    return sorted(glob.glob(os.path.join(folder, "*.csv")))


@pytest.mark.parametrize("path", _csvs(RESULTS), ids=os.path.basename)
def test_offline_csv_parses(path):
    """Κάθε CSV του results/ διαβάζεται από pandas και δεν είναι κενό."""
    df = pd.read_csv(path)
    assert len(df) > 0, f"{os.path.basename(path)}: κενό"
    assert len(df.columns) > 0


@pytest.mark.parametrize("path", _csvs(LIVE), ids=os.path.basename)
def test_live_csv_parses(path):
    """Κάθε CSV του results/live/ διαβάζεται από pandas (regression για 4.8)."""
    df = pd.read_csv(path)
    assert len(df) > 0, f"{os.path.basename(path)}: κενό"


@pytest.mark.skipif(not os.path.exists(os.path.join(LIVE, "experiment_summary.csv")),
                    reason="experiment_summary.csv δεν έχει παραχθεί")
def test_summary_has_fixed_schema():
    df = pd.read_csv(os.path.join(LIVE, "experiment_summary.csv"))
    assert list(df.columns) == SUMMARY_SCHEMA, f"Λάθος σχήμα: {list(df.columns)}"


@pytest.mark.skipif(not os.path.exists(os.path.join(LIVE, "experiment_summary.csv")),
                    reason="experiment_summary.csv δεν έχει παραχθεί")
def test_summary_covers_all_scenarios():
    """Η σύνοψη πρέπει να περιέχει ΟΛΑ τα σενάρια, όχι μόνο το DDoS."""
    df = pd.read_csv(os.path.join(LIVE, "experiment_summary.csv"))
    scenarios = set(df["scenario"])
    expected = {"ddos_syn_flood", "port_scan", "data_exfiltration",
                "flow_exhaustion", "lateral_movement", "arp_spoof"}
    missing = expected - scenarios
    assert not missing, f"Λείπουν σενάρια από τη σύνοψη: {missing}"


@pytest.mark.skipif(not os.path.exists(os.path.join(LIVE, "experiment_summary.csv")),
                    reason="experiment_summary.csv δεν έχει παραχθεί")
def test_experiment_type_is_declared():
    """Μόνο η πλημμύρα SYN είναι πείραμα σε επίπεδο πακέτου."""
    df = pd.read_csv(os.path.join(LIVE, "experiment_summary.csv"))
    assert set(df["experiment_type"]) <= {"packet_level", "api_telemetry"}
    pkt = set(df.loc[df["experiment_type"] == "packet_level", "scenario"])
    assert pkt == {"ddos_syn_flood"}, f"Απροσδόκητα packet-level σενάρια: {pkt}"


@pytest.mark.parametrize("path", sorted(glob.glob(os.path.join(LIVE, "*.json"))),
                         ids=os.path.basename)
def test_live_json_valid(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    assert "scenario" in d
