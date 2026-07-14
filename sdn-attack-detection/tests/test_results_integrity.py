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

# Στήλες που κάθε γραμμή (API-level ή packet-level) οφείλει να έχει. Οι packet-level
# γραμμές προσθέτουν επιπλέον στήλες προέλευσης (run_id, code_commit, coverage κ.λπ.),
# οπότε ο έλεγχος είναι υποσύνολο και όχι ακριβής ισότητα.
SUMMARY_CORE_COLUMNS = [
    "scenario", "experiment_type", "duration_s", "detection_latency_s",
    "attacker_blocked", "detections", "success",
]
# Στήλες προέλευσης που ΠΡΕΠΕΙ να φέρει κάθε packet-level γραμμή (απαίτηση 4.7).
PACKET_PROVENANCE_COLUMNS = [
    "run_id", "code_commit", "dropped_packets", "mitigation_coverage_pct",
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
def test_summary_has_core_columns():
    df = pd.read_csv(os.path.join(LIVE, "experiment_summary.csv"))
    missing = [c for c in SUMMARY_CORE_COLUMNS if c not in df.columns]
    assert not missing, f"Λείπουν βασικές στήλες: {missing}"


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
    """Κάθε γραμμή δηλώνει ρητά τον τύπο του πειράματος (api_telemetry ή packet_level).

    Το ενιαίο summary συνδυάζει τις δύο διαδρομές, οπότε ο τύπος πρέπει να είναι πάντα
    δηλωμένος και έγκυρος, ώστε να μη συγχέονται οι API-level με τις packet-level
    μετρήσεις (η σύγχυσή τους ήταν το πρόβλημα 4.3/4.7).
    """
    df = pd.read_csv(os.path.join(LIVE, "experiment_summary.csv"))
    assert set(df["experiment_type"]) <= {"packet_level", "api_telemetry"}, (
        f"Μη έγκυρος τύπος πειράματος: {set(df['experiment_type'])}")
    assert df["experiment_type"].notna().all(), "Υπάρχει γραμμή χωρίς experiment_type"


@pytest.mark.skipif(not os.path.exists(os.path.join(LIVE, "experiment_summary.csv")),
                    reason="experiment_summary.csv δεν έχει παραχθεί")
def test_packet_level_row_has_provenance():
    """Το packet-level πείραμα εμφανίζεται στο ενιαίο summary με πλήρη προέλευση (4.7).

    Αν υπάρχει έστω μία packet_level γραμμή, οφείλει να φέρει run_id, code_commit,
    αριθμό απορριφθέντων πακέτων και κάλυψη αντιμετώπισης, ώστε κάθε νούμερο να ανάγεται
    σε συγκεκριμένη εκτέλεση και commit.
    """
    df = pd.read_csv(os.path.join(LIVE, "experiment_summary.csv"))
    packet = df[df["experiment_type"] == "packet_level"]
    if packet.empty:
        pytest.skip("δεν έχει καταγραφεί ακόμη packet-level run")
    for col in PACKET_PROVENANCE_COLUMNS:
        assert col in df.columns, f"Λείπει στήλη προέλευσης: {col}"
        assert packet[col].notna().all(), f"packet_level γραμμή χωρίς {col}"


@pytest.mark.parametrize("path", sorted(glob.glob(os.path.join(LIVE, "*.json"))),
                         ids=os.path.basename)
def test_live_json_valid(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    assert "scenario" in d
