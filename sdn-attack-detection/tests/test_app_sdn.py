#!/usr/bin/env python3
"""
test_app_sdn.py  (έλεγχοι για το application-level SDN)
------------------------------------------------------
Ελέγχει τα κομμάτια της αρχιτεκτονικής microservices (Control/Data/Defense Plane)
χωρίς να χρειάζεται να τρέχει ζωντανός HTTP server.

Τρέξε:  pytest tests/test_app_sdn.py -v
"""

import os
import sys
import numpy as np
import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
sys.path.append(os.path.join(BASE, "app_sdn"))

import config


# ---------------------- Flow Table ---------------------- #
def test_flow_table_install_and_expire():
    from controller import FlowTable
    ft = FlowTable()
    assert ft.action_for("10.0.0.6") == "FORWARD"        # default
    ft.install("10.0.0.6", "DROP", ttl=60)
    assert ft.action_for("10.0.0.6") == "DROP"           # μετά την εγκατάσταση
    # με μηδενικό ttl πρέπει να λήξει
    ft.install("10.0.0.7", "DROP", ttl=-1)
    assert ft.action_for("10.0.0.7") == "FORWARD"        # έληξε αμέσως


# ---------------------- Global Network View ---------------------- #
def test_global_network_view():
    from controller import GlobalNetworkView
    gnv = GlobalNetworkView()
    gnv.add_node("h1", "host", "10.0.0.1")
    gnv.update_flow("10.0.0.1", "10.0.0.5", 100, 60000)
    gnv.set_node_status("10.0.0.1", "blocked")
    d = gnv.as_dict()
    assert len(d["nodes"]) == 1
    assert d["nodes"][0]["status"] == "blocked"
    assert len(d["edges"]) == 1


# ---------------------- Defense Engine ---------------------- #
def test_defense_engine_detects_flood():
    from controller import DefenseEngine
    de = DefenseEngine()
    # flood: πολλές σύντομες ροές με λίγα πακέτα
    attack_flows = [(2, 100, 0.1) for _ in range(90)]
    verdict, feats = de.analyze(attack_flows)
    assert verdict == "Attack"
    assert feats[0] == 90        # flow_count


def test_defense_engine_passes_normal():
    from controller import DefenseEngine
    de = DefenseEngine()
    # κανονικό: λίγες ροές με αρκετά πακέτα κανονικού μεγέθους
    normal_flows = [(120, 120 * 800, 6.0) for _ in range(3)]
    verdict, _ = de.analyze(normal_flows)
    assert verdict == "Normal"


# ---------------------- Switch (Data Plane) ---------------------- #
def test_switch_ingest_and_block():
    from switch import Switch
    sw = Switch("s1", "http://127.0.0.1:9999")  # δεν χρειάζεται live server
    assert sw.ingest("10.0.0.1", "10.0.0.5", 800) == "FORWARD"
    # προσομοίωση κανόνα DROP
    sw.blocked.add("10.0.0.6")
    assert sw.ingest("10.0.0.6", "10.0.0.5", 50) == "DROP"


def test_switch_builds_flows_per_destination():
    from switch import Switch
    sw = Switch("s1", "http://127.0.0.1:9999")
    # μία πηγή προς 3 διαφορετικούς προορισμούς
    for dst in ["10.0.0.5", "10.0.0.7", "10.0.0.8"]:
        sw.ingest("10.0.0.1", dst, 600)
    rec = sw.stats["10.0.0.1"]
    flows = sw._build_flows(rec)
    assert len(flows) == 3       # μία ροή ανά προορισμό


# ---------------------- Isolation Forest defense model ---------------------- #
def test_isolation_forest_live_model_logic():
    import train_defense_engine as tde
    X = tde.gen_normal_aggregate(n=200)
    assert X.shape[1] == len(config.LIVE_FEATURE_COLUMNS)
    # τα φυσιολογικά πρέπει να έχουν χαμηλό short_ratio
    assert X[:, 7].mean() < 0.3


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
