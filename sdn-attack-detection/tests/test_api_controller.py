#!/usr/bin/env python3
"""
test_api_controller.py — Flask REST API tests using test client.
Run: pytest tests/test_api_controller.py -v
"""
import os, sys, json, time
import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "app_sdn"))
sys.path.insert(0, os.path.join(BASE, "ml_pipeline"))

os.environ.setdefault("SWITCH_API_KEY", "sdn-secret-2024")
os.environ.setdefault("ADMIN_API_KEY",  "sdn-admin-2024")
os.environ.setdefault("DEFENSE_MODE",   "0")

# Χωρίς Flask εγκατεστημένο, τα API tests παραλείπονται καθαρά αντί να προκαλέσουν
# σφάλμα συλλογής (ModuleNotFoundError) που σταματά όλη τη σουίτα.
pytest.importorskip("flask")

import controller as ctrl

HEADERS_AUTH  = {"X-Switch-Token": "sdn-secret-2024", "Content-Type": "application/json"}
HEADERS_NOAUTH = {"Content-Type": "application/json"}
HEADERS_ADMIN  = {"X-Admin-Token": "sdn-admin-2024", "Content-Type": "application/json"}

@pytest.fixture
def client():
    ctrl.app.config["TESTING"] = True
    with ctrl.app.test_client() as c:
        # Reset state before each test
        c.post("/reset", headers=HEADERS_AUTH)
        yield c


# ── /health ───────────────────────────────────────────────────────────────────
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    d = r.get_json()
    assert d["status"] == "ok"
    assert "defense_engine" in d


# ── /register ─────────────────────────────────────────────────────────────────
def test_register_host(client):
    r = client.post("/register", json={"node_id": "h1", "type": "host", "ip": "10.0.0.1"},
                    headers=HEADERS_AUTH)
    assert r.status_code == 200
    assert r.get_json()["status"] == "registered"


def test_register_missing_fields(client):
    r = client.post("/register", json={"node_id": "h1"}, headers=HEADERS_AUTH)
    assert r.status_code == 400


def test_register_invalid_json(client):
    r = client.post("/register", data="not-json", headers=HEADERS_AUTH)
    assert r.status_code == 400


# ── /telemetry ────────────────────────────────────────────────────────────────
def test_telemetry_normal_verdict(client):
    payload = {"src": "10.0.0.1", "dst": "10.0.0.5",
               "flows": [[120, 96000, 5.0], [100, 80000, 5.0], [110, 88000, 5.0]]}
    r = client.post("/telemetry", json=payload, headers=HEADERS_AUTH)
    assert r.status_code == 200
    d = r.get_json()
    assert "verdict" in d
    assert "action" in d
    assert d["action"] in ("FORWARD", "DROP")


def test_telemetry_attack_verdict(client):
    # SYN-flood pattern: 90 flows, 2 packets each, very short
    flows = [[2, 100, 0.05] for _ in range(90)]
    r = client.post("/telemetry",
                    json={"src": "10.0.0.6", "dst": "10.0.0.5", "flows": flows},
                    headers=HEADERS_AUTH)
    assert r.status_code == 200
    d = r.get_json()
    assert d["verdict"] == "Attack"
    assert d["action"] == "DROP"


def test_telemetry_no_token_logged(client):
    r = client.post("/telemetry",
                    json={"src": "10.0.0.99", "dst": "10.0.0.5", "flows": [[10, 1000, 1.0]]},
                    headers=HEADERS_NOAUTH)
    # In DEFENSE_MODE=0 it's allowed but logged
    assert r.status_code == 200
    # injection attempt was logged
    stats = client.get("/injection_stats").get_json()
    assert stats["attempts"] >= 1


def test_telemetry_missing_flows(client):
    r = client.post("/telemetry", json={"src": "10.0.0.1"}, headers=HEADERS_AUTH)
    assert r.status_code == 400


def test_telemetry_invalid_flows_format(client):
    r = client.post("/telemetry",
                    json={"src": "10.0.0.1", "flows": "not-a-list"},
                    headers=HEADERS_AUTH)
    assert r.status_code == 400


def test_telemetry_rate_limit(client):
    # Send many requests rapidly — should get 429 eventually
    payload = {"src": "10.0.0.88", "dst": "10.0.0.5", "flows": [[1, 100, 0.1]]}
    results = []
    for _ in range(150):
        r = client.post("/telemetry", json=payload, headers=HEADERS_AUTH)
        results.append(r.status_code)
    # At least some should be 429
    assert 429 in results


# ── /stats ────────────────────────────────────────────────────────────────────
def test_stats_fields(client):
    r = client.get("/stats")
    assert r.status_code == 200
    d = r.get_json()
    for field in ("nodes", "active_flows", "drop_rules", "total_detections", "recent_log"):
        assert field in d, f"Missing field: {field}"


def test_stats_detections_increment(client):
    before = client.get("/stats").get_json()["total_detections"]
    flows  = [[2, 100, 0.05] for _ in range(90)]
    client.post("/telemetry",
                json={"src": "10.0.0.77", "dst": "10.0.0.5", "flows": flows},
                headers=HEADERS_AUTH)
    after = client.get("/stats").get_json()["total_detections"]
    assert after > before


# ── /flow_table ───────────────────────────────────────────────────────────────
def test_flow_table_empty_initially(client):
    r = client.get("/flow_table")
    assert r.status_code == 200
    assert r.get_json() == {}


def test_flow_table_has_drop_after_attack(client):
    flows = [[2, 100, 0.05] for _ in range(90)]
    client.post("/telemetry",
                json={"src": "10.0.0.6", "dst": "10.0.0.5", "flows": flows},
                headers=HEADERS_AUTH)
    ft = client.get("/flow_table").get_json()
    assert "10.0.0.6" in ft


# ── /topology ─────────────────────────────────────────────────────────────────
def test_topology_structure(client):
    client.post("/register", json={"node_id": "h1", "type": "host", "ip": "10.0.0.1"},
                headers=HEADERS_AUTH)
    r = client.get("/topology")
    assert r.status_code == 200
    d = r.get_json()
    assert "nodes" in d and "edges" in d
    assert len(d["nodes"]) >= 1


# ── /reset + /unblock ─────────────────────────────────────────────────────────
def test_reset_clears_state(client):
    # First create some state
    client.post("/register", json={"node_id": "h1", "type": "host", "ip": "10.0.0.1"},
                headers=HEADERS_AUTH)
    flows = [[2, 100, 0.05] for _ in range(90)]
    client.post("/telemetry",
                json={"src": "10.0.0.6", "dst": "10.0.0.5", "flows": flows},
                headers=HEADERS_AUTH)
    # Reset
    r = client.post("/reset", headers=HEADERS_AUTH)
    assert r.status_code == 200
    # State should be clear
    assert client.get("/flow_table").get_json() == {}


def test_unblock_clears_drop_rules(client):
    flows = [[2, 100, 0.05] for _ in range(90)]
    client.post("/telemetry",
                json={"src": "10.0.0.6", "dst": "10.0.0.5", "flows": flows},
                headers=HEADERS_AUTH)
    assert "10.0.0.6" in client.get("/flow_table").get_json()
    client.post("/unblock", headers=HEADERS_AUTH)
    assert client.get("/flow_table").get_json() == {}


# ── /simulate ────────────────────────────────────────────────────────────────
def test_simulate_command_and_poll(client):
    cmd = {"cmd": "start", "attackers": ["h6"], "victim": "h5", "attack_type": "syn"}
    r = client.post("/simulate/command", json=cmd, headers=HEADERS_AUTH)
    assert r.status_code == 200
    polled = client.get("/simulate/poll").get_json()
    assert polled["cmd"] == "start"
    # Second poll returns empty (one-shot)
    polled2 = client.get("/simulate/poll").get_json()
    assert polled2 == {}


# ── /anomaly_scores ───────────────────────────────────────────────────────────
def test_anomaly_scores_endpoint(client):
    r = client.get("/anomaly_scores")
    assert r.status_code == 200
    assert isinstance(r.get_json(), dict)


# ── /enforcement ──────────────────────────────────────────────────────────────
# Ο μπλοκαρισμένος κόμβος παύει να στέλνει ροές, οπότε η εγγραφή του ελεγκτή θα έληγε
# ενώ ο κανόνας στο data plane ανανεωνόταν. Το endpoint κρατά τις δύο όψεις σύμφωνες.
def test_enforcement_installs_drop_rule(client):
    r = client.post("/enforcement",
                    json={"src": "10.0.0.6", "action": "DROP", "renewal": False},
                    headers=HEADERS_AUTH)
    assert r.status_code == 200
    assert r.get_json()["src"] == "10.0.0.6"
    assert client.get("/flow_table").get_json()["10.0.0.6"]["action"] == "DROP"


def test_enforcement_renewal_keeps_host_blocked(client):
    client.post("/enforcement", json={"src": "10.0.0.6", "action": "DROP"},
                headers=HEADERS_AUTH)
    r = client.post("/enforcement",
                    json={"src": "10.0.0.6", "action": "DROP",
                          "renewal": True, "dropped_packets": 123456},
                    headers=HEADERS_AUTH)
    assert r.status_code == 200
    assert client.get("/flow_table").get_json()["10.0.0.6"]["action"] == "DROP"


def test_enforcement_requires_src(client):
    r = client.post("/enforcement", json={"action": "DROP"}, headers=HEADERS_AUTH)
    assert r.status_code == 400
