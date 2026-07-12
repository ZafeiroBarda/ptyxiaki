#!/usr/bin/env python3
"""
test_security_validation.py — Security hardening tests for the controller.
Run: pytest tests/test_security_validation.py -v
"""
import os, sys
import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "app_sdn"))
sys.path.insert(0, os.path.join(BASE, "ml_pipeline"))

os.environ["DEFENSE_MODE"]   = "0"
os.environ["SWITCH_API_KEY"] = "sdn-secret-2024"
os.environ["ADMIN_API_KEY"]  = "sdn-admin-2024"
os.environ["RATE_LIMIT_MAX"] = "50"

import controller as ctrl

AUTH   = {"X-Switch-Token": "sdn-secret-2024", "Content-Type": "application/json"}
NOAUTH = {"Content-Type": "application/json"}
BADAUTH = {"X-Switch-Token": "wrong-token", "Content-Type": "application/json"}

@pytest.fixture
def client():
    ctrl.app.config["TESTING"] = True
    with ctrl.app.test_client() as c:
        c.post("/reset", headers=AUTH)
        # Reset rate counter for test isolation
        with ctrl._rate_lock:
            ctrl._rate_counters.clear()
        yield c


# ── Token validation ──────────────────────────────────────────────────────────

def test_no_token_logged_as_injection(client):
    client.post("/telemetry",
                json={"src": "10.0.0.99", "dst": "10.0.0.5", "flows": [[10, 1000, 1.0]]},
                headers=NOAUTH)
    stats = client.get("/injection_stats").get_json()
    assert stats["attempts"] >= 1


def test_wrong_token_logged_as_injection(client):
    client.post("/telemetry",
                json={"src": "10.0.0.99", "dst": "10.0.0.5", "flows": [[10, 1000, 1.0]]},
                headers=BADAUTH)
    stats = client.get("/injection_stats").get_json()
    assert stats["attempts"] >= 1


def test_injection_source_tracked(client):
    client.post("/telemetry",
                json={"src": "10.0.0.99", "dst": "10.0.0.5", "flows": [[1, 100, 0.1]]},
                headers=NOAUTH)
    stats = client.get("/injection_stats").get_json()
    # Some IP should be in sources
    assert len(stats["sources"]) >= 1


def test_defense_mode_blocks_no_token(client, monkeypatch):
    monkeypatch.setattr(ctrl, "DEFENSE_MODE", True)
    r = client.post("/telemetry",
                    json={"src": "10.0.0.99", "dst": "10.0.0.5", "flows": [[10, 1000, 1.0]]},
                    headers=NOAUTH)
    assert r.status_code == 401
    monkeypatch.setattr(ctrl, "DEFENSE_MODE", False)


def test_valid_token_passes_defense_mode(client, monkeypatch):
    monkeypatch.setattr(ctrl, "DEFENSE_MODE", True)
    r = client.post("/telemetry",
                    json={"src": "10.0.0.1", "dst": "10.0.0.5",
                          "flows": [[100, 80000, 5.0], [120, 96000, 5.0]]},
                    headers=AUTH)
    assert r.status_code == 200
    monkeypatch.setattr(ctrl, "DEFENSE_MODE", False)


# ── Rate limiting ─────────────────────────────────────────────────────────────

def test_rate_limit_triggers(client, monkeypatch):
    # RATE_LIMIT_MAX from os.environ (line 16) only applies if this module is the
    # first to import controller; under the full suite the module is already cached
    # with the default (120), so pin the limit explicitly.
    monkeypatch.setattr(ctrl, "RATE_LIMIT_MAX", 50)
    payload = {"src": "10.0.0.77", "dst": "10.0.0.5", "flows": [[1, 100, 0.1]]}
    codes = []
    for _ in range(80):
        r = client.post("/telemetry", json=payload, headers=AUTH)
        codes.append(r.status_code)
    # Should have some 429s after exceeding RATE_LIMIT_MAX=50
    assert 429 in codes, "Rate limiting not triggered"


def test_rate_limit_different_ips_independent(client):
    # Different IPs should have independent rate limits
    for i in range(40):
        r1 = client.post("/telemetry",
                         json={"src": f"10.0.1.{i}", "dst": "10.0.0.5",
                               "flows": [[1, 100, 0.1]]},
                         headers=AUTH)
        assert r1.status_code == 200, f"Fresh IP got rate-limited too early"


# ── Input validation ─────────────────────────────────────────────────────────

def test_malformed_json_returns_400(client):
    r = client.post("/telemetry",
                    data='{"broken": json',
                    content_type="application/json")
    assert r.status_code in (400, 422)


def test_empty_body_returns_400(client):
    r = client.post("/telemetry", data="", content_type="application/json")
    assert r.status_code == 400


def test_oversized_flows_rejected(client):
    flows = [[1, 100, 0.1]] * 5001  # over max 5000
    r = client.post("/telemetry",
                    json={"src": "10.0.0.1", "dst": "10.0.0.5", "flows": flows},
                    headers=AUTH)
    assert r.status_code == 400


def test_ip_field_too_long_rejected(client):
    r = client.post("/telemetry",
                    json={"src": "A" * 100, "dst": "10.0.0.5", "flows": [[1, 100, 1.0]]},
                    headers=AUTH)
    assert r.status_code == 400


# ── Injection stats ───────────────────────────────────────────────────────────

def test_injection_stats_increment_correctly(client):
    before = client.get("/injection_stats").get_json()["attempts"]
    for _ in range(3):
        client.post("/telemetry",
                    json={"src": "10.0.0.99", "flows": [[1, 100, 0.1]]},
                    headers=NOAUTH)
    after = client.get("/injection_stats").get_json()["attempts"]
    assert after == before + 3


def test_reset_clears_injection_stats(client):
    client.post("/telemetry",
                json={"src": "10.0.0.99", "flows": [[1, 100, 0.1]]},
                headers=NOAUTH)
    client.post("/reset", headers=AUTH)
    stats = client.get("/injection_stats").get_json()
    assert stats["attempts"] == 0
    assert stats["blocked"] == 0


# ── /reset: admin-only σε DEFENSE_MODE ───────────────────────────────────────

def test_defense_mode_reset_requires_admin_token(client, monkeypatch):
    monkeypatch.setattr(ctrl, "DEFENSE_MODE", True)
    r = client.post("/reset", headers=AUTH)   # switch token δεν αρκεί
    assert r.status_code == 401
    r = client.post("/reset")                 # χωρίς κανένα token
    assert r.status_code == 401


def test_defense_mode_reset_with_admin_token(client, monkeypatch):
    monkeypatch.setattr(ctrl, "DEFENSE_MODE", True)
    r = client.post("/reset",
                    headers={"X-Admin-Token": "sdn-admin-2024",
                             "Content-Type": "application/json"})
    assert r.status_code == 200
    assert r.get_json()["status"] == "reset"
