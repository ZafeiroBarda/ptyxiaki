#!/usr/bin/env python3
"""
test_live_scenarios.py — Tests for simulation scenarios (standalone mode, mocked controller).
Run: pytest tests/test_live_scenarios.py -v
"""
import os, sys, json
from unittest.mock import patch, MagicMock
import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "simulation"))
sys.path.insert(0, os.path.join(BASE, "app_sdn"))
sys.path.insert(0, os.path.join(BASE, "ml_pipeline"))


def _make_mock_response(verdict="Normal", action="FORWARD"):
    mock = MagicMock()
    mock.ok = True
    mock.status_code = 200
    mock.json.return_value = {"verdict": verdict, "action": action}
    return mock


def _make_mock_stats(detections=0, drop_rules=0):
    mock = MagicMock()
    mock.ok = True
    mock.json.return_value = {
        "total_detections": detections, "drop_rules": drop_rules,
        "nodes": 6, "active_flows": 5, "recent_log": [],
    }
    return mock


def _make_mock_flow_table(blocked=None):
    mock = MagicMock()
    mock.ok = True
    mock.json.return_value = {ip: {"action": "DROP"} for ip in (blocked or [])}
    return mock


# ── Port Scan scenario ────────────────────────────────────────────────────────

def test_port_scan_imports():
    from scenarios import port_scan
    assert hasattr(port_scan, "run")


def test_port_scan_standalone_completes():
    with patch("requests.post") as mock_post, \
         patch("requests.get") as mock_get:

        call_count = [0]
        def side_post(*a, **kw):
            call_count[0] += 1
            verdict = "Attack" if call_count[0] > 3 else "Normal"
            return _make_mock_response(verdict, "DROP" if verdict == "Attack" else "FORWARD")

        mock_post.side_effect = side_post
        mock_get.return_value = _make_mock_stats(detections=5)

        from scenarios import port_scan
        result = port_scan.run(controller_url="http://fake:9000",
                               duration=5, standalone=True)
        assert isinstance(result, dict)
        assert "scenario" in result
        assert result["scenario"] == "port_scan"
        assert "duration" in result


# ── Flow Exhaustion scenario ──────────────────────────────────────────────────

def test_flow_exhaustion_imports():
    from scenarios import flow_exhaustion
    assert hasattr(flow_exhaustion, "run")


def test_flow_exhaustion_sends_many_flows():
    telemetry_calls = []
    with patch("requests.post") as mock_post, \
         patch("requests.get") as mock_get:

        def capture_post(url, *a, **kw):
            if "telemetry" in url:
                body = kw.get("json", {})
                telemetry_calls.append(len(body.get("flows", [])))
            return _make_mock_response("Attack", "DROP")

        mock_post.side_effect = capture_post
        mock_get.return_value = _make_mock_stats()

        from scenarios import flow_exhaustion
        flow_exhaustion.run(controller_url="http://fake:9000",
                            duration=3, standalone=True)

    # Flow exhaustion should have sent calls with many flows
    assert len(telemetry_calls) > 0
    max_flows = max(telemetry_calls) if telemetry_calls else 0
    assert max_flows > 10, f"Expected >10 flows per call, got max={max_flows}"


# ── Lateral Movement scenario ─────────────────────────────────────────────────

def test_lateral_movement_imports():
    from scenarios import lateral_movement
    assert hasattr(lateral_movement, "run")


def test_lateral_movement_targets_multiple_hosts():
    targets_hit = set()
    with patch("requests.post") as mock_post, \
         patch("requests.get") as mock_get:

        def capture_post(url, *a, **kw):
            if "telemetry" in url:
                dst = kw.get("json", {}).get("dst", "")
                if dst:
                    targets_hit.add(dst)
            return _make_mock_response("Normal", "FORWARD")

        mock_post.side_effect = capture_post
        mock_get.return_value = _make_mock_stats()

        from scenarios import lateral_movement
        lateral_movement.run(controller_url="http://fake:9000",
                             duration=5, standalone=True)

    assert len(targets_hit) >= 2, \
        f"Lateral movement should target ≥2 hosts, got {targets_hit}"


# ── Data Exfiltration scenario ────────────────────────────────────────────────

def test_data_exfiltration_imports():
    from scenarios import data_exfiltration
    assert hasattr(data_exfiltration, "run")


def test_data_exfiltration_high_byte_rate():
    bytes_sent = []
    with patch("requests.post") as mock_post, \
         patch("requests.get") as mock_get:

        def capture_post(url, *a, **kw):
            if "telemetry" in url:
                flows = kw.get("json", {}).get("flows", [])
                total_b = sum(f[1] for f in flows if len(f) > 1)
                bytes_sent.append(total_b)
            return _make_mock_response("Attack", "DROP")

        mock_post.side_effect = capture_post
        mock_get.return_value = _make_mock_stats()

        from scenarios import data_exfiltration
        data_exfiltration.run(controller_url="http://fake:9000",
                              duration=3, standalone=True)

    assert len(bytes_sent) > 0
    avg_bytes = sum(bytes_sent) / len(bytes_sent)
    # Exfiltration should have very high byte counts per window
    assert avg_bytes > 10_000, f"Expected >10KB avg, got {avg_bytes:.0f}"


# ── ARP Spoof scenario ────────────────────────────────────────────────────────

def test_arp_spoof_imports():
    from scenarios import arp_spoof
    assert hasattr(arp_spoof, "run")


def test_arp_spoof_completes(monkeypatch):
    with patch("requests.post") as mock_post, \
         patch("requests.get") as mock_get:
        mock_post.return_value = _make_mock_response("Attack", "DROP")
        mock_get.return_value  = _make_mock_stats(detections=2)

        from scenarios import arp_spoof
        result = arp_spoof.run(controller_url="http://fake:9000",
                               duration=3, standalone=True)
        assert isinstance(result, dict)
        assert result.get("scenario") == "arp_spoof"
