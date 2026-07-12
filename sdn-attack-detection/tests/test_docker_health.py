#!/usr/bin/env python3
"""
test_docker_health.py — Docker / infrastructure health tests.
Run: pytest tests/test_docker_health.py -v
(Tests are skipped if services are not running)
"""
import os, sys, shutil, subprocess
import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _docker_ready():
    """True μόνο αν υπάρχει το docker CLI ΚΑΙ ο daemon απαντά.

    Χωρίς τον έλεγχο αυτόν, σε μηχάνημα χωρίς Docker το subprocess.run θα
    πετούσε FileNotFoundError (δεν επιστρέφει 127), και με σταματημένο daemon
    οι εντολές αποτυγχάνουν — και στις δύο περιπτώσεις το σωστό είναι skip.
    """
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


DOCKER_AVAILABLE = _docker_ready()

try:
    import requests as _req
    _controller_available = False
    try:
        r = _req.get("http://localhost:9000/health", timeout=2)
        _controller_available = r.ok
    except Exception:
        pass
    _dashboard_available = False
    try:
        r = _req.get("http://localhost:8050", timeout=2)
        _dashboard_available = r.ok
    except Exception:
        pass
except ImportError:
    _req = None
    _controller_available = False
    _dashboard_available  = False


# ── docker-compose.yml validation ─────────────────────────────────────────────

def test_compose_file_exists():
    path = os.path.join(BASE, "app_sdn", "docker-compose.yml")
    assert os.path.exists(path), "docker-compose.yml not found"


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="Docker not installed or daemon not running")
def test_compose_config_valid():
    compose_path = os.path.join(BASE, "app_sdn", "docker-compose.yml")
    result = subprocess.run(
        ["docker", "compose", "-f", compose_path, "config", "--quiet"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, \
        f"docker-compose config invalid:\n{result.stderr}"


# ── Live service tests (skipped if not running) ───────────────────────────────

@pytest.mark.skipif(not _controller_available, reason="Controller not running on :9000")
def test_controller_health():
    r = _req.get("http://localhost:9000/health", timeout=3)
    assert r.ok
    d = r.json()
    assert d["status"] == "ok"
    assert "defense_engine" in d


@pytest.mark.skipif(not _controller_available, reason="Controller not running on :9000")
def test_controller_stats_endpoint():
    r = _req.get("http://localhost:9000/stats", timeout=3)
    assert r.ok
    d = r.json()
    assert "drop_rules" in d
    assert "total_detections" in d


@pytest.mark.skipif(not _controller_available, reason="Controller not running on :9000")
def test_controller_flow_table_endpoint():
    r = _req.get("http://localhost:9000/flow_table", timeout=3)
    assert r.ok
    assert isinstance(r.json(), dict)


@pytest.mark.skipif(not _controller_available, reason="Controller not running on :9000")
def test_controller_topology_endpoint():
    r = _req.get("http://localhost:9000/topology", timeout=3)
    assert r.ok
    d = r.json()
    assert "nodes" in d
    assert "edges" in d


@pytest.mark.skipif(not _dashboard_available, reason="Dashboard not running on :8050")
def test_dashboard_responds():
    r = _req.get("http://localhost:8050", timeout=5)
    assert r.ok
    assert "SDN" in r.text or "dashboard" in r.text.lower()


@pytest.mark.skipif(not _dashboard_available, reason="Dashboard not running on :8050")
def test_dashboard_export_flows_endpoint():
    r = _req.get("http://localhost:8050/export/flows.csv", timeout=5)
    assert r.ok
    assert "text/csv" in r.headers.get("Content-Type", "")


# ── Docker container status ───────────────────────────────────────────────────

@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="Docker not installed or daemon not running")
def test_docker_containers_running():
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True,
    )
    if not _controller_available:
        pytest.skip("Stack not running")
    containers = result.stdout.strip().split("\n")
    assert "sdn_controller" in containers, "sdn_controller container not running"
    assert "sdn_dashboard"  in containers, "sdn_dashboard container not running"
