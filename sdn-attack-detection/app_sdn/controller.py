#!/usr/bin/env python3
"""
controller.py  (Control Plane + Intelligence/Defense Plane)
-----------------------------------------------------------
Κεντρικός SDN Controller σε Python/Flask, σύμφωνα με την αρχιτεκτονική της
διπλωματικής (application-level SDN, microservices).

Διατηρεί:
  - Global Network View: ο γράφος του δικτύου G=(V,E) (κόμβοι + ενεργές ροές).
  - Flow Table: οι κανόνες προώθησης/απόρριψης ανά πηγή.
  - Defense Engine: Isolation Forest που ανιχνεύει ανωμαλίες (f(x) < 0) και
    ενεργοποιεί αυτόματο αποκλεισμό (drop) της κακόβουλης ροής.

REST API (southbound, προσομοιώνει OpenFlow):
  POST /register     -> εγγραφή κόμβου (host/switch) στο Global Network View
  POST /telemetry    -> ο switch στέλνει στατιστικά ροών· ο controller αποφασίζει
  GET  /flow_table   -> τρέχον flow table
  GET  /topology     -> Global Network View (για το dashboard)
  GET  /stats        -> στατιστικά ανίχνευσης
  POST /reset        -> καθαρισμός κατάστασης (για tests)

Εκτέλεση:
  python3 app_sdn/controller.py            # στο http://127.0.0.1:9000
"""

import os
import sys
import time
import threading
import numpy as np
from flask import Flask, request, jsonify

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config
import detection_engine as engine

try:
    import joblib
    # live Isolation Forest: εκπαιδευμένο στα 8 aggregate features της τηλεμετρίας
    _ISO = joblib.load(os.path.join(config.MODELS_DIR, "isolation_forest_live.pkl"))
    _ISO_SCALER = joblib.load(os.path.join(config.MODELS_DIR, "isolation_forest_live_scaler.pkl"))
except Exception:
    _ISO, _ISO_SCALER = None, None


class GlobalNetworkView:
    """Ο γράφος του δικτύου: κόμβοι (V) και ενεργές ροές (E)."""

    def __init__(self):
        self.nodes = {}      # node_id -> {type, ip, status}
        self.flows = {}      # (src,dst) -> {packets, bytes, last_seen}
        self.lock = threading.Lock()

    def add_node(self, node_id, node_type, ip):
        with self.lock:
            self.nodes[node_id] = {"type": node_type, "ip": ip, "status": "active"}

    def update_flow(self, src, dst, packets, bytes_):
        with self.lock:
            self.flows[(src, dst)] = {"packets": packets, "bytes": bytes_, "last_seen": time.time()}

    def set_node_status(self, ip, status):
        with self.lock:
            for n in self.nodes.values():
                if n["ip"] == ip:
                    n["status"] = status

    def as_dict(self):
        with self.lock:
            return {
                "nodes": [{"id": k, **v} for k, v in self.nodes.items()],
                "edges": [{"src": s, "dst": d, **info} for (s, d), info in self.flows.items()],
            }


class FlowTable:
    """Πίνακας ροών: κανόνες FORWARD / DROP ανά πηγή IP."""

    def __init__(self):
        self.rules = {}      # src_ip -> {action, priority, expires}
        self.lock = threading.Lock()

    def install(self, src_ip, action, priority=100, ttl=60):
        with self.lock:
            self.rules[src_ip] = {"action": action, "priority": priority,
                                  "expires": time.time() + ttl}

    def action_for(self, src_ip):
        with self.lock:
            rule = self.rules.get(src_ip)
            if rule and time.time() < rule["expires"]:
                return rule["action"]
            if rule:  # έληξε
                del self.rules[src_ip]
            return "FORWARD"

    def expire(self):
        with self.lock:
            now = time.time()
            for ip in [ip for ip, r in self.rules.items() if now >= r["expires"]]:
                del self.rules[ip]

    def as_dict(self):
        with self.lock:
            return {ip: {**r, "expires_in": round(r["expires"] - time.time(), 1)}
                    for ip, r in self.rules.items()}


class DefenseEngine:
    """
    Intelligence & Defense Plane.
    Χρησιμοποιεί Isolation Forest (αν υπάρχει) ή το κοινό detection_engine ως εφεδρεία.
    """

    def __init__(self, iso=_ISO, scaler=_ISO_SCALER):
        self.iso = iso
        self.scaler = scaler
        self.live_model, self.live_scaler = engine.load_live_model()
        self.detections = 0

    def analyze(self, flows):
        """flows: λίστα (packets, bytes, duration) για μία πηγή. -> 'Attack'/'Normal'."""
        feats = engine.aggregate_features(flows)
        # 1η επιλογή: Isolation Forest (unsupervised, όπως ορίζει η αρχιτεκτονική)
        if self.iso is not None and self.scaler is not None:
            # χρησιμοποιεί τα 8 aggregate features -> χρειάζεται ταίριασμα διαστάσεων
            try:
                X = self.scaler.transform(feats.reshape(1, -1))
                verdict = "Attack" if self.iso.predict(X)[0] == -1 else "Normal"
            except Exception:
                verdict = engine.classify(feats, self.live_model, self.live_scaler)
        else:
            verdict = engine.classify(feats, self.live_model, self.live_scaler)
        if verdict == "Attack":
            self.detections += 1
        return verdict, feats


# ---------------------- Flask εφαρμογή ----------------------
app = Flask(__name__)
gnv = GlobalNetworkView()
flow_table = FlowTable()
defense = DefenseEngine()
_log = []


def log_event(msg):
    entry = {"t": round(time.time(), 2), "msg": msg}
    _log.append(entry)
    print(f"[CONTROLLER] {msg}")


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    gnv.add_node(data["node_id"], data.get("type", "host"), data["ip"])
    log_event(f"Εγγραφή κόμβου {data['node_id']} ({data['ip']})")
    return jsonify({"status": "registered", "node_id": data["node_id"]})


@app.route("/telemetry", methods=["POST"])
def telemetry():
    """
    Ο switch στέλνει στατιστικά ανά πηγή IP:
      { "src": "10.0.0.6", "dst": "10.0.0.5",
        "flows": [[packets, bytes, duration], ...] }
    Ο controller τα αναλύει (Defense Engine) και επιστρέφει την ενέργεια.
    """
    data = request.get_json(force=True)
    src = data["src"]
    dst = data.get("dst", "?")
    flows = data["flows"]

    total_pkts = sum(f[0] for f in flows)
    total_bytes = sum(f[1] for f in flows)
    gnv.update_flow(src, dst, total_pkts, total_bytes)

    verdict, feats = defense.analyze(flows)
    if verdict == "Attack" and flow_table.action_for(src) != "DROP":
        flow_table.install(src, "DROP", priority=100, ttl=60)
        gnv.set_node_status(src, "blocked")
        log_event(f"🚨 ΑΝΩΜΑΛΙΑ από {src} (flows={int(feats[0])}, "
                  f"short_ratio={feats[7]:.2f}) -> DROP rule")

    action = flow_table.action_for(src)
    return jsonify({"src": src, "action": action, "verdict": verdict})


@app.route("/flow_table", methods=["GET"])
def get_flow_table():
    flow_table.expire()
    return jsonify(flow_table.as_dict())


@app.route("/topology", methods=["GET"])
def get_topology():
    return jsonify(gnv.as_dict())


@app.route("/stats", methods=["GET"])
def get_stats():
    return jsonify({
        "nodes": len(gnv.nodes),
        "active_flows": len(gnv.flows),
        "drop_rules": len(flow_table.as_dict()),
        "total_detections": defense.detections,
        "recent_log": _log[-10:],
    })


@app.route("/reset", methods=["POST"])
def reset():
    gnv.nodes.clear(); gnv.flows.clear()
    flow_table.rules.clear(); _log.clear()
    defense.detections = 0
    return jsonify({"status": "reset"})


@app.route("/health", methods=["GET"])
def health():
    engine_name = "Isolation Forest" if defense.iso is not None else "detection_engine (fallback)"
    return jsonify({"status": "ok", "defense_engine": engine_name})


if __name__ == "__main__":
    print("=" * 60)
    print(" SDN Controller (Flask) — Control + Defense Plane")
    print(f" Defense Engine: {'Isolation Forest' if _ISO else 'fallback heuristic/live model'}")
    print(" http://127.0.0.1:9000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=9000, threaded=True)
