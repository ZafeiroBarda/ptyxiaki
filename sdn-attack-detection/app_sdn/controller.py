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

import csv
import os
import sys
import time
import threading
from collections import deque

import numpy as np
from flask import Flask, request, jsonify

# DEFENSE_MODE=1  → απορρίπτει telemetry χωρίς έγκυρο X-Switch-Token header
# SWITCH_API_KEY  → το μυστικό token που πρέπει να γνωρίζουν οι νόμιμοι switches
# ADMIN_API_KEY   → token για admin-only endpoints (/reset, /unblock)
DEFENSE_MODE   = os.environ.get("DEFENSE_MODE",   "0") == "1"
SWITCH_API_KEY = os.environ.get("SWITCH_API_KEY", "sdn-secret-2024")
ADMIN_API_KEY  = os.environ.get("ADMIN_API_KEY",  "sdn-admin-2024")

# Rate limiting: max requests per IP per RATE_WINDOW seconds on /telemetry
RATE_LIMIT_MAX    = int(os.environ.get("RATE_LIMIT_MAX",    "120"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))

# Διάρκεια ζωής (lease) του κανόνα DROP. ΚΟΙΝΗ μεταβλητή για όλα τα μονοπάτια
# επιβολής (Flask flow table, ovs-ofctl στο mininet_live, Ryu/OpenFlow bridge),
# ώστε control plane και data plane να λήγουν την ίδια στιγμή.
BLOCK_TTL = int(os.environ.get("BLOCK_TTL", "10"))

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config
import detection_engine as engine

try:
    import joblib
    # live Isolation Forest: εκπαιδευμένο στα 8 aggregate features της τηλεμετρίας
    _ISO = joblib.load(os.path.join(config.MODELS_DIR, "isolation_forest_live.pkl"))
    _ISO_SCALER = joblib.load(os.path.join(config.MODELS_DIR, "isolation_forest_live_scaler.pkl"))
except Exception as e:
    print(f"[CONTROLLER] Προειδοποίηση: αποτυχία φόρτωσης Isolation Forest live model ({e}); "
          f"θα χρησιμοποιηθεί το εφεδρικό detection_engine.")
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

# Rolling metrics history for the dashboard chart.
_metrics: deque = deque(maxlen=1500)
_metrics_lock = threading.Lock()
_metrics_t0: float = None

# ── Control Plane Security: injection attack detection ────────────────────────
# Αποθηκεύει IPs εγγεγραμμένων switches (εγγράφονται μέσω POST /register).
# Σε DEFENSE_MODE, μόνο αυτές οι IPs επιτρέπεται να στέλνουν telemetry.
_trusted_switch_ips: set = set()
_trusted_lock = threading.Lock()

# Στατιστικά injection attempts για το dashboard / evaluation
_injection_stats = {"attempts": 0, "blocked": 0, "sources": {}}
_injection_lock  = threading.Lock()

# ── Manual simulation control (triggered from dashboard) ─────────────────────
_sim_pending: dict = {}   # set by /simulate/command, cleared on /simulate/poll
_sim_lock = threading.Lock()

# ── Rate limiter ──────────────────────────────────────────────────────────────
_rate_counters: dict = {}   # ip -> {"count": int, "window_start": float}
_rate_lock = threading.Lock()

# ── Live CSV flow export ──────────────────────────────────────────────────────
_LIVE_CSV = os.path.join(BASE, "data", "live_mininet_flows.csv")
_CSV_HEADER = ["timestamp", "src_ip", "dst_ip", "packets", "bytes",
               "flow_count", "packet_rate", "byte_rate", "short_flow_ratio",
               "avg_duration", "avg_pkt_size", "verdict", "action",
               "anomaly_score", "scenario"]
_csv_lock = threading.Lock()
_csv_initialized = False

def _init_csv():
    global _csv_initialized
    if _csv_initialized:
        return
    os.makedirs(os.path.dirname(_LIVE_CSV), exist_ok=True)
    write_header = not os.path.exists(_LIVE_CSV) or os.path.getsize(_LIVE_CSV) == 0
    if write_header:
        with open(_LIVE_CSV, "w", newline="") as f:
            csv.writer(f).writerow(_CSV_HEADER)
    _csv_initialized = True

def _append_csv(row: dict):
    _init_csv()
    with _csv_lock:
        with open(_LIVE_CSV, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_HEADER)
            w.writerow(row)

# ── Per-host anomaly score cache (latest score per IP) ────────────────────────
_anomaly_scores: dict = {}  # ip -> float (IF decision_function: >0 normal, <0 anomaly)
_scores_lock = threading.Lock()


def _check_rate_limit(ip: str) -> bool:
    """Return True if request is allowed, False if rate limit exceeded."""
    now = time.time()
    with _rate_lock:
        rec = _rate_counters.get(ip)
        if rec is None or now - rec["window_start"] > RATE_LIMIT_WINDOW:
            _rate_counters[ip] = {"count": 1, "window_start": now}
            return True
        rec["count"] += 1
        return rec["count"] <= RATE_LIMIT_MAX


def log_event(msg):
    entry = {"t": round(time.time(), 2), "msg": msg}
    _log.append(entry)
    print(f"[CONTROLLER] {msg}")


def _require_switch_token():
    """Έλεγχος X-Switch-Token. Επιστρέφει response 401 σε DEFENSE_MODE, αλλιώς None.

    Καταγράφει πάντα την απόπειρα, ώστε να μετριέται ακόμη και όταν η άμυνα
    είναι ανενεργή (λειτουργία επίδειξης).
    """
    if request.headers.get("X-Switch-Token", "") == SWITCH_API_KEY:
        return None
    caller = request.remote_addr
    with _injection_lock:
        _injection_stats["attempts"] += 1
        _injection_stats["sources"][caller] = _injection_stats["sources"].get(caller, 0) + 1
    log_event(f"⚠️  Μη εξουσιοδοτημένη πρόσβαση από {caller} στο {request.path}")
    if DEFENSE_MODE:
        with _injection_lock:
            _injection_stats["blocked"] += 1
        return jsonify({"error": "Unauthorized: missing or invalid X-Switch-Token"}), 401
    return None


def _require_admin_token():
    """Έλεγχος X-Admin-Token. Επιστρέφει response 401 σε DEFENSE_MODE, αλλιώς None."""
    if not DEFENSE_MODE:
        return None
    if request.headers.get("X-Admin-Token", "") == ADMIN_API_KEY:
        return None
    log_event(f"⚠️  Απόπειρα διαχειριστικής ενέργειας χωρίς token από {request.remote_addr}")
    return jsonify({"error": "Unauthorized: X-Admin-Token required"}), 401


@app.route("/register", methods=["POST"])
def register():
    # Το /register ήταν εντελώς ανοιχτό, ενώ προσθέτει τον καλούντα στις
    # έμπιστες πηγές τηλεμετρίας όταν δηλώνεται ως switch. Οποιοσδήποτε
    # μπορούσε έτσι να αποκτήσει καθεστώς έμπιστου μεταγωγέα και να
    # παρακάμψει τον έλεγχο δηλητηρίασης τηλεμετρίας.
    denied = _require_switch_token()
    if denied:
        return denied

    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid or missing JSON body"}), 400
    missing = [f for f in ("node_id", "ip") if f not in data]
    if missing:
        return jsonify({"error": f"missing required field(s): {', '.join(missing)}"}), 400

    gnv.add_node(data["node_id"], data.get("type", "host"), data["ip"])
    log_event(f"Εγγραφή κόμβου {data['node_id']} ({data['ip']})")

    # Αν είναι switch, εμπιστευόμαστε την IP του ως πηγή telemetry
    if data.get("type") == "switch":
        caller_ip = request.remote_addr
        with _trusted_lock:
            _trusted_switch_ips.add(caller_ip)
            _trusted_switch_ips.add(data["ip"])   # και η declared IP
        log_event(f"Trusted switch IP: {caller_ip} / {data['ip']}")

    return jsonify({"status": "registered", "node_id": data["node_id"]})


@app.route("/telemetry", methods=["POST"])
def telemetry():
    """
    Ο switch στέλνει στατιστικά ανά πηγή IP:
      { "src": "10.0.0.6", "dst": "10.0.0.5",
        "flows": [[packets, bytes, duration], ...] }
    Ο controller τα αναλύει (Defense Engine) και επιστρέφει την ενέργεια.
    """
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid or missing JSON body"}), 400
    missing = [f for f in ("src", "flows") if f not in data]
    if missing:
        return jsonify({"error": f"missing required field(s): {', '.join(missing)}"}), 400

    src = data["src"]
    dst = data.get("dst", "?")
    flows = data["flows"]
    if not isinstance(flows, list) or not all(
        isinstance(f, (list, tuple)) and len(f) >= 2 for f in flows
    ):
        return jsonify({"error": "'flows' must be a list of [packets, bytes, ...] entries"}), 400

    # ── Rate limiting ─────────────────────────────────────────────────────────
    caller_ip = request.remote_addr
    if not _check_rate_limit(caller_ip):
        return jsonify({"error": "Rate limit exceeded. Max "
                        f"{RATE_LIMIT_MAX} requests per {RATE_LIMIT_WINDOW}s."}), 429

    # ── Input validation ──────────────────────────────────────────────────────
    if len(flows) > 5000:
        return jsonify({"error": "Too many flows in single request (max 5000)"}), 400
    if len(src) > 45 or len(dst) > 45:
        return jsonify({"error": "IP address field too long"}), 400

    # ── Control Plane Security: API token validation ──────────────────────────
    token    = request.headers.get("X-Switch-Token", "")
    token_ok = (token == SWITCH_API_KEY)

    if not token_ok:
        with _injection_lock:
            _injection_stats["attempts"] += 1
            _injection_stats["sources"][caller_ip] = \
                _injection_stats["sources"].get(caller_ip, 0) + 1
        log_event(f"⚠️  INJECTION ATTEMPT από {caller_ip} — ισχυρίζεται ότι src={src} επιτίθεται")
        if DEFENSE_MODE:
            with _injection_lock:
                _injection_stats["blocked"] += 1
            return jsonify({
                "error": "Unauthorized: missing or invalid X-Switch-Token",
                "detail": "Only registered switches may submit telemetry.",
            }), 401

    total_pkts  = sum(f[0] for f in flows)
    total_bytes = sum(f[1] for f in flows)
    gnv.update_flow(src, dst, total_pkts, total_bytes)

    # Record in server-side metrics history
    global _metrics_t0
    now = time.time()
    with _metrics_lock:
        if _metrics_t0 is None:
            _metrics_t0 = now
        _metrics.append({
            "t":       round(now - _metrics_t0, 1),
            "src":     src,
            "packets": total_pkts,
            "bytes":   total_bytes,
        })

    verdict, feats = defense.analyze(flows)

    # Calibrated anomaly score for the dashboard. decision_function() centers the
    # score on the model's own decision boundary (offset_): >0 -> normal, <0 ->
    # anomaly. score_samples() would return the raw path-length score (here always
    # ~ -0.5 because offset_ ~ -0.57), which is indistinguishable between normal
    # and attack and made every host read 100% threat.
    anomaly_score = None
    if defense.iso is not None and defense.scaler is not None:
        try:
            X = defense.scaler.transform(feats.reshape(1, -1))
            anomaly_score = float(defense.iso.decision_function(X)[0])
            with _scores_lock:
                _anomaly_scores[src] = anomaly_score
        except Exception:
            pass

    if verdict == "Attack" and flow_table.action_for(src) != "DROP":
        # Το lease λήγει μετά από BLOCK_TTL δευτερόλεπτα. Αν η επίθεση συνεχίζεται,
        # η επόμενη τηλεμετρία με verdict=Attack το ξαναεγκαθιστά (action_for()
        # επιστρέφει FORWARD μόλις λήξει), οπότε ο αποκλεισμός ανανεώνεται.
        flow_table.install(src, "DROP", priority=100, ttl=BLOCK_TTL)
        gnv.set_node_status(src, "blocked")
        log_event(f"🚨 ΑΝΩΜΑΛΙΑ από {src} (flows={int(feats[0])}, "
                  f"short_ratio={feats[7]:.2f}) -> DROP rule")

    action = flow_table.action_for(src)

    # ── Live CSV export ────────────────────────────────────────────────────────
    try:
        _append_csv({
            "timestamp":       round(now, 2),
            "src_ip":          src,
            "dst_ip":          dst,
            "packets":         total_pkts,
            "bytes":           total_bytes,
            "flow_count":      int(feats[0]),
            "packet_rate":     round(float(feats[1]), 3),
            "byte_rate":       round(float(feats[2]), 3),
            "short_flow_ratio":round(float(feats[7]), 3) if len(feats) > 7 else 0,
            # feats[5]=avg_duration, feats[6]=avg_pkt_size (config.LIVE_FEATURE_COLUMNS)
            "avg_duration":    round(float(feats[5]), 3) if len(feats) > 5 else 0,
            "avg_pkt_size":    round(float(feats[6]), 1) if len(feats) > 6 else 0,
            "verdict":         verdict,
            "action":          action,
            "anomaly_score":   round(anomaly_score, 4) if anomaly_score is not None else "",
            "scenario":        "live",
        })
    except Exception:
        pass

    return jsonify({"src": src, "action": action, "verdict": verdict,
                    "anomaly_score": anomaly_score})


@app.route("/metrics", methods=["GET"])
def get_metrics():
    """Server-side packet rate history — used by dashboard to survive page refreshes."""
    with _metrics_lock:
        return jsonify(list(_metrics))


@app.route("/flow_table", methods=["GET"])
def get_flow_table():
    flow_table.expire()
    return jsonify(flow_table.as_dict())


@app.route("/topology", methods=["GET"])
def get_topology():
    return jsonify(gnv.as_dict())


@app.route("/stats", methods=["GET"])
def get_stats():
    with _injection_lock:
        inj = dict(_injection_stats)
    return jsonify({
        "nodes": len(gnv.nodes),
        "active_flows": len(gnv.flows),
        "drop_rules": len([r for r in flow_table.as_dict().values() if r["expires_in"] > 0]),
        "total_detections": defense.detections,
        "injection_attempts": inj["attempts"],
        "injection_blocked":  inj["blocked"],
        "recent_log": _log[-10:],
        "rate_limited_ips": sum(
            1 for v in _rate_counters.values()
            if v["count"] > RATE_LIMIT_MAX and
               time.time() - v["window_start"] < RATE_LIMIT_WINDOW
        ),
    })


@app.route("/injection_stats", methods=["GET"])
def injection_stats():
    """Αναλυτικά στατιστικά injection attempts — για evaluation."""
    with _injection_lock:
        return jsonify(dict(_injection_stats))


@app.route("/trusted_switches", methods=["GET"])
def trusted_switches():
    with _trusted_lock:
        return jsonify({"trusted_ips": list(_trusted_switch_ips),
                        "defense_mode": DEFENSE_MODE})


@app.route("/anomaly_scores", methods=["GET"])
def get_anomaly_scores():
    """Latest IF anomaly score per host IP (lower = more anomalous, threshold ~0)."""
    with _scores_lock:
        return jsonify(dict(_anomaly_scores))


@app.route("/enforcement", methods=["POST"])
def enforcement():
    """Ο μεταγωγέας αναφέρει ότι (επαν)εγκατέστησε κανόνα DROP στο data plane.

    Μόλις μια πηγή αποκλειστεί, η κίνησή της απορρίπτεται και παύει να εμφανίζεται ως
    ροή, οπότε ο ελεγκτής δεν λαμβάνει πλέον τηλεμετρία γι' αυτήν και το δικό του lease
    θα έληγε, ενώ ο κανόνας στο data plane θα εξακολουθούσε να ανανεώνεται. Το endpoint
    κρατά τις δύο όψεις συγχρονισμένες: ο μεταγωγέας δηλώνει την επιβολή που όντως
    εφαρμόζει και ο ελεγκτής ανανεώνει αντίστοιχα την εγγραφή του.

    ΔΕΝ αποτελεί νέα ανίχνευση: η απόφαση έχει ήδη ληφθεί από το μοντέλο.
    """
    if DEFENSE_MODE:
        token = request.headers.get("X-Switch-Token", "")
        if token != SWITCH_API_KEY:
            log_event(f"⛔ Μη εξουσιοδοτημένη πρόσβαση από {request.remote_addr} "
                      f"στο /enforcement")
            return jsonify({"error": "Unauthorized: X-Switch-Token required"}), 401

    data = request.get_json(silent=True) or {}
    src  = data.get("src")
    if not src:
        return jsonify({"error": "src required"}), 400
    if data.get("action", "DROP") != "DROP":
        return jsonify({"error": "only DROP is reported"}), 400

    renewal = bool(data.get("renewal"))
    flow_table.install(src, "DROP", priority=100, ttl=BLOCK_TTL)
    gnv.set_node_status(src, "blocked")
    if renewal:
        log_event(f"🔁 Ανανέωση κανόνα DROP για {src} "
                  f"(η επίθεση συνεχίζεται, {data.get('dropped_packets', '?')} πακέτα)")
    return jsonify({"status": "enforced", "src": src, "ttl": BLOCK_TTL})


@app.route("/unblock", methods=["POST"])
def unblock():
    """Clear DROP rules + reset blocked node statuses. Admin-only in DEFENSE_MODE."""
    if DEFENSE_MODE:
        token = request.headers.get("X-Admin-Token", "")
        if token != ADMIN_API_KEY:
            return jsonify({"error": "Unauthorized: X-Admin-Token required"}), 401
    with flow_table.lock:
        flow_table.rules.clear()
    with gnv.lock:
        for n in gnv.nodes.values():
            if n.get("status") == "blocked":
                n["status"] = "active"
    return jsonify({"status": "unblocked"})


@app.route("/reset", methods=["POST"])
def reset():
    """Full state reset. Admin-only in DEFENSE_MODE."""
    if DEFENSE_MODE:
        token = request.headers.get("X-Admin-Token", "")
        if token != ADMIN_API_KEY:
            return jsonify({"error": "Unauthorized: X-Admin-Token required"}), 401
    global _metrics_t0
    gnv.nodes.clear(); gnv.flows.clear()
    flow_table.rules.clear(); _log.clear()
    defense.detections = 0
    with _metrics_lock:
        _metrics.clear()
        _metrics_t0 = None
    with _injection_lock:
        _injection_stats["attempts"] = 0
        _injection_stats["blocked"]  = 0
        _injection_stats["sources"]  = {}
    with _trusted_lock:
        _trusted_switch_ips.clear()
    with _rate_lock:
        _rate_counters.clear()
    return jsonify({"status": "reset"})


@app.route("/simulate/command", methods=["POST"])
def simulate_command():
    """Dashboard → set a pending sim command {cmd, attackers, victim}.

    Διαχειριστική ενέργεια: εκκινεί/σταματά επιθέσεις στο δίκτυο, οπότε
    προστατεύεται με admin token όπως τα /reset και /unblock.
    """
    denied = _require_admin_token()
    if denied:
        return denied
    with _sim_lock:
        _sim_pending.clear()
        _sim_pending.update(request.json or {})
    return jsonify({"status": "queued"})


@app.route("/simulate/poll", methods=["GET"])
def simulate_poll():
    """Mininet polls this to pick up pending commands (one-shot, clears on read).

    Μόνο εγγεγραμμένοι μεταγωγείς επιτρέπεται να παραλαμβάνουν εντολές.
    """
    denied = _require_switch_token()
    if denied:
        return denied
    with _sim_lock:
        cmd = dict(_sim_pending)
        _sim_pending.clear()
    return jsonify(cmd)


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
