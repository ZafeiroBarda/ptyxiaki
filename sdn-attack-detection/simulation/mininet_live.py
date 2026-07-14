#!/usr/bin/env python3
"""
mininet_live.py — End-to-end live demo: Mininet + Flask controller.

Scenario (automated):
  1. Wait for Flask controller (http://controller:9000)
  2. Build Mininet topology: OVS switch (standalone mode) + 6 hosts
  3. Start background telemetry thread (polls ovs-ofctl every 5s)
  4. Phase 1 (30s): normal traffic — h1-h4 ping h5
  5. Phase 2 (30s): SYN flood from h6 → h5 (hping3)
  6. Print detection/mitigation results

No Ryu/OpenFlow controller required.
OVS runs in standalone (self-learning L2) mode.
Traffic stats polled via 'ovs-ofctl dump-ports'.
"""

import os
import re
import subprocess
import sys
import threading
import time

import requests

BASE            = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTROLLER_URL  = os.environ.get("CONTROLLER_URL",  "http://controller:9000")
SWITCH_API_KEY  = os.environ.get("SWITCH_API_KEY",  "sdn-secret-2024")
NORMAL_PHASE    = int(os.environ.get("NORMAL_PHASE",    "30"))
ATTACK_PHASE    = int(os.environ.get("ATTACK_PHASE",    "30"))
RECOVERY_PHASE  = int(os.environ.get("RECOVERY_PHASE",  "20"))
LOOP_CYCLES     = int(os.environ.get("LOOP_CYCLES",     "0"))   # 0 = infinite
TELEM_INTERVAL  = 2

# Διάρκεια ζωής (lease) του κανόνα απόρριψης. Κοινή μεταβλητή για ΟΛΑ τα μονοπάτια
# επιβολής (Flask controller, ovs-ofctl εδώ, Ryu/OpenFlow bridge), ώστε control plane
# και data plane να μη λήγουν σε διαφορετικές στιγμές.
BLOCK_TTL       = int(os.environ.get("BLOCK_TTL", "10"))
# Περιθώριο προληπτικής ανανέωσης: ο κανόνας ανανεώνεται όταν του απομένουν λιγότερα
# από τόσα δευτερόλεπτα ζωής ΚΑΙ η πηγή εξακολουθεί να κρίνεται κακόβουλη.
BLOCK_RENEW_MARGIN = int(os.environ.get("BLOCK_RENEW_MARGIN", "3"))
# Ρυθμός απορριπτόμενων πακέτων (pkts/s) πάνω από τον οποίο η επίθεση θεωρείται ότι
# ΣΥΝΕΧΙΖΕΤΑΙ. Όσο ο κόμβος είναι μπλοκαρισμένος δεν παράγει πλέον τηλεμετρία ροών, οπότε
# ο ίδιος ο μετρητής του κανόνα απόρριψης είναι η μόνη ζωντανή ένδειξη γι' αυτόν.
ATTACK_ONGOING_PPS = int(os.environ.get("ATTACK_ONGOING_PPS", "50"))

_SWITCH_HEADERS = {"X-Switch-Token": SWITCH_API_KEY}
ADMIN_API_KEY   = os.environ.get("ADMIN_API_KEY", "sdn-admin-2024")
_ADMIN_HEADERS  = {"X-Admin-Token": ADMIN_API_KEY}


# ──────────────────────────────────────────────────────────────────────────────
#  Flask controller helpers
# ──────────────────────────────────────────────────────────────────────────────

def wait_for_flask(timeout=90):
    print(f"[LIVE] Waiting for Flask controller ({CONTROLLER_URL})...", flush=True)
    for i in range(timeout):
        try:
            r = requests.get(f"{CONTROLLER_URL}/health", timeout=2)
            if r.ok:
                info = r.json()
                print(f"[LIVE] Controller OK — Defense Engine: "
                      f"{info.get('defense_engine', '?')}", flush=True)
                # Clear any state from previous runs
                try:
                    requests.post(f"{CONTROLLER_URL}/reset",
                                  headers=_ADMIN_HEADERS, timeout=3)
                    print("[LIVE] Controller state reset.", flush=True)
                except Exception:
                    pass
                return
        except Exception:
            pass
        if i % 10 == 9:
            print(f"[LIVE]   ...still waiting ({i+1}s)", flush=True)
        time.sleep(1)
    raise RuntimeError(f"Flask controller not responding after {timeout}s")


def register_host(name, ip):
    try:
        requests.post(f"{CONTROLLER_URL}/register",
                      json={"node_id": name, "type": "host", "ip": ip},
                      headers=_SWITCH_HEADERS, timeout=3)
    except Exception:
        pass


def get_stats():
    try:
        return requests.get(f"{CONTROLLER_URL}/stats", timeout=5).json()
    except Exception:
        return {"total_detections": "?", "drop_rules": "?", "nodes": 0, "active_flows": 0, "recent_log": []}


def get_flow_table():
    try:
        return requests.get(f"{CONTROLLER_URL}/flow_table", timeout=5).json()
    except Exception:
        return {}


def get_topology():
    try:
        return requests.get(f"{CONTROLLER_URL}/topology", timeout=5).json()
    except Exception:
        return {"nodes": [], "edges": []}


# ──────────────────────────────────────────────────────────────────────────────
#  OVS stats helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_ovs_port_stats(bridge="s1"):
    """Return {port_number: {packets, bytes}} via ovs-ofctl dump-ports."""
    try:
        result = subprocess.run(
            ["ovs-ofctl", "dump-ports", bridge],
            capture_output=True, text=True, timeout=5,
        )
        stats = {}
        for line in result.stdout.splitlines():
            m = re.match(r"\s+port\s+(\d+):\s+rx pkts=(\d+),\s*bytes=(\d+)", line)
            if m:
                stats[int(m.group(1))] = {
                    "packets": int(m.group(2)),
                    "bytes":   int(m.group(3)),
                }
        return stats
    except Exception:
        return {}


def install_pair_flows(hosts, bridge="s1"):
    """Εγκαθιστά κανόνες ανά ζεύγος (nw_src, nw_dst) που προωθούν κανονικά.

    Σε λειτουργία standalone ο μεταγωγέας έχει έναν προεπιλεγμένο κανόνα NORMAL,
    οπότε το dump-flows δίνει έναν μόνο συγκεντρωτικό μετρητή. Προσθέτοντας
    κανόνες υψηλότερης προτεραιότητας ανά ζεύγος IP (με ενέργεια NORMAL, ώστε η
    προώθηση να μη μεταβάλλεται), ο πίνακας ροών αποκτά ΞΕΧΩΡΙΣΤΗ καταχώρηση ανά
    ζεύγος, καθεμία με δικούς της μετρητές n_packets/n_bytes/duration. Έτσι η
    τηλεμετρία διαβάζει πραγματικές per-flow στατιστικές (OpenFlow flow stats),
    αντί για μία διαφορά μετρητή θύρας.
    """
    ips = [h.IP() for h in hosts.values()]
    n = 0
    for s in ips:
        for d in ips:
            if s == d:
                continue
            r = subprocess.run(
                ["ovs-ofctl", "add-flow", bridge,
                 f"priority=10,ip,nw_src={s},nw_dst={d},actions=normal"],
                capture_output=True, text=True,
            )
            if r.returncode == 0:
                n += 1
    print(f"[OVS]  Εγκαταστάθηκαν {n} κανόνες ροής ανά ζεύγος (per-flow stats)", flush=True)


def get_ovs_flow_stats(bridge="s1"):
    """Επιστρέφει την ακατέργαστη έξοδο του ovs-ofctl dump-flows (per-flow)."""
    try:
        r = subprocess.run(["ovs-ofctl", "dump-flows", bridge],
                           capture_output=True, text=True, timeout=5)
        return r.stdout
    except Exception:
        return ""


def get_drop_rule_info(src_ip, bridge="s1"):
    """Κατάσταση του ενεργού DROP κανόνα (priority=100) της πηγής, ή None.

    Επιστρέφει n_packets (πόσα πακέτα έχει κόψει το τρέχον lease), duration (πόση
    ώρα ζει) και hard_timeout, ώστε να μπορεί να υπολογιστεί ο χρόνος που του
    απομένει και να ανανεωθεί πριν λήξει. None σημαίνει ότι ο κανόνας δεν υπάρχει
    στο data plane, δηλαδή έληξε μέσω hard_timeout ή δεν εγκαταστάθηκε ποτέ.
    """
    for line in get_ovs_flow_stats(bridge).splitlines():
        if f"nw_src={src_ip}" in line and "actions=drop" in line:
            def _g(pat, cast, default):
                m = re.search(pat, line)
                return cast(m.group(1)) if m else default
            return {
                "n_packets":    _g(r"n_packets=(\d+)",      int,   0),
                "duration":     _g(r"duration=([\d.]+)s",   float, 0.0),
                "hard_timeout": _g(r"hard_timeout=(\d+)",   int,   BLOCK_TTL),
            }
    return None


def get_drop_rule_packets(src_ip, bridge="s1"):
    """Το n_packets του τρέχοντος DROP lease, ή None αν δεν υπάρχει κανόνας.

    Αποτελεί ΑΜΕΣΗ απόδειξη ότι ο κανόνας απόρριψης έκοψε πραγματικά πακέτα στο
    data plane (και όχι απλώς ότι εγκαταστάθηκε). Προσοχή: μετά από ανανέωση του
    lease ο μετρητής ξεκινά από το μηδέν· το αθροιστικό σύνολο κρατείται στο
    drop_state (βλ. ensure_drop_lease).
    """
    info = get_drop_rule_info(src_ip, bridge)
    return info["n_packets"] if info else None


def ping_rtt(host, target_ip, count=5):
    """Μέση καθυστέρηση (ms) του ping host->target· None αν δεν υπάρχει σύνδεση."""
    try:
        out = host.cmd(f"ping -c {count} -w {count+2} {target_ip}")
        m = re.search(r"= [\d.]+/([\d.]+)/", out)
        loss = re.search(r"(\d+)% packet loss", out)
        return {"avg_rtt_ms": float(m.group(1)) if m else None,
                "loss_pct": int(loss.group(1)) if loss else 100}
    except Exception:
        return {"avg_rtt_ms": None, "loss_pct": 100}


def read_iface_rx(iface):
    """Fallback: read rx_packets + rx_bytes from /sys/class/net."""
    try:
        p = int(open(f"/sys/class/net/{iface}/statistics/rx_packets").read())
        b = int(open(f"/sys/class/net/{iface}/statistics/rx_bytes").read())
        return p, b
    except Exception:
        return 0, 0


def install_drop_flow(src_ip, bridge="s1", hard_timeout=None):
    """Inject a high-priority DROP flow directly into OVS (bypasses controller).

    Ο κανόνας φέρει hard_timeout ίσο με το TTL του ελεγκτή (BLOCK_TTL), ώστε να
    λήγει μόνος του και να μη μένει η πηγή μπλοκαρισμένη στο data plane αφότου ο
    ελεγκτής θεωρεί τον κανόνα ληγμένο. Επιστρέφει True/False (επιτυχία) ώστε ο
    καλών να μπορεί να χρονοσημάνει τη στιγμή εγκατάστασης.
    """
    hard_timeout = BLOCK_TTL if hard_timeout is None else hard_timeout
    r = subprocess.run(
        ["ovs-ofctl", "add-flow", bridge,
         f"priority=100,ip,nw_src={src_ip},hard_timeout={hard_timeout},actions=drop"],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        return True
    print(f"[OVS]  DROP failed for {src_ip}: {r.stderr.strip()}", flush=True)
    return False


def new_drop_state():
    """Κοινή κατάσταση των leases απόρριψης, μοιραζόμενη μεταξύ των νημάτων.

    Την πειράζουν το νήμα τηλεμετρίας (πρώτη ανίχνευση) και το νήμα lease_keeper
    (ανανέωση/αποδέσμευση), οπότε προστατεύεται με κλειδαριά.
    """
    return {"hosts": {}, "timeline": {}, "lock": threading.Lock(),
            "coverage": {"samples": 0, "covered": 0,
                         "samples_after_install": 0, "covered_after_install": 0}}


def _lease(drop_state, src_ip):
    return drop_state["hosts"].setdefault(src_ip, {
        "leases": 0,             # πόσες φορές εγκαταστάθηκε ο κανόνας συνολικά
        "proactive_renewals": 0, # ανανεώσεις ΠΡΙΝ λήξει το lease (lease_keeper)
        "reactive_reinstalls": 0,# επανεγκαταστάσεις ΑΦΟΥ έληξε και ξαναφάνηκε η πηγή
        "dropped_finalised": 0,  # πακέτα από leases που έχουν ήδη λήξει/αντικατασταθεί
        "dropped_current": 0,    # πακέτα του τρέχοντος lease
    })


def dropped_total(drop_state, src_ip):
    """Αθροιστικά απορριφθέντα πακέτα σε ΟΛΑ τα leases της πηγής."""
    st = _lease(drop_state, src_ip)
    return st["dropped_finalised"] + st["dropped_current"]


def total_renewals(st):
    """Συνολικές (επαν)εγκαταστάσεις πέρα από την πρώτη: προληπτικές + αντιδραστικές."""
    return st["proactive_renewals"] + st["reactive_reinstalls"]


def report_enforcement(src_ip, renewal, dropped):
    """Ενημερώνει τον ελεγκτή για την επιβολή που εφαρμόστηκε στο data plane.

    Χωρίς αυτό, η εγγραφή του ελεγκτή θα έληγε (δεν φτάνει τηλεμετρία από μπλοκαρισμένο
    κόμβο) ενώ ο κανόνας στο data plane θα ανανεωνόταν: ο πίνακας ροών και το dashboard
    θα έδειχναν τον κόμβο ελεύθερο ενώ η κίνησή του θα απορριπτόταν.
    """
    try:
        requests.post(f"{CONTROLLER_URL}/enforcement",
                      json={"src": src_ip, "action": "DROP",
                            "renewal": renewal, "dropped_packets": dropped},
                      headers=_SWITCH_HEADERS, timeout=2)
    except Exception:
        pass


def _install_lease(src_ip, drop_state, kind):
    """(Επαν)εγκατάσταση του κανόνα. Ο καλών κρατά ήδη την κλειδαριά.

    Η επανεγκατάσταση του ίδιου match μηδενίζει τους μετρητές του OVS, οπότε τα πακέτα
    του lease που αντικαθίσταται μεταφέρονται πρώτα στο dropped_finalised, αλλιώς το
    αθροιστικό σύνολο των απορριφθέντων πακέτων θα ξεκινούσε από την αρχή σε κάθε
    ανανέωση.
    """
    st = _lease(drop_state, src_ip)
    st["dropped_finalised"] += st["dropped_current"]
    st["dropped_current"] = 0
    st["probe"] = None
    if not install_drop_flow(src_ip):
        return "failed"
    st["leases"] += 1
    # Διαχωρισμός των δύο τύπων επανεγκατάστασης, γιατί έχουν διαφορετική σημασία:
    # η προληπτική ανανέωση (renewed) αποτρέπει τη λήξη ώστε να μη μεσολαβήσει κενό,
    # ενώ η αντιδραστική (reinstalled) διορθώνει εκ των υστέρων ένα ήδη ληγμένο lease.
    if kind == "renewed":
        st["proactive_renewals"] += 1
    elif kind == "reinstalled":
        st["reactive_reinstalls"] += 1
    drop_state["timeline"].setdefault("first_rule_installed_mono", time.monotonic())
    labels = {"installed": "installed",
              "reinstalled": "REINSTALLED (reactive, lease had expired)",
              "renewed": "renewed (proactive, η επίθεση συνεχίζεται)"}
    total = dropped_total(drop_state, src_ip)
    print(f"[OVS]  DROP {labels[kind]}: {src_ip} (hard_timeout={BLOCK_TTL}s, "
          f"lease #{st['leases']}, σύνολο απορριφθέντων={total})", flush=True)
    report_enforcement(src_ip, renewal=(kind != "installed"), dropped=total)
    return kind


def ensure_drop_lease(src_ip, drop_state):
    """Εγγυάται ότι υπάρχει ΕΝΕΡΓΟΣ κανόνας DROP όταν η τηλεμετρία κρίνει την πηγή κακόβουλη.

    Καλείται από το νήμα τηλεμετρίας σε κάθε verdict=Attack. Καλύπτει την πρώτη
    ανίχνευση και την περίπτωση όπου το lease είχε λήξει και η πηγή ξαναφάνηκε.
    Η ΠΡΟΛΗΠΤΙΚΗ ανανέωση δεν γίνεται εδώ: όσο ο κόμβος είναι μπλοκαρισμένος δεν
    παράγει πλέον ροές, άρα δεν φτάνει τηλεμετρία γι' αυτόν. Την αναλαμβάνει ο
    lease_keeper, που παρακολουθεί τον ίδιο τον κανόνα.
    """
    with drop_state["lock"]:
        st   = _lease(drop_state, src_ip)
        info = get_drop_rule_info(src_ip)
        if info is None:
            kind = "installed" if st["leases"] == 0 else "reinstalled"
            return _install_lease(src_ip, drop_state, kind)
        st["dropped_current"] = info["n_packets"]
        return "active"


def keep_lease_alive(src_ip, drop_state):
    """Ανανεώνει το lease ΠΡΙΝ λήξει, όσο η επίθεση αποδεδειγμένα συνεχίζεται.

    Μόλις εγκατασταθεί ο κανόνας, η κίνηση της πηγής απορρίπτεται και δεν εμφανίζεται
    πλέον ως ροή στον πίνακα ροών, οπότε το μοντέλο παύει να «βλέπει» τον επιτιθέμενο.
    Ζωντανή ένδειξη μένει ο μετρητής του ίδιου του κανόνα απόρριψης: όσο κόβει πακέτα
    με ρυθμό πάνω από ATTACK_ONGOING_PPS, η κακόβουλη κίνηση συνεχίζεται και το lease
    ανανεώνεται. Όταν ο ρυθμός πέσει, το lease αφήνεται να λήξει και η πηγή
    αποδεσμεύεται, ώστε ο αποκλεισμός να μην είναι μόνιμος.
    """
    with drop_state["lock"]:
        st   = _lease(drop_state, src_ip)
        info = get_drop_rule_info(src_ip)
        now  = time.monotonic()

        if info is None:
            st["probe"] = None
            return "expired"

        st["dropped_current"] = info["n_packets"]
        if info["n_packets"] > 0:
            drop_state["timeline"].setdefault("first_packet_dropped_mono", now)

        prev = st.get("probe")
        st["probe"] = (now, info["n_packets"])

        if info["hard_timeout"] - info["duration"] > BLOCK_RENEW_MARGIN:
            return "active"

        pps = 0.0
        if prev and now > prev[0]:
            pps = (info["n_packets"] - prev[1]) / (now - prev[0])
        if pps < ATTACK_ONGOING_PPS:
            return "release"      # η κακόβουλη κίνηση σταμάτησε: άφησε το lease να λήξει

        return _install_lease(src_ip, drop_state, "renewed")


def lease_keeper(drop_state, stop_event, interval=0.5):
    """Background thread — κρατά ενεργά τα leases όσο οι επιθέσεις συνεχίζονται.

    Τρέχει ανεξάρτητα από τον ρυθμό της τηλεμετρίας. Αν η ανανέωση γινόταν μόνο στο
    νήμα τηλεμετρίας, ο κανόνας θα προλάβαινε να λήξει (ο μπλοκαρισμένος κόμβος δεν
    στέλνει πια ροές) και η επίθεση θα περνούσε ανεμπόδιστη ώσπου να ξαναανιχνευθεί.
    """
    while not stop_event.is_set():
        for ip in list(drop_state["hosts"].keys()):
            try:
                keep_lease_alive(ip, drop_state)
            except Exception:
                pass
        stop_event.wait(interval)


# ──────────────────────────────────────────────────────────────────────────────
#  Background telemetry thread
# ──────────────────────────────────────────────────────────────────────────────

def sim_control_loop(hosts, stop_event):
    """
    Background thread — polls /simulate/poll for manual attack commands
    sent from the dashboard. Allows victim/attacker selection at runtime.
    """
    active_attackers: set = set()

    while not stop_event.is_set():
        stop_event.wait(timeout=3)
        if stop_event.is_set():
            break
        try:
            cmd = requests.get(f"{CONTROLLER_URL}/simulate/poll",
                               headers=_SWITCH_HEADERS, timeout=2).json()
        except Exception:
            continue
        if not cmd or "cmd" not in cmd:
            continue

        if cmd["cmd"] == "start":
            # Stop any existing manual attack first
            for a in active_attackers:
                hosts[a].cmd("pkill hping3 2>/dev/null; true")
            active_attackers.clear()

            victim      = cmd.get("victim", "h5")
            attackers   = cmd.get("attackers", [])
            attack_type = cmd.get("attack_type", "syn")

            _attack_flags = {
                "syn":  "--syn  --flood -p 80",
                "udp":  "--udp  --flood -p 53",
                "icmp": "--icmp --flood",
            }
            flags = _attack_flags.get(attack_type, "--syn --flood -p 80")

            if victim not in hosts:
                print(f"[SIM] Unknown victim: {victim}", flush=True)
                continue
            victim_ip_manual = hosts[victim].IP()
            for a in attackers:
                if a not in hosts or a == victim:
                    continue
                hosts[a].cmd(
                    f"hping3 {flags} {victim_ip_manual} "
                    f"> /tmp/attack_{a}.log 2>&1 &"
                )
                active_attackers.add(a)
                print(f"[SIM] Manual {attack_type} attack: {a}({hosts[a].IP()}) → "
                      f"{victim}({victim_ip_manual})", flush=True)

        elif cmd["cmd"] == "stop":
            for a in active_attackers:
                hosts[a].cmd("pkill hping3 2>/dev/null; true")
            print(f"[SIM] Manual attack stopped ({', '.join(active_attackers)})", flush=True)
            active_attackers.clear()


def _submit_telemetry(src_ip, victim_ip, flows, drop_state):
    """Στέλνει μία λίστα ροών μιας πηγής στον controller και εφαρμόζει DROP.

    Χρονοσημαίνει (monotonic) την αποστολή της τηλεμετρίας και την παραλαβή της
    απόφασης, ώστε η καθυστέρηση ανίχνευσης να είναι μετρήσιμη και όχι εκτιμώμενη.
    """
    tl = drop_state["timeline"]
    t_sent = time.monotonic()
    try:
        resp = requests.post(
            f"{CONTROLLER_URL}/telemetry",
            json={"src": src_ip, "dst": victim_ip, "flows": flows},
            headers=_SWITCH_HEADERS, timeout=3,
        )
        result = resp.json()
    except Exception as e:
        print(f"[TELEM] Error ({src_ip}): {e}", flush=True)
        return
    t_verdict = time.monotonic()

    verdict = result.get("verdict", "Normal")
    action  = result.get("action", "FORWARD")
    total_pkts = sum(f[0] for f in flows)
    print(f"[TELEM] {src_ip:12s}  flows={len(flows):3d}  pkts={total_pkts:6d}"
          f"  verdict={verdict}  action={action}", flush=True)

    if verdict != "Attack":
        return
    if src_ip == tl.get("attacker_ip"):
        tl.setdefault("first_malicious_telemetry_mono", t_sent)
        tl.setdefault("first_verdict_mono", t_verdict)
    ensure_drop_lease(src_ip, drop_state)


def mitigation_monitor(attacker_ip, drop_state, stop_event, sample=0.5):
    """Δειγματοληπτεί την ΠΑΡΟΥΣΙΑ του κανόνα DROP καθ' όλη τη διάρκεια της επίθεσης.

    Δίνει τη μετρική mitigation coverage: το ποσοστό του χρόνου της επίθεσης κατά
    το οποίο υπήρχε πράγματι ενεργός κανόνας απόρριψης στο data plane. Καταγράφει
    επίσης τη στιγμή του πρώτου πραγματικά απορριφθέντος πακέτου, με ακρίβεια
    δειγματοληψίας μισού δευτερολέπτου.
    """
    cov = drop_state["coverage"]
    tl  = drop_state["timeline"]
    while not stop_event.is_set():
        info = get_drop_rule_info(attacker_ip)
        cov["samples"] += 1
        if info is not None:
            cov["covered"] += 1
            if info["n_packets"] > 0:
                tl.setdefault("first_packet_dropped_mono", time.monotonic())
        # Χωριστή μέτρηση από τη στιγμή που εγκαταστάθηκε ο πρώτος κανόνας και μετά:
        # το διάστημα ΠΡΙΝ την ανίχνευση είναι εγγενώς ακάλυπτο (δεν μπορείς να κόψεις
        # κίνηση που δεν έχεις ακόμη δει), ενώ το διάστημα ΜΕΤΑ δείχνει αν το lease
        # έμεινε πράγματι ενεργό σε όλη τη διάρκεια της επίθεσης.
        if "first_rule_installed_mono" in tl:
            cov["samples_after_install"] += 1
            if info is not None:
                cov["covered_after_install"] += 1
        stop_event.wait(sample)


def telemetry_loop(port_to_ip, victim_ip, stop_event, drop_state,
                   interval=TELEM_INTERVAL):
    """
    Background thread — runs across all cycles until stop_event is set.
    drop_state is a shared mutable dict (βλ. new_drop_state) που κρατά τα leases
    των κανόνων DROP και τα χρονοσήματα του τρέχοντος κύκλου, ώστε το κύριο νήμα
    να μπορεί να τα μηδενίζει ανάμεσα στους κύκλους χωρίς επανεκκίνηση του νήματος.

    ΠΡΩΤΕΥΟΝ ΜΟΝΟΠΑΤΙ: per-flow στατιστικά από τον πίνακα ροών (dump-flows),
    ώστε κάθε πηγή να στέλνει ΠΟΛΛΑΠΛΕΣ πραγματικές ροές (flow_count > 1) με
    δικές τους διάρκειες. ΕΦΕΔΡΙΚΟ: αν ο πίνακας ροών δεν έχει ακόμη per-flow
    καταχωρήσεις (π.χ. πριν εγκατασταθούν οι κανόνες ζεύγους), χρησιμοποιείται
    η παλαιότερη προσέγγιση διαφοράς μετρητή θύρας.
    """
    import flow_telemetry as ft

    prev_flows = {}   # (nw_src, nw_dst) -> {"packets","bytes"} για per-flow deltas
    prev_port = {p: {"packets": 0, "bytes": 0} for p in port_to_ip}

    while not stop_event.is_set():
        stop_event.wait(timeout=interval)
        if stop_event.is_set():
            break

        # ── Πρωτεύον: per-flow τηλεμετρία ────────────────────────────────────
        dump = get_ovs_flow_stats()
        parsed = ft.parse_ofctl_flows(dump) if dump else []
        if parsed:
            per_source, prev_flows = ft.window_deltas(parsed, prev_flows)
            for src_ip, flows in per_source.items():
                if src_ip == victim_ip:            # αγνόησε την κίνηση-απάντηση
                    continue
                if sum(f[0] for f in flows) < 4:    # αγνόησε micro-flows
                    continue
                _submit_telemetry(src_ip, victim_ip, flows, drop_state)
            continue

        # ── Εφεδρικό: διαφορά μετρητή θύρας (μία συγκεντρωτική ροή) ──────────
        curr = get_ovs_port_stats()
        if not curr:
            for port in port_to_ip:
                p, b = read_iface_rx(f"s1-eth{port}")
                curr[port] = {"packets": p, "bytes": b}

        for port, src_ip in port_to_ip.items():
            if port not in curr:
                continue
            if src_ip == victim_ip:
                prev_port[port] = curr[port]
                continue
            dpkts  = max(0, curr[port]["packets"] - prev_port[port]["packets"])
            dbytes = max(0, curr[port]["bytes"]   - prev_port[port]["bytes"])
            prev_port[port] = curr[port]
            if dpkts < 4:
                continue
            _submit_telemetry(src_ip, victim_ip, [[dpkts, dbytes, interval]], drop_state)


# ──────────────────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────────────────

# Κρίσιμες τιμές της κατανομής t (Student) για διπλής όψης 95% (0,975), ανά βαθμούς
# ελευθερίας. Για μικρά δείγματα και άγνωστη διασπορά, η t δίνει ορθότερα (ευρύτερα)
# διαστήματα από την κανονική z=1,96. Το mininet container έχει μόνο το requests, οπότε
# η τιμή διαβάζεται από πίνακα αντί για scipy. df>30 -> προσέγγιση με z.
_T_975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
          8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
          15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
          21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056,
          27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042}


def _t_critical(df):
    if df <= 0:
        return 0.0
    if df in _T_975:
        return _T_975[df]
    return 1.96  # df>30: η t πλησιάζει την κανονική


def _stats(values):
    """median, mean, p95, τυπική απόκλιση και 95% CI του μέσου για μια λίστα τιμών.

    Καθαρή Python (statistics), χωρίς numpy/scipy. Το CI υπολογίζεται με την κατανομή t
    (Student) με n-1 βαθμούς ελευθερίας, που είναι το ενδεδειγμένο για μικρά δείγματα με
    άγνωστη διασπορά και δίνει ελαφρώς ευρύτερα διαστήματα από την κανονική προσέγγιση.
    """
    import math
    import statistics as st
    xs = sorted(v for v in values if v is not None)
    if not xs:
        return None
    n = len(xs)
    mean = st.fmean(xs)
    sd = st.pstdev(xs) if n < 2 else st.stdev(xs)
    p95 = xs[min(n - 1, int(math.ceil(0.95 * n)) - 1)]
    ci = _t_critical(n - 1) * sd / math.sqrt(n) if n > 1 else 0.0
    return {"n": n, "median": round(st.median(xs), 3), "mean": round(mean, 3),
            "p95": round(p95, 3), "std": round(sd, 3),
            "ci_method": "t", "ci95_low": round(mean - ci, 3),
            "ci95_high": round(mean + ci, 3)}


def aggregate_cycles(cycles):
    """Συγκεντρωτικές μετρικές πάνω σε πολλούς ανεξάρτητους κύκλους (πειράματα 2, 3).

    Μία μόνο εκτέλεση δεν επιτρέπει διαστήματα εμπιστοσύνης· με πολλούς κύκλους
    (LOOP_CYCLES>1) εξάγονται κατανομές για την καθυστέρηση ανίχνευσης, την κάλυψη
    και τα απορριφθέντα πακέτα.
    """
    if not cycles:
        return None
    verdict = [c["latencies_s"].get("first_verdict_s") for c in cycles]
    firstdrop = [c["latencies_s"].get("first_dropped_packet_s") for c in cycles]
    cov = [c.get("mitigation_coverage_pct") for c in cycles]
    cov_after = [c.get("mitigation_coverage_after_detection_pct") for c in cycles]
    dropped = [c.get("ovs_drop_rule_total_packets") for c in cycles]
    blocked = sum(1 for c in cycles if c.get("controller_flow_table_blocked"))
    fp = sum(1 for c in cycles if c.get("false_positive_on_legit"))
    return {
        "cycles": len(cycles),
        "detection_rate_pct": round(100.0 * blocked / len(cycles), 1),
        "false_positive_cycles": fp,
        "detection_latency_s": _stats(verdict),
        "first_dropped_packet_s": _stats(firstdrop),
        "mitigation_coverage_pct": _stats(cov),
        "mitigation_coverage_after_detection_pct": _stats(cov_after),
        "dropped_packets": _stats(dropped),
    }


def main():
    from mininet.net import Mininet
    from mininet.node import OVSSwitch
    from mininet.link import TCLink
    from mininet.log import setLogLevel

    setLogLevel("warning")

    # ── 1. Flask controller ──────────────────────────────────────────────────
    wait_for_flask()

    # ── 2. Build topology ───────────────────────────────────────────────────
    print("[LIVE] Building Mininet topology (6 hosts, 1 OVS switch)...", flush=True)

    # controller=None → no remote controller needed
    net = Mininet(switch=OVSSwitch, link=TCLink, autoSetMacs=True, controller=None)

    # failMode='standalone': OVS learns MACs autonomously (no controller required)
    # datapath='user':       userspace OVS (works on WSL2 without kernel module)
    s1 = net.addSwitch("s1", failMode="standalone", datapath="user")

    hosts = {}
    for i in range(1, 7):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        net.addLink(h, s1, bw=10, delay="1ms")
        hosts[f"h{i}"] = h

    net.start()
    time.sleep(3)

    victim_ip   = hosts["h5"].IP()
    attacker_ip = hosts["h6"].IP()
    legit       = [hosts[f"h{i}"] for i in range(1, 5)]

    # Port numbers are assigned in insertion order (h1→port1, h2→port2, …)
    port_to_ip = {i: hosts[f"h{i}"].IP() for i in range(1, 7)}

    print(f"[LIVE] h1-h4 legit | h5={victim_ip} victim | "
          f"h6={attacker_ip} attacker", flush=True)

    # ── 3. Register hosts + εγκατάσταση κανόνων ροής ανά ζεύγος ──────────────
    for name, h in hosts.items():
        register_host(name, h.IP())
    install_pair_flows(hosts)   # ώστε το dump-flows να δίνει per-flow στατιστικά
    print("[LIVE] Hosts registered.\n", flush=True)

    # ── 4. Start telemetry + sim-control threads ────────────────────────────
    drop_state = new_drop_state()
    stop_event = threading.Event()
    telem = threading.Thread(
        target=telemetry_loop,
        args=(port_to_ip, victim_ip, stop_event, drop_state),
        daemon=True,
    )
    telem.start()
    sim_ctrl = threading.Thread(
        target=sim_control_loop,
        args=(hosts, stop_event),
        daemon=True,
    )
    sim_ctrl.start()
    keeper = threading.Thread(
        target=lease_keeper,
        args=(drop_state, stop_event),
        daemon=True,
    )
    keeper.start()

    # ── Main demo loop ────────────────────────────────────────────────────────
    cycle = 0
    _run_evidence = None   # ορίζεται πάντα, ώστε το summary να γράφεται ακόμη και
                           # αν ο βρόχος διακοπεί πριν ολοκληρωθεί ο πρώτος κύκλος
    cycles_evidence = []   # evidence κάθε κύκλου (για στατιστική πολλαπλών runs)
    loop_label = f"{LOOP_CYCLES} cycle(s)" if LOOP_CYCLES else "∞ (Ctrl-C to stop)"
    print(f"[LIVE] Demo loop: {loop_label}\n", flush=True)

    try:
        while True:
            cycle += 1
            bar = "=" * 60

            # ── Phase 1: Normal traffic ──────────────────────────────────────
            print(f"{bar}", flush=True)
            print(f"  CYCLE {cycle} · PHASE 1: Normal traffic ({NORMAL_PHASE}s)",
                  flush=True)
            print(f"{bar}", flush=True)

            deadline = time.time() + NORMAL_PHASE
            while time.time() < deadline:
                for h in legit:
                    h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
                time.sleep(5)
                elapsed = int(time.time() - (deadline - NORMAL_PHASE))
                print(f"[LIVE] C{cycle} Phase 1 — {elapsed}s/{NORMAL_PHASE}s",
                      flush=True)

            # RTT/απώλεια νόμιμου host ΚΑΤΑ τη φάση κανονικής κίνησης (baseline δικτύου
            # χωρίς επίθεση, για τη μέτρηση επίδρασης στο δίκτυο — πείραμα 4).
            rtt_normal = ping_rtt(legit[0], victim_ip)
            p1 = get_stats()
            print(f"\n[LIVE] End Phase 1 — detections: {p1['total_detections']} | "
                  f"DROP: {p1['drop_rules']} | rtt_normal={rtt_normal}\n", flush=True)

            # ── Phase 2: DDoS SYN flood ──────────────────────────────────────
            print(f"{bar}", flush=True)
            print(f"  CYCLE {cycle} · PHASE 2: SYN flood h6 → h5 ({ATTACK_PHASE}s)",
                  flush=True)
            print(f"{bar}", flush=True)

            # Μηδενισμός κατάστασης του κύκλου και εκκίνηση του δειγματολήπτη κάλυψης
            # ΠΡΙΝ ξεκινήσει η επίθεση, ώστε να μη χαθεί το πρώτο απορριφθέν πακέτο.
            drop_state["hosts"].pop(attacker_ip, None)
            drop_state["coverage"] = {"samples": 0, "covered": 0,
                                      "samples_after_install": 0,
                                      "covered_after_install": 0}
            drop_state["timeline"] = {"attacker_ip": attacker_ip}
            mon_stop = threading.Event()
            mon = threading.Thread(
                target=mitigation_monitor,
                args=(attacker_ip, drop_state, mon_stop),
                daemon=True,
            )
            mon.start()

            t_attack_start = time.monotonic()
            drop_state["timeline"]["attack_start_mono"] = t_attack_start
            drop_state["timeline"]["attack_start_wall"] = time.time()
            hosts["h6"].cmd(
                f"hping3 --syn --flood -p 80 {victim_ip} > /tmp/attack.log 2>&1 &"
            )

            deadline = time.time() + ATTACK_PHASE
            while time.time() < deadline:
                for h in legit:
                    h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
                time.sleep(5)
                elapsed = int(time.time() - (deadline - ATTACK_PHASE))
                s_now = get_stats()
                info  = get_drop_rule_info(attacker_ip)
                lease = _lease(drop_state, attacker_ip)
                print(f"[LIVE] C{cycle} Phase 2 — {elapsed}s/{ATTACK_PHASE}s | "
                      f"detections: {s_now['total_detections']} | "
                      f"DROP: {s_now['drop_rules']} | "
                      f"rule={'ACTIVE' if info else 'expired'} | "
                      f"leases={lease['leases']} | "
                      f"dropped_pkts(total)={dropped_total(drop_state, attacker_ip)}",
                      flush=True)

            # Καθυστέρηση/απώλεια ping νόμιμου host ΚΑΤΑ την επίθεση (θύμα-πλευρά)
            rtt_during = ping_rtt(legit[0], victim_ip)

            hosts["h6"].cmd("pkill hping3 2>/dev/null; true")
            attack_duration = time.monotonic() - t_attack_start
            mon_stop.set()
            mon.join(timeout=3)

            # ── Cycle results ────────────────────────────────────────────────
            ft = get_flow_table()
            blocked = attacker_ip in ft
            fp      = any(h.IP() in ft for h in legit)
            lease   = _lease(drop_state, attacker_ip)
            total_dropped = dropped_total(drop_state, attacker_ip)

            tl = drop_state["timeline"]

            def _lat(key):
                """Καθυστέρηση από την έναρξη της επίθεσης (monotonic, δευτερόλεπτα)."""
                v = tl.get(key)
                return round(v - t_attack_start, 3) if v is not None else None

            latencies = {
                "first_malicious_telemetry_s": _lat("first_malicious_telemetry_mono"),
                "first_verdict_s":             _lat("first_verdict_mono"),
                "rule_installed_s":            _lat("first_rule_installed_mono"),
                "first_dropped_packet_s":      _lat("first_packet_dropped_mono"),
            }
            cov = drop_state["coverage"]
            coverage_pct = (round(100.0 * cov["covered"] / cov["samples"], 1)
                            if cov["samples"] else None)
            coverage_after_pct = (
                round(100.0 * cov["covered_after_install"] / cov["samples_after_install"], 1)
                if cov["samples_after_install"] else None)

            print(f"\n[LIVE] C{cycle} result: "
                  f"{'✅ attacker blocked' if blocked else '⚠️ NOT blocked'} | "
                  f"dropped_pkts={total_dropped} | "
                  f"leases={lease['leases']} (proactive={lease['proactive_renewals']}, "
                  f"reactive={lease['reactive_reinstalls']}) | "
                  f"mitigation coverage={coverage_pct}% της επίθεσης "
                  f"({coverage_after_pct}% μετά την ανίχνευση) | "
                  f"{'✅ no FP' if not fp else '⚠️ FP on legit host'}", flush=True)
            print(f"[LIVE] C{cycle} latencies (s from attack start): {latencies}\n",
                  flush=True)

            _run_evidence = {
                "cycle": cycle, "attacker_ip": attacker_ip,
                "controller_flow_table_blocked": blocked,
                "attack_duration_s": round(attack_duration, 2),
                "ovs_drop_rule_total_packets": total_dropped,
                "drop_rule_leases": lease["leases"],
                "drop_rule_renewals": total_renewals(lease),
                "drop_rule_proactive_renewals": lease["proactive_renewals"],
                "drop_rule_reactive_reinstalls": lease["reactive_reinstalls"],
                "block_ttl_s": BLOCK_TTL,
                "mitigation_coverage_pct": coverage_pct,
                "mitigation_coverage_after_detection_pct": coverage_after_pct,
                "coverage_samples": cov["samples"],
                "latencies_s": latencies,
                "false_positive_on_legit": fp,
                "legit_ping_normal_phase": rtt_normal,
                "legit_ping_during_attack": rtt_during,
            }
            cycles_evidence.append(_run_evidence)

            # ── Check loop exit condition ────────────────────────────────────
            if LOOP_CYCLES > 0 and cycle >= LOOP_CYCLES:
                break

            # ── Recovery phase: unblock and wait before next cycle ───────────
            print(f"[LIVE] Recovery ({RECOVERY_PHASE}s) — "
                  f"clearing DROP rules for next cycle...", flush=True)
            try:
                requests.post(f"{CONTROLLER_URL}/unblock",
                              headers=_ADMIN_HEADERS, timeout=3)
            except Exception:
                pass
            # Remove ONLY the priority-100 DROP flow so the attacker can flood
            # again next cycle. --strict + priority keeps the priority-10
            # per-pair NORMAL flows intact (needed for per-flow telemetry).
            subprocess.run(
                ["ovs-ofctl", "--strict", "del-flows", "s1",
                 f"priority=100,ip,nw_src={attacker_ip}"],
                capture_output=True,
            )
            drop_state["hosts"].pop(attacker_ip, None)   # νέο lease στον επόμενο κύκλο

            deadline = time.time() + RECOVERY_PHASE
            while time.time() < deadline:
                for h in legit:
                    h.cmd(f"ping -c 20 -i 0.2 -q {victim_ip} > /dev/null 2>&1 &")
                time.sleep(5)
                elapsed = int(time.time() - (deadline - RECOVERY_PHASE))
                print(f"[LIVE] Recovery — {elapsed}s/{RECOVERY_PHASE}s", flush=True)

    except KeyboardInterrupt:
        print("\n[LIVE] Interrupted by user.", flush=True)

    # ── Final results ─────────────────────────────────────────────────────────
    stop_event.set()
    telem.join(timeout=10)

    stats = get_stats()
    print(f"\n[LIVE] Total cycles: {cycle} | "
          f"Total detections: {stats['total_detections']}", flush=True)

    # ── Πλήρες summary του run ────────────────────────────────────────────────
    # Ping μετά την αποκατάσταση: επιβεβαιώνει ότι το δίκτυο επανήλθε για τους
    # νόμιμους hosts αφού λήξει/αρθεί ο κανόνας απόρριψης.
    rtt_after = ping_rtt(legit[0], victim_ip)
    try:
        import json
        run_dir = os.path.join(BASE, "results", "live",
                               f"mininet_run_{time.strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(run_dir, exist_ok=True)
        # στιγμιότυπο πίνακα ροών (raw evidence)
        with open(os.path.join(run_dir, "ovs_dump_flows.txt"), "w") as f:
            f.write(get_ovs_flow_stats())
        evidence = _run_evidence if _run_evidence else None
        summary = {
            "run_id": os.path.basename(run_dir),
            "experiment_type": "packet_level",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "code_commit": os.environ.get("CODE_COMMIT", "unknown"),
            "topology": "Mininet 6 hosts + OVS s1 (userspace, standalone)",
            "attack_tool": "hping3 --syn --flood",
            "config": {
                "normal_phase_s": NORMAL_PHASE,
                "attack_phase_s": ATTACK_PHASE,
                "recovery_phase_s": RECOVERY_PHASE,
                "telemetry_interval_s": TELEM_INTERVAL,
                "block_ttl_s": BLOCK_TTL,
                "block_renew_margin_s": BLOCK_RENEW_MARGIN,
                "attack_ongoing_pps": ATTACK_ONGOING_PPS,
                "loop_cycles": LOOP_CYCLES,
            },
            "total_cycles": cycle,
            "total_detections": stats.get("total_detections"),
            "last_cycle_evidence": evidence,
            "all_cycles_evidence": cycles_evidence,
            "aggregate": aggregate_cycles(cycles_evidence),
            "legit_ping_after_recovery": rtt_after,
            "note": (
                "ovs_drop_rule_total_packets > 0 αποδεικνύει ΠΡΑΓΜΑΤΙΚΗ απόρριψη πακέτων "
                "στο data plane και όχι απλώς εγκατάσταση κανόνα. Το lease του κανόνα "
                f"λήγει μέσω hard_timeout={BLOCK_TTL}s και ΑΝΑΝΕΩΝΕΤΑΙ όσο η πηγή "
                "εξακολουθεί να κρίνεται κακόβουλη, οπότε το mitigation_coverage_pct "
                "δείχνει το ποσοστό της επίθεσης που καλύφθηκε από ενεργό κανόνα. Οι "
                "καθυστερήσεις είναι monotonic μετρήσεις από τη στιγμή εκκίνησης της "
                "επίθεσης. Το ping μετά την αποκατάσταση δείχνει επαναφορά της νόμιμης "
                "συνδεσιμότητας."
            ),
        }
        with open(os.path.join(run_dir, "summary.json"), "w") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(f"[LIVE] Summary γράφτηκε: {run_dir}/summary.json", flush=True)

        # Τα artifacts εκπέμπονται και στο stdout: το container δεν έχει volume mount
        # και σταματά μόλις τελειώσει το σενάριο, οπότε αυτός είναι ο μόνος τρόπος να
        # τα ανακτήσει ο host runner με ένα βήμα (docker logs) και όχι χειροκίνητα.
        print("[ARTIFACT] summary.json <<<", flush=True)
        print(json.dumps(summary, ensure_ascii=False), flush=True)
        print("[ARTIFACT] >>>", flush=True)
        print("[ARTIFACT] ovs_dump_flows.txt <<<", flush=True)
        print(get_ovs_flow_stats(), flush=True)
        print("[ARTIFACT] >>>", flush=True)
    except Exception as e:
        print(f"[LIVE] Αποτυχία εγγραφής summary: {e}", flush=True)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    print("\n[LIVE] Stopping Mininet...", flush=True)
    net.stop()
    print("[LIVE] Done.", flush=True)


if __name__ == "__main__":
    main()
