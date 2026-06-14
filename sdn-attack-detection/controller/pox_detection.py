#!/usr/bin/env python3
"""
pox_detection.py  (ΜΕΘΟΔΟΣ A — 2η εκδοχή controller: POX)
---------------------------------------------------------
Εναλλακτική υλοποίηση του detection controller με τον **POX** αντί για Ryu.
Έτσι η διπλωματική μπορεί να συγκρίνει δύο διαφορετικούς Python SDN controllers
(Ryu vs POX) στο ίδιο σενάριο ανίχνευσης + αντιμετώπισης.

Διαφορές POX vs Ryu:
  - Ο POX χρησιμοποιεί OpenFlow 1.0 (ο Ryu εδώ 1.3).
  - Event-driven API μέσω του αντικειμένου `core` και listeners.
  - Πιο απλό/εκπαιδευτικό, ιδανικό για μικρές τοπολογίες.

Λειτουργία (ίδια λογική με τον Ryu controller):
  1. Learning switch (L2).
  2. Περιοδικό αίτημα flow-stats (Timer).
  3. Aggregate features ανά πηγή IP -> live μοντέλο -> Attack/Normal.
  4. Mitigation: εγκατάσταση drop-rule για την κακόβουλη πηγή.

ΕΚΤΕΛΕΣΗ (μέσα στο POX directory ή με PYTHONPATH στο pox):
    # 1) εκπαίδευσε το live μοντέλο (όπως και στον Ryu):
    python3 controller/train_live_model.py
    # 2) τρέξε τον POX με αυτό το component:
    ./pox.py log.level --DEBUG controller.pox_detection
    # 3) σε άλλο τερματικό η τοπολογία (OpenFlow 1.0):
    sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo single,6 \
            --switch ovsk,protocols=OpenFlow10

ΣΗΜΕΙΩΣΗ: Ο POX τρέχει συνήθως με Python 3 στις πρόσφατες εκδόσεις (branch
'gar'/'halosaur'). Αντίγραψε αυτό το αρχείο στον φάκελο pox/ext/ ή πρόσθεσέ το
στο PYTHONPATH ώστε να το βρει το import.
"""

import os
import sys
import joblib
import numpy as np

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr

# ρυθμίσεις από το ml_pipeline
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config

log = core.getLogger()

POLL_INTERVAL = config.POLL_INTERVAL
SHORT_FLOW_PKT_THRESHOLD = config.SHORT_FLOW_PKT_THRESHOLD


class POXDetectionSwitch(object):
    """Ένα instance ανά συνδεδεμένο switch."""

    def __init__(self, connection, controller):
        self.connection = connection
        self.controller = controller
        self.mac_to_port = {}
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        self.mac_to_port[packet.src] = event.port

        # αν η πηγή είναι μπλοκαρισμένη, μην προωθείς (η drop-rule το χειρίζεται)
        ipv4 = packet.find("ipv4")
        if ipv4 and str(ipv4.srcip) in self.controller.blocked:
            return

        out_port = self.mac_to_port.get(packet.dst)
        msg = of.ofp_packet_out(data=event.ofp)
        if out_port is None:
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        else:
            # εγκατάσταση flow ώστε να μη ξαναέρθει στον controller
            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(packet, event.port)
            fm.idle_timeout = 30
            fm.actions.append(of.ofp_action_output(port=out_port))
            self.connection.send(fm)
            msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)


class POXDetectionController(object):
    """Κεντρικός controller: διαχειρίζεται switches, polling, ML, mitigation."""

    def __init__(self):
        self.switches = {}
        self.blocked = {}   # src_ip -> χρόνος μπλοκαρίσματος

        # φόρτωση live μοντέλου
        self.model, self.scaler = None, None
        self._load_model()

        core.openflow.addListeners(self)
        # περιοδικό polling
        Timer(POLL_INTERVAL, self._request_all_stats, recurring=True)
        log.info("POXDetectionController έτοιμος. Poll κάθε %ss.", POLL_INTERVAL)

    def _load_model(self):
        try:
            self.model = joblib.load(os.path.join(config.MODELS_DIR, "live_model.pkl"))
            self.scaler = joblib.load(os.path.join(config.MODELS_DIR, "live_scaler.pkl"))
            log.info("[ML] Φορτώθηκε live μοντέλο.")
        except Exception as e:
            log.warning("[ML] Δεν φορτώθηκε μοντέλο (%s). Fallback heuristic.", e)

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s συνδέθηκε", dpid_to_str(event.dpid))
        self.switches[event.dpid] = POXDetectionSwitch(event.connection, self)

    def _request_all_stats(self):
        for conn in core.openflow.connections:
            conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_FlowStatsReceived(self, event):
        """Λήψη flow-stats -> aggregate ανά πηγή -> ML -> mitigation."""
        per_src = {}
        for f in event.stats:
            # ο POX δίνει το match ως ofp_match
            src = getattr(f.match, "nw_src", None)
            if src is None:
                continue
            dur = f.duration_sec + f.duration_nsec / 1e9
            per_src.setdefault(str(src), []).append(
                (f.packet_count, f.byte_count, dur))

        for src_ip, flows in per_src.items():
            feats = self._aggregate(flows)
            if self._classify(feats) == "Attack" and src_ip not in self.blocked:
                log.warning("[DETECT] ΕΠΙΘΕΣΗ από %s (flows=%d) -> ΜΠΛΟΚΑΡΙΣΜΑ",
                            src_ip, int(feats[0]))
                self._mitigate(event.connection, src_ip)

    def _aggregate(self, flows):
        fc = len(flows)
        tp = sum(f[0] for f in flows)
        tb = sum(f[1] for f in flows)
        durs = [f[2] for f in flows]
        avg_p = tp / fc if fc else 0
        avg_b = tb / fc if fc else 0
        avg_d = sum(durs) / fc if fc else 0
        avg_ps = tb / tp if tp else 0
        short = sum(1 for f in flows if f[0] <= SHORT_FLOW_PKT_THRESHOLD)
        sr = short / fc if fc else 0
        return np.array([fc, tp, tb, avg_p, avg_b, avg_d, avg_ps, sr], dtype=float)

    def _classify(self, feats):
        if self.model is not None and self.scaler is not None:
            X = self.scaler.transform(feats.reshape(1, -1))
            return "Attack" if int(self.model.predict(X)[0]) == 1 else "Normal"
        # fallback heuristic
        if feats[0] > config.ATTACK_FLOW_THRESHOLD and feats[7] > 0.6:
            return "Attack"
        return "Normal"

    def _mitigate(self, connection, src_ip, block_seconds=60):
        """Εγκατάσταση drop-rule (κενές actions = drop) για την πηγή."""
        fm = of.ofp_flow_mod()
        fm.priority = 100
        fm.match.dl_type = 0x0800            # IPv4
        fm.match.nw_src = IPAddr(src_ip)
        fm.hard_timeout = block_seconds
        # καμία action -> drop
        connection.send(fm)
        import time
        self.blocked[src_ip] = time.time()
        log.info("[MITIGATE] DROP-rule για %s (%ds)", src_ip, block_seconds)


def launch():
    """Σημείο εισόδου του POX component."""
    core.registerNew(POXDetectionController)
