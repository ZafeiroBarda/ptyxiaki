#!/usr/bin/env python3
"""
detection_controller.py  (ΜΕΘΟΔΟΣ A — ο "εγκέφαλος" του συστήματος)
-------------------------------------------------------------------
Ryu SDN controller που:
  1. Λειτουργεί ως learning switch (L2) — μαθαίνει MAC->port και προωθεί.
  2. Ζητάει περιοδικά flow-statistics από τα switches (FlowStatsRequest).
  3. Συγκεντρώνει aggregate χαρακτηριστικά ΑΝΑ ΠΗΓΗ IP μέσα σε κάθε παράθυρο.
  4. Τρέχει το προεκπαιδευμένο live μοντέλο (models/live_model.pkl).
  5. ΑΝΤΙΜΕΤΩΠΙΣΗ (mitigation): αν ανιχνευτεί επίθεση από κάποια πηγή,
     εγκαθιστά flow-rule που ΑΠΟΡΡΙΠΤΕΙ (drop) την κίνηση από αυτή την πηγή
     για ορισμένο χρόνο (hard_timeout).

Εκτέλεση (σε Linux με Ryu):
    1) Εκπαίδευσε το live μοντέλο:   python3 controller/train_live_model.py
    2) Ξεκίνα τον controller:        ryu-manager controller/detection_controller.py
    3) Σε άλλο τερματικό:            sudo python3 simulation/topology.py
    4) Παρήγαγε κίνηση/επιθέσεις:    simulation/traffic_*.py

Σημείωση συμβατότητας: αν χρησιμοποιείς os-ken (συντηρούμενο fork του Ryu),
αντικατέστησε τα 'ryu.' με 'os_ken.' στα imports.
"""

import os
import time
import joblib
import numpy as np

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.ofproto import ofproto_v1_3

# --- φόρτωση ρυθμίσεων από το ml_pipeline ---
import sys
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config


class DetectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}          # {dpid: {mac: port}}
        self.datapaths = {}            # ενεργά switches
        self.blocked = {}              # {src_ip: timestamp μπλοκαρίσματος}

        # --- Φόρτωση live μοντέλου ---
        self.model = None
        self.scaler = None
        self._load_model()

        # νήμα παρακολούθησης (polling των flow-stats)
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("[INIT] DetectionController ξεκίνησε. "
                         "Poll κάθε %ss.", config.POLL_INTERVAL)

    # ------------------------------------------------------------------ #
    #  Φόρτωση μοντέλου ML
    # ------------------------------------------------------------------ #
    def _load_model(self):
        model_path = os.path.join(config.MODELS_DIR, "live_model.pkl")
        scaler_path = os.path.join(config.MODELS_DIR, "live_scaler.pkl")
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.logger.info("[ML] Φορτώθηκε live μοντέλο από %s", model_path)
        except Exception as e:
            self.logger.warning("[ML] ΔΕΝ φορτώθηκε μοντέλο (%s). "
                                "Τρέξε train_live_model.py. Λειτουργία μόνο switch.", e)

    # ------------------------------------------------------------------ #
    #  Switch setup: table-miss + learning switch
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # table-miss: ό,τι δεν ταιριάζει -> στείλ' το στον controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("[SWITCH] Συνδέθηκε switch dpid=%s", datapath.id)

    def add_flow(self, datapath, priority, match, actions,
                 hard_timeout=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # έλεγχος: είναι μπλοκαρισμένη πηγή; (mitigation ήδη ενεργό)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt and ip_pkt.src in self.blocked:
            return  # αγνόησε — η drop-rule το χειρίζεται

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # εγκατάσταση flow ώστε να μη ξαναέρθει στον controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    # ------------------------------------------------------------------ #
    #  Παρακολούθηση datapaths (για polling)
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER and datapath.id in self.datapaths:
            del self.datapaths[datapath.id]

    def _monitor(self):
        """Κάθε POLL_INTERVAL ζητάει flow-stats από όλα τα switches."""
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(config.POLL_INTERVAL)
            self._expire_blocks()

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # ------------------------------------------------------------------ #
    #  Λήψη flow-stats -> feature extraction -> ML -> mitigation
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        # συγκέντρωση ροών ανά πηγή IP
        per_src = {}  # src_ip -> list of (packets, bytes, duration)
        for stat in ev.msg.body:
            if stat.priority == 0:
                continue  # αγνόησε το table-miss
            src_ip = stat.match.get("ipv4_src")
            if src_ip is None:
                continue
            dur = stat.duration_sec + stat.duration_nsec / 1e9
            per_src.setdefault(src_ip, []).append(
                (stat.packet_count, stat.byte_count, dur))

        for src_ip, flows in per_src.items():
            feats = self._aggregate_features(flows)
            verdict = self._classify(feats)
            if verdict == "Attack" and src_ip not in self.blocked:
                self.logger.warning(
                    "[DETECT] ΕΠΙΘΕΣΗ από %s | flows=%d pkts=%d -> ΜΠΛΟΚΑΡΙΣΜΑ",
                    src_ip, int(feats[0]), int(feats[1]))
                self._mitigate(datapath, src_ip)

    def _aggregate_features(self, flows):
        """Υπολογίζει τα config.LIVE_FEATURE_COLUMNS από τις ροές μιας πηγής."""
        flow_count = len(flows)
        total_packets = sum(f[0] for f in flows)
        total_bytes = sum(f[1] for f in flows)
        durations = [f[2] for f in flows]
        avg_packets = total_packets / flow_count if flow_count else 0
        avg_bytes = total_bytes / flow_count if flow_count else 0
        avg_duration = sum(durations) / flow_count if flow_count else 0
        avg_pkt_size = total_bytes / total_packets if total_packets else 0
        short_flows = sum(1 for f in flows if f[0] <= config.SHORT_FLOW_PKT_THRESHOLD)
        short_ratio = short_flows / flow_count if flow_count else 0
        return np.array([flow_count, total_packets, total_bytes, avg_packets,
                         avg_bytes, avg_duration, avg_pkt_size, short_ratio],
                        dtype=float)

    def _classify(self, feats):
        """Επιστρέφει 'Attack' ή 'Normal'. Fallback σε κανόνα αν δεν υπάρχει μοντέλο."""
        if self.model is not None and self.scaler is not None:
            X = self.scaler.transform(feats.reshape(1, -1))
            pred = self.model.predict(X)[0]
            return "Attack" if int(pred) == 1 else "Normal"
        # fallback heuristic (χωρίς ML): πολλές σύντομες ροές
        flow_count, short_ratio = feats[0], feats[7]
        if flow_count > config.ATTACK_FLOW_THRESHOLD and short_ratio > 0.6:
            return "Attack"
        return "Normal"

    # ------------------------------------------------------------------ #
    #  MITIGATION — εγκατάσταση drop-rule για την κακόβουλη πηγή
    # ------------------------------------------------------------------ #
    def _mitigate(self, datapath, src_ip, block_seconds=60):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        # κενές actions = DROP. Υψηλή προτεραιότητα ώστε να υπερισχύει.
        self.add_flow(datapath, priority=100, match=match, actions=[],
                      hard_timeout=block_seconds)
        self.blocked[src_ip] = time.time()
        self.logger.info("[MITIGATE] Εγκαταστάθηκε DROP-rule για %s (%ds)",
                         src_ip, block_seconds)

    def _expire_blocks(self, block_seconds=60):
        """Καθαρίζει τη λίστα μπλοκαρισμένων όταν λήξει ο χρόνος."""
        now = time.time()
        expired = [ip for ip, t in self.blocked.items() if now - t > block_seconds]
        for ip in expired:
            del self.blocked[ip]
            self.logger.info("[MITIGATE] Άρση μπλοκαρίσματος για %s", ip)
