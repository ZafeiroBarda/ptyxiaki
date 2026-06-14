#!/usr/bin/env python3
"""
collect_flow_stats.py  (ΜΕΘΟΔΟΣ A — συλλογή δικού σου dataset)
-------------------------------------------------------------
Ryu app που δειγματοληπτεί flow-stats και ΓΡΑΦΕΙ aggregate χαρακτηριστικά
ανά πηγή IP σε CSV. Έτσι χτίζεις το δικό σου SDN dataset από την προσομοίωση.

Η ετικέτα (Label) δίνεται μέσω μεταβλητής περιβάλλοντος FLOW_LABEL:
    # Πρώτα τρέξε νόμιμη κίνηση και κατέγραψέ την ως Normal:
    FLOW_LABEL=Normal ryu-manager simulation/collect_flow_stats.py
    # (σε άλλο τερματικό) sudo python3 simulation/traffic_normal.py

    # Μετά τρέξε επιθέσεις και κατέγραψέ τες ως Attack:
    FLOW_LABEL=Attack ryu-manager simulation/collect_flow_stats.py
    # (σε άλλο τερματικό) sudo python3 simulation/traffic_attack.py

Το CSV (data/collected_live_flows.csv) μετά τροφοδοτεί το:
    python3 controller/train_live_model.py --collected
"""

import os
import csv
import sys
import numpy as np

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config


class FlowStatsCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.label = os.environ.get("FLOW_LABEL", "Unknown")
        self.csv_path = os.path.join(config.DATA_DIR, "collected_live_flows.csv")
        os.makedirs(config.DATA_DIR, exist_ok=True)
        self._init_csv()
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("[COLLECT] Καταγραφή με ετικέτα '%s' -> %s",
                         self.label, self.csv_path)

    def _init_csv(self):
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", newline="") as f:
                csv.writer(f).writerow(config.LIVE_FEATURE_COLUMNS + ["Label"])

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            del self.datapaths[dp.id]

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
            hub.sleep(config.POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply(self, ev):
        per_src = {}
        for stat in ev.msg.body:
            if stat.priority == 0:
                continue
            src_ip = stat.match.get("ipv4_src")
            if src_ip is None:
                continue
            dur = stat.duration_sec + stat.duration_nsec / 1e9
            per_src.setdefault(src_ip, []).append(
                (stat.packet_count, stat.byte_count, dur))

        rows = []
        for src_ip, flows in per_src.items():
            fc = len(flows)
            tp = sum(f[0] for f in flows)
            tb = sum(f[1] for f in flows)
            durs = [f[2] for f in flows]
            avg_p = tp / fc if fc else 0
            avg_b = tb / fc if fc else 0
            avg_d = sum(durs) / fc if fc else 0
            avg_ps = tb / tp if tp else 0
            short = sum(1 for f in flows if f[0] <= config.SHORT_FLOW_PKT_THRESHOLD)
            sr = short / fc if fc else 0
            rows.append([fc, tp, tb, avg_p, avg_b, avg_d, avg_ps, sr, self.label])

        if rows:
            with open(self.csv_path, "a", newline="") as f:
                csv.writer(f).writerows(rows)
            self.logger.info("[COLLECT] +%d γραμμές (ετικέτα '%s')", len(rows), self.label)
