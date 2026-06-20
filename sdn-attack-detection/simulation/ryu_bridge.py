#!/usr/bin/env python3
"""
ryu_bridge.py — Ryu/os-ken app που γεφυρώνει το Mininet switch με τον Flask controller.

Ρόλοι:
  1. OpenFlow learning switch (L2 forwarding)
  2. Telemetry collector: κάθε POLL_INTERVAL δευτερόλεπτα αθροίζει κίνηση ανά src IP
     και στέλνει στον Flask controller (POST /telemetry)
  3. Enforcer: εγκαθιστά OpenFlow DROP rules για IPs που ο Flask βαθμολογεί ως Attack

Εκτέλεση (αυτόματα από mininet_live.py):
  ryu-manager simulation/ryu_bridge.py --ofp-tcp-listen-port 6653
  ή
  os-ken-manager simulation/ryu_bridge.py --ofp-tcp-listen-port 6653
"""

import os
import time
import requests

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import (
        CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls,
    )
    from ryu.lib import hub
    from ryu.lib.packet import packet, ethernet, ether_types, ipv4
    from ryu.ofproto import ofproto_v1_3
except ImportError:
    from os_ken.base import app_manager
    from os_ken.controller import ofp_event
    from os_ken.controller.handler import (
        CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls,
    )
    from os_ken.lib import hub
    from os_ken.lib.packet import packet, ethernet, ether_types, ipv4
    from os_ken.ofproto import ofproto_v1_3


CONTROLLER_URL  = os.environ.get("CONTROLLER_URL",  "http://controller:9000")
SWITCH_API_KEY  = os.environ.get("SWITCH_API_KEY",  "sdn-secret-2024")
POLL_INTERVAL   = int(os.environ.get("POLL_INTERVAL", "5"))
SHORT_FLOW_PKT_THRESHOLD = 3   # ροή με <= τόσα packets θεωρείται "σύντομη" (flood)

_AUTH_HEADERS = {"X-Switch-Token": SWITCH_API_KEY, "Content-Type": "application/json"}


class RyuBridge(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port  = {}   # {dpid: {mac: port}}
        self.datapaths    = {}   # {dpid: datapath}
        self.blocked_ips  = set()
        # ανά παράθυρο: src_ip -> {dsts: set, pkts: int, bytes: int}
        self._window      = {}
        self._poll_thread = hub.spawn(self._poll_loop)

    # ------------------------------------------------------------------ #
    #  Switch setup
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp
        # table-miss → PACKET_IN
        self._add_flow(dp, 0, parser.OFPMatch(),
                       [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self.logger.info("[BRIDGE] Switch %s συνδέθηκε.", dp.id)
        try:
            requests.post(f"{CONTROLLER_URL}/register",
                          json={"node_id": f"s{dp.id}", "type": "switch", "ip": "0.0.0.0"},
                          timeout=3)
        except Exception:
            pass

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def _add_flow(self, dp, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout))

    # ------------------------------------------------------------------ #
    #  PACKET_IN: L2 learning + IP stats tracking
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp  = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # --- IP stats για telemetry ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            if src_ip in self.blocked_ips:
                return  # η DROP rule το χειρίζεται στο switch
            rec = self._window.setdefault(src_ip,
                                          {"dsts": set(), "pkts": 0, "bytes": 0})
            rec["dsts"].add(ip_pkt.dst)
            rec["pkts"]  += 1
            rec["bytes"] += len(msg.data)

        # --- L2 forwarding ---
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=eth.dst, eth_src=eth.src)
            self._add_flow(dp, 1, match, actions, idle_timeout=20)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

    # ------------------------------------------------------------------ #
    #  Polling loop
    # ------------------------------------------------------------------ #
    def _poll_loop(self):
        hub.sleep(10)  # αναμονή για τοπολογία
        while True:
            hub.sleep(POLL_INTERVAL)
            self._flush_window()

    def _flush_window(self):
        snapshot, self._window = self._window, {}
        for src_ip, rec in snapshot.items():
            flow_count = max(1, len(rec["dsts"]))
            total_pkts = rec["pkts"]
            total_bytes = rec["bytes"]
            if total_pkts == 0:
                continue

            avg_pkts_per_flow  = total_pkts  / flow_count
            avg_bytes_per_flow = total_bytes / flow_count
            avg_duration       = POLL_INTERVAL / flow_count   # proxy
            avg_pkt_size       = total_bytes / total_pkts
            short_flows        = sum(1 for _ in rec["dsts"]
                                     if avg_pkts_per_flow <= SHORT_FLOW_PKT_THRESHOLD)
            short_ratio        = short_flows / flow_count

            # κατασκευή flows list για το Flask /telemetry API
            flows = [[max(1, round(avg_pkts_per_flow)),
                      max(1, round(avg_bytes_per_flow)),
                      avg_duration]
                     for _ in rec["dsts"]]
            self._send_telemetry(src_ip, flows)

    def _send_telemetry(self, src_ip, flows):
        try:
            r = requests.post(
                f"{CONTROLLER_URL}/telemetry",
                json={"src": src_ip, "dst": "network", "flows": flows},
                headers=_AUTH_HEADERS,
                timeout=3,
            )
            action = r.json().get("action", "FORWARD")
            if action == "DROP" and src_ip not in self.blocked_ips:
                self.blocked_ips.add(src_ip)
                for dp in self.datapaths.values():
                    self._install_drop(dp, src_ip)
                self.logger.warning("[BRIDGE] %s → DROP (60s)", src_ip)
            elif action == "FORWARD" and src_ip in self.blocked_ips:
                # block λήξε στον controller → αφαίρεσε από local set
                self.blocked_ips.discard(src_ip)
        except Exception as e:
            self.logger.debug("[BRIDGE] telemetry error %s: %s", src_ip, e)

    def _install_drop(self, dp, src_ip, ttl=60):
        parser = dp.ofproto_parser
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self._add_flow(dp, 100, match, [], hard_timeout=ttl)
