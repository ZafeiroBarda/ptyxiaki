#!/usr/bin/env python3
"""
test_flow_telemetry.py — Έλεγχος του parser per-flow τηλεμετρίας (4.10).

Επαληθεύει ότι η εξαγωγή πραγματικών ροών από την έξοδο του ovs-ofctl
dump-flows δίνει σωστά per-source flow lists με flow_count > 1, ώστε τα
aggregate features (flow_count, short_flow_ratio, avg_duration) να έχουν νόημα.
Δεν απαιτεί Mininet/OVS — τροφοδοτείται με ρεαλιστική δειγματική έξοδο.

Run: pytest tests/test_flow_telemetry.py -v
"""
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "simulation"))

import flow_telemetry as ft

# Ρεαλιστική έξοδος `ovs-ofctl dump-flows s1`: ο επιτιθέμενος 10.0.0.6 έχει
# πολλές σύντομες ροές (SYN flood) προς 10.0.0.5, ενώ οι νόμιμοι hosts λίγες.
SAMPLE = """ cookie=0x0, duration=30.5s, table=0, n_packets=0, n_bytes=0, priority=0 actions=NORMAL
 cookie=0x0, duration=12.1s, table=0, n_packets=95, n_bytes=5700, priority=10,ip,nw_src=10.0.0.6,nw_dst=10.0.0.5 actions=NORMAL
 cookie=0x0, duration=12.0s, table=0, n_packets=88, n_bytes=5280, priority=10,ip,nw_src=10.0.0.6,nw_dst=10.0.0.4 actions=NORMAL
 cookie=0x0, duration=11.8s, table=0, n_packets=200, n_bytes=280000, priority=10,ip,nw_src=10.0.0.1,nw_dst=10.0.0.5 actions=NORMAL
 cookie=0x0, duration=10.0s, table=0, n_packets=20, n_bytes=1600, priority=10,arp actions=NORMAL
"""


def test_parse_extracts_only_ip_flows():
    flows = ft.parse_ofctl_flows(SAMPLE)
    # 3 IP ροές με nw_src/nw_dst· ο NORMAL default και ο ARP κανόνας αγνοούνται.
    assert len(flows) == 3
    assert all("nw_src" in f and "nw_dst" in f for f in flows)


def test_parse_fields():
    flows = ft.parse_ofctl_flows(SAMPLE)
    f = next(x for x in flows if x["nw_dst"] == "10.0.0.5" and x["nw_src"] == "10.0.0.6")
    assert f["packets"] == 95
    assert f["bytes"] == 5700
    assert abs(f["duration"] - 12.1) < 1e-6


def test_deltas_produce_multiflow_per_source():
    curr = ft.parse_ofctl_flows(SAMPLE)
    per_source, _ = ft.window_deltas(curr, prev_by_key={})
    # Ο 10.0.0.6 έχει ΔΥΟ ροές (προς .5 και .4) -> flow_count = 2, όχι 1.
    assert len(per_source["10.0.0.6"]) == 2
    assert len(per_source["10.0.0.1"]) == 1


def test_deltas_subtract_previous_window():
    curr = ft.parse_ofctl_flows(SAMPLE)
    prev = {("10.0.0.6", "10.0.0.5"): {"packets": 90, "bytes": 5400}}
    per_source, new_prev = ft.window_deltas(curr, prev)
    # Η ροή .6->.5 έστειλε 5 νέα πακέτα (95-90) στο παράθυρο.
    d = [t for t in per_source["10.0.0.6"] if t[0] == 5]
    assert d, "delta πακέτων δεν υπολογίστηκε σωστά"
    assert new_prev[("10.0.0.6", "10.0.0.5")]["packets"] == 95


def test_deltas_skip_idle_flows():
    curr = ft.parse_ofctl_flows(SAMPLE)
    # Αν όλα τα πακέτα έχουν ήδη μετρηθεί, καμία ροή δεν προωθείται.
    prev = {(f["nw_src"], f["nw_dst"]): {"packets": f["packets"], "bytes": f["bytes"]}
            for f in curr}
    per_source, _ = ft.window_deltas(curr, prev)
    assert per_source == {}


def test_flowstats_to_telemetry_groups_by_source():
    stats = [
        {"nw_src": "10.0.0.6", "packets": 95, "bytes": 5700, "duration": 12.1},
        {"nw_src": "10.0.0.6", "packets": 88, "bytes": 5280, "duration": 12.0},
        {"nw_src": "10.0.0.1", "packets": 200, "bytes": 280000, "duration": 11.8},
    ]
    per_source = ft.flowstats_to_telemetry(stats)
    assert len(per_source["10.0.0.6"]) == 2
    assert per_source["10.0.0.6"][0] == (95, 5700, 12.1)


def test_empty_input():
    assert ft.parse_ofctl_flows("") == []
    assert ft.window_deltas([], {}) == ({}, {})
