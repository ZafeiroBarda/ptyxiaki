#!/usr/bin/env python3
"""
flow_telemetry.py — Εξαγωγή τηλεμετρίας ανά ΡΟΗ (flow) από τα στατιστικά του
πίνακα ροών του Open vSwitch.

ΓΙΑΤΙ: παλαιότερα η τηλεμετρία βασιζόταν στη διαφορά ΕΝΟΣ μετρητή θύρας
(ovs-ofctl dump-ports) ανά host και παράθυρο, οπότε κάθε πηγή έστελνε μία μόνο
συγκεντρωτική "ροή" (flow_count = 1). Έτσι τα χαρακτηριστικά flow_count,
avg_duration και short_flow_ratio ήταν εκφυλισμένα.

Εδώ διαβάζονται τα per-flow στατιστικά του πίνακα ροών (ovs-ofctl dump-flows),
όπου κάθε καταχώρηση αντιστοιχεί σε ένα ζεύγος διευθύνσεων (nw_src, nw_dst) και
φέρει τους δικούς της μετρητές n_packets / n_bytes / duration. Ομαδοποιώντας
ανά διεύθυνση προέλευσης προκύπτει ΠΡΑΓΜΑΤΙΚΗ λίστα πολλαπλών ροών ανά πηγή, με
νόημα για όλα τα aggregate features.

Οι συναρτήσεις είναι καθαρές (pure) και δοκιμάζονται χωρίς Mininet/OVS —
βλ. tests/test_flow_telemetry.py.
"""
import re
from collections import defaultdict

# Γραμμή του `ovs-ofctl dump-flows` που ταιριάζει σε IPv4 ροή με nw_src/nw_dst.
_DUR   = re.compile(r"duration=([\d.]+)s")
_NPK   = re.compile(r"n_packets=(\d+)")
_NBY   = re.compile(r"n_bytes=(\d+)")
_SRC   = re.compile(r"nw_src=([\d.]+)")
_DST   = re.compile(r"nw_dst=([\d.]+)")


def parse_ofctl_flows(text):
    """Επιστρέφει λίστα από dicts, μία ανά ροή IP με nw_src/nw_dst.

    Κάθε dict: {"nw_src", "nw_dst", "packets", "bytes", "duration"}.
    Γραμμές χωρίς nw_src (π.χ. ο προεπιλεγμένος κανόνας NORMAL, LLDP) αγνοούνται.
    """
    flows = []
    for line in text.splitlines():
        src = _SRC.search(line)
        dst = _DST.search(line)
        if not src or not dst:
            continue
        npk = _NPK.search(line)
        nby = _NBY.search(line)
        dur = _DUR.search(line)
        flows.append({
            "nw_src":   src.group(1),
            "nw_dst":   dst.group(1),
            "packets":  int(npk.group(1)) if npk else 0,
            "bytes":    int(nby.group(1)) if nby else 0,
            "duration": float(dur.group(1)) if dur else 0.0,
        })
    return flows


def window_deltas(curr_flows, prev_by_key):
    """Υπολογίζει τη ΔΙΑΦΟΡΑ μετρητών ανά ροή μεταξύ δύο δειγματοληψιών.

    curr_flows:   έξοδος του parse_ofctl_flows στην τρέχουσα στιγμή.
    prev_by_key:  dict {(nw_src, nw_dst): {"packets", "bytes"}} της προηγούμενης.

    Επιστρέφει (per_source, new_prev), όπου:
      per_source = {nw_src: [(dpackets, dbytes, duration), ...]}  (μόνο ροές με
                   dpackets > 0 στο τρέχον παράθυρο)
      new_prev   = ενημερωμένο prev_by_key για την επόμενη κλήση.
    """
    per_source = defaultdict(list)
    new_prev = {}
    for f in curr_flows:
        key = (f["nw_src"], f["nw_dst"])
        prev = prev_by_key.get(key, {"packets": 0, "bytes": 0})
        dpk = max(0, f["packets"] - prev["packets"])
        dby = max(0, f["bytes"] - prev["bytes"])
        new_prev[key] = {"packets": f["packets"], "bytes": f["bytes"]}
        if dpk > 0:
            per_source[f["nw_src"]].append((dpk, dby, f["duration"]))
    return dict(per_source), new_prev


def flowstats_to_telemetry(flow_stats):
    """Μετατρέπει per-flow στατιστικά (από OpenFlow OFPFlowStatsReply) σε λίστες
    ανά πηγή, κατάλληλες για το /telemetry API.

    flow_stats: iterable από dicts {"nw_src", "packets", "bytes", "duration"}.
    Επιστρέφει {nw_src: [(packets, bytes, duration), ...]}.
    """
    per_source = defaultdict(list)
    for s in flow_stats:
        src = s.get("nw_src")
        if not src:
            continue
        per_source[src].append((int(s.get("packets", 0)),
                                int(s.get("bytes", 0)),
                                float(s.get("duration", 0.0))))
    return dict(per_source)
