#!/usr/bin/env python3
"""append_experiment_summary.py — Εγγραφή ενός packet-level run στο ενιαίο CSV.

Το results/live/experiment_summary.csv περιείχε μόνο σενάρια api_telemetry, οπότε το
πραγματικό packet-level πείραμα (Mininet + OVS) δεν εμφανιζόταν πουθενά στο ίδιο,
μηχαναγνώσιμο πίνακα προέλευσης. Το script διαβάζει το summary.json ενός run και
προσθέτει (ή αντικαθιστά, αν ξανατρέξει το ίδιο run_id) την αντίστοιχη γραμμή.

Χρήση:
    python3 scripts/append_experiment_summary.py results/live/mininet_run_YYYYmmdd_HHMMSS
"""
import csv
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE, "results", "live", "experiment_summary.csv")


def row_from_summary(summary):
    ev  = summary.get("last_cycle_evidence") or {}
    lat = ev.get("latencies_s") or {}
    cfg = summary.get("config") or {}

    # Καθυστέρηση ανίχνευσης = από την εκκίνηση της επίθεσης έως την πρώτη απόφαση
    # "Attack" του μοντέλου. Μετρημένη με monotonic ρολόι μέσα στο ίδιο run, όχι
    # εκτιμώμενη. Όπου λείπει, γράφεται ρητά not_measured.
    def val(x):
        return x if x is not None else "not_measured"

    return {
        "scenario":              "ddos_syn_flood",
        "experiment_type":       "packet_level",
        "run_id":                summary.get("run_id"),
        "code_commit":           summary.get("code_commit", "unknown"),
        "duration_s":            ev.get("attack_duration_s"),
        "detection_latency_s":   val(lat.get("first_verdict_s")),
        "rule_install_latency_s": val(lat.get("rule_installed_s")),
        "first_dropped_packet_s": val(lat.get("first_dropped_packet_s")),
        "dropped_packets":       ev.get("ovs_drop_rule_total_packets"),
        "drop_rule_leases":      ev.get("drop_rule_leases"),
        "drop_rule_renewals":    ev.get("drop_rule_renewals"),
        "block_ttl_s":           cfg.get("block_ttl_s"),
        # Ρυθμός-κατώφλι πάνω από τον οποίο ανανεώνεται το lease. Ένα εξωπραγματικά
        # υψηλό κατώφλι απενεργοποιεί την ανανέωση και δίνει το baseline «χωρίς renewal».
        "renewal_enabled":       (cfg.get("attack_ongoing_pps", 50) or 0) < 100000,
        "mitigation_coverage_pct": val(ev.get("mitigation_coverage_pct")),
        "mitigation_coverage_after_detection_pct":
            val(ev.get("mitigation_coverage_after_detection_pct")),
        "attacker_blocked":      ev.get("controller_flow_table_blocked"),
        "false_positives":       1 if ev.get("false_positive_on_legit") else 0,
        "detections":            summary.get("total_detections"),
        "success":               bool(ev.get("controller_flow_table_blocked")
                                      and not ev.get("false_positive_on_legit")),
    }


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run_dir = sys.argv[1]
    with open(os.path.join(run_dir, "summary.json"), encoding="utf-8") as f:
        summary = json.load(f)

    new_row = row_from_summary(summary)

    rows, fields = [], []
    if os.path.exists(CSV_PATH):
        with open(CSV_PATH, newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            fields = list(r.fieldnames or [])
            rows = [dict(x) for x in r]

    # Ένωση των στηλών: οι παλιές γραμμές api_telemetry μένουν ως έχουν, με κενά
    # στις νέες στήλες που αφορούν μόνο το packet-level πείραμα.
    for k in new_row:
        if k not in fields:
            fields.append(k)

    rows = [x for x in rows if x.get("run_id") != new_row["run_id"]]
    rows.append(new_row)

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for x in rows:
            w.writerow({k: x.get(k, "") for k in fields})

    print(f"[OK] Γράφτηκε στο {CSV_PATH}: run_id={new_row['run_id']}")
    print(f"     dropped_packets={new_row['dropped_packets']} | "
          f"coverage={new_row['mitigation_coverage_pct']}% | "
          f"leases={new_row['drop_rule_leases']} (renewals={new_row['drop_rule_renewals']})")


if __name__ == "__main__":
    main()
