#!/usr/bin/env python3
"""
aggregate_live_results.py — Ενοποίηση των αποτελεσμάτων των ζωντανών σεναρίων.

Κάθε σενάριο γράφει το δικό του αρχείο μετρικών με ΔΙΑΦΟΡΕΤΙΚΟ σχήμα στηλών.
Ο προηγούμενος aggregator χρησιμοποιούσε τα πεδία του πρώτου μόνο αρχείου, με
αποτέλεσμα γραμμές με λάθος πλήθος πεδίων (μη αναγνώσιμο CSV) και σύνοψη που
περιείχε ένα μόνο σενάριο.

Εδώ όλα τα σενάρια κανονικοποιούνται σε ΕΝΙΑΙΟ σχήμα και οι λίστες/λεξικά
σειριοποιούνται με json.dumps, ώστε τα αρχεία να διαβάζονται από οποιονδήποτε
τυπικό CSV parser (π.χ. pandas.read_csv).

Χρήση:  python3 simulation/aggregate_live_results.py
Έξοδοι: results/live/experiment_summary.csv
        results/live/mitigation_latency.csv
"""
import csv
import glob
import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
LIVE = BASE / "results" / "live"

# Ενιαίο σχήμα για όλα τα σενάρια. Ό,τι λείπει από ένα σενάριο μένει κενό.
SCHEMA = [
    "scenario",             # όνομα σεναρίου
    "experiment_type",      # packet_level | api_telemetry
    "duration_s",
    "detection_latency_s",  # κενό αν δεν υπήρξε ανίχνευση
    "true_positives",
    "false_positives",
    "true_negatives",
    "false_negatives",
    "attacker_blocked",
    "blocked_ips",          # JSON-encoded λίστα
    "detections",
    "success",              # όπως το δηλώνει το ίδιο το σενάριο
]

# Μόνο η πλημμύρα SYN εκτελείται σε επίπεδο πακέτου (Mininet/OVS).
PACKET_LEVEL = {"ddos_syn_flood"}


def norm(v):
    """Κανονικοποίηση τιμής για ασφαλή εγγραφή σε CSV."""
    if v is None:
        return ""
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, str) and v.strip().lower() in ("none", "null"):
        return ""
    return v


def load_records():
    """Διαβάζει τα per-scenario αρχεία. Προτεραιότητα στο JSON (κανονική πηγή)."""
    records = {}

    for f in sorted(LIVE.glob("*_metrics.json")):
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
        records[d.get("scenario", f.stem)] = d

    # Το σενάριο DDoS γράφει μόνο CSV.
    for f in sorted(LIVE.glob("*_metrics.csv")):
        with open(f, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                name = row.get("scenario")
                if name and name not in records:
                    records[name] = row

    return records


def to_schema(name, d):
    return {
        "scenario":            name,
        "experiment_type":     "packet_level" if name in PACKET_LEVEL else "api_telemetry",
        "duration_s":          norm(d.get("duration_s", d.get("duration"))),
        "detection_latency_s": norm(d.get("detection_latency_s")),
        "true_positives":      norm(d.get("true_positives")),
        "false_positives":     norm(d.get("false_positives")),
        "true_negatives":      norm(d.get("true_negatives")),
        "false_negatives":     norm(d.get("false_negatives")),
        "attacker_blocked":    norm(d.get("attacker_blocked")),
        "blocked_ips":         norm(d.get("blocked_ips")),
        "detections":          norm(d.get("detections", d.get("total_detections"))),
        "success":             norm(d.get("success")),
    }


def main():
    LIVE.mkdir(parents=True, exist_ok=True)
    records = load_records()
    if not records:
        print("[!] Δεν βρέθηκαν αρχεία μετρικών στο results/live/")
        return

    rows = [to_schema(n, d) for n, d in sorted(records.items())]

    summary = LIVE / "experiment_summary.csv"
    with open(summary, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SCHEMA)
        w.writeheader()
        w.writerows(rows)
    print(f"[OK] {summary.relative_to(BASE)} — {len(rows)} σενάρια")

    # Καθυστέρηση αντιμετώπισης: μόνο όσα σενάρια είχαν ανίχνευση.
    lat = LIVE / "mitigation_latency.csv"
    fields = ["scenario", "experiment_type", "detection_latency_s",
              "attacker_blocked", "false_positives"]
    with open(lat, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        n = 0
        for r in rows:
            if r["detection_latency_s"] != "":
                w.writerow({k: r[k] for k in fields})
                n += 1
    print(f"[OK] {lat.relative_to(BASE)} — {n} σενάρια με ανίχνευση")


if __name__ == "__main__":
    main()
