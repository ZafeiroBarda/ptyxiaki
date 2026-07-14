#!/usr/bin/env python3
"""extract_run_artifacts.py — Ανακτά τα artifacts ενός packet-level run από το log.

Ο mininet container δεν έχει volume mount και τερματίζει μόλις τελειώσει το σενάριο,
οπότε το summary.json και ο ακατέργαστος πίνακας ροών εκπέμπονται στο stdout μέσα σε
δείκτες [ARTIFACT]. Το script τα ξαναγράφει στον host, ώστε η αλυσίδα
run -> raw evidence -> summary να είναι πλήρως αυτοματοποιημένη.

Χρήση:
    docker logs sdn_mininet > /tmp/run.log
    python3 scripts/extract_run_artifacts.py /tmp/run.log
    -> τυπώνει τον φάκελο του run (results/live/mininet_run_<ts>)
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BEGIN = re.compile(r"^\[ARTIFACT\] (\S+) <<<\s*$")
END = "[ARTIFACT] >>>"


def parse_artifacts(log_text):
    artifacts, name, buf = {}, None, []
    for line in log_text.splitlines():
        stripped = line.rstrip("\r")
        if name is None:
            m = BEGIN.match(stripped)
            if m:
                name, buf = m.group(1), []
            continue
        if stripped == END:
            artifacts[name] = "\n".join(buf)
            name = None
            continue
        buf.append(stripped)
    return artifacts


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    log_text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    artifacts = parse_artifacts(log_text)

    if "summary.json" not in artifacts:
        sys.exit("Δεν βρέθηκε summary.json στο log. Το run μάλλον δεν ολοκληρώθηκε.")

    summary = json.loads(artifacts["summary.json"])
    run_dir = os.path.join(BASE, "results", "live", summary["run_id"])
    os.makedirs(run_dir, exist_ok=True)

    with open(os.path.join(run_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    if "ovs_dump_flows.txt" in artifacts:
        with open(os.path.join(run_dir, "ovs_dump_flows.txt"), "w", encoding="utf-8") as f:
            f.write(artifacts["ovs_dump_flows.txt"])
    with open(os.path.join(run_dir, "mininet_full.log"), "w", encoding="utf-8") as f:
        f.write(log_text)

    print(os.path.relpath(run_dir, BASE))


if __name__ == "__main__":
    main()
