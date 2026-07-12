#!/usr/bin/env python3
"""
switch.py  (Data Plane — application-level SDN overlay)
------------------------------------------------------
Κόμβος Data Plane που υλοποιεί προώθηση πακέτων σε επίπεδο εφαρμογής
(Application-level SDN Overlay) με UDP sockets, σύμφωνα με την αρχιτεκτονική
της διπλωματικής.

Ρόλος:
  - Λαμβάνει "πακέτα" (UDP datagrams) από hosts.
  - Συγκεντρώνει τοπικά στατιστικά ροών ανά πηγή IP.
  - Στέλνει περιοδικά τηλεμετρία στον Controller (REST) και εφαρμόζει την
    ενέργεια που επιστρέφει (FORWARD ή DROP).

Η κλάση Switch μπορεί να χρησιμοποιηθεί:
  (α) ως πραγματικός UDP κόμβος (μέθοδος run_udp), ή
  (β) προγραμματιστικά μέσω της μεθόδου ingest() (για προσομοίωση/tests).
"""

import os
import sys
import time
import socket
import threading
import requests

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


SWITCH_API_KEY = os.environ.get("SWITCH_API_KEY", "sdn-secret-2024")


class Switch:
    def __init__(self, switch_id, controller_url="http://127.0.0.1:9000",
                 poll_interval=3):
        self.switch_id = switch_id
        self.controller_url = controller_url.rstrip("/")
        self.poll_interval = poll_interval
        self._auth_headers = {"X-Switch-Token": SWITCH_API_KEY}
        # στατιστικά ανά πηγή IP: src -> {dst, flows:[(pkts,bytes,dur)...], start}
        self.stats = {}
        self.blocked = set()        # πηγές με κανόνα DROP
        self.lock = threading.Lock()
        self._running = False

    # ---------------- εγγραφή στον controller ----------------
    def register(self):
        try:
            requests.post(f"{self.controller_url}/register",
                          json={"node_id": self.switch_id, "type": "switch",
                                "ip": "0.0.0.0"},
                          headers=self._auth_headers, timeout=3)
        except Exception as e:
            print(f"[SWITCH {self.switch_id}] Αποτυχία εγγραφής: {e}")

    # ---------------- λήψη "πακέτου" (προγραμματιστικά) ----------------
    def ingest(self, src, dst, size_bytes):
        """Καταγράφει ένα πακέτο από src->dst μεγέθους size_bytes.

        Τα στατιστικά κρατούνται ανά (src) και ανά προορισμό (dst), ώστε κάθε
        ξεχωριστός προορισμός να αντιστοιχεί σε μία ροή — έτσι τα aggregate
        features (flow_count, short_flow_ratio κ.λπ.) έχουν φυσική σημασία.
        """
        with self.lock:
            if src in self.blocked:
                return "DROP"   # ο κανόνας DROP εφαρμόζεται στο Data Plane
            rec = self.stats.setdefault(
                src, {"dests": {}, "pkts": 0, "bytes": 0, "start": time.time()})
            rec["pkts"] += 1
            rec["bytes"] += size_bytes
            d = rec["dests"].setdefault(dst, {"pkts": 0, "bytes": 0})
            d["pkts"] += 1
            d["bytes"] += size_bytes
        return "FORWARD"

    # ---------------- αποστολή τηλεμετρίας ----------------
    def _build_flows(self, rec):
        """Μία ροή (packets, bytes, duration) ανά προορισμό της πηγής."""
        n = max(1, len(rec["dests"]))
        dur = max(0.05, time.time() - rec["start"])
        return [(d["pkts"], d["bytes"], dur / n) for d in rec["dests"].values()]

    def sync_flow_table(self):
        """Ευθυγραμμίζει τους τοπικούς κανόνες DROP με τον πίνακα ροών του ελεγκτή.

        ΓΙΑΤΙ ΧΡΕΙΑΖΕΤΑΙ: μόλις μια πηγή μπει στο self.blocked, το ingest()
        απορρίπτει τα πακέτα της, οπότε δεν συγκεντρώνονται στατιστικά και δεν
        στέλνεται ποτέ νέα τηλεμετρία γι' αυτήν. Χωρίς ανεξάρτητο μηχανισμό, ο
        αποκλεισμός δεν θα λάμβανε ποτέ απάντηση FORWARD και θα παρέμενε τοπικά
        για πάντα, ακόμη και αφού ο ελεγκτής άρει τον κανόνα (π.χ. μέσω
        /unblock ή λήξης).

        Σωστή σημασιολογία SDN: το επίπεδο δεδομένων αντικατοπτρίζει το επίπεδο
        ελέγχου. Ο πίνακας ροών του ελεγκτή είναι η μοναδική πηγή αλήθειας.
        """
        try:
            r = requests.get(f"{self.controller_url}/flow_table",
                             headers=self._auth_headers, timeout=3)
            table = r.json()
            if not isinstance(table, dict):
                return
            active = {ip for ip, rule in table.items()
                      if (rule.get("action", "DROP") if isinstance(rule, dict) else "DROP") == "DROP"}
            with self.lock:
                released = self.blocked - active
                self.blocked = active
            for ip in released:
                print(f"[SWITCH {self.switch_id}] Άρση αποκλεισμού: {ip}")
        except Exception as e:
            print(f"[SWITCH {self.switch_id}] Σφάλμα συγχρονισμού flow_table: {e}")

    def push_telemetry(self):
        """Στέλνει τηλεμετρία για κάθε πηγή και εφαρμόζει την απόφαση."""
        # Πρώτα ευθυγράμμιση με τον ελεγκτή: αν ένας κανόνας DROP έχει αρθεί,
        # η πηγή ξαναρχίζει να προωθείται και η τηλεμετρία της επανέρχεται.
        self.sync_flow_table()

        with self.lock:
            snapshot = dict(self.stats)
            self.stats.clear()
        for src, rec in snapshot.items():
            flows = self._build_flows(rec)
            dst = next(iter(rec["dests"]), "?") if rec["dests"] else "?"
            try:
                r = requests.post(f"{self.controller_url}/telemetry",
                                  json={"src": src, "dst": dst, "flows": flows},
                                  headers=self._auth_headers, timeout=3)
                action = r.json().get("action", "FORWARD")
                with self.lock:
                    if action == "DROP":
                        self.blocked.add(src)
                    else:
                        self.blocked.discard(src)
            except Exception as e:
                print(f"[SWITCH {self.switch_id}] Σφάλμα τηλεμετρίας: {e}")

    # ---------------- βρόχος polling ----------------
    def start_polling(self):
        self._running = True

        def loop():
            while self._running:
                self.push_telemetry()
                time.sleep(self.poll_interval)
        threading.Thread(target=loop, daemon=True).start()

    def stop(self):
        self._running = False

    # ---------------- πραγματικός UDP κόμβος ----------------
    def run_udp(self, listen_port=8000):
        """Πραγματική λειτουργία: ακούει UDP datagrams ως 'πακέτα'.

        Μορφή datagram (κείμενο): "src_ip;dst_ip;payload"
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", listen_port))
        self.register()
        self.start_polling()
        print(f"[SWITCH {self.switch_id}] UDP listener στη θύρα {listen_port}")
        while True:
            data, _ = sock.recvfrom(4096)
            try:
                src, dst, payload = data.decode().split(";", 2)
                self.ingest(src, dst, len(payload))
            except ValueError:
                continue


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", default="s1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--controller", default="http://127.0.0.1:9000")
    args = parser.parse_args()
    Switch(args.id, args.controller).run_udp(args.port)
