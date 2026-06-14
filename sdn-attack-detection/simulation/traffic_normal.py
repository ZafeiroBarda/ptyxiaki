#!/usr/bin/env python3
"""
traffic_normal.py  (ΜΕΘΟΔΟΣ A)
------------------------------
Παράγει ΝΟΜΙΜΗ (legitimate) κίνηση μέσα στην τοπολογία Mininet, ώστε να
συλλεχθούν ροές "Normal" για το δικό σου dataset.

Μπορεί να κληθεί:
  (α) μέσα από το Mininet CLI με source επί των hosts, ή
  (β) ως ξεχωριστή τοπολογία που κάνει τα πάντα προγραμματιστικά (παρακάτω main).

Είδη νόμιμης κίνησης:
  - ICMP ping (περιοδικά)
  - iperf TCP (μεταφορά αρχείων / web-like)
  - iperf UDP με λογικό ρυθμό (streaming-like)
"""

import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from topology import build_network


def generate_normal_traffic(net, hosts, duration=60):
    """Παράγει ισορροπημένη, ρεαλιστική νόμιμη κίνηση."""
    server = hosts["h5"]

    info("*** Εκκίνηση iperf server στο h5\n")
    server.cmd("iperf -s -p 5001 &")        # TCP server
    server.cmd("iperf -s -u -p 5002 &")     # UDP server
    time.sleep(1)

    info(f"*** Παραγωγή νόμιμης κίνησης για {duration}s\n")
    clients = [hosts["h1"], hosts["h2"], hosts["h3"], hosts["h4"]]

    # ping (ICMP) στο παρασκήνιο
    for c in clients:
        c.cmd(f"ping -i 1 {server.IP()} > /tmp/ping_{c.name}.log &")

    # iperf TCP — ρεαλιστικά "web/file" sessions
    for c in clients:
        c.cmd(f"iperf -c {server.IP()} -p 5001 -t {duration} -i 5 "
              f"> /tmp/iperf_tcp_{c.name}.log &")

    # iperf UDP — streaming-like, ΛΟΓΙΚΟΣ ρυθμός (όχι flood)
    hosts["h1"].cmd(f"iperf -c {server.IP()} -u -p 5002 -b 2M -t {duration} "
                    f"> /tmp/iperf_udp_h1.log &")

    info("*** Η κίνηση τρέχει... περιμένουμε ολοκλήρωση.\n")
    time.sleep(duration + 3)

    # καθάρισμα
    for h in hosts.values():
        h.cmd("kill %ping 2>/dev/null; kill %iperf 2>/dev/null")
    server.cmd("kill %iperf 2>/dev/null")
    info("*** Ολοκληρώθηκε η νόμιμη κίνηση.\n")


def main():
    setLogLevel("info")
    net, hosts = build_network()
    net.start()
    time.sleep(2)  # να συνδεθεί ο controller
    generate_normal_traffic(net, hosts, duration=60)
    net.stop()


if __name__ == "__main__":
    main()
