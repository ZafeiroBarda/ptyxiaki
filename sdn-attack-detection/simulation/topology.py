#!/usr/bin/env python3
"""
topology.py  (ΜΕΘΟΔΟΣ A — προσομοίωση)
--------------------------------------
Στήνει μια τοπολογία SDN στο Mininet, συνδεδεμένη σε εξωτερικό Ryu controller.

Τοπολογία:
    - 1 OpenFlow switch (s1) με OpenFlow 1.3
    - 6 hosts:
        h1..h4  -> νόμιμοι χρήστες (legitimate)
        h5      -> server / θύμα (victim)
        h6      -> επιτιθέμενος (attacker)

ΑΠΑΙΤΗΣΕΙΣ (τρέχει ΜΟΝΟ σε Linux):
    sudo apt install mininet
    pip install ryu        (ή: pip install os-ken για συντηρούμενη έκδοση)

ΕΚΤΕΛΕΣΗ:
    # Τερματικό 1 — ξεκίνα τον controller:
    ryu-manager controller/detection_controller.py
    # Τερματικό 2 — ξεκίνα την τοπολογία (χρειάζεται sudo):
    sudo python3 simulation/topology.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


def build_network(controller_ip="127.0.0.1", controller_port=6653):
    """Δημιουργεί και επιστρέφει το δίκτυο Mininet."""
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    info("*** Προσθήκη remote controller (Ryu)\n")
    c0 = net.addController(
        "c0", controller=RemoteController,
        ip=controller_ip, port=controller_port,
    )

    info("*** Προσθήκη switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Προσθήκη hosts\n")
    hosts = {}
    # νόμιμοι χρήστες
    for i in range(1, 5):
        hosts[f"h{i}"] = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
    # server / θύμα
    hosts["h5"] = net.addHost("h5", ip="10.0.0.5/24")
    # επιτιθέμενος
    hosts["h6"] = net.addHost("h6", ip="10.0.0.6/24")

    info("*** Δημιουργία ζεύξεων (links)\n")
    for name, h in hosts.items():
        # ζεύξη με ρεαλιστικό bandwidth/καθυστέρηση
        net.addLink(h, s1, bw=10, delay="2ms")

    return net, hosts


def main():
    setLogLevel("info")
    net, hosts = build_network()
    net.start()
    info("\n*** Δίκτυο έτοιμο.\n")
    info("    Νόμιμοι: h1..h4 | Server/θύμα: h5 (10.0.0.5) | Επιτιθέμενος: h6 (10.0.0.6)\n")
    info("    Δοκίμασε: pingall  ή  h1 ping h5\n")
    info("    Για επιθέσεις/κίνηση τρέξε τα scripts traffic_normal.py / traffic_attack.py\n\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
