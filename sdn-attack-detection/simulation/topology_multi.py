#!/usr/bin/env python3
"""
topology_multi.py  (ΜΕΘΟΔΟΣ A — 2η εκδοχή τοπολογίας: πολλαπλά switches)
-----------------------------------------------------------------------
Πιο ρεαλιστική, ιεραρχική (tree) τοπολογία με ΠΟΛΛΑΠΛΑ switches, ώστε να
δοκιμαστεί η ανίχνευση/αντιμετώπιση σε δίκτυο με βάθος (όχι ένα μόνο switch).

           s1  (core / πυρήνας)
          /  \
        s2    s3   (edge switches)
       /|      |\
     h1 h2   h3 h4 ... + server (h5) + attacker (h6)

Σενάριο: ο επιτιθέμενος (h6) βρίσκεται σε διαφορετικό edge switch από το θύμα
(h5), οπότε η κακόβουλη κίνηση διασχίζει τον πυρήνα — ρεαλιστικό για το πώς ένα
DDoS διαπερνά το δίκτυο προς τον controller/θύμα.

ΕΚΤΕΛΕΣΗ:
    ryu-manager controller/detection_controller.py
    sudo python3 simulation/topology_multi.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


def build_tree_network(controller_ip="127.0.0.1", controller_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    info("*** Remote controller\n")
    net.addController("c0", controller=RemoteController,
                      ip=controller_ip, port=controller_port)

    info("*** Switches (1 core + 2 edge)\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")  # core
    s2 = net.addSwitch("s2", protocols="OpenFlow13")  # edge A
    s3 = net.addSwitch("s3", protocols="OpenFlow13")  # edge B

    info("*** Hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    h4 = net.addHost("h4", ip="10.0.0.4/24")
    h5 = net.addHost("h5", ip="10.0.0.5/24")  # server / θύμα
    h6 = net.addHost("h6", ip="10.0.0.6/24")  # attacker

    info("*** Links\n")
    # core <-> edges (μεγαλύτερο bandwidth στον κορμό)
    net.addLink(s1, s2, bw=20, delay="1ms")
    net.addLink(s1, s3, bw=20, delay="1ms")
    # edge A: νόμιμοι χρήστες + server
    net.addLink(h1, s2, bw=10, delay="2ms")
    net.addLink(h2, s2, bw=10, delay="2ms")
    net.addLink(h5, s2, bw=10, delay="2ms")   # θύμα στο edge A
    # edge B: χρήστες + attacker
    net.addLink(h3, s3, bw=10, delay="2ms")
    net.addLink(h4, s3, bw=10, delay="2ms")
    net.addLink(h6, s3, bw=10, delay="2ms")   # attacker στο edge B (διασχίζει core)

    hosts = {"h1": h1, "h2": h2, "h3": h3, "h4": h4, "h5": h5, "h6": h6}
    return net, hosts


def main():
    setLogLevel("info")
    net, hosts = build_tree_network()
    net.start()
    info("\n*** Tree τοπολογία έτοιμη (s1 core, s2/s3 edge).\n")
    info("    Θύμα h5 @ s2 | Attacker h6 @ s3 -> η επίθεση διασχίζει τον πυρήνα.\n")
    info("    Δοκίμασε: pingall  ή  h6 ping h5\n\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
