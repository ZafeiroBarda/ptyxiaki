#!/usr/bin/env python3
"""
test_drop_lease_renewal.py — Ο κανόνας DROP πρέπει να ΑΝΑΝΕΩΝΕΤΑΙ όσο η επίθεση συνεχίζεται.

Καλύπτει την αστοχία όπου το lease του κανόνα έληγε μέσω hard_timeout και δεν
επανεγκαθιστάτο, με αποτέλεσμα η πραγματική αντιμετώπιση να καλύπτει μόνο το πρώτο
TTL μιας επίθεσης πολύ μεγαλύτερης διάρκειας.

Το ομοίωμα αναπαράγει τη ΚΡΙΣΙΜΗ ιδιότητα του πραγματικού συστήματος: όσο ο κόμβος
είναι μπλοκαρισμένος, η κίνησή του απορρίπτεται και δεν εμφανίζεται ως ροή, οπότε ΔΕΝ
φτάνει τηλεμετρία γι' αυτόν. Άρα η ανανέωση δεν μπορεί να στηρίζεται στην τηλεμετρία
και την αναλαμβάνει ο lease_keeper, που παρακολουθεί τον μετρητή του ίδιου του κανόνα.

Run: pytest tests/test_drop_lease_renewal.py -v
"""
import os
import sys

import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "simulation"))

import mininet_live as ml

ATTACKER = "10.0.0.6"
KEEPER_TICK = 0.5      # ρυθμός του lease_keeper
TELEM_TICK = 2.0       # ρυθμός της τηλεμετρίας


class FakeOVS:
    """Ελάχιστο ομοίωμα του OVS: ο κανόνας αυτο-διαγράφεται στο hard_timeout."""

    def __init__(self, pkts_per_s=1000):
        self.rule = None
        self.now = 0.0
        self.installs = 0
        self.pkts_per_s = pkts_per_s
        self.attack_on = True
        self.gap_ticks = 0     # δείγματα χρόνου ΧΩΡΙΣ ενεργό κανόνα ενώ η επίθεση τρέχει

    def tick(self, dt):
        self.now += dt
        if self.rule and self.now - self.rule["t0"] >= self.rule["ht"]:
            self.rule = None                       # λήξη μέσω hard_timeout
        elif self.rule and self.attack_on:
            self.rule["pkts"] += int(self.pkts_per_s * dt)
        if self.rule is None and self.attack_on:
            self.gap_ticks += 1

    def install(self, ip, bridge="s1", hard_timeout=None):
        self.rule = {"t0": self.now, "ht": ml.BLOCK_TTL, "pkts": 0}
        self.installs += 1
        return True

    def info(self, ip, bridge="s1"):
        if not self.rule:
            return None
        return {"n_packets": self.rule["pkts"],
                "duration": self.now - self.rule["t0"],
                "hard_timeout": self.rule["ht"]}

    @property
    def traffic_visible(self):
        """Η τηλεμετρία βλέπει τον κόμβο μόνο όταν η κίνησή του ΔΕΝ απορρίπτεται."""
        return self.rule is None


@pytest.fixture
def ovs(monkeypatch):
    fake = FakeOVS()
    monkeypatch.setattr(ml, "install_drop_flow", fake.install)
    monkeypatch.setattr(ml, "get_drop_rule_info", fake.info)
    return fake


def _run_attack(ovs, seconds):
    """Τρέχει keeper (0,5s) και τηλεμετρία (2s) όπως στο πραγματικό σύστημα."""
    state = ml.new_drop_state()
    ticks = int(seconds / KEEPER_TICK)
    for i in range(ticks):
        ml.keep_lease_alive(ATTACKER, state)
        if (i * KEEPER_TICK) % TELEM_TICK == 0 and ovs.traffic_visible and ovs.attack_on:
            ml.ensure_drop_lease(ATTACKER, state)   # verdict=Attack από το μοντέλο
        ovs.tick(KEEPER_TICK)
    return state


def test_first_detection_installs_rule(ovs):
    state = ml.new_drop_state()
    assert ml.ensure_drop_lease(ATTACKER, state) == "installed"
    assert ovs.installs == 1


def test_rule_is_renewed_during_long_attack(ovs):
    """Επίθεση 60s με TTL 10s: χωρίς ανανέωση θα υπήρχε ένα μόνο lease."""
    attack_s = 6 * ml.BLOCK_TTL
    state = _run_attack(ovs, attack_s)
    lease = state["hosts"][ATTACKER]

    assert lease["renewals"] >= 4, "ο κανόνας δεν ανανεώθηκε όσο η επίθεση συνεχιζόταν"
    assert ovs.rule is not None, "η επίθεση τελείωσε χωρίς ενεργό κανόνα"


def test_no_uncovered_gap_while_attack_continues(ovs):
    """Η προληπτική ανανέωση δεν αφήνει παράθυρο χωρίς κανόνα στο data plane."""
    _run_attack(ovs, 60)
    assert ovs.gap_ticks <= 1, (
        f"{ovs.gap_ticks} παράθυρα χωρίς ενεργό κανόνα ενώ η επίθεση συνεχιζόταν")


def test_dropped_packets_accumulate_across_leases(ovs):
    """Η επανεγκατάσταση μηδενίζει τους μετρητές του OVS: το άθροισμα πρέπει να κρατιέται."""
    state = _run_attack(ovs, 60)
    total = ml.dropped_total(state, ATTACKER)
    single_lease_max = ovs.pkts_per_s * ml.BLOCK_TTL

    assert total > single_lease_max, (
        "τα απορριφθέντα πακέτα δεν αθροίζονται πέρα από το πρώτο lease")


def test_lease_is_released_when_attack_stops(ovs):
    """Ο αποκλεισμός ΔΕΝ είναι μόνιμος: όταν ο ρυθμός πέσει, το lease αφήνεται να λήξει."""
    state = ml.new_drop_state()
    ml.ensure_drop_lease(ATTACKER, state)
    assert ovs.info(ATTACKER) is not None

    ovs.attack_on = False                       # ο επιτιθέμενος σταματά
    for _ in range(int((ml.BLOCK_TTL + 2) / KEEPER_TICK)):
        ml.keep_lease_alive(ATTACKER, state)
        ovs.tick(KEEPER_TICK)

    assert ovs.info(ATTACKER) is None, "ο κανόνας έμεινε ενεργός αν και η επίθεση σταμάτησε"
    assert state["hosts"][ATTACKER]["renewals"] == 0, "ανανεώθηκε lease χωρίς επίθεση"
