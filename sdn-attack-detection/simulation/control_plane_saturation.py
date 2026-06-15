#!/usr/bin/env python3
"""
control_plane_saturation.py  — Επίθεση Κορεσμού Control Plane (Table-Miss Flooding)
====================================================================================
Προσομοιώνει την πιο SDN-specific επίθεση: ο επιτιθέμενος στέλνει πακέτα με
ΤΥΧΑΙΕΣ πηγές (src IPs/MACs) → κάθε πακέτο προκαλεί "table-miss" → ο switch
στέλνει PACKET_IN στον controller → ο controller κατακλύζεται και δεν μπορεί
να εξυπηρετήσει νόμιμες αιτήσεις (de facto DoS στο control plane).

Αυτή η επίθεση ΔΕΝ χρειάζεται Mininet — προσομοιώνεται πλήρως σε Python.

Αρχιτεκτονική SDN που μοντελοποιείται:
  ┌─────────────────────────────────────────┐
  │  Control Plane  (SDN Controller / Ryu)  │  ← στόχος επίθεσης
  │   • PACKET_IN queue (πεπερασμένη)       │
  │   • Processing rate: 100 msg/s          │
  └────────────────────┬────────────────────┘
                       │ OpenFlow (PACKET_IN / Flow-Mod)
  ┌────────────────────▼────────────────────┐
  │  Data Plane  (OVS Switch)               │
  │   • Flow Table: 100 entries (TCAM)      │
  │   • Table-miss → PACKET_IN στον ctrl   │
  └──────┬──────────┬──────────┬────────────┘
         │          │          │
    h1-h5 (νόμιμοι)    h6 (επιτιθέμενος: random src IPs)

Φάσεις προσομοίωσης:
  Φάση 1 (0–19s):   Κανονική λειτουργία
  Φάση 2 (20–49s):  Επίθεση table-miss flooding
  Φάση 3 (50–54s):  Ανίχνευση & εφαρμογή mitigation (rate limiting)
  Φάση 4 (55–79s):  Mitigation ενεργό — ανάκαμψη

Μετρικές:
  • Βάθος ουράς controller (queue depth)
  • Καθυστέρηση απόκρισης για νόμιμες αιτήσεις (RTT estimation)
  • Ρυθμός PACKET_IN (νόμιμος vs κακόβουλος)
  • Πληρότητα flow table
  • Εντροπία Shannon πηγών IP (δείκτης ανίχνευσης)
  • Ποσοστό επιτυχίας νόμιμων αιτήσεων

Παράγει:
  results/ctrl_plane_overview.png     — 4-panel επισκόπηση
  results/ctrl_plane_detection.png    — ανίχνευση & mitigation
  results/ctrl_plane_stats.csv        — αριθμητικά αποτελέσματα

Χρήση:
  python3 simulation/control_plane_saturation.py
"""

import os
import sys
import math
import warnings
import collections
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

warnings.filterwarnings("ignore")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE, "ml_pipeline"))
import config

# ══════════════════════════════════════════════════════════════════
#  ΠΑΡΑΜΕΤΡΟΙ ΠΡΟΣΟΜΟΙΩΣΗΣ
# ══════════════════════════════════════════════════════════════════
TOTAL_SECONDS          = 80
PHASE2_START           = 20    # έναρξη επίθεσης
PHASE3_START           = 50    # ανίχνευση & εφαρμογή mitigation
PHASE4_START           = 55    # mitigation πλήρως ενεργό

# Controller
CTRL_PROCESSING_RATE   = 100   # PACKET_IN που επεξεργάζεται ο controller/s
CTRL_QUEUE_MAX         = 250   # μέγιστο μέγεθος ουράς PACKET_IN
CTRL_QUEUE_WARN        = 150   # προειδοποίηση (>60% πλήρωση)

# Switch
FLOW_TABLE_CAPACITY    = 100   # εγγραφές (TCAM entries)
FLOW_TTL               = 30    # δευτερόλεπτα ζωής ανά κανόνα

# Κανονική κίνηση
N_LEGIT_HOSTS          = 5
NEW_FLOWS_PER_HOST     = 2     # νέες ροές/host/s → table-miss events
LEGIT_PACKET_IN_RATE   = N_LEGIT_HOSTS * NEW_FLOWS_PER_HOST  # = 10/s

# Επίθεση
ATTACK_PACKET_IN_RATE  = 400   # PACKET_IN/s από τον επιτιθέμενο (random IPs)
ATTACK_IP_POOL         = 50000  # μέγεθος pool τυχαίων IPs

# Ανίχνευση
DETECT_WINDOW          = 8     # παράθυρο ανίχνευσης (s) — χρειάζεται πλήρες παράθυρο
DETECT_RATE_THRESH     = 150   # PACKET_IN/s threshold
DETECT_ENTROPY_THRESH  = 5.0   # Shannon entropy threshold (bits)
# Η ανίχνευση απαιτεί τουλάχιστον DETECT_WINDOW δευτερόλεπτα δεδομένων
# (αποφεύγει false positives από στιγμιαίους bursts)
DETECT_MIN_T           = PHASE2_START + DETECT_WINDOW

# Mitigation
RATE_LIMIT_AFTER_DETECT = 80   # max PACKET_IN/s μετά rate limiting
ENTROPY_NORMAL         = math.log2(N_LEGIT_HOSTS)  # ≈ 2.32 bits


# ══════════════════════════════════════════════════════════════════
#  ΜΟΝΤΕΛΟ CONTROLLER
# ══════════════════════════════════════════════════════════════════
class ControllerModel:
    """Απλοποιημένο μοντέλο SDN controller με πεπερασμένη ουρά PACKET_IN."""

    def __init__(self):
        self.queue        = collections.deque()  # (timestamp, src_ip, is_legit)
        self.queue_depth  = 0
        self.total_drops  = 0   # PACKET_IN που χάθηκαν λόγω πλήρους ουράς
        self.legit_drops  = 0
        self.legit_processed   = 0
        self.attack_processed  = 0

    def enqueue(self, t, src_ip, is_legit):
        """Προσθέτει PACKET_IN στην ουρά. Αν πλήρης → drop."""
        if len(self.queue) >= CTRL_QUEUE_MAX:
            self.total_drops += 1
            if is_legit:
                self.legit_drops += 1
            return False
        self.queue.append((t, src_ip, is_legit))
        return True

    def process(self, budget=CTRL_PROCESSING_RATE):
        """Επεξεργάζεται έως budget PACKET_IN (εγκατάσταση flow rules)."""
        processed = 0
        while self.queue and processed < budget:
            _, _, is_legit = self.queue.popleft()
            processed += 1
            if is_legit:
                self.legit_processed += 1
            else:
                self.attack_processed += 1
        return processed

    @property
    def queue_depth_now(self):
        return len(self.queue)

    def response_time(self):
        """Εκτίμηση RTT (s): βάθος ουράς / processing rate."""
        return len(self.queue) / CTRL_PROCESSING_RATE


# ══════════════════════════════════════════════════════════════════
#  ΜΟΝΤΕΛΟ SWITCH (flow table)
# ══════════════════════════════════════════════════════════════════
class SwitchModel:
    """OVS switch με flow table πεπερασμένης χωρητικότητας."""

    def __init__(self):
        self.flow_table = {}   # src_ip → expiry_time

    def lookup(self, src_ip, t):
        """True αν υπάρχει ενεργός κανόνας για αυτή την πηγή."""
        exp = self.flow_table.get(src_ip)
        return exp is not None and exp > t

    def install_rule(self, src_ip, t):
        """Εγκαθιστά κανόνα (από τον controller μετά PACKET_IN)."""
        if len(self.flow_table) < FLOW_TABLE_CAPACITY:
            self.flow_table[src_ip] = t + FLOW_TTL
        # αν flow table πλήρης: κανόνας δεν εγκαθίσταται → table-miss κάθε φορά

    def expire_rules(self, t):
        """Αφαιρεί ληγμένους κανόνες."""
        self.flow_table = {k: v for k, v in self.flow_table.items() if v > t}

    @property
    def occupancy(self):
        return len(self.flow_table)

    @property
    def occupancy_pct(self):
        return 100 * len(self.flow_table) / FLOW_TABLE_CAPACITY


# ══════════════════════════════════════════════════════════════════
#  ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ
# ══════════════════════════════════════════════════════════════════
def shannon_entropy(ip_list):
    """Shannon entropy (bits) λίστας IPs — υψηλή = πολλές διαφορετικές πηγές."""
    if not ip_list:
        return 0.0
    counts = collections.Counter(ip_list)
    total  = len(ip_list)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def legit_src_ips(rng):
    """
    Επιστρέφει PACKET_IN events από νόμιμους hosts.
    Κάθε host δημιουργεί NEW_FLOWS_PER_HOST νέες (src, dst) ροές/s → table-miss.
    Παρότι η src IP είναι γνωστή, κάθε νέος προορισμός = νέος κανόνας = table-miss.
    Χρησιμοποιούμε μοναδικά pseudo-IPs για να αναπαραστήσουμε (src, dst) pairs.
    """
    ips = []
    for i in range(1, N_LEGIT_HOSTS + 1):
        for j in range(NEW_FLOWS_PER_HOST):
            # Κάθε ροή έχει unique "session key" — αντιπροσωπεύει νέα σύνδεση
            ips.append(f"10.0.0.{i}")
    return ips


def attack_src_ips(rng, n=ATTACK_PACKET_IN_RATE):
    """Τυχαίες IPs για table-miss flooding."""
    pool = rng.integers(1, ATTACK_IP_POOL, size=n)
    return [f"192.168.{ip // 256}.{ip % 256}" for ip in pool]


# ══════════════════════════════════════════════════════════════════
#  ΚΥΡΙΑ ΠΡΟΣΟΜΟΙΩΣΗ
# ══════════════════════════════════════════════════════════════════
def run_simulation(seed=config.RANDOM_STATE):
    rng        = np.random.default_rng(seed)
    ctrl       = ControllerModel()
    sw         = SwitchModel()

    # ΔΕΝ προεγκαθιστούμε κανόνες — οι legit hosts δημιουργούν table-miss
    # για κάθε νέα (src, dst) ροή, αναπαριστάμε με "session counter"
    session_counter = 0

    records              = []
    recent_packet_in_ips = collections.deque()  # (t, src_ip)
    mitigation_active    = False
    mitigation_start_t   = None  # πότε ξεκινά το rate limiting
    detection_event_t    = None
    log_events           = []
    MITIGATION_DELAY     = 3     # s μεταξύ ανίχνευσης & ενεργοποίησης mitigation

    for t in range(TOTAL_SECONDS):
        sw.expire_rules(t)
        is_attack    = t >= PHASE2_START
        is_mitigated = (mitigation_start_t is not None and t >= mitigation_start_t)

        # — κανονική κίνηση: κάθε host δημιουργεί NEW_FLOWS_PER_HOST νέες ροές —
        # Χρησιμοποιούμε session_counter για μοναδικά (src, dst) combos
        legit_packet_in = []
        for i in range(1, N_LEGIT_HOSTS + 1):
            for _ in range(NEW_FLOWS_PER_HOST):
                session_counter += 1
                session_key = f"10.0.0.{i}_sess{session_counter % 20}"
                if not sw.lookup(session_key, t):
                    legit_packet_in.append(f"10.0.0.{i}")
                    ctrl.enqueue(t, f"10.0.0.{i}", is_legit=True)
                    sw.install_rule(session_key, t)

        # — επίθεση: τυχαίες src IPs → κάθε πακέτο είναι table-miss —
        attack_packet_in = []
        if is_attack:
            if is_mitigated:
                # rate limiting: ο switch περιορίζει το PACKET_IN budget
                budget  = max(0, RATE_LIMIT_AFTER_DETECT - len(legit_packet_in))
                atk_ips = attack_src_ips(rng, budget)
            else:
                atk_ips = attack_src_ips(rng, ATTACK_PACKET_IN_RATE)
            for src in atk_ips:
                if not sw.lookup(src, t):
                    attack_packet_in.append(src)
                    ctrl.enqueue(t, src, is_legit=False)

        # — controller επεξεργάζεται PACKET_IN —
        ctrl.process(CTRL_PROCESSING_RATE)

        # — sliding window ανίχνευσης —
        all_now = [(t, s) for s in legit_packet_in + attack_packet_in]
        recent_packet_in_ips.extend(all_now)
        while recent_packet_in_ips and recent_packet_in_ips[0][0] < t - DETECT_WINDOW:
            recent_packet_in_ips.popleft()

        recent_ips     = [s for _, s in recent_packet_in_ips]
        window_rate    = len(recent_ips) / DETECT_WINDOW
        window_entropy = shannon_entropy(recent_ips)

        # — αυτόματη ανίχνευση —
        # Απαιτείται πλήρες παράθυρο δεδομένων (DETECT_WINDOW s) πριν αποφασίσει
        detected_now = (t >= DETECT_MIN_T and
                        (window_rate > DETECT_RATE_THRESH or
                         window_entropy > DETECT_ENTROPY_THRESH))
        if detected_now and detection_event_t is None:
            detection_event_t = t
            mitigation_start_t = t + MITIGATION_DELAY
            log_events.append(
                f"[t={t:02d}s] [ΑΝΙΧΝΕΥΣΗ] PACKET_IN rate={window_rate:.0f}/s, "
                f"entropy={window_entropy:.2f} bits (>{DETECT_ENTROPY_THRESH}) "
                f"→ ΕΦΑΡΜΟΓΗ RATE LIMITING σε {MITIGATION_DELAY}s"
            )
        if mitigation_start_t and t == mitigation_start_t:
            mitigation_active = True
            log_events.append(
                f"[t={t:02d}s] [MITIGATION] Rate limit ενεργό: "
                f"max {RATE_LIMIT_AFTER_DETECT} PACKET_IN/s συνολικά → ουρά αποσυμφορείται"
            )

        # — φάση για οπτικοποίηση —
        if detection_event_t and mitigation_start_t:
            if t < PHASE2_START:
                phase = 1
            elif t < detection_event_t:
                phase = 2
            elif t < mitigation_start_t:
                phase = 3
            else:
                phase = 4
        else:
            phase = (1 if t < PHASE2_START else 2)

        records.append({
            "t":                  t,
            "phase":              phase,
            "is_attack":          int(is_attack),
            "is_mitigated":       int(is_mitigated),
            "queue_depth":        ctrl.queue_depth_now,
            "queue_pct":          100 * ctrl.queue_depth_now / CTRL_QUEUE_MAX,
            "response_time_ms":   ctrl.response_time() * 1000,
            "legit_packet_in":    len(legit_packet_in),
            "attack_packet_in":   len(attack_packet_in),
            "total_packet_in":    len(legit_packet_in) + len(attack_packet_in),
            "flow_table_pct":     sw.occupancy_pct,
            "entropy":            window_entropy,
            "window_rate":        window_rate,
            "detected":           int(t == detection_event_t),
            "mitigation_active":  int(is_mitigated),
            "legit_drops_cumul":  ctrl.legit_drops,
        })

    return pd.DataFrame(records), log_events


# ══════════════════════════════════════════════════════════════════
#  ΓΡΑΦΗΜΑΤΑ
# ══════════════════════════════════════════════════════════════════
PHASE_COLORS = {1: "#3498db", 2: "#e74c3c", 3: "#e67e22", 4: "#2ecc71"}
PHASE_LABELS = {
    1: "Φάση 1: Κανονική",
    2: "Φάση 2: Flooding",
    3: "Φάση 3: Ανίχνευση",
    4: "Φάση 4: Mitigation",
}


def _add_phase_bands(ax, df):
    prev_phase, start = df["phase"].iloc[0], 0
    for i, row in df.iterrows():
        if row["phase"] != prev_phase or i == len(df) - 1:
            end = row["t"] if i < len(df) - 1 else TOTAL_SECONDS
            ax.axvspan(start, end, color=PHASE_COLORS[prev_phase], alpha=0.07, zorder=0)
            prev_phase = row["phase"]
            start      = row["t"]
    # κατακόρυφες γραμμές στις αλλαγές φάσης
    for phase_t in df.groupby("phase")["t"].first().values[1:]:
        ax.axvline(phase_t, color="grey", lw=0.8, linestyle="--", zorder=1)


def plot_overview(df, out_path):
    fig, axes = plt.subplots(4, 1, figsize=(13, 12), sharex=True)
    t = df["t"].values

    # 1. PACKET_IN rate
    ax = axes[0]
    ax.fill_between(t, df["legit_packet_in"], alpha=0.7, color="#3498db",
                    label=f"Νόμιμη κίνηση (~{LEGIT_PACKET_IN_RATE}/s)")
    ax.fill_between(t, df["total_packet_in"], df["legit_packet_in"],
                    alpha=0.7, color="#e74c3c", label="Επίθεση (table-miss flood)")
    ax.axhline(DETECT_RATE_THRESH, color="orange", lw=1.2, linestyle=":",
               label=f"Threshold ανίχνευσης ({DETECT_RATE_THRESH}/s)")
    ax.axhline(CTRL_PROCESSING_RATE, color="purple", lw=1.2, linestyle=":",
               label=f"Controller capacity ({CTRL_PROCESSING_RATE}/s)")
    ax.set_ylabel("PACKET_IN / δευτερόλεπτο", fontsize=10)
    ax.set_title("Ρυθμός PACKET_IN προς Controller (Control Plane Load)", fontsize=11)
    ax.legend(fontsize=8, ncol=2, loc="upper left")
    _add_phase_bands(ax, df)

    # 2. Queue depth
    ax = axes[1]
    ax.plot(t, df["queue_depth"], color="#8e44ad", lw=2, label="Βάθος ουράς")
    ax.fill_between(t, df["queue_depth"], alpha=0.2, color="#8e44ad")
    ax.axhline(CTRL_QUEUE_MAX, color="red", lw=1, linestyle="--",
               label=f"Max ουρά ({CTRL_QUEUE_MAX})")
    ax.axhline(CTRL_QUEUE_WARN, color="orange", lw=1, linestyle=":",
               label=f"Προειδοποίηση ({CTRL_QUEUE_WARN})")
    ax.set_ylabel("Εκκρεμή PACKET_IN", fontsize=10)
    ax.set_title("Βάθος Ουράς Controller (Controller Queue Depth)", fontsize=11)
    ax.legend(fontsize=8, ncol=2, loc="upper left")
    _add_phase_bands(ax, df)

    # 3. Response time
    ax = axes[2]
    ax.plot(t, df["response_time_ms"], color="#e67e22", lw=2)
    ax.fill_between(t, df["response_time_ms"], alpha=0.2, color="#e67e22")
    ax.set_ylabel("Εκτιμώμενο RTT (ms)", fontsize=10)
    ax.set_title("Καθυστέρηση Απόκρισης Controller (Εκτίμηση RTT)", fontsize=11)
    ax.axhline(1000, color="red", lw=1, linestyle="--", label="1 second SLA")
    ax.legend(fontsize=8, loc="upper left")
    _add_phase_bands(ax, df)

    # 4. Flow table occupancy
    ax = axes[3]
    ax.plot(t, df["flow_table_pct"], color="#27ae60", lw=2)
    ax.fill_between(t, df["flow_table_pct"], alpha=0.2, color="#27ae60")
    ax.axhline(100, color="red", lw=1, linestyle="--", label="Flow table πλήρης")
    ax.set_ylabel("Πληρότητα Flow Table (%)", fontsize=10)
    ax.set_xlabel("Χρόνος (s)", fontsize=10)
    ax.set_title("Πληρότητα Flow Table Switch (TCAM Exhaustion)", fontsize=11)
    ax.set_ylim(0, 115)
    ax.legend(fontsize=8, loc="upper left")
    _add_phase_bands(ax, df)

    # legend φάσεων
    phase_patches = [mpatches.Patch(color=PHASE_COLORS[p], alpha=0.4, label=PHASE_LABELS[p])
                     for p in sorted(PHASE_COLORS)]
    fig.legend(handles=phase_patches, loc="lower center", ncol=4,
               fontsize=9, bbox_to_anchor=(0.5, -0.01), framealpha=0.9)

    fig.suptitle(
        "Επίθεση Κορεσμού Control Plane SDN (Table-Miss Flooding)\n"
        f"Controller capacity: {CTRL_PROCESSING_RATE} PACKET_IN/s | "
        f"Flow table: {FLOW_TABLE_CAPACITY} entries | "
        f"Επίθεση: {ATTACK_PACKET_IN_RATE} PACKET_IN/s",
        fontsize=12, y=1.01,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out_path}")


def plot_detection(df, log_events, out_path):
    fig, axes = plt.subplots(3, 1, figsize=(13, 9), sharex=True)
    t = df["t"].values

    # 1. Entropy (δείκτης ανίχνευσης)
    ax = axes[0]
    ax.plot(t, df["entropy"], color="#2980b9", lw=2, label="Εντροπία Shannon (bits)")
    ax.fill_between(t, df["entropy"], alpha=0.15, color="#2980b9")
    ax.axhline(DETECT_ENTROPY_THRESH, color="red", lw=1.5, linestyle="--",
               label=f"Threshold ανίχνευσης ({DETECT_ENTROPY_THRESH} bits)")
    ax.axhline(ENTROPY_NORMAL, color="green", lw=1, linestyle=":",
               label=f"Φυσιολογική εντροπία ({ENTROPY_NORMAL:.2f} bits, {N_LEGIT_HOSTS} hosts)")
    ax.set_ylabel("Εντροπία Shannon (bits)", fontsize=10)
    ax.set_title(
        "Εντροπία Shannon Πηγών IP στο PACKET_IN stream\n"
        "(Υψηλή εντροπία = πολλές τυχαίες IPs = table-miss flooding)",
        fontsize=11,
    )
    ax.legend(fontsize=8, loc="upper left")
    ax.set_ylim(-0.2, 18)
    _add_phase_bands(ax, df)

    # 2. PACKET_IN rate (sliding window)
    ax = axes[1]
    ax.plot(t, df["window_rate"], color="#8e44ad", lw=2,
            label=f"PACKET_IN/s (παράθυρο {DETECT_WINDOW}s)")
    ax.axhline(DETECT_RATE_THRESH, color="red", lw=1.5, linestyle="--",
               label=f"Threshold ρυθμού ({DETECT_RATE_THRESH}/s)")
    ax.fill_between(t, df["window_rate"], alpha=0.15, color="#8e44ad")
    ax.set_ylabel("PACKET_IN/s (sliding window)", fontsize=10)
    ax.set_title("Ρυθμός PACKET_IN — Sliding Window Ανίχνευση", fontsize=11)
    ax.legend(fontsize=8, loc="upper left")
    _add_phase_bands(ax, df)

    # Annotation ανίχνευσης
    detect_t = df[df["detected"] == 1]["t"].values
    if len(detect_t):
        first_det = detect_t[0]
        for axi in axes[:2]:
            axi.axvline(first_det, color="red", lw=2, linestyle="-", alpha=0.7)
            axi.annotate(f"Ανίχνευση\n(t={first_det}s)",
                         xy=(first_det, axi.get_ylim()[1] * 0.7),
                         xytext=(first_det + 2, axi.get_ylim()[1] * 0.75),
                         fontsize=8, color="red",
                         arrowprops=dict(arrowstyle="->", color="red", lw=1.2))

    # Annotation mitigation
    mit_t = df[df["mitigation_active"] == 1]["t"].min()
    if not np.isnan(mit_t):
        for axi in axes[:2]:
            axi.axvline(PHASE4_START, color="#27ae60", lw=2, linestyle="-", alpha=0.7)

    # 3. Legit drops cumulative
    ax = axes[2]
    ax.plot(t, df["legit_drops_cumul"], color="#e74c3c", lw=2,
            label="Απώλειες νόμιμων PACKET_IN (αθροιστικά)")
    ax.fill_between(t, df["legit_drops_cumul"], alpha=0.2, color="#e74c3c")
    ax.set_ylabel("Αθροιστικές απώλειες", fontsize=10)
    ax.set_xlabel("Χρόνος (s)", fontsize=10)
    ax.set_title(
        "Αθροιστικές Απώλειες Νόμιμων PACKET_IN\n"
        "(Controller queue πλήρης → νόμιμες αιτήσεις απορρίπτονται)",
        fontsize=11,
    )
    ax.legend(fontsize=8, loc="upper left")
    _add_phase_bands(ax, df)

    # Σχολιασμός μηδενικών απωλειών μετά mitigation
    post_mit = df[df["t"] >= PHASE4_START]["legit_drops_cumul"]
    if len(post_mit) >= 2 and post_mit.diff().dropna().abs().max() < 1:
        ax.annotate("Καμία νέα απώλεια\nμετά το mitigation",
                    xy=(PHASE4_START + 5, post_mit.iloc[5] if len(post_mit) > 5 else post_mit.iloc[-1]),
                    xytext=(PHASE4_START + 10, post_mit.max() * 0.8),
                    fontsize=8, color="#27ae60",
                    arrowprops=dict(arrowstyle="->", color="#27ae60"))

    phase_patches = [mpatches.Patch(color=PHASE_COLORS[p], alpha=0.4, label=PHASE_LABELS[p])
                     for p in sorted(PHASE_COLORS)]
    fig.legend(handles=phase_patches, loc="lower center", ncol=4,
               fontsize=9, bbox_to_anchor=(0.5, -0.01), framealpha=0.9)

    fig.suptitle(
        "Ανίχνευση & Αντιμετώπιση Επίθεσης Κορεσμού Control Plane\n"
        f"(Μέθοδοι: Shannon Entropy + Rate Threshold | Mitigation: Rate Limiting στο switch)",
        fontsize=12, y=1.01,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] {out_path}")


def save_csv(df, out_path):
    export_cols = [
        "t", "phase", "is_attack", "is_mitigated",
        "queue_depth", "queue_pct", "response_time_ms",
        "legit_packet_in", "attack_packet_in", "total_packet_in",
        "flow_table_pct", "entropy", "window_rate",
        "detected", "mitigation_active", "legit_drops_cumul",
    ]
    df[export_cols].to_csv(out_path, index=False)
    print(f"[OK] {out_path}")


def print_summary(df, log_events):
    p1 = df[df["phase"] == 1]
    p2 = df[df["phase"] == 2]
    p4 = df[df["phase"] == 4]

    print("\n" + "=" * 65)
    print("  ΑΠΟΤΕΛΕΣΜΑΤΑ: ΕΠΙΘΕΣΗ ΚΟΡΕΣΜΟΥ CONTROL PLANE")
    print("=" * 65)

    print(f"\n[Φάση 1 — Κανονική λειτουργία]")
    print(f"  Μέσος ρυθμός PACKET_IN: {p1['total_packet_in'].mean():.1f}/s")
    print(f"  Μέσο βάθος ουράς:       {p1['queue_depth'].mean():.1f} / {CTRL_QUEUE_MAX}")
    print(f"  Μέσο RTT:               {p1['response_time_ms'].mean():.1f} ms")
    print(f"  Μέση εντροπία:          {p1['entropy'].mean():.2f} bits")

    print(f"\n[Φάση 2 — Table-miss flooding ({ATTACK_PACKET_IN_RATE}/s)]")
    print(f"  Μέσος ρυθμός PACKET_IN: {p2['total_packet_in'].mean():.0f}/s")
    print(f"  Μέγιστο βάθος ουράς:   {p2['queue_depth'].max()} / {CTRL_QUEUE_MAX} "
          f"({100 * p2['queue_depth'].max() / CTRL_QUEUE_MAX:.0f}%)")
    print(f"  Μέσο RTT:               {p2['response_time_ms'].mean():.0f} ms "
          f"(×{p2['response_time_ms'].mean() / max(1, p1['response_time_ms'].mean()):.0f} αύξηση)")
    print(f"  Μέγιστη εντροπία:       {p2['entropy'].max():.2f} bits (vs {ENTROPY_NORMAL:.2f} κανονική)")
    print(f"  Απώλειες νόμιμων PACKET_IN: {df['legit_drops_cumul'].max()} συνολικά")

    if not p4.empty:
        print(f"\n[Φάση 4 — Μετά mitigation (rate limit {RATE_LIMIT_AFTER_DETECT}/s)]")
        print(f"  Μέσο βάθος ουράς:    {p4['queue_depth'].mean():.1f}")
        print(f"  Μέσο RTT:             {p4['response_time_ms'].mean():.1f} ms")
        new_legit_drops = (df[df["t"] >= PHASE4_START]["legit_drops_cumul"].diff()
                           .fillna(0).sum())
        print(f"  Νέες απώλειες νόμιμων: {int(new_legit_drops)}")

    detect_t = df[df["detected"] == 1]["t"].min()
    if not np.isnan(detect_t):
        print(f"\n  Χρόνος ανίχνευσης: t={detect_t:.0f}s "
              f"(+{detect_t - PHASE2_START:.0f}s από έναρξη επίθεσης)")

    print("\n--- ΗΜΕΡΟΛΟΓΙΟ ΣΥΜΒΑΝΤΩΝ ---")
    for line in log_events:
        print(f"  {line}")


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    print("[*] Προσομοίωση Επίθεσης Κορεσμού Control Plane SDN")
    print(f"    Controller: {CTRL_PROCESSING_RATE} PACKET_IN/s | "
          f"Queue: {CTRL_QUEUE_MAX} | Flow table: {FLOW_TABLE_CAPACITY} entries")
    print(f"    Επίθεση: {ATTACK_PACKET_IN_RATE} PACKET_IN/s (random src IPs)\n")

    df, log_events = run_simulation()

    print_summary(df, log_events)

    plot_overview(df, os.path.join(config.RESULTS_DIR, "ctrl_plane_overview.png"))
    plot_detection(df, log_events, os.path.join(config.RESULTS_DIR, "ctrl_plane_detection.png"))
    save_csv(df, os.path.join(config.RESULTS_DIR, "ctrl_plane_stats.csv"))

    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] Αποτελέσματα αποθηκεύτηκαν στο results/")


if __name__ == "__main__":
    main()
