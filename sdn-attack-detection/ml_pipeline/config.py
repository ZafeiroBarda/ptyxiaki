"""
config.py
---------
Κεντρικές ρυθμίσεις του ML pipeline για ανίχνευση επιθέσεων σε SDN.

Τα ονόματα των χαρακτηριστικών (features) ακολουθούν τη λογική του CICFlowMeter,
που είναι η ίδια δομή με το δημόσιο dataset InSDN. Έτσι ο ίδιος κώδικας δουλεύει
τόσο με τα συνθετικά δεδομένα (για ανάπτυξη/δοκιμή του pipeline) όσο και με το
πραγματικό InSDN CSV, αρκεί να μπει στον φάκελο data/.
"""

import os

# --- Διαδρομές (paths) ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
MODELS_DIR = os.path.join(BASE_DIR, "models")

SYNTHETIC_CSV = os.path.join(DATA_DIR, "sdn_flows_synthetic.csv")
INSDN_CSV = os.path.join(DATA_DIR, "InSDN_dataset.csv")  # βάλε εδώ το πραγματικό InSDN

# --- Στήλη ετικέτας (label) ---
LABEL_COL = "Label"

# --- Κλάσεις κίνησης (όπως στο InSDN) ---
# Normal + 4 τύποι επίθεσης που εμφανίζονται συχνότερα στη βιβλιογραφία SDN.
CLASSES = ["Normal", "DDoS", "DoS", "Probe", "BFA"]

# --- Χαρακτηριστικά ροής (flow features), δομή τύπου CICFlowMeter / InSDN ---
FEATURE_COLUMNS = [
    "Flow_Duration",            # διάρκεια ροής (μs)
    "Tot_Fwd_Pkts",             # σύνολο πακέτων εμπρός
    "Tot_Bwd_Pkts",             # σύνολο πακέτων πίσω
    "TotLen_Fwd_Pkts",          # συνολικά bytes εμπρός
    "TotLen_Bwd_Pkts",          # συνολικά bytes πίσω
    "Fwd_Pkt_Len_Mean",         # μέσο μήκος πακέτου εμπρός
    "Bwd_Pkt_Len_Mean",         # μέσο μήκος πακέτου πίσω
    "Flow_Byts_s",              # bytes ανά δευτερόλεπτο
    "Flow_Pkts_s",              # πακέτα ανά δευτερόλεπτο
    "Flow_IAT_Mean",            # μέσος χρόνος μεταξύ πακέτων (inter-arrival time)
    "Flow_IAT_Std",             # τυπική απόκλιση IAT
    "Fwd_IAT_Mean",             # IAT εμπρός
    "Bwd_IAT_Mean",             # IAT πίσω
    "SYN_Flag_Cnt",             # πλήθος SYN flags
    "ACK_Flag_Cnt",             # πλήθος ACK flags
    "FIN_Flag_Cnt",             # πλήθος FIN flags
    "RST_Flag_Cnt",             # πλήθος RST flags
    "Pkt_Len_Mean",             # μέσο μήκος πακέτου (συνολικά)
    "Pkt_Len_Std",              # τυπική απόκλιση μήκους πακέτου
    "Down_Up_Ratio",            # λόγος download/upload
    "Pkt_Size_Avg",             # μέσο μέγεθος πακέτου
    "Active_Mean",              # μέσος χρόνος "ενεργής" ροής
    "Idle_Mean",                # μέσος χρόνος αδράνειας
    "Init_Fwd_Win_Byts",        # αρχικό παράθυρο TCP εμπρός
]

# --- Χαρακτηριστικά για LIVE ανίχνευση στον Ryu controller ---
# Το OpenFlow δίνει ανά ροή μόνο: packet_count, byte_count, duration.
# Άρα ο live controller ΔΕΝ μπορεί να υπολογίσει τα πλούσια CICFlowMeter features.
# Αντ' αυτού συγκεντρώνει (aggregate) στατιστικά ανά πηγή IP μέσα σε κάθε
# παράθυρο δειγματοληψίας — η τυπική προσέγγιση για live DDoS detection σε SDN.
LIVE_FEATURE_COLUMNS = [
    "flow_count",            # πλήθος ενεργών ροών από την πηγή
    "total_packets",         # σύνολο πακέτων
    "total_bytes",           # σύνολο bytes
    "avg_packets_per_flow",  # μέσος όρος πακέτων ανά ροή
    "avg_bytes_per_flow",    # μέσος όρος bytes ανά ροή
    "avg_duration",          # μέση διάρκεια ροών
    "avg_pkt_size",          # μέσο μέγεθος πακέτου (bytes/packet)
    "short_flow_ratio",      # ποσοστό "σύντομων" ροών (ένδειξη flood)
]
LIVE_LABELS = ["Normal", "Attack"]  # δυαδική ταξινόμηση για το live σύστημα

# --- Ρυθμίσεις εκπαίδευσης ---
RANDOM_STATE = 42
TEST_SIZE = 0.30
# Ποσοστό του συνόλου που αποσπάται (από το train) ως validation set. Η επιλογή
# μοντέλου και υπερπαραμέτρων γίνεται ΜΟΝΟ εκεί, ώστε το test set να παραμένει
# αόρατο μέχρι την τελική, μία και μοναδική αξιολόγηση.
VAL_SIZE = 0.15
# Στρατηγική διαχωρισμού: "group" = τα πανομοιότυπα διανύσματα χαρακτηριστικών
# δεν μοιράζονται μεταξύ train και test (leakage-resistant, απαραίτητο για το
# InSDN όπου το 47,5% των εγγραφών είναι διπλότυπα). "random" = κλασικός.
SPLIT_STRATEGY = "group"

# --- Ρυθμίσεις live controller ---
POLL_INTERVAL = 5          # δευτερόλεπτα μεταξύ αιτημάτων flow-stats
SHORT_FLOW_PKT_THRESHOLD = 3   # ροή με <= τόσα πακέτα θεωρείται "σύντομη"
ATTACK_FLOW_THRESHOLD = 20     # πάνω από τόσες ροές/πηγή/παράθυρο = ύποπτο
