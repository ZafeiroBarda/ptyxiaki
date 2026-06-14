# Ανίχνευση και Αντιμετώπιση Επιθέσεων σε Δίκτυα Οριζόμενα από Λογισμικό (SDN)

Διπλωματική εργασία — υλοποίηση σε **Python**. Το έργο καλύπτει δύο
συμπληρωματικές προσεγγίσεις:

- **Μέθοδος Β — Offline ανίχνευση με Μηχανική Μάθηση** σε δημόσιο dataset
  (τύπου **InSDN**, δομή CICFlowMeter). Εκπαίδευση & σύγκριση πολλών μοντέλων.
- **Μέθοδος Α — Live ανίχνευση & αντιμετώπιση** μέσα σε προσομοίωση
  **Mininet + Ryu controller** (Linux), με αυτόματο μπλοκάρισμα της επίθεσης.

---

## 1. Δομή του έργου

```
sdn-attack-detection/
├── README.md
├── requirements.txt
├── run_all.sh                     # τρέχει ΟΛΟ το Python pipeline με 1 εντολή
├── data/                          # datasets (συνθετικά + InSDN)
├── models/                        # αποθηκευμένα μοντέλα (.pkl)
├── results/                       # γραφήματα & μετρικές (12 αρχεία)
├── ml_pipeline/                   # === ΜΕΘΟΔΟΣ Β (offline ML) ===
│   ├── config.py                  #   κεντρικές ρυθμίσεις & features
│   ├── generate_synthetic_dataset.py   # γεννήτορας (--hard: θόρυβος/επικάλυψη)
│   ├── preprocess.py              #   φόρτωση/καθαρισμός (synthetic + InSDN)
│   ├── train.py                   #   εκπαίδευση & σύγκριση 6 κλασικών μοντέλων
│   ├── evaluate.py                #   γραφήματα: comparison, confusion, importance
│   ├── deep_learning.py           #   2η εκδοχή: Deep MLP + 1D-CNN (Keras)
│   ├── advanced_eval.py           #   cross-validation + ROC curves
│   ├── final_comparison.py        #   ενιαία σύγκριση ΟΛΩΝ των μοντέλων
│   └── detection_engine.py        #   κοινή μηχανή ανίχνευσης (χωρίς Ryu)
├── simulation/                    # === ΜΕΘΟΔΟΣ Α (Mininet, Linux) ===
│   ├── topology.py                #   τοπολογία 6 hosts + 1 switch
│   ├── topology_multi.py          #   2η εκδοχή: tree, 3 switches (core+edge)
│   ├── traffic_normal.py          #   νόμιμη κίνηση (iperf/ping)
│   ├── traffic_attack.py          #   επιθέσεις (DDoS/SYN flood/scan/BFA)
│   └── collect_flow_stats.py      #   συλλογή δικού σου dataset σε CSV
├── controller/                    # === ΜΕΘΟΔΟΣ Α (controllers) ===
│   ├── detection_controller.py    #   Ryu: learning switch + live ML + mitigation
│   ├── pox_detection.py           #   2η εκδοχή controller: POX
│   ├── train_live_model.py        #   εκπαίδευση ελαφριού live μοντέλου
│   └── offline_replay.py          #   live detection ΧΩΡΙΣ Mininet (τρέχει παντού)
├── tests/
│   ├── test_pipeline.py           #   11 αυτοματοποιημένα tests (pytest)
│   └── test_app_sdn.py            #   7 tests για το application-level SDN
├── app_sdn/                       # === ΑΡΧΙΤΕΚΤΟΝΙΚΗ ΔΙΠΛΩΜΑΤΙΚΗΣ (microservices) ===
│   ├── controller.py              #   Control Plane + Defense Plane (Flask + Isolation Forest)
│   ├── switch.py                  #   Data Plane (application-level overlay, UDP sockets)
│   ├── dashboard.py               #   Management Plane (Dash/Cytoscape, real-time)
│   ├── train_defense_engine.py    #   εκπαίδευση live Isolation Forest (unsupervised)
│   ├── simulate.py                #   end-to-end προσομοίωση (χωρίς Docker/Mininet)
│   ├── Dockerfile                 #   image για τις υπηρεσίες
│   ├── docker-compose.yml         #   orchestration (controller+dashboard+switch)
│   └── requirements.txt
└── docs/
    ├── thesis_outline.md          #   περίγραμμα θεωρητικού μέρους
    ├── architecture_mapping.md    #   ΧΑΡΤΟΓΡΑΦΗΣΗ κώδικα ↔ αρχιτεκτονικής PDF
    ├── Theoretical_Chapter.docx   #   θεωρητικό μέρος (Κεφ. 1-4)
    └── Results_Chapter.docx       #   πειράματα & αποτελέσματα (Κεφ. 5-7) με γραφήματα
```

### Δύο αρχιτεκτονικές στο ίδιο project
1. **`app_sdn/` — η αρχιτεκτονική της διπλωματικής σου** (application-level SDN Digital Twin): Docker/Flask/sockets + **Isolation Forest (unsupervised)** + Dash/Cytoscape dashboard. Δες `docs/architecture_mapping.md`.
2. **`ml_pipeline/` + `simulation/` + `controller/`** — Mininet/Ryu + **supervised ML**, που χρησιμεύει ως **ακαδημαϊκή σύγκριση** (επιβλεπόμενη vs μη επιβλεπόμενη ανίχνευση) και για τα θεωρητικά κεφάλαια.

### Γρήγορη εκκίνηση (μία εντολή, οποιοδήποτε OS)
```bash
pip install -r requirements.txt
bash run_all.sh            # ML + DL + CV/ROC + offline demo, βγάζει όλα τα γραφήματα
pytest tests/ -v           # επιβεβαίωση ότι όλα δουλεύουν (18 tests)
```

### Εκτέλεση με το ΠΡΑΓΜΑΤΙΚΟ InSDN dataset
```bash
# 1. Προετοίμασε το InSDN (ένωση 3 CSV + κανονικοποίηση -> data/InSDN_dataset.csv)
python3 ml_pipeline/prepare_insdn.py --src /διαδρομή/InSDN_DatasetCSV
# 2. Τρέξε τα μοντέλα στα πραγματικά δεδομένα
python3 ml_pipeline/train.py --insdn
python3 ml_pipeline/isolation_forest_detector.py --insdn
```

### Αποτελέσματα στο ΠΡΑΓΜΑΤΙΚΟ InSDN (343.516 ροές, 5 κλάσεις)
| Μοντέλο | Accuracy | F1 (macro) |
|---|---|---|
| **Random Forest** | **0.989** | **0.948** |
| Decision Tree | 0.988 | 0.948 |
| KNN | 0.988 | 0.947 |
| MLP (Neural Net) | 0.976 | 0.860 |
| SVM (RBF) | 0.947 | 0.833 |
| Logistic Regression | 0.897 | 0.704 |
| **Isolation Forest** (unsupervised, μόνο σε normal) | — | **ROC AUC 0.93** |

Σημαντικό εύρημα: τα network flow features είναι **log-normal**· ο λογαριθμικός μετασχηματισμός (`log1p`) ανεβάζει το Isolation Forest από **AUC 0.70 → 0.93** στα πραγματικά δεδομένα. Το BFA είναι η δυσκολότερη κλάση (F1≈0.71) λόγω ελάχιστων δειγμάτων (1.405 από 343k).

### Δύο εκδοχές ανά μέθοδο (όπως ζητήθηκε)
| | Εκδοχή 1 | Εκδοχή 2 |
|---|---|---|
| **Μέθοδος Β (ML)** | Κλασικά μοντέλα (`train.py`) | Deep Learning (`deep_learning.py`) |
| **Μέθοδος Α (controller)** | Ryu (`detection_controller.py`) | POX (`pox_detection.py`) |
| **Μέθοδος Α (τοπολογία)** | Single-switch (`topology.py`) | Multi-switch tree (`topology_multi.py`) |
| **Live detection** | Σε Linux/Mininet | Offline, παντού (`offline_replay.py`) |

---

## 2. Μέθοδος Β — Offline ML (τρέχει σε ΟΠΟΙΟΔΗΠΟΤΕ OS)

### Εγκατάσταση
```bash
pip install -r requirements.txt
```

### Εκτέλεση (με τα συνθετικά δεδομένα — άμεσα)
```bash
python3 ml_pipeline/generate_synthetic_dataset.py   # φτιάχνει data/sdn_flows_synthetic.csv
python3 ml_pipeline/evaluate.py                      # εκπαιδεύει, συγκρίνει, βγάζει γραφήματα
```
Παράγονται στο `results/`:
- `model_comparison.png` — σύγκριση Accuracy/Precision/Recall/F1 ανά μοντέλο
- `confusion_matrix.png` — confusion matrix του καλύτερου μοντέλου
- `feature_importance.png` — σημαντικότητα χαρακτηριστικών (Random Forest)
- `classification_report.txt` — αναλυτικές μετρικές ανά κλάση
- `model_comparison.csv` — πίνακας αποτελεσμάτων

### Εκτέλεση με το ΠΡΑΓΜΑΤΙΚΟ InSDN dataset
1. Κατέβασε το InSDN (αναζήτησε **"InSDN dataset"** σε Kaggle ή στο
   πανεπιστημιακό repository — TU Dublin) και βάλ' το ως `data/InSDN_dataset.csv`.
2. Άνοιξε το `ml_pipeline/preprocess.py` → συνάρτηση `load_insdn()` και
   προσάρμοσε το `label_map` στα πραγματικά ονόματα κλάσεων του dataset.
3. Τρέξε:
   ```bash
   python3 ml_pipeline/evaluate.py --insdn
   ```

> **Σημείωση για τη διπλωματική:** Τα συνθετικά δεδομένα χρησιμεύουν για την
> *ανάπτυξη και επίδειξη* του pipeline (γι' αυτό τα ποσοστά είναι πολύ υψηλά —
> οι κλάσεις έχουν καθαρές υπογραφές). Τα **τελικά αποτελέσματα** της εργασίας
> πρέπει να προέλθουν από το πραγματικό InSDN ή από τα δεδομένα της δικής σου
> προσομοίωσης (μέθοδος Α), όπου υπάρχει ρεαλιστική επικάλυψη κλάσεων.

---

## 3. Μέθοδος Α — Live προσομοίωση (απαιτεί LINUX)

> Το Mininet τρέχει μόνο σε Linux. Σε Windows/Mac χρησιμοποίησε **Ubuntu VM**
> (VirtualBox) — υπάρχει και έτοιμο Mininet VM image.

### Εγκατάσταση (μέσα στο Ubuntu VM)
```bash
sudo apt update
sudo apt install mininet hping3 nmap iperf
pip install ryu scikit-learn pandas numpy joblib
# (εναλλακτικά για συντηρούμενο controller: pip install os-ken)
```

### Ροή εκτέλεσης

**Βήμα 1 — Εκπαίδευσε το live μοντέλο** (μία φορά):
```bash
python3 controller/train_live_model.py
# -> models/live_model.pkl, models/live_scaler.pkl
```

**Βήμα 2 — Ξεκίνα τον controller** (Τερματικό 1):
```bash
ryu-manager controller/detection_controller.py
```

**Βήμα 3 — Ξεκίνα την τοπολογία** (Τερματικό 2):
```bash
sudo python3 simulation/topology.py
```

**Βήμα 4 — Παρήγαγε κίνηση** (από το Mininet CLI ή ξεχωριστά):
```bash
# νόμιμη κίνηση
sudo python3 simulation/traffic_normal.py
# επιθέσεις (DDoS, SYN flood, port scan, brute force)
sudo python3 simulation/traffic_attack.py
```

Στα logs του controller θα δεις:
```
[DETECT] ΕΠΙΘΕΣΗ από 10.0.0.6 | flows=130 pkts=... -> ΜΠΛΟΚΑΡΙΣΜΑ
[MITIGATE] Εγκαταστάθηκε DROP-rule για 10.0.0.6 (60s)
```

### (Προαιρετικά) Φτιάξε το ΔΙΚΟ σου dataset από την προσομοίωση
```bash
# Τρέξε με ετικέτα Normal ενώ παράγεις νόμιμη κίνηση:
FLOW_LABEL=Normal ryu-manager simulation/collect_flow_stats.py
# Μετά με ετικέτα Attack ενώ τρέχεις επιθέσεις:
FLOW_LABEL=Attack ryu-manager simulation/collect_flow_stats.py
# Εκπαίδευσε το live μοντέλο στα δικά σου δεδομένα:
python3 controller/train_live_model.py --collected
```

---

## 4. Τι δείχνει η εργασία (αφήγηση)

1. **Θεωρία**: αρχιτεκτονική SDN, control/data plane, OpenFlow, απειλές
   (DoS/DDoS στον controller, flow-rule injection, υποκλοπή).
2. **Πρόβλημα**: γιατί οι παραδοσιακές μέθοδοι υστερούν → ανάγκη για ML.
3. **Μέθοδος Β**: εκπαίδευση & σύγκριση μοντέλων ML σε δεδομένα ροών.
4. **Μέθοδος Α**: ενσωμάτωση του μοντέλου σε live SDN controller, ανίχνευση
   σε πραγματικό χρόνο και **αυτόματη αντιμετώπιση** (drop-rules).
5. **Αξιολόγηση**: μετρικές (accuracy/precision/recall/F1), χρόνος ανίχνευσης,
   επίδραση του mitigation στην κίνηση.

---

## 5. Ηθική / νομική σημείωση
Τα εργαλεία επιθέσεων (`hping3`, `nmap`) χρησιμοποιούνται **αποκλειστικά** μέσα
στο απομονωμένο εικονικό εργαστήριο Mininet, ως μέρος **αμυντικής** έρευνας.
Δεν επιτρέπεται η χρήση τους σε πραγματικά δίκτυα ή συστήματα χωρίς ρητή άδεια.
