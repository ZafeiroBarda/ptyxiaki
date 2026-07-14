# Ανίχνευση και Αντιμετώπιση Επιθέσεων σε Δίκτυα Οριζόμενα από Λογισμικό (SDN)

Διπλωματική εργασία — υλοποίηση σε **Python**. Το έργο καλύπτει δύο
συμπληρωματικές προσεγγίσεις:

- **Μέθοδος Α — Live ανίχνευση & αντιμετώπιση** σε **Mininet / Open vSwitch**,
  με **υβριδικό Flask-based controller** (η τελική αρχιτεκτονική της
  διπλωματικής) και **προαιρετικό Ryu/OpenFlow profile**, με αυτόματο
  μπλοκάρισμα της επίθεσης.
- **Μέθοδος Β — Offline ανίχνευση με Μηχανική Μάθηση** σε δημόσιο dataset
  (τύπου **InSDN**, δομή CICFlowMeter). Εκπαίδευση & σύγκριση πολλών μοντέλων.

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
bash reproduce_thesis.sh   # ΠΛΗΡΗΣ αναπαραγωγή· bash run_all.sh για μόνο τον κορμό ML/DL/CV/adversarial
pytest tests/ -v           # 140 tests: 133 pass, 7 skip χωρίς Docker/προαιρετικές εξαρτήσεις
```
Λεπτομέρειες αναπαραγωγιμότητας: **§6**.

### Εκτέλεση με το ΠΡΑΓΜΑΤΙΚΟ InSDN dataset
```bash
# 1. Προετοίμασε το InSDN (ένωση 3 CSV + κανονικοποίηση -> data/InSDN_dataset.csv)
python3 ml_pipeline/prepare_insdn.py --src /διαδρομή/InSDN_DatasetCSV
# 2. Τρέξε τα μοντέλα στα πραγματικά δεδομένα
python3 ml_pipeline/train.py --insdn
python3 ml_pipeline/isolation_forest_detector.py --insdn
```

### Αποτελέσματα στο ΠΡΑΓΜΑΤΙΚΟ InSDN (343.516 ροές, 5 κλάσεις)
Πηγή: `results/model_comparison_insdn.csv` (`bash run_all.sh --insdn`).

| Μοντέλο | Accuracy | F1 (macro) | Χρόνος πρόβλεψης |
|---|---|---|---|
| KNN | 0.9898 | **0.9523** | 11,9 s |
| **Random Forest** | **0.9899** | 0.9446 | **0,08 s** |
| Decision Tree | 0.9893 | 0.9435 | 0,01 s |
| MLP (Neural Net) | 0.9740 | 0.9306 | 0,04 s |
| SVM (RBF) | 0.9386 | 0.8322 | 85,2 s |
| Logistic Regression | 0.9107 | 0.7289 | 0,01 s |
| **Isolation Forest** (unsupervised, μόνο σε normal) | — | F1 0.804 | ROC-AUC **0.930** |

Ο KNN έχει οριακά υψηλότερο macro-F1, αλλά ~150× μεγαλύτερο χρόνο πρόβλεψης·
το **Random Forest** παραμένει η πρακτικά προτιμότερη επιλογή για ανάπτυξη σε
ελεγκτή SDN, και έτσι το τεκμηριώνει το κείμενο.

Σημαντικό εύρημα: τα network flow features είναι **log-normal**· ο λογαριθμικός μετασχηματισμός (`log1p`) ανεβάζει το Isolation Forest από **AUC 0.70 → 0.93** στα πραγματικά δεδομένα. Το BFA είναι η δυσκολότερη κλάση (F1≈0.71) λόγω ελάχιστων δειγμάτων (1.405 από 343k).

> **Περιορισμός (δηλώνεται και στο κείμενο):** το 47,5% των εγγραφών του InSDN
> είναι ακριβή διπλότυπα σε επίπεδο διανύσματος χαρακτηριστικών (98,8% στην
> κλάση DDoS), κάτι εγγενές στις επιθέσεις πλημμύρας. Με τυχαίο διαχωρισμό,
> πανομοιότυπα διανύσματα εμφανίζονται σε train και test, γεγονός που ευνοεί
> την απομνημόνευση και ανεβάζει την ορθότητα. Γι' αυτό το **macro-F1** είναι
> το αντιπροσωπευτικό μέτρο, όχι το accuracy.

### Δύο εκδοχές ανά μέθοδο (όπως ζητήθηκε)
| | Εκδοχή 1 | Εκδοχή 2 |
|---|---|---|
| **Μέθοδος Α (controller)** | Ryu (`detection_controller.py`) | POX (`pox_detection.py`) |
| **Μέθοδος Α (τοπολογία)** | Single-switch (`topology.py`) | Multi-switch tree (`topology_multi.py`) |
| **Μέθοδος Β (ML)** | Κλασικά μοντέλα (`train.py`) | Deep Learning (`deep_learning.py`) |
| **Live detection** | Σε Linux/Mininet | Offline, παντού (`offline_replay.py`) |

---

## 2. Μέθοδος Α — Live προσομοίωση (απαιτεί LINUX)

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

## 3. Μέθοδος Β — Offline ML (τρέχει σε ΟΠΟΙΟΔΗΠΟΤΕ OS)

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

> **Σημείωση:** τα συνθετικά δεδομένα έχουν καθαρές, μη επικαλυπτόμενες
> υπογραφές ανά κλάση — γι' αυτό τα ποσοστά είναι πολύ υψηλά (RF F1 ≈ 0,9998).
> Το κείμενο το δηλώνει ρητά και δεν τα παρουσιάζει ως ένδειξη γενίκευσης: τα
> **ουσιαστικά** συμπεράσματα στηρίζονται στο πραγματικό **InSDN** (§7) και στα
> ζωντανά σενάρια. Για έλεγχο ευρωστίας υπάρχει η εκδοχή
> `bash run_all.sh --hard` (θόρυβος + επικάλυψη κλάσεων).

---

## 4. Τι δείχνει η εργασία (αφήγηση)

1. **Θεωρία**: αρχιτεκτονική SDN, control/data plane, OpenFlow, απειλές
   (DoS/DDoS στον controller, flow-rule injection, υποκλοπή).
2. **Πρόβλημα**: γιατί οι παραδοσιακές μέθοδοι υστερούν → ανάγκη για ML.
3. **Μέθοδος Α**: ενσωμάτωση του μοντέλου σε live SDN controller, ανίχνευση
   σε πραγματικό χρόνο και **αυτόματη αντιμετώπιση** (drop-rules).
4. **Μέθοδος Β**: εκπαίδευση & σύγκριση μοντέλων ML σε δεδομένα ροών.
5. **Αξιολόγηση**: μετρικές (accuracy/precision/recall/F1), χρόνος ανίχνευσης,
   επίδραση του mitigation στην κίνηση.

---

## 5. Ασφάλεια του demo (tokens & DEFENSE_MODE)

Ο controller προστατεύεται με δύο tokens και rate limiting:

| Μεταβλητή | Προεπιλογή (demo) | Ρόλος |
|---|---|---|
| `SWITCH_API_KEY` | `sdn-secret-2024` | Header `X-Switch-Token` για `/telemetry` |
| `ADMIN_API_KEY` | `sdn-admin-2024` | Header `X-Admin-Token` για `/reset`, `/unblock` |
| `DEFENSE_MODE` | `1` (ενεργό στο compose) | `1` → telemetry χωρίς έγκυρο token απορρίπτεται με 401· `0` → καταγράφεται μόνο ως injection attempt |

> ⚠️ Οι παραπάνω τιμές είναι **demo defaults** για το απομονωμένο εργαστήριο.
> Σε οποιαδήποτε πραγματική χρήση πρέπει να ορίζονται ισχυρά, μυστικά tokens
> μέσω environment variables (ή secrets manager) — ποτέ hardcoded στον κώδικα.

---

## 6. Αναπαραγωγή των επίσημων αποτελεσμάτων

```bash
pip install -r requirements.txt
bash reproduce_thesis.sh          # <- ΠΛΗΡΗΣ αναπαραγωγή ΟΛΩΝ των αποτελεσμάτων
bash run_all.sh                   # μόνο ο βασικός κορμός (ML/DL/CV/adversarial)
bash run_packet_level_experiment.sh   # packet-level πείραμα (Mininet+OVS, απαιτεί Docker)
pytest tests/ -v                  # 140 tests: 133 pass, 7 skip χωρίς Docker/προαιρετικές εξαρτήσεις
```

**Πλήρης έναντι βασικής αναπαραγωγής**: το `bash run_all.sh` τρέχει τον κορμό
(dataset, κλασικά μοντέλα, cross-validation, τελική σύγκριση, adversarial
training). Δεν καλύπτει όμως τις μελέτες διαρροής, easy/hard, ρύθμισης
υπερπαραμέτρων, Isolation Forest και SHAP, των οποίων τα αποτελέσματα
παρουσιάζονται επίσης στο κείμενο. Το **`bash reproduce_thesis.sh`** εκτελεί
ρητά ΟΛΑ αυτά τα βήματα και αναφέρει στο τέλος όποιο βήμα παραλείφθηκε λόγω
προαιρετικής εξάρτησης που λείπει (π.χ. TensorFlow για το Deep Learning). Το
packet-level πείραμα του κεφαλαίου 6 (πραγματικά dropped packets, κάλυψη
αντιμετώπισης) τρέχει ξεχωριστά με το **`bash run_packet_level_experiment.sh`**,
που παράγει `results/live/mininet_run_<ts>/` και προσθέτει τη γραμμή
`packet_level` στο ενιαίο `results/live/experiment_summary.csv`.

Η παραγωγή του συνθετικού dataset είναι ντετερμινιστική (σταθερό seed), οπότε
το `data/sdn_flows_synthetic.csv` αναδημιουργείται **bit-for-bit** — γι' αυτό
δεν συμπεριλαμβάνεται στο zip.

| Εντολή | Dataset | Αντιστοιχεί στο κείμενο; |
|---|---|---|
| `bash run_all.sh` | συνθετικό, προεπιλογή | ✅ ναι — Πίνακες 9, 10, 13, Παράρτημα Β, adversarial |
| `bash run_all.sh --hard` | συνθετικό + θόρυβος/επικάλυψη | ❌ όχι — παραλλαγή **ευρωστίας** (χαμηλότερα, πιο ρεαλιστικά νούμερα) |
| `bash run_all.sh --insdn` | πραγματικό InSDN | ✅ ναι — Πίνακας 12 (χρειάζεται `data/InSDN_dataset.csv`) |

> ⚠️ Η εκδοχή `--hard` προσθέτει 15% θόρυβο και 8% επικάλυψη κλάσεων. Δίνει
> σκόπιμα **διαφορετικά** αποτελέσματα (π.χ. RF F1 ≈ 0,995 αντί 0,9998) και
> μετατοπίζει το adversarial cliff. Χρησιμεύει ως έλεγχος ευρωστίας, **δεν**
> είναι η πηγή των αριθμών του κειμένου.

**Εκδόσεις βιβλιοθηκών**: τα `models/*.pkl` εκπαιδεύτηκαν με scikit-learn 1.9
(καταγεγραμμένο στο `models/meta.json` → `trained_with`). Με παλαιότερη έκδοση
θα δεις `InconsistentVersionWarning`· λύνεται είτε τηρώντας το
`requirements.txt` είτε αναδημιουργώντας τα μοντέλα με `bash run_all.sh`.

**Ακριβής αναπαραγωγιμότητα**: για δεσμευμένες εκδόσεις χρησιμοποίησε το `requirements-lock.txt` (exact pins, π.χ. scikit-learn==1.9.0). Το `MANIFEST.sha256` περιέχει SHA-256 hashes των μοντέλων, του συνθετικού dataset και των κύριων αρχείων αποτελεσμάτων, ώστε να επαληθεύεται η ταυτότητα των artifacts.

---

## 7. Επίσημα αποτελέσματα — αντιστοίχιση με το κείμενο της διπλωματικής

Ο φάκελος `results/` περιέχει και βοηθητικά/εξερευνητικά αρχεία. Τα αρχεία
που αντιστοιχούν **στους πίνακες και τα σχήματα του κειμένου** είναι:

| Στοιχείο κειμένου | Αρχείο | Παράγεται από |
|---|---|---|
| Πίνακας 9 (σύγκριση, συνθετικό) | `results/model_comparison.csv` | `ml_pipeline/evaluate.py` |
| Πίνακας 10 (5-fold CV) | `results/cross_validation.csv` | `ml_pipeline/advanced_eval.py` |
| Πίνακας 12 (σύγκριση, InSDN) | `results/model_comparison_insdn.csv` | `ml_pipeline/evaluate.py --insdn` |
| Πίνακας 13 (Isolation Forest, συνθετικό) | `results/isolation_forest_metrics.csv` | `ml_pipeline/isolation_forest_detector.py` |
| Isolation Forest στο InSDN | `results/isolation_forest_metrics_insdn.csv` | `ml_pipeline/isolation_forest_detector.py --insdn` |
| Παράρτημα Β (IF tuning) | `results/isolation_forest_tuning.csv` | `ml_pipeline/hyperparameter_tuning.py` |
| Adversarial (Original vs Robust RF) | `results/adv_robust_*.csv` | `ml_pipeline/adversarial_training.py` |
| Σχήματα IF confusion/ROC/scores | `results/thesis_if_*.png` | `ml_pipeline/thesis_eval.py` (stratified subsample 60k του InSDN) |
| Live σενάρια (API-level) | `results/live/*.csv` | `run_live_experiments.sh` |
| Πίνακας 6-12 (packet-level κάλυψη, TTL sweep) | `results/live/mininet_run_*/summary.json`, `results/live/experiment_summary.csv` | `run_packet_level_experiment.sh` |

Σημείωση: στο πλήρες InSDN ο KNN πετυχαίνει οριακά υψηλότερο macro-F1 (0,952)
από το Random Forest (0,945), αλλά με χρόνο πρόβλεψης ~150× μεγαλύτερο· το
κείμενο το αναφέρει ρητά και εξηγεί γιατί το Random Forest παραμένει η
πρακτικά προτιμότερη επιλογή. Το `results/thesis_comparison.csv` προέρχεται
από το subsampled setup του `thesis_eval.py` και είναι **συμπληρωματικό** —
δεν είναι η πηγή του Πίνακα 12.

---

## 8. Ρόλος του φακέλου `controller/`

Η **τελική αρχιτεκτονική** της διπλωματικής είναι το υβριδικό μοντέλο
Flask + OVS του `app_sdn/` (application-level SDN). Ο φάκελος `controller/`
(Ryu `detection_controller.py`, POX `pox_detection.py`) τεκμηριώνει την
εναλλακτική/κλασική διαδρομή με OpenFlow controller, η οποία εξετάστηκε και
περιγράφεται στο κείμενο ως σχεδιαστικός συμβιβασμός — δεν αποτελεί την κύρια
υλοποίηση.

---

## 9. Ηθική / νομική σημείωση
Τα εργαλεία επιθέσεων (`hping3`, `nmap`) χρησιμοποιούνται **αποκλειστικά** μέσα
στο απομονωμένο εικονικό εργαστήριο Mininet, ως μέρος **αμυντικής** έρευνας.
Δεν επιτρέπεται η χρήση τους σε πραγματικά δίκτυα ή συστήματα χωρίς ρητή άδεια.
