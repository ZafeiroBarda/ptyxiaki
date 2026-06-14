# Περίγραμμα Διπλωματικής — Θεωρητικό & Πρακτικό Μέρος

> Προτεινόμενη δομή κεφαλαίων για ~2 μήνες εργασίας. Κάθε κεφάλαιο συνδέεται
> με συγκεκριμένα παραδοτέα του κώδικα.

## Κεφάλαιο 1 — Εισαγωγή
- Πλαίσιο & κίνητρο: γιατί η ασφάλεια SDN είναι κρίσιμη.
- Στόχοι εργασίας (ανίχνευση + αντιμετώπιση με Python/ML).
- Συνεισφορά & δομή της εργασίας.

## Κεφάλαιο 2 — Υπόβαθρο στα SDN
- Παραδοσιακά δίκτυα vs SDN.
- Διαχωρισμός control plane / data plane.
- Αρχιτεκτονική: εφαρμογές, northbound/southbound APIs, controller.
- Πρωτόκολλο **OpenFlow** (flow tables, match-action, flow stats).
- Controllers: Ryu, POX, ONOS, OpenDaylight — γιατί επιλέχθηκε ο Ryu (Python,
  ακαδημαϊκή χρήση). Αναφορά στο os-ken ως συντηρούμενο fork.

## Κεφάλαιο 3 — Απειλές & επιθέσεις σε SDN
- Επιφάνεια επίθεσης ανά επίπεδο (application/control/data plane).
- **DoS/DDoS** εναντίον του controller (κορεσμός flow table, control channel).
- **Flow-rule injection** / πλαστοί κανόνες ροής.
- Υποκλοπή πακέτων, spoofing, topology poisoning.
- Port scanning / probing, brute force.
- Γιατί ο κεντρικός controller είναι single point of failure.

## Κεφάλαιο 4 — Μέθοδοι ανίχνευσης
- Παραδοσιακές (signature-based, threshold-based) και οι αδυναμίες τους.
- Ανίχνευση βασισμένη σε **Μηχανική Μάθηση**: επιβλεπόμενη ταξινόμηση ροών.
- Επισκόπηση αλγορίθμων: Decision Tree, Random Forest, SVM, KNN, MLP.
- Δημόσια datasets: **InSDN**, CICDDoS2019, NSL-KDD — γιατί το InSDN είναι
  ειδικό για SDN.
- Χαρακτηριστικά ροής (flow features) & ο ρόλος του CICFlowMeter.

## Κεφάλαιο 5 — Μεθοδολογία & υλοποίηση
### 5.1 Μέθοδος Β (offline ML)  →  φάκελος `ml_pipeline/`
- Περιγραφή dataset & χαρακτηριστικών (`config.py`).
- Προεπεξεργασία: καθαρισμός, κωδικοποίηση, κανονικοποίηση, split (`preprocess.py`).
- Εκπαίδευση & σύγκριση 6 μοντέλων (`train.py`).
- Μετρικές & γραφήματα (`evaluate.py`).
### 5.2 Μέθοδος Α (live προσομοίωση)  →  φάκελοι `simulation/`, `controller/`
- Τοπολογία Mininet (`topology.py`).
- Παραγωγή νόμιμης & κακόβουλης κίνησης (`traffic_normal.py`, `traffic_attack.py`).
- Συλλογή χαρακτηριστικών από flow-stats (`collect_flow_stats.py`).
- Live μοντέλο & aggregate features (`train_live_model.py`).
- Ενσωμάτωση στον controller: ανίχνευση + **αντιμετώπιση** με drop-rules
  (`detection_controller.py`).

## Κεφάλαιο 6 — Πειράματα & αποτελέσματα
- Πειραματική διάταξη (VM specs, εκδόσεις λογισμικού).
- Σύγκριση μοντέλων (πίνακας + γραφήματα).
- Confusion matrix & ανάλυση ανά κλάση επίθεσης.
- Σημαντικότητα χαρακτηριστικών.
- Live σενάριο: χρόνος ανίχνευσης, επιτυχία mitigation, false positives.

## Κεφάλαιο 7 — Συμπεράσματα & μελλοντική εργασία
- Σύνοψη ευρημάτων.
- Περιορισμοί (π.χ. live features < offline features, single switch).
- Επεκτάσεις: deep learning (LSTM/CNN), κατανεμημένοι controllers,
  adversarial robustness, πραγματικά testbeds.

## Βιβλιογραφία (ενδεικτικές κατηγορίες πηγών)
- Πρωτογενείς: OpenFlow spec, τεκμηρίωση Ryu/Mininet.
- Datasets: δημοσίευση InSDN.
- Έρευνα: papers ML-based IDS για SDN (RF/SVM/DL), DDoS detection σε SDN.

---

### Χρονοδιάγραμμα 2 μηνών (πρόταση)
- **Εβδ. 1–2:** Θεωρία (Κεφ. 1–3) + στήσιμο VM/Mininet/Ryu.
- **Εβδ. 3–4:** Μέθοδος Β — InSDN, εκπαίδευση/σύγκριση μοντέλων (Κεφ. 4–5.1).
- **Εβδ. 5–6:** Μέθοδος Α — προσομοίωση, controller, mitigation (Κεφ. 5.2).
- **Εβδ. 7:** Πειράματα & γραφήματα (Κεφ. 6).
- **Εβδ. 8:** Συγγραφή, διόρθωση, συμπεράσματα (Κεφ. 7), παρουσίαση.
