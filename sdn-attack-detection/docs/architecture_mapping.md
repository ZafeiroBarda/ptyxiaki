# Χαρτογράφηση Υλοποίησης ↔ Αρχιτεκτονικής Διπλωματικής

Αυτό το έγγραφο δείχνει πώς ο κώδικας του `app_sdn/` υλοποιεί ΑΚΡΙΒΩΣ την
αρχιτεκτονική microservices που περιγράφεται στη διπλωματική (SDN Digital Twin).

## Τα τέσσερα επίπεδα (Planes)

| Επίπεδο (από το PDF) | Τεχνολογία (PDF) | Αρχείο υλοποίησης |
|---|---|---|
| **Data Plane** | Application-level overlay, UDP sockets | `app_sdn/switch.py` |
| **Control Plane** | Python/Flask, Global Network View, Flow Table | `app_sdn/controller.py` |
| **Intelligence & Defense Plane** | Isolation Forest | `app_sdn/controller.py` (κλάση `DefenseEngine`) + `app_sdn/train_defense_engine.py` |
| **Management Plane** | Dash / Cytoscape.js | `app_sdn/dashboard.py` |
| **Orchestration** | Docker Compose | `app_sdn/docker-compose.yml` + `app_sdn/Dockerfile` |

## Αντιστοίχιση εννοιών του PDF με τον κώδικα

| Έννοια στο PDF | Πού υλοποιείται |
|---|---|
| Global Network View (γράφος G=(V,E)) | κλάση `GlobalNetworkView` (nodes=V, flows=E) |
| Flow Table (δυναμική διαχείριση) | κλάση `FlowTable` (install/expire κανόνων FORWARD/DROP) |
| Feature Engineering (packet rate, byte rate → vectors) | `detection_engine.aggregate_features()` |
| Isolation Forest, ανίχνευση outliers με f(x) < 0 | `DefenseEngine.analyze()` (`iso.predict() == -1`) |
| Automated Mitigation (drop κακόβουλης ροής) | `controller._mitigate` → `FlowTable.install(DROP)` |
| Real-time Feedback / callbacks dashboard | `dashboard.update()` με `dcc.Interval` |
| RESTful API Switch↔Controller (προσομοιώνει OpenFlow) | endpoints `/register`, `/telemetry`, `/flow_table` |
| Infrastructure as Code | `docker-compose.yml` (controller, dashboard, switch) |

## Μεθοδολογία (Κεφ. 5 του PDF) ↔ ροή εκτέλεσης

Ο κύκλος που περιγράφεις (**Data Collection → Model Training → Real-time
Inference → Automated Mitigation**) υλοποιείται ως εξής:

1. **Data Collection** — `switch.py` συλλέγει στατιστικά ανά πηγή IP.
2. **Model Training** — `train_defense_engine.py` εκπαιδεύει το Isolation Forest
   ΜΟΝΟ σε φυσιολογική κίνηση (unsupervised, χωρίς ετικέτες — όπως ορίζεις).
3. **Real-time Inference** — `controller.py` (`/telemetry`) τρέχει το `f(x)` σε
   κάθε παράθυρο και αποφασίζει Normal/Attack.
4. **Automated Mitigation** — με `f(x) < 0` εγκαθίσταται κανόνας DROP στο Flow Table.

## Σενάρια επιθέσεων (Κεφ. 4 του PDF)

| Σενάριο (PDF) | Κάλυψη στην υλοποίηση |
|---|---|
| Flow Table Exhaustion (DDoS) | `simulate.py` → `attack_burst` (πολλές μικρο-ροές) ✅ |
| Network Reconnaissance (Port/IP Scan) | ίδια υπογραφή: υψηλό flow_count + short_ratio ✅ |
| Lateral Movement | επεκτείνεται με πολλαπλές πηγές-στόχους (μελλοντικό) |
| Data Exfiltration | ανιχνεύσιμο ως ασυνήθιστος όγκος εξόδου (μελλοντικό) |
| MitM (ARP/Flow spoofing) | απαιτεί έλεγχο ακεραιότητας ροών (μελλοντικό) |

## Τι από το προηγούμενο υλικό (Mininet/Ryu) παραμένει χρήσιμο

Παρότι η δική σου αρχιτεκτονική είναι application-level (Docker/Flask), τα εξής
από την προηγούμενη υλοποίηση παραμένουν άμεσα αξιοποιήσιμα στη διπλωματική:

- Το **offline ML κομμάτι** (`ml_pipeline/`) ως **σύγκριση επιβλεπόμενης vs μη
  επιβλεπόμενης** ανίχνευσης: το Isolation Forest (unsupervised) έναντι Random
  Forest/SVM/Deep Learning (supervised). Αυτή η σύγκριση είναι ισχυρό ακαδημαϊκό
  εύρημα για το κεφάλαιο αποτελεσμάτων.
- Τα **θεωρητικά κεφάλαια** (SDN, OpenFlow, απειλές, μέθοδοι ανίχνευσης).
- Η **μηχανή ανίχνευσης** (`detection_engine.py`) — κοινή και στις δύο αρχιτεκτονικές.
- Τα **γραφήματα αξιολόγησης** (confusion matrix, ROC, κατανομή anomaly score).

## Γρήγορη εκτέλεση όλης της νέας αρχιτεκτονικής

```bash
# 1. Εκπαίδευση Defense Engine (Isolation Forest, unsupervised)
python3 app_sdn/train_defense_engine.py

# 2α. Όλα μαζί, τοπικά (χωρίς Docker) — προσομοίωση end-to-end:
python3 app_sdn/simulate.py

# 2β. Ή με πραγματικά microservices (Docker Compose):
docker compose -f app_sdn/docker-compose.yml up --build
#   dashboard: http://localhost:8050
```
