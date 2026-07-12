# Δεδομένα

Ο φάκελος αυτός ΔΕΝ περιλαμβάνεται πλήρης στο zip παράδοσης λόγω μεγέθους.
Τα datasets αναπαράγονται ως εξής:

## 1. Συνθετικό dataset (`sdn_flows_synthetic.csv`)

Παράγεται ντετερμινιστικά (σταθερό seed):

```bash
python3 ml_pipeline/generate_synthetic_dataset.py          # καθαρές υπογραφές (easy)
python3 ml_pipeline/generate_synthetic_dataset.py --hard   # με θόρυβο/επικάλυψη
```

Τα αποτελέσματα του κειμένου (Πίνακες 9, 10, 13, Παράρτημα Β) αντιστοιχούν
στην **προεπιλεγμένη (easy)** εκδοχή.

## 2. Πραγματικό dataset InSDN (`InSDN_dataset.csv`)

Το InSDN (Elsayed et al., 2020) διατίθεται δωρεάν:
https://aseados.ucd.ie/datasets/SDN/

Κατέβασε τα CSV και ενοποίησέ τα:

```bash
python3 ml_pipeline/prepare_insdn.py   # -> data/InSDN_dataset.csv (343.516 ροές)
```

## 3. Live ροές (`live_mininet_flows.csv`)

Παράγεται αυτόματα από το live demo (docker compose + Mininet) — δεν
χρειάζεται να υπάρχει εκ των προτέρων.
