#!/usr/bin/env bash
###############################################################################
# run_all.sh — Τρέχει ΟΛΟΚΛΗΡΟ το Python pipeline (Μέθοδος Β + offline demo).
#
# Χρήση:
#   bash run_all.sh            # ΕΠΙΣΗΜΗ ΑΝΑΠΑΡΑΓΩΓΗ των αποτελεσμάτων του κειμένου
#                              # (συνθετικό dataset, προεπιλεγμένη εκδοχή)
#   bash run_all.sh --hard     # παραλλαγή ευρωστίας: +θόρυβος & επικάλυψη κλάσεων
#   bash run_all.sh --insdn    # με το πραγματικό InSDN (βάλε data/InSDN_dataset.csv)
#
# ΣΗΜΕΙΩΣΗ ΑΝΑΠΑΡΑΓΩΓΙΜΟΤΗΤΑΣ: η προεπιλεγμένη εκτέλεση αναπαράγει ΑΚΡΙΒΩΣ τους
# πίνακες και τα σχήματα της διπλωματικής. Το συνθετικό dataset παράγεται
# ντετερμινιστικά (σταθερό seed), οπότε το data/sdn_flows_synthetic.csv
# αναδημιουργείται bit-for-bit. Η εκδοχή --hard δίνει ΔΙΑΦΟΡΕΤΙΚΑ (χαμηλότερα,
# πιο ρεαλιστικά) νούμερα και ΔΕΝ αντιστοιχεί στα επίσημα αποτελέσματα.
#
# ΔΕΝ απαιτεί Linux/Mininet — τρέχει σε οποιοδήποτε OS με Python.
###############################################################################
set -e
cd "$(dirname "$0")"

INSDN_FLAG=""
HARD_FLAG=""
case "${1:-}" in
    --insdn)
        INSDN_FLAG="--insdn"
        echo ">>> Λειτουργία: ΠΡΑΓΜΑΤΙΚΟ InSDN dataset"
        ;;
    --hard)
        HARD_FLAG="--hard"
        echo ">>> Λειτουργία: συνθετικά δεδομένα (HARD — θόρυβος/επικάλυψη)"
        echo ">>> ΠΡΟΣΟΧΗ: τα νούμερα ΔΕΝ θα ταυτίζονται με το κείμενο."
        ;;
    "")
        echo ">>> Λειτουργία: συνθετικά δεδομένα (επίσημη αναπαραγωγή του κειμένου)"
        ;;
    *)
        echo "Άγνωστη επιλογή: $1"
        echo "Χρήση: bash run_all.sh [--hard | --insdn]"
        exit 1
        ;;
esac

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 1/8 — Δημιουργία dataset"
echo "==================================================================="
if [ -z "$INSDN_FLAG" ]; then
    python3 ml_pipeline/generate_synthetic_dataset.py $HARD_FLAG
fi

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 2/8 — Εκπαίδευση & σύγκριση κλασικών ML μοντέλων"
echo "==================================================================="
python3 ml_pipeline/evaluate.py $INSDN_FLAG

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 3/8 — Deep Learning (MLP + 1D-CNN)"
echo "==================================================================="
if python3 -c "import tensorflow" 2>/dev/null; then
    python3 ml_pipeline/deep_learning.py $INSDN_FLAG --epochs 30
else
    echo ">>> tensorflow not installed — παράλειψη Deep Learning"
    echo ">>> (προαιρετική εγκατάσταση: pip install tensorflow)"
fi

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 4/8 — Cross-validation & ROC curves"
echo "==================================================================="
python3 ml_pipeline/advanced_eval.py $INSDN_FLAG

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 5/8 — Τελική συγκεντρωτική σύγκριση"
echo "==================================================================="
python3 ml_pipeline/final_comparison.py $INSDN_FLAG

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 6/8 — Live μοντέλο + offline demo ανίχνευσης/mitigation"
echo "==================================================================="
python3 controller/train_live_model.py
python3 controller/offline_replay.py --windows 30

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 7/8 — Extended ML comparison (XGBoost / Autoencoder / ablation)"
echo "==================================================================="
if python3 -c "import xgboost" 2>/dev/null; then
    python3 ml_pipeline/extended_eval.py $INSDN_FLAG
else
    echo ">>> xgboost not installed — τρέχω thesis_eval.py αντί"
    python3 ml_pipeline/thesis_eval.py $INSDN_FLAG
fi

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 8/8 — Adversarial training (Original vs Robust RF)"
echo "==================================================================="
python3 ml_pipeline/adversarial_training.py

echo ""
echo "==================================================================="
echo " ΟΛΟΚΛΗΡΩΘΗΚΕ! Όλα τα αποτελέσματα & γραφήματα στον φάκελο results/"
echo "==================================================================="
ls -1 results/
