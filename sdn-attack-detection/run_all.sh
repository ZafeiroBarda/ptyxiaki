#!/usr/bin/env bash
###############################################################################
# run_all.sh — Τρέχει ΟΛΟΚΛΗΡΟ το Python pipeline (Μέθοδος Β + offline demo).
#
# Χρήση:
#   bash run_all.sh            # με συνθετικά δεδομένα (hard mode)
#   bash run_all.sh --insdn    # με το πραγματικό InSDN (βάλε data/InSDN_dataset.csv)
#
# ΔΕΝ απαιτεί Linux/Mininet — τρέχει σε οποιοδήποτε OS με Python.
###############################################################################
set -e
cd "$(dirname "$0")"

INSDN_FLAG=""
if [ "$1" == "--insdn" ]; then
    INSDN_FLAG="--insdn"
    echo ">>> Λειτουργία: ΠΡΑΓΜΑΤΙΚΟ InSDN dataset"
else
    echo ">>> Λειτουργία: συνθετικά δεδομένα (hard mode)"
fi

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 1/6 — Δημιουργία dataset"
echo "==================================================================="
if [ -z "$INSDN_FLAG" ]; then
    python3 ml_pipeline/generate_synthetic_dataset.py --hard
fi

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 2/6 — Εκπαίδευση & σύγκριση κλασικών ML μοντέλων"
echo "==================================================================="
python3 ml_pipeline/evaluate.py $INSDN_FLAG

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 3/6 — Deep Learning (MLP + 1D-CNN)"
echo "==================================================================="
python3 ml_pipeline/deep_learning.py $INSDN_FLAG --epochs 30

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 4/6 — Cross-validation & ROC curves"
echo "==================================================================="
python3 ml_pipeline/advanced_eval.py $INSDN_FLAG

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 5/6 — Τελική συγκεντρωτική σύγκριση"
echo "==================================================================="
python3 ml_pipeline/final_comparison.py $INSDN_FLAG

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 6/6 — Live μοντέλο + offline demo ανίχνευσης/mitigation"
echo "==================================================================="
python3 controller/train_live_model.py
python3 controller/offline_replay.py --windows 30

echo ""
echo "==================================================================="
echo " ΒΗΜΑ 7/7 — Extended ML comparison (XGBoost / Autoencoder / ablation)"
echo "==================================================================="
if python3 -c "import xgboost" 2>/dev/null; then
    python3 ml_pipeline/extended_eval.py $INSDN_FLAG
else
    echo ">>> xgboost not installed — τρέχω thesis_eval.py αντί"
    python3 ml_pipeline/thesis_eval.py $INSDN_FLAG
fi

echo ""
echo "==================================================================="
echo " ΟΛΟΚΛΗΡΩΘΗΚΕ! Όλα τα αποτελέσματα & γραφήματα στον φάκελο results/"
echo "==================================================================="
ls -1 results/
