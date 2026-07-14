#!/usr/bin/env bash
###############################################################################
# reproduce_thesis.sh — ΠΛΗΡΗΣ αναπαραγωγή ΟΛΩΝ των αποτελεσμάτων του κειμένου.
#
# Το run_all.sh τρέχει μόνο τον βασικό κορμό (dataset, κλασικά μοντέλα, CV,
# τελική σύγκριση, adversarial training). ΔΕΝ έτρεχε τις μελέτες leakage,
# easy/hard, hyperparameter tuning, Isolation Forest και SHAP, παρότι τα
# αποτελέσματά τους παρουσιάζονται στο κείμενο. Εδώ εκτελούνται ΟΛΑ ρητά.
#
# Χρήση:
#   bash reproduce_thesis.sh              # συνθετικό dataset (επίσημα αποτελέσματα)
#   bash reproduce_thesis.sh --insdn      # με το πραγματικό InSDN
#
# Το packet-level πείραμα (Mininet + OVS) απαιτεί Docker και τρέχει ΞΕΧΩΡΙΣΤΑ:
#   bash run_packet_level_experiment.sh
###############################################################################
set -e
cd "$(dirname "$0")"

FLAG="${1:-}"
MISSING=()

have() { python3 -c "import $1" 2>/dev/null; }

echo "==================================================================="
echo " ΕΛΕΓΧΟΣ ΠΡΟΑΙΡΕΤΙΚΩΝ ΕΞΑΡΤΗΣΕΩΝ"
echo "==================================================================="
for mod in tensorflow xgboost shap; do
    if have "$mod"; then
        echo "  [OK]      $mod"
    else
        echo "  [ΛΕΙΠΕΙ]  $mod"
        MISSING+=("$mod")
    fi
done

echo ""
echo "==================================================================="
echo " ΜΕΡΟΣ 1/3 — Βασικός κορμός (run_all.sh)"
echo "==================================================================="
bash run_all.sh $FLAG

echo ""
echo "==================================================================="
echo " ΜΕΡΟΣ 2/3 — Μελέτες που ΔΕΝ κάλυπτε το run_all.sh"
echo "==================================================================="

echo ">>> Μελέτη διαρροής δεδομένων (duplicates, group-aware split)"
python3 ml_pipeline/leakage_study.py $FLAG

echo ">>> Σύγκριση easy/hard εκδοχής του συνθετικού συνόλου"
python3 ml_pipeline/synthetic_mode_study.py

echo ">>> Βελτιστοποίηση υπερπαραμέτρων"
python3 ml_pipeline/hyperparameter_tuning.py $FLAG

echo ">>> Isolation Forest (μοντέλο του ζωντανού συστήματος)"
python3 ml_pipeline/isolation_forest_detector.py $FLAG

if have shap; then
    echo ">>> Ερμηνευσιμότητα (SHAP)"
    python3 ml_pipeline/shap_analysis.py $FLAG
else
    echo ">>> ΠΑΡΑΛΕΙΨΗ SHAP (λείπει το shap): pip install shap"
fi

echo ""
echo "==================================================================="
echo " ΜΕΡΟΣ 3/3 — Ανάλυση καθυστέρησης και αντιμετώπισης"
echo "==================================================================="
python3 ml_pipeline/latency_analysis.py
python3 ml_pipeline/mitigation_analysis.py

echo ""
echo "==================================================================="
if [ ${#MISSING[@]} -eq 0 ]; then
    echo " ΟΛΟΚΛΗΡΩΘΗΚΕ — αναπαράχθηκαν ΟΛΑ τα αποτελέσματα του κειμένου."
else
    echo " ΟΛΟΚΛΗΡΩΘΗΚΕ ΜΕΡΙΚΩΣ."
    echo " Λείπουν οι εξής προαιρετικές εξαρτήσεις: ${MISSING[*]}"
    echo " Τα αντίστοιχα αποτελέσματα ΔΕΝ αναπαράχθηκαν:"
    for m in "${MISSING[@]}"; do
        case "$m" in
            tensorflow) echo "   - Deep Learning (MLP, 1D-CNN): pip install tensorflow" ;;
            xgboost)    echo "   - Extended ML (XGBoost): pip install xgboost" ;;
            shap)       echo "   - Ερμηνευσιμότητα (SHAP): pip install shap" ;;
        esac
    done
fi
echo "==================================================================="
echo " Αποτελέσματα: results/    Το packet-level πείραμα: run_packet_level_experiment.sh"
