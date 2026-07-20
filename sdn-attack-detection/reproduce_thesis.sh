#!/usr/bin/env bash
###############################################################################
# reproduce_thesis.sh — ΠΛΗΡΗΣ offline αναπαραγωγή για το επιλεγμένο dataset.
#
# ΠΕΔΙΟ: εκτελεί ΟΛΟ το OFFLINE workflow (dataset, κλασικά μοντέλα, CV, leakage,
# easy/hard, hyperparameter tuning, offline Isolation Forest, SHAP, adversarial
# training) για ΕΝΑ dataset τη φορά. ΔΕΝ αναπαράγει τα packet-level πειράματα.
#
# ΠΡΟΣΟΧΗ:
#   * Χωρίς flag τρέχει το synthetic offline workflow, με --insdn το InSDN workflow.
#     Το --insdn είναι εκτέλεση ΑΞΙΟΛΟΓΗΣΗΣ και ΔΕΝ αντικαθιστά τα deployable
#     synthetic artifacts (βλ. train.py). Τα offline IF artifacts φέρουν επίθεμα
#     dataset (_synthetic/_insdn), ώστε οι δύο εκτελέσεις να μη συγκρούονται.
#   * Το offline Isolation Forest (24 χαρακτηριστικά) ΔΕΝ είναι το ίδιο artifact με
#     το deployed live μοντέλο (8 συγκεντρωτικά χαρακτηριστικά, app_sdn/train_defense_engine.py).
#
# Χρήση:
#   bash reproduce_thesis.sh              # συνθετικό dataset (επίσημα offline αποτελέσματα)
#   bash reproduce_thesis.sh --insdn      # με το πραγματικό InSDN (αξιολόγηση)
#
# Τα packet-level πειράματα (Mininet + OVS) απαιτούν Docker και τρέχουν ΞΕΧΩΡΙΣΤΑ:
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

echo ">>> Isolation Forest (OFFLINE, 24 χαρακτηριστικά — ΟΧΙ το deployed live μοντέλο)"
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
