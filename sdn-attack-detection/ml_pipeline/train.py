"""
train.py
--------
Εκπαιδεύει & συγκρίνει πολλαπλά μοντέλα Μηχανικής Μάθησης για ανίχνευση
επιθέσεων σε SDN, και αποθηκεύει το καλύτερο μαζί με τον scaler & τον encoder.

Μοντέλα (τα πιο διαδεδομένα στη βιβλιογραφία SDN IDS):
  - Random Forest
  - Decision Tree
  - K-Nearest Neighbors
  - SVM (RBF)
  - Logistic Regression (baseline)
  - MLP (μικρό νευρωνικό δίκτυο)

Χρήση:
  python3 ml_pipeline/train.py                # τρέχει στο συνθετικό dataset
  python3 ml_pipeline/train.py --insdn        # τρέχει στο πραγματικό InSDN
"""

import os
import sys
import time
import argparse
import json
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess


def build_models():
    """Επιστρέφει τα μοντέλα προς σύγκριση."""
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=120, max_depth=None, n_jobs=-1,
            random_state=config.RANDOM_STATE,
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=20, random_state=config.RANDOM_STATE,
        ),
        "KNN": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "SVM (RBF)": SVC(
            kernel="rbf", C=10, gamma="scale", probability=False,
            random_state=config.RANDOM_STATE,
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=config.RANDOM_STATE,
        ),
        "MLP (Neural Net)": MLPClassifier(
            hidden_layer_sizes=(64, 32), max_iter=300,
            random_state=config.RANDOM_STATE,
        ),
    }


def evaluate_model(model, X_test, y_test):
    """Υπολογίζει τις βασικές μετρικές αξιολόγησης (macro-averaged)."""
    t0 = time.perf_counter()
    y_pred = model.predict(X_test)
    pred_time = time.perf_counter() - t0
    return {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, average="macro", zero_division=0),
        "recall": recall_score(y_test, y_pred, average="macro", zero_division=0),
        "f1": f1_score(y_test, y_pred, average="macro", zero_division=0),
        "pred_time_s": pred_time,
        "y_pred": y_pred,
    }


def main(use_insdn=False, output=None):
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    os.makedirs(config.RESULTS_DIR, exist_ok=True)

    # --- Φόρτωση δεδομένων ---
    if use_insdn:
        print("[*] Φόρτωση πραγματικού InSDN dataset...")
        df = preprocess.load_insdn()
    else:
        print("[*] Φόρτωση συνθετικού dataset (για ανάπτυξη pipeline)...")
        df = preprocess.load_synthetic()

    print(f"    Σύνολο ροών: {len(df)} | Κλάσεις: {df[config.LABEL_COL].nunique()}")
    data = preprocess.prepare(df, scale=True,
                              split=config.SPLIT_STRATEGY,
                              val_size=config.VAL_SIZE)
    X_train, X_test = data["X_train"], data["X_test"]
    y_train, y_test = data["y_train"], data["y_test"]
    X_val, y_val = data["X_val"], data["y_val"]
    class_names = data["class_names"]
    print(f"    Διαχωρισμός: {data['split']} | train={len(y_train)} "
          f"val={len(y_val)} test={len(y_test)}")

    # --- Εκπαίδευση, επιλογή στο VALIDATION, τελική μέτρηση στο TEST ---
    # Το test set δεν συμμετέχει στην επιλογή μοντέλου. Η κατάταξη γίνεται με
    # βάση το validation macro-F1· οι τιμές του test αναφέρονται μόνο ως τελική,
    # ανεξάρτητη αξιολόγηση.
    results = []
    trained = {}
    for name, model in build_models().items():
        print(f"\n[*] Εκπαίδευση: {name}")
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        train_time = time.perf_counter() - t0
        val_metrics = evaluate_model(model, X_val, y_val)
        test_metrics = evaluate_model(model, X_test, y_test)
        trained[name] = model
        results.append({
            "model": name,
            "val_f1": val_metrics["f1"],
            "accuracy": test_metrics["accuracy"],
            "precision": test_metrics["precision"],
            "recall": test_metrics["recall"],
            "f1": test_metrics["f1"],
            "train_time_s": train_time,
            "pred_time_s": test_metrics["pred_time_s"],
        })
        print(f"    val F1={val_metrics['f1']:.4f} | test F1={test_metrics['f1']:.4f} "
              f"(train {train_time:.2f}s)")

    # Κατάταξη κατά VALIDATION F1 (η επιλογή μοντέλου δεν βλέπει το test set)
    res_df = (pd.DataFrame(results)
              .sort_values("val_f1", ascending=False)
              .reset_index(drop=True))
    print("\n" + "=" * 70)
    print("ΣΥΓΚΡΙΤΙΚΑ ΑΠΟΤΕΛΕΣΜΑΤΑ (επιλογή κατά val_f1, τελικές τιμές στο test)")
    print("=" * 70)
    print(res_df.to_string(index=False))

    # Αποθήκευση πίνακα αποτελεσμάτων. Το όνομα εξαρτάται από το dataset ώστε το
    # τρέχον pipeline να παράγει ΑΜΕΣΑ το artifact που αναφέρεται στη διπλωματική
    # (π.χ. model_comparison_insdn.csv) — καθαρή αλυσίδα κώδικας → CSV → πίνακας.
    default_name = "model_comparison_insdn.csv" if use_insdn else "model_comparison.csv"
    res_csv = output or os.path.join(config.RESULTS_DIR, default_name)
    res_df.to_csv(res_csv, index=False)
    print(f"\n[OK] Πίνακας αποτελεσμάτων: {res_csv}")

    # --- Αποθήκευση καλύτερου μοντέλου + artifacts ---
    best_name = res_df.iloc[0]["model"]        # <- επιλογή βάσει validation
    best_model = trained[best_name]
    print(f"\n[*] Καλύτερο μοντέλο (κατά validation): {best_name}")

    joblib.dump(best_model, os.path.join(config.MODELS_DIR, "best_model.pkl"))
    joblib.dump(data["scaler"], os.path.join(config.MODELS_DIR, "scaler.pkl"))
    joblib.dump(data["label_encoder"], os.path.join(config.MODELS_DIR, "label_encoder.pkl"))
    with open(os.path.join(config.MODELS_DIR, "feature_columns.json"), "w") as f:
        json.dump(data["feature_columns"], f, indent=2)
    # Καταγράφουμε και το περιβάλλον εκπαίδευσης: τα .pkl είναι δεμένα με την
    # έκδοση της scikit-learn που τα παρήγαγε (unpickle σε άλλη έκδοση βγάζει
    # InconsistentVersionWarning).
    import platform
    import sklearn
    import numpy as _np
    import pandas as _pd
    with open(os.path.join(config.MODELS_DIR, "meta.json"), "w") as f:
        json.dump({
            "best_model": best_name,
            "classes": class_names,
            "dataset": "InSDN" if use_insdn else "synthetic (default)",
            "random_state": config.RANDOM_STATE,
            "test_size": config.TEST_SIZE,
            "trained_with": {
                "python": platform.python_version(),
                "scikit-learn": sklearn.__version__,
                "numpy": _np.__version__,
                "pandas": _pd.__version__,
                "joblib": joblib.__version__,
            },
        }, f, indent=2, ensure_ascii=False)
    print(f"[OK] Αποθηκεύτηκαν μοντέλο/scaler/encoder στο: {config.MODELS_DIR}")

    # Επιστροφή για χρήση από το evaluate.py
    return {
        "best_name": best_name, "best_model": best_model,
        "data": data, "results_df": res_df, "trained": trained,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--insdn", action="store_true",
                        help="Χρήση πραγματικού InSDN dataset αντί για το συνθετικό")
    parser.add_argument("--output", default=None,
                        help="Διαδρομή για το CSV αποτελεσμάτων (υπερισχύει του "
                             "προεπιλεγμένου model_comparison[_insdn].csv)")
    args = parser.parse_args()
    main(use_insdn=args.insdn, output=args.output)
