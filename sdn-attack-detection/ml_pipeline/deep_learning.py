#!/usr/bin/env python3
"""
deep_learning.py  (ΜΕΘΟΔΟΣ Β — 2η εκδοχή: Deep Learning)
--------------------------------------------------------
Εκπαιδεύει & αξιολογεί μοντέλα Βαθιάς Μάθησης (Deep Learning) για ανίχνευση
επιθέσεων SDN, ώστε να συγκριθούν με τα κλασικά ML μοντέλα του train.py.

Μοντέλα:
  1. Deep MLP (πλήρως συνδεδεμένο νευρωνικό δίκτυο)
  2. 1D-CNN (συνελικτικό — αντιμετωπίζει τα features ως 1D σήμα)

Παράγει (suffix _insdn μόνο με --insdn, ώστε να μη γράφονται πάνω στα synthetic):
  results/dl_training_history[_insdn].png   (καμπύλες loss/accuracy ανά εποχή)
  results/dl_confusion_matrix[_insdn].png
  results/dl_comparison[_insdn].csv

Χρήση:
  python3 ml_pipeline/deep_learning.py
  python3 ml_pipeline/deep_learning.py --insdn
"""

import os
import sys
import argparse
import time
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Καταστολή verbose logs του TensorFlow
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")

import tensorflow as tf
from tensorflow.keras import layers, models, callbacks, utils
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
import preprocess

sns.set_theme(style="whitegrid")
tf.random.set_seed(config.RANDOM_STATE)


def build_mlp(input_dim, n_classes):
    """Deep MLP με dropout & batch normalization."""
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(128, activation="relu"),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(64, activation="relu"),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(32, activation="relu"),
        layers.Dense(n_classes, activation="softmax"),
    ], name="Deep_MLP")
    model.compile(optimizer="adam", loss="categorical_crossentropy",
                  metrics=["accuracy"])
    return model


def build_cnn(input_dim, n_classes):
    """1D-CNN: αντιμετωπίζει το διάνυσμα χαρακτηριστικών ως 1D σήμα.

    Με λίγα features (~24) αποφεύγουμε επιθετικό pooling που "σβήνει"
    πληροφορία — χρησιμοποιούμε Flatten ώστε να διατηρηθεί η τοπική δομή.
    Χαμηλό learning rate για σταθερή σύγκλιση (το CNN αλλιώς καταρρέει
    περιστασιακά σε μία κλάση).
    """
    from tensorflow.keras.optimizers import Adam
    model = models.Sequential([
        layers.Input(shape=(input_dim, 1)),
        layers.Conv1D(32, kernel_size=3, activation="relu", padding="same"),
        layers.BatchNormalization(),
        layers.Conv1D(32, kernel_size=3, activation="relu", padding="same"),
        layers.MaxPooling1D(pool_size=2),
        layers.Conv1D(16, kernel_size=3, activation="relu", padding="same"),
        layers.Flatten(),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.3),
        layers.Dense(n_classes, activation="softmax"),
    ], name="CNN_1D")
    model.compile(optimizer=Adam(learning_rate=5e-4),
                  loss="categorical_crossentropy", metrics=["accuracy"])
    return model


def plot_history(histories, out_path):
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    for name, h in histories.items():
        axes[0].plot(h.history["val_accuracy"], label=f"{name} (val)")
        axes[1].plot(h.history["val_loss"], label=f"{name} (val)")
    axes[0].set_title("Validation Accuracy ανά εποχή")
    axes[0].set_xlabel("Εποχή"); axes[0].set_ylabel("Accuracy"); axes[0].legend()
    axes[1].set_title("Validation Loss ανά εποχή")
    axes[1].set_xlabel("Εποχή"); axes[1].set_ylabel("Loss"); axes[1].legend()
    plt.tight_layout(); plt.savefig(out_path, dpi=150); plt.close()
    print(f"[OK] {out_path}")


def plot_confusion(y_true, y_pred, class_names, out_path, title):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6.5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Greens",
                xticklabels=class_names, yticklabels=class_names)
    plt.title(title); plt.ylabel("Πραγματική"); plt.xlabel("Προβλεπόμενη")
    plt.tight_layout(); plt.savefig(out_path, dpi=150); plt.close()
    print(f"[OK] {out_path}")


def main(use_insdn=False, epochs=40):
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    # Ίδια σύμβαση ονομασίας με το train.py: suffix _insdn μόνο για το InSDN
    # run, ώστε να μην αντικαθίστανται τα synthetic αρχεία (και αντίστροφα).
    suffix = "_insdn" if use_insdn else ""

    df = preprocess.load_insdn() if use_insdn else preprocess.load_synthetic()
    data = preprocess.prepare(df, scale=True)
    X_train, X_test = data["X_train"], data["X_test"]
    y_train, y_test = data["y_train"], data["y_test"]
    class_names = data["class_names"]
    n_classes = len(class_names)
    input_dim = X_train.shape[1]

    # one-hot encoding για το softmax
    y_train_oh = utils.to_categorical(y_train, n_classes)
    y_test_oh = utils.to_categorical(y_test, n_classes)

    early = callbacks.EarlyStopping(monitor="val_loss", patience=8,
                                    restore_best_weights=True)

    results, histories = [], {}

    # --- MLP ---
    print("\n[*] Εκπαίδευση Deep MLP...")
    mlp = build_mlp(input_dim, n_classes)
    t0 = time.perf_counter()
    h_mlp = mlp.fit(X_train, y_train_oh, validation_split=0.2, epochs=epochs,
                    batch_size=128, callbacks=[early], verbose=0)
    t_mlp = time.perf_counter() - t0
    histories["Deep MLP"] = h_mlp
    y_pred_mlp = mlp.predict(X_test, verbose=0).argmax(axis=1)

    # --- CNN ---
    print("[*] Εκπαίδευση 1D-CNN...")
    X_train_cnn = X_train[..., np.newaxis]
    X_test_cnn = X_test[..., np.newaxis]
    cnn = build_cnn(input_dim, n_classes)
    t0 = time.perf_counter()
    h_cnn = cnn.fit(X_train_cnn, y_train_oh, validation_split=0.2, epochs=epochs,
                    batch_size=128, callbacks=[early], verbose=0)
    t_cnn = time.perf_counter() - t0
    histories["1D-CNN"] = h_cnn
    y_pred_cnn = cnn.predict(X_test_cnn, verbose=0).argmax(axis=1)

    # --- Μετρικές ---
    for name, y_pred, ttime in [("Deep MLP", y_pred_mlp, t_mlp),
                                ("1D-CNN", y_pred_cnn, t_cnn)]:
        results.append({
            "model": name,
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average="macro", zero_division=0),
            "recall": recall_score(y_test, y_pred, average="macro", zero_division=0),
            "f1": f1_score(y_test, y_pred, average="macro", zero_division=0),
            "train_time_s": ttime,
        })

    res_df = pd.DataFrame(results).sort_values("f1", ascending=False)
    print("\n" + "=" * 60)
    print("DEEP LEARNING — ΑΠΟΤΕΛΕΣΜΑΤΑ")
    print("=" * 60)
    print(res_df.to_string(index=False))
    res_df.to_csv(os.path.join(config.RESULTS_DIR, f"dl_comparison{suffix}.csv"), index=False)

    # καλύτερο DL μοντέλο για το confusion matrix
    best_row = res_df.iloc[0]
    best_pred = y_pred_mlp if best_row["model"] == "Deep MLP" else y_pred_cnn
    print("\n[Classification report — " + best_row["model"] + "]")
    print(classification_report(y_test, best_pred, target_names=class_names,
                                digits=4, zero_division=0))

    plot_history(histories, os.path.join(config.RESULTS_DIR, f"dl_training_history{suffix}.png"))
    plot_confusion(y_test, best_pred, class_names,
                   os.path.join(config.RESULTS_DIR, f"dl_confusion_matrix{suffix}.png"),
                   f"Confusion Matrix — {best_row['model']} (Deep Learning)")
    print("\n[ΟΛΟΚΛΗΡΩΘΗΚΕ] DL αποτελέσματα στο results/.")
    return res_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--insdn", action="store_true")
    parser.add_argument("--epochs", type=int, default=40)
    args = parser.parse_args()
    main(use_insdn=args.insdn, epochs=args.epochs)
