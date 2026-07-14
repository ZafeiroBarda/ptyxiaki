#!/usr/bin/env bash
# =============================================================================
# make_final_zip.sh — Παράγει το ΚΑΘΑΡΟ zip τελικής παράδοσης.
#
#   bash make_final_zip.sh
#   -> ../sdn-attack-detection-final.zip
#
# Περιλαμβάνει μόνο ό,τι χρειάζεται η επιτροπή: κώδικα, tests, μοντέλα,
# αποτελέσματα, τεκμηρίωση. Αποκλείει venv, caches, backups, προσωρινά.
# Δεν απαιτεί zip/unzip — χρησιμοποιεί το zipfile της Python.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PYEOF'
import os, zipfile

OUT = "../sdn-attack-detection-final.zip"
ROOT = "sdn-attack-detection-final"

INCLUDE_FILES = [
    "README.md", "requirements.txt", "run_all.sh", "run_live_experiments.sh",
    "demo_10min.sh", "make_final_zip.sh", ".gitignore",
    # Αναπαραγωγιμότητα: αναφέρονται στο README και στο Παράρτημα Α, οπότε ΠΡΕΠΕΙ να
    # συνοδεύουν την παράδοση. Έλειπαν από το zip, δίνοντας την εντύπωση ότι δεν
    # υπάρχουν καθόλου κλείδωμα εκδόσεων και επαλήθευση artifacts.
    "requirements-lock.txt", "MANIFEST.sha256", "RESULTS_VERIFICATION.md",
    "reproduce_thesis.sh", "run_packet_level_experiment.sh",
    "data/README_DATA.md",
    "docs/Diplomatiki_Full.pdf",
    "docs/Τεχνική_Αναφορά_Μοντέλα_και_Ροή_Δεδομένων.pdf",
    "docs/architecture_mapping.md",
]
INCLUDE_DIRS = ["app_sdn", "ml_pipeline", "simulation", "controller",
                "tests", "models", "results", "scripts", "docs/figures"]
EXCLUDE_PARTS = ("__pycache__", ".pytest_cache", "BACKUP", "USEREDIT", "~$")
EXCLUDE_EXT = (".pyc", ".pyo")

def excluded(path):
    return any(p in path for p in EXCLUDE_PARTS) or path.endswith(EXCLUDE_EXT)

if os.path.exists(OUT):
    os.remove(OUT)

n = 0
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for f in INCLUDE_FILES:
        if os.path.isfile(f) and not excluded(f):
            z.write(f, f"{ROOT}/{f}")
            n += 1
        else:
            print(f"  [!] λείπει: {f}")
    for d in INCLUDE_DIRS:
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if not excluded(os.path.join(root, x))]
            for fn in files:
                p = os.path.join(root, fn)
                if not excluded(p):
                    z.write(p, f"{ROOT}/{p}")
                    n += 1

size_mb = os.path.getsize(OUT) / 1e6
print(f"Δημιουργήθηκε: {os.path.abspath(OUT)}")
print(f"Αρχεία: {n} | Μέγεθος: {size_mb:.1f} MB")
PYEOF
