#!/usr/bin/env bash
###############################################################################
# run_packet_level_experiment.sh — ΠΛΗΡΩΣ αυτοματοποιημένο packet-level πείραμα.
#
# Κλείνει την αλυσίδα: εκτέλεση -> ακατέργαστα δεδομένα -> summary -> ενιαίο CSV,
# χωρίς κανένα χειροκίνητο βήμα, ώστε κάθε νούμερο του κεφαλαίου 6 να ανάγεται σε
# ένα συγκεκριμένο run_id και commit.
#
# Χρήση:
#   bash run_packet_level_experiment.sh                 # 60s επίθεση, TTL 10s
#   ATTACK_PHASE=60 BLOCK_TTL=5 bash run_packet_level_experiment.sh
#
# Παράγει:
#   results/live/mininet_run_<ts>/summary.json        (μετρήσεις του run)
#   results/live/mininet_run_<ts>/ovs_dump_flows.txt  (ακατέργαστος πίνακας ροών)
#   results/live/mininet_run_<ts>/mininet_full.log    (πλήρες log της εκτέλεσης)
#   results/live/experiment_summary.csv               (+1 γραμμή packet_level)
#
# ΑΠΑΙΤΕΙ: Docker. Σε WSL2 όπου δεν υπάρχει native docker CLI, δώσε:
#   DOCKER=docker.exe bash run_packet_level_experiment.sh
###############################################################################
set -euo pipefail
cd "$(dirname "$0")"

DOCKER=${DOCKER:-docker}

# Η επίθεση διαρκεί ΠΟΛΛΑΠΛΑΣΙΑ του TTL, ώστε να ελεγχθεί ότι ο κανόνας DROP
# ανανεώνεται και δεν καλύπτει μόνο το πρώτο lease.
NORMAL_PHASE=${NORMAL_PHASE:-20}
ATTACK_PHASE=${ATTACK_PHASE:-60}
RECOVERY_PHASE=${RECOVERY_PHASE:-10}
LOOP_CYCLES=${LOOP_CYCLES:-1}
BLOCK_TTL=${BLOCK_TTL:-10}
BLOCK_RENEW_MARGIN=${BLOCK_RENEW_MARGIN:-3}
ATTACK_ONGOING_PPS=${ATTACK_ONGOING_PPS:-50}
CODE_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

# Οι παράμετροι δίνονται στο compose μέσω --env-file και όχι μέσω του περιβάλλοντος:
# σε WSL2 το docker.exe είναι εκτελέσιμο των Windows και ΔΕΝ κληρονομεί τις μεταβλητές
# του shell, οπότε η υποκατάσταση ${ATTACK_PHASE} θα έπαιρνε σιωπηλά τις προεπιλογές.
ENV_FILE=".experiment.env"
cat > "$ENV_FILE" <<EOF
NORMAL_PHASE=$NORMAL_PHASE
ATTACK_PHASE=$ATTACK_PHASE
RECOVERY_PHASE=$RECOVERY_PHASE
LOOP_CYCLES=$LOOP_CYCLES
BLOCK_TTL=$BLOCK_TTL
BLOCK_RENEW_MARGIN=$BLOCK_RENEW_MARGIN
ATTACK_ONGOING_PPS=$ATTACK_ONGOING_PPS
CODE_COMMIT=$CODE_COMMIT
EOF
trap 'rm -f "$ENV_FILE"' EXIT

COMPOSE="$DOCKER compose --env-file $ENV_FILE -f app_sdn/docker-compose.yml"

echo ">>> Packet-level πείραμα | attack=${ATTACK_PHASE}s TTL=${BLOCK_TTL}s "\
"cycles=${LOOP_CYCLES} commit=${CODE_COMMIT}"

$COMPOSE down --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up --build -d

# Έλεγχος ότι οι παράμετροι ΟΝΤΩΣ έφτασαν στο container (και δεν έπεσε σιωπηλά σε
# προεπιλογές), αλλιώς το πείραμα θα μετρούσε κάτι διαφορετικό από όσα δηλώνει.
ACTUAL=$($DOCKER inspect sdn_mininet --format '{{range .Config.Env}}{{println .}}{{end}}' \
         | grep -E "^(ATTACK_PHASE|BLOCK_TTL|LOOP_CYCLES)=" | sort | tr '\n' ' ')
echo ">>> Ενεργές παράμετροι στο container: $ACTUAL"
case "$ACTUAL" in
    *"ATTACK_PHASE=$ATTACK_PHASE"*) ;;
    *) echo "!!! Οι παράμετροι δεν έφτασαν στο container." >&2; exit 1 ;;
esac

echo ">>> Αναμονή ολοκλήρωσης του σεναρίου..."
TIMEOUT=$(( (NORMAL_PHASE + ATTACK_PHASE + RECOVERY_PHASE) * LOOP_CYCLES + 300 ))
deadline=$(( $(date +%s) + TIMEOUT ))
while true; do
    if $DOCKER logs sdn_mininet 2>&1 | grep -q "\[LIVE\] Done\."; then
        echo ">>> Το σενάριο ολοκληρώθηκε."
        break
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "!!! Timeout μετά από ${TIMEOUT}s." >&2
        $DOCKER logs --tail 30 sdn_mininet >&2 || true
        $COMPOSE down >/dev/null 2>&1 || true
        exit 1
    fi
    sleep 5
done

# Τα artifacts (summary.json, ακατέργαστο dump-flows) εκπέμπονται στο stdout του
# container μέσα σε δείκτες [ARTIFACT] και ανακτώνται από το ίδιο log της εκτέλεσης,
# ώστε να προέρχονται ΑΠΟΔΕΔΕΙΓΜΕΝΑ από το ίδιο run και όχι εκ των υστέρων.
LOG=$(mktemp)
$DOCKER logs sdn_mininet > "$LOG" 2>&1
RUN_DIR=$(python3 scripts/extract_run_artifacts.py "$LOG")
rm -f "$LOG"

echo ">>> Artifacts: ${RUN_DIR}/"
python3 scripts/append_experiment_summary.py "$RUN_DIR"

$COMPOSE down >/dev/null 2>&1 || true
echo ">>> Τέλος."
