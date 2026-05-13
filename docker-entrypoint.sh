#!/bin/bash
set -euo pipefail

LEANSIM_ROOT="/root/leansim"
OUT_DIR="${OUTPUT_DIR:-/mnt/output}"
mkdir -p "${OUT_DIR}"

EXPERIMENT="${1:-experiments/local-bench.toml}"
NETVIZ_OUT="${2:-}"

# Resolve experiment path (relative to leansim root)
if [ -f "${LEANSIM_ROOT}/${EXPERIMENT}" ]; then
    EXPERIMENT_PATH="${LEANSIM_ROOT}/${EXPERIMENT}"
else
    EXPERIMENT_PATH="${EXPERIMENT}"
fi

SHADOW_YAML="${OUT_DIR}/shadow.yaml"

echo "==> Experiment: ${EXPERIMENT_PATH}"
echo "==> Output dir: ${OUT_DIR}"
echo "==> Generating Shadow config..."

"${LEANSIM_ROOT}/target/release/leansim" gen-shadow \
    --experiment "${EXPERIMENT_PATH}" \
    --out "${SHADOW_YAML}"

# Fix binary path in shadow.yaml if gen-shadow picked up wrong path
sed -i 's|/netviz/target/release/leansim|/root/leansim/target/release/leansim|g' "${SHADOW_YAML}"

# Copy topology.gml to output dir (shadow.yaml references it via relative path)
if [ -f topology.gml ]; then
    cp topology.gml "${OUT_DIR}/"
fi

# Shadow writes shadow.data into CWD, so run from output dir
cd "${OUT_DIR}"

echo "==> Shadow config: ${SHADOW_YAML}"
echo "==> Starting Shadow simulation..."
~/.local/bin/shadow "${SHADOW_YAML}"

echo "==> Simulation complete. Data in ${OUT_DIR}/shadow.data/"

if [ -n "${NETVIZ_OUT}" ]; then
    echo "==> Generating netviz trace..."
    "${LEANSIM_ROOT}/target/release/leansim" netviz \
        --experiment "${EXPERIMENT_PATH}" \
        --shadow-data shadow.data \
        --out "${NETVIZ_OUT}"
    echo "==> Netviz trace written to ${NETVIZ_OUT}"
fi
