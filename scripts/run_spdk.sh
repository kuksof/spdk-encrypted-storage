#!/bin/bash

SPDK_DIR="$(dirname "$0")/../extern/spdk"
CONF="$1"

if [ -z "$CONF" ]; then
  echo "Usage: run_spdk.sh <config.json>"
  exit 1
fi

if [ ! -f "$CONF" ]; then
  echo "[ERROR] Config file not found: $CONF"
  exit 1
fi

if [ ! -x "$SPDK_DIR/build/bin/nvmf_tgt" ]; then
  echo "[ERROR] SPDK is not built. Run scripts/install_spdk.sh"
  exit 1
fi

sudo HUGEMEM=1024 "$SPDK_DIR/build/bin/nvmf_tgt" \
  -m 0xF \
  -s 4096 \
  -c "$CONF"