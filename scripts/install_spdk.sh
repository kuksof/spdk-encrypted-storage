#!/bin/bash
set -e

echo "[INFO] Installing SPDK dependencies..."
sudo apt update
sudo apt install -y \
    git build-essential pkg-config \
    libaio-dev libnuma-dev libssl-dev \
    python3 python3-pip python3-venv \
    libcunit1-dev libiscsi-dev \
    libunwind-dev libtool uuid-dev nasm \
    cmake ninja-build

echo "[INFO] Checking SPDK directory..."
SPDK_DIR="$(dirname "$0")/../extern/spdk"

if [ ! -d "$SPDK_DIR" ]; then
  echo "[ERROR] extern/spdk not found. run: git submodule update --init"
  exit 1
fi

echo "[INFO] Updating SPDK submodules..."
cd "$SPDK_DIR"
git submodule update --init

echo "[INFO] Running SPDK pkgdep.sh..."
sudo ./scripts/pkgdep.sh || true

echo "[INFO] Configuring SPDK..."
./configure --with-crypto --enable-debug

echo "[INFO] Building SPDK..."
make -j"$(nproc)"

echo "[INFO] SPDK build complete."