#!/usr/bin/env bash
set -e  # Script bricht bei Fehlern sofort ab

echo "=== Rust installieren ==="
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

echo "=== Python & Pip prüfen ==="
python3 --version
pip3 --version

echo "=== Maturin installieren ==="
pip3 install --upgrade pip
pip3 install maturin

echo "=== Projekt mit Maturin bauen ==="
maturin develop --release
