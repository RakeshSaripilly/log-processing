#!/usr/bin/env bash
set -e
echo "Building ULPF Hybrid Rust Core (rust_core)..."
pip install maturin
maturin develop --release --manifest-path rust_core/Cargo.toml
echo "ULPF Rust Core build complete."
