#!/usr/bin/env bash
set -euo pipefail
TARGET=aarch64-unknown-linux-gnu
if command -v cross >/dev/null 2>&1; then
  cross build --release --target "$TARGET" -p zk-core -p verifier
else
  echo "cross not found; trying cargo with linker (install: cargo install cross)"
  cargo build --release --target "$TARGET" -p zk-core -p verifier
fi
echo "Artifacts:"
ls -lh target/$TARGET/release/zk-core target/$TARGET/release/verifier 2>/dev/null || true
