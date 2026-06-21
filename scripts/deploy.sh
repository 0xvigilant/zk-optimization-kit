#!/usr/bin/env bash
set -euo pipefail
PI_HOST="${1:?usage: deploy.sh user@pi-host}"
TARGET=aarch64-unknown-linux-gnu
./scripts/cross-build.sh
ssh "$PI_HOST" 'mkdir -p ~/zk-optimization-kit/static'
scp target/$TARGET/release/zk-core "$PI_HOST":~/zk-optimization-kit/
scp target/$TARGET/release/verifier "$PI_HOST":~/zk-optimization-kit/
scp -r zk-core/static/* "$PI_HOST":~/zk-optimization-kit/static/
echo "Deployed. On the Pi run: cd ~/zk-optimization-kit && ./zk-core serve --port 8080"
