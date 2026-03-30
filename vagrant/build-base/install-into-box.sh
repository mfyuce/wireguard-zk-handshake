#!/bin/bash
# Bakes only the kernel + runtime dependencies into the base box.
# wireguard.ko and daemon binaries are NOT included here —
# they are copied from the host at each "vagrant up" via the synced folder.
set -euo pipefail

KERNEL="6.8.0-59-generic"

echo "==> Kernel: $(uname -r)"
[ "$(uname -r)" = "$KERNEL" ] || { echo "ERROR: wrong kernel $(uname -r)"; exit 1; }

# Install runtime tools needed by provision scripts
export DEBIAN_FRONTEND=noninteractive
apt-get install -y wireguard-tools iproute2 iputils-ping

echo "==> Base box ready (kernel + tools only)."
echo "    wireguard.ko and daemon will be loaded from the host at vagrant up."
echo "    Run: vagrant package --output ../wgzk-base.box"
