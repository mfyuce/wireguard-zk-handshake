#!/bin/bash
# Build the wgzk-base Vagrant box and register it locally.
#
# Run this ONCE on the host before "vagrant up" in the project root.
# Pre-requisites (host):
#   cd wireguard-6.8 && make -C /lib/modules/6.8.0-59-generic/build M=$(pwd) modules
#   cd userspace/wg-zk-daemon && cargo build --release
#   cd userspace/gen-pk && cargo build --release
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build-base"
BOX_OUT="$SCRIPT_DIR/wgzk-base.box"
BOX_NAME="wgzk-base"

echo "==> Building wgzk-base box..."
cd "$BUILD_DIR"
vagrant destroy -f 2>/dev/null || true
vagrant up --provider=virtualbox

echo "==> Packaging box to $BOX_OUT ..."
vagrant package --output "$BOX_OUT"
vagrant destroy -f

echo "==> Registering box as '$BOX_NAME' ..."
vagrant box remove "$BOX_NAME" --force 2>/dev/null || true
vagrant box add "$BOX_NAME" "$BOX_OUT"

echo ""
echo "Done! You can now run 'vagrant up' from the project root."
