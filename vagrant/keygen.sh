#!/bin/bash
# Pre-generate all keys before vagrant up.
# Runs on the HOST via Vagrant trigger.
set -euo pipefail

KEYS_DIR="$(dirname "$0")/keys"
GENPK="$(dirname "$0")/../userspace/gen-pk/target/release/gen-pk"

mkdir -p "$KEYS_DIR"

# Only regenerate if keys don't exist yet
if [ -f "$KEYS_DIR/public_right" ] && [ -f "$KEYS_DIR/public_left" ] && [ -f "$KEYS_DIR/zk.env" ]; then
    echo "==> Keys already exist, skipping keygen."
    exit 0
fi

echo "==> Generating WireGuard keys..."
umask 077
wg genkey > "$KEYS_DIR/private_right"
wg pubkey < "$KEYS_DIR/private_right" > "$KEYS_DIR/public_right"
wg genkey > "$KEYS_DIR/private_left"
wg pubkey < "$KEYS_DIR/private_left" > "$KEYS_DIR/public_left"
echo "    gateway pubkey: $(cat $KEYS_DIR/public_right)"
echo "    client  pubkey: $(cat $KEYS_DIR/public_left)"

echo "==> Generating ZK keys (Ristretto255 Schnorr++)..."
if [ ! -f "$GENPK" ]; then
    echo "ERROR: $GENPK not found. Build: cd userspace/gen-pk && cargo build --release"
    exit 1
fi
"$GENPK" | grep -E "WGZK_(SK|PK)_HEX" > "$KEYS_DIR/zk.env"
source "$KEYS_DIR/zk.env"
echo "    ZK PK: $WGZK_PK_HEX"
echo "==> Keys ready in $KEYS_DIR"
