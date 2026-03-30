#!/bin/bash
# Bakes wireguard.ko and daemon binaries into the base box image.
# Runs inside the builder VM after the kernel reboot.
set -euo pipefail

KERNEL="6.8.0-59-generic"
KO="/vagrant/wireguard-6.8/wireguard.ko"
DAEMON="/vagrant/userspace/wg-zk-daemon/target/release/wg-zk-daemon"
GENPK="/vagrant/userspace/gen-pk/target/release/gen-pk"

echo "==> Kernel: $(uname -r)"
[ "$(uname -r)" = "$KERNEL" ] || { echo "ERROR: wrong kernel $(uname -r)"; exit 1; }

# ── Check pre-built binaries exist ────────────────────────────────────────────
for f in "$KO" "$DAEMON" "$GENPK"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: $f not found on host."
        echo "       Build on host first (see README — Building section)."
        exit 1
    fi
done

# ── Install wireguard.ko into the image ───────────────────────────────────────
install -D -m 644 "$KO" /lib/modules/${KERNEL}/extra/wireguard.ko
depmod -a ${KERNEL}
echo "==> wireguard.ko installed"

# ── Copy daemon binaries ──────────────────────────────────────────────────────
install -m 755 "$DAEMON" /usr/local/bin/wg-zk-daemon
install -m 755 "$GENPK"  /usr/local/bin/gen-pk
echo "==> wg-zk-daemon and gen-pk installed"

# ── Verify module loads cleanly ───────────────────────────────────────────────
# Load deps
for mod in libchacha20poly1305 libcurve25519 udp_tunnel ip6_udp_tunnel \
           curve25519-x86_64 libcurve25519-generic chacha20poly1305 \
           gcm aes_generic aesni_intel af_alg; do
    modprobe "$mod" 2>/dev/null || true
done
insmod /lib/modules/${KERNEL}/extra/wireguard.ko

if grep -q wgzk /proc/net/genetlink; then
    echo "==> wireguard.ko loads OK — wgzk genl registered"
else
    echo "ERROR: module loaded but wgzk genl not found"
    exit 1
fi

# Unload for clean box state — will be loaded fresh on each VM boot
rmmod wireguard

# ── Pre-generate all keys into the box ───────────────────────────────────────
# WireGuard keys (both sides baked in — no runtime exchange needed)
mkdir -p /etc/wireguard
umask 077
wg genkey > /etc/wireguard/private_right
wg pubkey < /etc/wireguard/private_right > /etc/wireguard/public_right
wg genkey > /etc/wireguard/private_left
wg pubkey < /etc/wireguard/private_left > /etc/wireguard/public_left
echo "==> WireGuard keys generated"
echo "    gateway pubkey: $(cat /etc/wireguard/public_right)"
echo "    client  pubkey: $(cat /etc/wireguard/public_left)"

# ZK keys (Ristretto255 Schnorr++)
/usr/local/bin/gen-pk | grep -E "WGZK_(SK|PK)_HEX" > /etc/wgzk.env
echo "==> ZK keys generated: $(cat /etc/wgzk.env | grep PK)"

echo "==> Base box ready. Run:"
echo "      vagrant package --output ../wgzk-base.box"
