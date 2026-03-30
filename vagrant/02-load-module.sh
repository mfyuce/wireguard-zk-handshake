#!/bin/bash
# Load the pre-installed wireguard.ko (baked into the base box).
set -euo pipefail

KERNEL="6.8.0-59-generic"
KO="/lib/modules/${KERNEL}/extra/wireguard.ko"

echo "==> Kernel: $(uname -r)"
if [ "$(uname -r)" != "$KERNEL" ]; then
    echo "ERROR: expected kernel $KERNEL but running $(uname -r)"
    echo "       Re-build the base box: cd vagrant && bash build-base.sh"
    exit 1
fi

[ -f "$KO" ] || { echo "ERROR: $KO not found — base box not built correctly"; exit 1; }

# Remove stock wireguard if present
rmmod wireguard 2>/dev/null || true

# Load dependencies (order matters — same as README)
for mod in libchacha20poly1305 libcurve25519 udp_tunnel ip6_udp_tunnel \
           curve25519-x86_64 libcurve25519-generic chacha20poly1305 \
           gcm aes_generic aesni_intel af_alg; do
    modprobe "$mod" 2>/dev/null || true
done

insmod "$KO"

if grep -q wgzk /proc/net/genetlink; then
    echo "==> wireguard.ko loaded OK — wgzk genl registered"
else
    echo "ERROR: wgzk genl family not found after insmod"
    exit 1
fi
