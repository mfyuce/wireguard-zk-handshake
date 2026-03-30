#!/bin/bash
# Provision the GATEWAY (RIGHT) VM.
set -euo pipefail

PEER_IP="${PEER_IP:-192.168.100.2}"
DAEMON_SRC="/vagrant/userspace/wg-zk-daemon/target/release/wg-zk-daemon"
GENPK_SRC="/vagrant/userspace/gen-pk/target/release/gen-pk"
KEYS_DIR="/etc/wireguard"

# ── Check binaries ────────────────────────────────────────────────────────────
for f in "$DAEMON_SRC" "$GENPK_SRC"; do
    [ -f "$f" ] || { echo "ERROR: $f not found. Build on host first."; exit 1; }
done
install -m 755 "$DAEMON_SRC" /usr/local/bin/wg-zk-daemon
install -m 755 "$GENPK_SRC"  /usr/local/bin/gen-pk

# ── WireGuard keys (generate fresh) ──────────────────────────────────────────
mkdir -p "$KEYS_DIR"
umask 077
wg genkey > "$KEYS_DIR/private_right"
wg pubkey < "$KEYS_DIR/private_right" > "$KEYS_DIR/public_right"
echo "==> Gateway WG pubkey: $(cat $KEYS_DIR/public_right)"

# ── ZK keys (generate once, save for client to read) ─────────────────────────
# Use a file in /tmp on the shared network — but since /vagrant is available, use it.
ZK_ENV="/vagrant/vagrant/keys/zk.env"
mkdir -p "$(dirname $ZK_ENV)"
/usr/local/bin/gen-pk | grep -E "WGZK_(SK|PK)_HEX" > "$ZK_ENV"
source "$ZK_ENV"
echo "==> ZK PK: $WGZK_PK_HEX"

# Save gateway WG pubkey for client
cp "$KEYS_DIR/public_right" /vagrant/vagrant/keys/public_right

# ── Wait for client pubkey ────────────────────────────────────────────────────
# (client provisions after gateway, but just in case)
echo "==> Waiting for client pubkey..."
for i in $(seq 1 30); do
    [ -f /vagrant/vagrant/keys/public_left ] && break
    sleep 2
done
[ -f /vagrant/vagrant/keys/public_left ] || { echo "ERROR: client pubkey not found"; exit 1; }

# ── WireGuard interface ───────────────────────────────────────────────────────
ip link add wg1r type wireguard 2>/dev/null || true
ip addr add 192.168.1.2/32 dev wg1r 2>/dev/null || true
ip link set wg1r up
wg set wg1r private-key "$KEYS_DIR/private_right" listen-port 51921
ip link set wg1r mtu 1380
wg set wg1r \
    peer "$(cat /vagrant/vagrant/keys/public_left)" \
    allowed-ips 10.10.10.0/24 \
    endpoint "${PEER_IP}:51821" \
    persistent-keepalive 5
ip route replace 10.10.10.0/24 dev wg1r

# ── Dummy interface ───────────────────────────────────────────────────────────
ip link add dum0r type dummy 2>/dev/null || true
ip addr add 10.20.10.10/24 dev dum0r 2>/dev/null || true
ip link set dum0r up

# ── rp_filter ─────────────────────────────────────────────────────────────────
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.wg1r.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.dum0r.rp_filter=0 >/dev/null || true

# ── Daemon ────────────────────────────────────────────────────────────────────
cat > /etc/wgzk.env <<EOF
WGZK_MODE=gateway
WGZK_PK_HEX=${WGZK_PK_HEX}
EOF

cat > /etc/systemd/system/wgzk.service <<'EOF'
[Unit]
Description=WireGuard ZK Daemon
After=network.target
[Service]
EnvironmentFile=/etc/wgzk.env
ExecStart=/usr/local/bin/wg-zk-daemon
Restart=on-failure
RestartSec=1
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wgzk
systemctl restart wgzk
sleep 2
systemctl is-active wgzk && echo "==> wgzk daemon running (gateway)" || {
    journalctl -u wgzk --no-pager -n 20; exit 1
}
wg show wg1r
