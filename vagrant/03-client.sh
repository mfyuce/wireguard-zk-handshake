#!/bin/bash
# Provision the CLIENT (LEFT) VM.
set -euo pipefail

PEER_IP="${PEER_IP:-192.168.100.1}"
DAEMON_SRC="/vagrant/userspace/wg-zk-daemon/target/release/wg-zk-daemon"
KEYS_DIR="/etc/wireguard"

# ── Check binary ──────────────────────────────────────────────────────────────
[ -f "$DAEMON_SRC" ] || { echo "ERROR: $DAEMON_SRC not found. Build on host first."; exit 1; }
install -m 755 "$DAEMON_SRC" /usr/local/bin/wg-zk-daemon

# ── WireGuard keys (generate fresh) ──────────────────────────────────────────
mkdir -p "$KEYS_DIR"
umask 077
wg genkey > "$KEYS_DIR/private_left"
wg pubkey < "$KEYS_DIR/private_left" > "$KEYS_DIR/public_left"
echo "==> Client WG pubkey: $(cat $KEYS_DIR/public_left)"

# Publish pubkey and wait for gateway's pubkey + ZK env
mkdir -p /vagrant/vagrant/keys
cp "$KEYS_DIR/public_left" /vagrant/vagrant/keys/public_left

echo "==> Waiting for gateway pubkey and ZK keys..."
for i in $(seq 1 30); do
    [ -f /vagrant/vagrant/keys/public_right ] && \
    [ -f /vagrant/vagrant/keys/zk.env ] && break
    sleep 2
done
[ -f /vagrant/vagrant/keys/public_right ] || { echo "ERROR: gateway pubkey not found"; exit 1; }
[ -f /vagrant/vagrant/keys/zk.env ]       || { echo "ERROR: zk.env not found"; exit 1; }
source /vagrant/vagrant/keys/zk.env

# ── WireGuard interface ───────────────────────────────────────────────────────
ip link add wg1l type wireguard 2>/dev/null || true
ip addr add 192.168.1.1/32 dev wg1l 2>/dev/null || true
ip link set wg1l up
wg set wg1l private-key "$KEYS_DIR/private_left" listen-port 51821
ip link set wg1l mtu 1380
wg set wg1l \
    peer "$(cat /vagrant/vagrant/keys/public_right)" \
    allowed-ips 10.20.10.0/24 \
    endpoint "${PEER_IP}:51921" \
    persistent-keepalive 5
ip route replace 10.20.10.0/24 dev wg1l

# ── Dummy interface ───────────────────────────────────────────────────────────
ip link add dum0l type dummy 2>/dev/null || true
ip addr add 10.10.10.10/24 dev dum0l 2>/dev/null || true
ip link set dum0l up

# ── rp_filter ─────────────────────────────────────────────────────────────────
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.wg1l.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.dum0l.rp_filter=0 >/dev/null || true

# ── Daemon ────────────────────────────────────────────────────────────────────
cat > /etc/wgzk.env <<EOF
WGZK_MODE=client
WGZK_SK_HEX=${WGZK_SK_HEX}
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
systemctl is-active wgzk && echo "==> wgzk daemon running (client)" || {
    journalctl -u wgzk --no-pager -n 20; exit 1
}
wg show wg1l
