#!/bin/bash
# Provision the GATEWAY (RIGHT) VM.
# All keys pre-generated on host by vagrant/keygen.sh
set -euo pipefail

PEER_IP="${PEER_IP:-192.168.100.2}"
KEYS="/vagrant/vagrant/keys"

[ -f "$KEYS/private_right" ] || { echo "ERROR: keys not found. Run: bash vagrant/keygen.sh"; exit 1; }
[ -f "$KEYS/zk.env" ]        || { echo "ERROR: zk.env not found"; exit 1; }
source "$KEYS/zk.env"

install -m 755 /vagrant/userspace/wg-zk-daemon/target/release/wg-zk-daemon /usr/local/bin/wg-zk-daemon

# ── WireGuard interface ───────────────────────────────────────────────────────
ip link add wg1r type wireguard 2>/dev/null || true
ip addr add 192.168.1.2/32 dev wg1r 2>/dev/null || true
ip link set wg1r up
wg set wg1r private-key "$KEYS/private_right" listen-port 51921
ip link set wg1r mtu 1380
wg set wg1r \
    peer "$(cat $KEYS/public_left)" \
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
systemctl is-active wgzk && echo "==> wgzk daemon running (gateway)" || { journalctl -u wgzk --no-pager -n 20; exit 1; }
wg show wg1r
