#!/bin/bash
# Provision the CLIENT (LEFT) VM.
# All keys are pre-baked into the base box under /etc/wireguard/ and /etc/wgzk.env.
set -euo pipefail

PEER_IP="${PEER_IP:-192.168.100.1}"

source /etc/wgzk.env   # WGZK_SK_HEX, WGZK_PK_HEX

# ── WireGuard interface ───────────────────────────────────────────────────────
ip link add wg1l type wireguard 2>/dev/null || true
ip addr add 192.168.1.1/32 dev wg1l 2>/dev/null || true
ip link set wg1l up
wg set wg1l private-key /etc/wireguard/private_left listen-port 51821
ip link set wg1l mtu 1380
wg set wg1l \
    peer "$(cat /etc/wireguard/public_right)" \
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

# ── Daemon (systemd) ──────────────────────────────────────────────────────────
cat > /etc/wgzk-client.env <<EOF
WGZK_MODE=client
WGZK_SK_HEX=${WGZK_SK_HEX}
WGZK_PK_HEX=${WGZK_PK_HEX}
EOF

cat > /etc/systemd/system/wgzk.service <<EOF
[Unit]
Description=WireGuard ZK Daemon (client)
After=network.target

[Service]
EnvironmentFile=/etc/wgzk-client.env
ExecStart=/usr/local/bin/wg-zk-daemon
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wgzk
systemctl start wgzk
sleep 2
systemctl is-active wgzk && echo "==> wgzk daemon running (client)" || {
    journalctl -u wgzk --no-pager -n 20; exit 1
}

echo "==> Client ready"
wg show wg1l
