#!/bin/bash
# test_generic_vrf.sh (single-host, two VRFs)
# Usage: sudo ./test_generic_vrf.sh <cnt>
# Example: sudo ./test_generic_vrf.sh 0

set -euo pipefail
set -x

cnt="${1:?usage: $0 <cnt>}"

# ---- names & addressing ----
leftveth="veth${cnt}_1"
rightveth="veth${cnt}_2"

# Underlay (point-to-point /30 carried by the veth pair)
u_left="10.255.${cnt}.1/30"
u_right="10.255.${cnt}.2/30"
u_left_ip="10.255.${cnt}.1"
u_right_ip="10.255.${cnt}.2"

# WireGuard iface names
wg_left="wg$((cnt+1))l"
wg_right="wg$((cnt+1))r"

# WG point-to-point (/32 to avoid on-link /24 weirdness)
wg_left_ip="192.168.$((cnt+1)).$((cnt+1))/32"
wg_right_ip="192.168.$((cnt+1)).$((cnt+2))/32"

# Dummy subnets (application endpoints over WG)
dum_left="dum${cnt}l"
dum_right="dum${cnt}r"
dum_left_ip="10.10.$((cnt+10)).10/24"
dum_right_ip="10.20.$((cnt+10)).10/24"
dum_left_ip_host="10.10.$((cnt+10)).10"
dum_right_ip_host="10.20.$((cnt+10)).10"

# Ports (two distinct to avoid accidental reuse)
port_left=$((51820 + cnt + 1))   # right peer will dial this
port_right=$((51920 + cnt + 1))  # left peer will dial this

# VRFs
vrf_left="vrfL_${cnt}"
vrf_right="vrfR_${cnt}"
tbl_left=$((1001 + cnt))
tbl_right=$((1002 + cnt))

# ---- helpers ----
cleanup() {
  set +e
  # stop iperf3 server if running (in left VRF)
  ip vrf exec "${vrf_left}" pkill -f "iperf3 -s -B ${dum_left_ip_host}" 2>/dev/null || true

  # remove overlay routes in VRFs (ignore errors)
  ip route del table "${tbl_left}" "10.20.$((cnt+10)).0/24" dev "${wg_left}" 2>/dev/null || true
  ip route del table "${tbl_right}" "10.10.$((cnt+10)).0/24" dev "${wg_right}" 2>/dev/null || true

  # tear down wg ifaces
  ip link del "${wg_left}" 2>/dev/null || true
  ip link del "${wg_right}" 2>/dev/null || true

  # tear down dummy ifaces
  ip link del "${dum_left}" 2>/dev/null || true
  ip link del "${dum_right}" 2>/dev/null || true

  # tear down veth pair
  ip link del "${leftveth}" 2>/dev/null || true

  # tear down VRFs (after slaves are gone)
  ip link del "${vrf_left}" 2>/dev/null || true
  ip link del "${vrf_right}" 2>/dev/null || true

  # (keys left on disk by design; uncomment if you want auto-delete)
  # rm -f "private_left${cnt}" "private_right${cnt}" "publeft${cnt}" "pubright${cnt}" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_iperf() {
  for _ in $(seq 1 50); do
    ip vrf exec "${vrf_left}" ss -lntp | grep -q "iperf3" && return 0
    sleep 0.1
  done
  return 1
}

# ---- key material ----
umask 077

[[ -f "private_left${cnt}"  ]] || wg genkey > "private_left${cnt}"
[[ -f "private_right${cnt}" ]] || wg genkey > "private_right${cnt}"
wg pubkey < "private_left${cnt}"  > "publeft${cnt}"
wg pubkey < "private_right${cnt}" > "pubright${cnt}"
pbl_left="$(cat "publeft${cnt}")"
pbl_right="$(cat "pubright${cnt}")"

# ---- create VRFs ----
ip link add "${vrf_left}"  type vrf table "${tbl_left}"
ip link add "${vrf_right}" type vrf table "${tbl_right}"
ip link set "${vrf_left}" up
ip link set "${vrf_right}" up

# ---- underlay: veth point-to-point (then enslave) ----
ip link add "${leftveth}" type veth peer name "${rightveth}"
ip link set "${leftveth}"  master "${vrf_left}"
ip link set "${rightveth}" master "${vrf_right}"
ip addr add "${u_left}"  dev "${leftveth}"
ip addr add "${u_right}" dev "${rightveth}"
ip link set "${leftveth}" up
ip link set "${rightveth}" up

# ---- WG + dummy on LEFT (enslaved to left VRF) ----
ip link add dev "${wg_left}" type wireguard
ip link set "${wg_left}" master "${vrf_left}"
ip addr add "${wg_left_ip}" dev "${wg_left}" || true
ip link set "${wg_left}" up
wg set "${wg_left}" private-key "private_left${cnt}"
ip link set "${wg_left}" mtu 1380

ip link add "${dum_left}" type dummy
ip link set "${dum_left}" master "${vrf_left}"
ip addr add "${dum_left_ip}" dev "${dum_left}"
ip link set "${dum_left}" up

# ---- WG + dummy on RIGHT (enslaved to right VRF) ----
ip link add dev "${wg_right}" type wireguard
ip link set "${wg_right}" master "${vrf_right}"
ip addr add "${wg_right_ip}" dev "${wg_right}" || true
ip link set "${wg_right}" up
wg set "${wg_right}" private-key "private_right${cnt}"
ip link set "${wg_right}" mtu 1380

ip link add "${dum_right}" type dummy
ip link set "${dum_right}" master "${vrf_right}"
ip addr add "${dum_right_ip}" dev "${dum_right}"
ip link set "${dum_right}" up

# VRF + UDP accept so WireGuard transport works
sysctl -w net.ipv4.udp_l3mdev_accept=1 >/dev/null
sysctl -w net.ipv4.tcp_l3mdev_accept=1 >/dev/null

# (already present, but keep)
sysctl -w net.ipv4.conf.all.rp_filter=0       >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0   >/dev/null
for IF in "${wg_left}" "${wg_right}" "${leftveth}" "${rightveth}" "${dum_left}" "${dum_right}"; do
  sysctl -w "net.ipv4.conf.${IF}.rp_filter=0" >/dev/null
done

# ---- WG peer configs (endpoints are the underlay veth IPs) ----
wg set "${wg_left}" \
  listen-port "${port_left}" \
  peer "${pbl_right}" \
  allowed-ips "10.20.$((cnt+10)).0/24" \
  endpoint "${u_right_ip}:${port_right}" \
  persistent-keepalive 5

wg set "${wg_right}" \
  listen-port "${port_right}" \
  peer "${pbl_left}" \
  allowed-ips "10.10.$((cnt+10)).0/24" \
  endpoint "${u_left_ip}:${port_left}" \
  persistent-keepalive 5

# ---- per-VRF overlay routes (force overlay via WG inside each VRF) ----
ip route replace table "${tbl_left}"  "10.20.$((cnt+10)).0/24" dev "${wg_left}"
ip route replace table "${tbl_right}" "10.10.$((cnt+10)).0/24" dev "${wg_right}"

# ---- rp_filter off (avoid asymmetric drop), inside VRFs' member ifaces ----
for IF in "${wg_left}" "${wg_right}" "${leftveth}" "${rightveth}" "${dum_left}" "${dum_right}"; do
  sysctl -w "net.ipv4.conf.${IF}.rp_filter=0" >/dev/null
done
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null

# ---- quick checks ----
wg show "${wg_left}"
wg show "${wg_right}"

sleep $((cnt+3))

# With VRF, do lookups per VRF (should say dev wg*)
ip vrf exec "${vrf_right}" ip route get "${dum_left_ip_host}" from "${dum_right_ip_host}"
ip vrf exec "${vrf_left}"  ip route get "${dum_right_ip_host}" from "${dum_left_ip_host}"

# ---- overlay connectivity test (dummy↔dummy) ----
ip vrf exec "${vrf_right}" ping -c 1 "${dum_left_ip_host}" -I "${dum_right_ip_host}"

# ---- iperf test (server in LEFT VRF, client in RIGHT VRF) ----
ip vrf exec "${vrf_left}"  iperf3 -s -B "${dum_left_ip_host}" --forceflush --interval 1 2>&1 | tee "output_receive_${cnt}.txt" &
wait_for_iperf
ip vrf exec "${vrf_right}" iperf3 -c "${dum_left_ip_host}" -B "${dum_right_ip_host}" -t 1000 -P 1 -M 1310 --interval 1 2>&1 | tee "output_send_${cnt}.txt"
