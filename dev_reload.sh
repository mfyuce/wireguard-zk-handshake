#!/bin/bash
set -e

sudo modprobe udp_tunnel ip6_udp_tunnel libcurve25519 libchacha libblake2s

sudo rmmod wireguard 2>/dev/null || true
sudo insmod ./wireguard.ko
dmesg | tail
