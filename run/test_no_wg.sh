#!/bin/bash

cnt=1
netnsleft="leftns$cnt"
netnsright="rightns$cnt"
leftip=192.168.0.1 #+2 bir sonrakinde
rightip=192.168.0.2 #+2 bir sonrakinde
leftveth=veth0 #+2 bir sonrakinde
rightveth=veth1 #+2 bir sonrakinde

pkill iperf3

pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
sleep() { read -t "$1" -N 0 || true; }
waitiperf() { while [[ $(ss -N "$1" -tlp 'sport = 5201') != *iperf3* ]]; do sleep 0.1; done; }

cleanup() {
    ip netns del $netnsleft
    ip netns del $netnsright
    exit
}

trap cleanup EXIT

ip netns add $netnsleft
ip netns add $netnsright
umask 077
wg genkey > private_left$cnt
wg genkey > private_right$cnt
wg pubkey <private_left$cnt> publeft$cnt
wg pubkey <private_right$cnt> pubright$cnt
pbl_left=$(cat publeft$cnt)
pbl_right=$(cat pubright$cnt)

ip link add $leftveth type veth peer $rightveth
ip link set dev $leftveth netns $netnsleft
ip netns exec $netnsleft ip addr add $leftip/30 dev $leftveth
ip netns exec $netnsleft ip link set up dev $leftveth
ethtool $leftveth
ifconfig $leftveth
cat /sys/class/net/$leftveth/speed

#ip netns exec $netnsleft ip link add dev wg0 type wireguard
#ip netns exec $netnsleft address add dev wg0 192.168.2.1/24
#ip netns exec $netnsleft ip link set up dev wg0
#ip netns exec $netnsleft wg set wg0 private-key ./private_left$cnt
ip netns exec $netnsleft ip link add dum0 type dummy
ip netns exec $netnsleft ip addr add 10.10.10.10/24 dev dum0
ip netns exec $netnsleft ip link set up dev dum0
ip netns exec $netnsleft ip route add default dev $leftveth
#ip netns exec $netnsleft wg set wg0 listen-port 51820 peer $pbl_right allowed-ips 0.0.0.0/0 endpoint $rightip:51820


ip link set dev $rightveth netns $netnsright
ip netns exec $netnsright ip addr add $rightip/30 dev $rightveth
ip netns exec $netnsright ip link set up dev $rightveth
ethtool $rightveth
ifconfig $rightveth
cat /sys/class/net/$rightveth/speed

#ip netns exec $netnsright ip link add dev wg0 type wireguard
#ip netns exec $netnsright ip address add dev wg0 192.168.2.1/24
#ip netns exec $netnsright ip link set up dev wg0
#ip netns exec $netnsright wg set wg0 private-key ./private_right$cnt
ip netns exec $netnsright ip link add dum0 type dummy
ip netns exec $netnsright ip addr add 10.20.20.10/24 dev dum0
ip netns exec $netnsright ip link set up dev dum0
ip netns exec $netnsright ip route add default dev $rightveth
#ip netns exec $netnsright wg set wg0 listen-port 51820 peer $pbl_left allowed-ips 0.0.0.0/0 endpoint $leftip:51820



ip netns exec $netnsright ping -c 5 10.10.10.10 -I 10.20.20.10


ip netns exec $netnsleft iperf3  -s -B 10.10.10.10 |  grep 'SUM' &
waitiperf $netnsleft 
ip netns exec $netnsright iperf3 -c 10.10.10.10 -B 10.20.20.10 -t 50 -P 128  -M 9000  | grep 'SUM'

