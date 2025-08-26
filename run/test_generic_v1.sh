#!/bin/bash
set -x
cnt=$1

leftip=192.168.${cnt}.1
rightip=192.168.${cnt}.2
leftveth="veth${cnt}_1"
rightveth="veth${cnt}_2"

cleanup() {
    ip link del dev $leftveth
    ip link del dev $rightveth
    ip link del dev $wg_left
    ip link del dev $wg_right
    ip link del dev dum${cnt}l
    ip link del dev dum${cnt}r
    exit
}


trap cleanup EXIT

umask 077
wg genkey > private_left${cnt}
wg genkey > private_right${cnt}
wg pubkey < private_left${cnt} > publeft${cnt}
wg pubkey < private_right${cnt} > pubright${cnt}
pbl_left=$(cat publeft${cnt})
pbl_right=$(cat pubright${cnt})

# veth pair
ip link add $leftveth type veth peer name $rightveth
ip addr add $leftip/30 dev $leftveth
ip addr add $rightip/30 dev $rightveth
ip link set $leftveth up
ip link set $rightveth up

# left side WG
wg_left="wg$((${cnt} +1))l"
ip link add dev $wg_left type wireguard
ip addr add 192.168.$((${cnt}+1)).$((${cnt}+1))/24 dev $wg_left
ip link set $wg_left up
wg set $wg_left private-key ./private_left${cnt}
ip link add dum${cnt}l type dummy
ip addr add 10.10.$((${cnt}+10)).10/24 dev dum${cnt}l
ip link set dum${cnt}l up
ip route add default dev $wg_left
wg set $wg_left listen-port 519$((20+${cnt}+1)) peer "$pbl_right" allowed-ips 0.0.0.0/0 endpoint $rightip:518$((20+${cnt}+1))

# right side WG
wg_right="wg$((${cnt} +1))r"
ip link add dev $wg_right type wireguard
ip addr add 192.168.$((${cnt}+1)).$((${cnt}+2))/24 dev $wg_right
ip link set $wg_right up
wg set $wg_right private-key ./private_right${cnt}
ip link add dum${cnt}r type dummy
ip addr add 10.20.$((${cnt}+10)).10/24 dev dum${cnt}r
ip link set dum${cnt}r up
ip route add default dev $wg_right
wg set $wg_right listen-port 518$((20+${cnt}+1)) peer "$pbl_left" allowed-ips 0.0.0.0/0 endpoint $leftip:519$((20+${cnt}+1))

# test
sleep $((${cnt}+5))
ping -c 1 10.10.$((${cnt}+10)).10 -I 10.20.$((${cnt}+10)).10
iperf3 -s -B 10.10.$((${cnt}+10)).10 --forceflush --interval 1 2>&1 | tee output_receive_${cnt}.txt &
sleep 1
iperf3 -c 10.10.$((${cnt}+10)).10 -B 10.20.$((${cnt}+10)).10 -t 10 -P 1 -M 1310 --interval 1 2>&1 | tee output_send_${cnt}.txt

