#!/bin/bash
set -x

# ifconfig eth0 172.16.25.125 netmask 255.255.255.224 broadcast 172.16.25.63
# sudo route add default gw
cnt=0
netnsleft="leftns$cnt"
netnsright="rightns$cnt"
leftip=192.168.0.$(($cnt + 1)) #+2 bir sonrakinde
rightip=192.168.0.$(($cnt + 2)) #+2 bir sonrakinde
leftveth=veth$(($cnt)) #+2 bir sonrakinde
rightveth=veth$(($cnt+1)) #+2 bir sonrakinde

numrxqueues=20
numtxqueues=20
xdpprogram=xdp_cpu_map5_lb_hash_ip_pairs #xdp_prognum5_lb_hash_ip_pairs
#xdpprogram=xdp_prognum3_proto_separate
#xdpprogram=xdp_prognum2_round_robin

pkill iperf3

pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
sleep() { read -t "$1" -N 0 || true; }
waitiperf() { while [[ $(ss -N "$1" -tlp 'sport = 5201') != *iperf3* ]]; do sleep 0.1; done; }

cleanup() {
#    ip netns exec $netnsleft  ip link set dev wg0 xdpgeneric off
#    ip netns exec $netnsright  ip link set dev wg0 xdpgeneric off
 #   kill -9 $pidleft #$pidright
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

#ip netns exec $netnsleft ip link add dev wg0 numtxqueues $numtxqueues numrxqueues $numrxqueues type wireguard
ip netns exec $netnsleft ../wireguard-go/wireguard-go wg0
for ((i=0; i < $numtxqueues; i++)); do
    echo "ffffff,ffffffff,ffffffff" > /sys/class/net/wg0/queues/tx-$i/xps_cpus
    cat /sys/class/net/wg0/queues/tx-$i/xps_cpus
done
for ((i=0; i < $numrxqueues; i++)); do
    echo "ffffff,ffffffff,ffffffff" > /sys/class/net/wg0/queues/rx-$i/rps_cpus
    cat /sys/class/net/wg0/queues/rx-$i/rps_cpus
done

#ip netns exec $netnsleft  ./5.4/xdp_redirect_cpu -d wg0 -c 0 -c 1 -c 2 -c 3 -c 4 -c 5 -c 6 -c 7 -c 8 -c 9 -c 10 -S -v -p $xdpprogram &
#pidleft=$!

#ip netns exec $netnsleft  tc qdisc add dev wg0 parent root handle 1: hfsc default 1
#ip netns exec $netnsleft  tc class add dev wg0 parent 1: classid 1:1 hfsc sc rate 10000mbit ul rate 10000mbit

ip netns exec $netnsleft address add dev wg0 192.168.2.1/24
ip netns exec $netnsleft ip link set up dev wg0
ip netns exec $netnsleft wg set wg0 private-key ./private_left$cnt
ip netns exec $netnsleft ip link add dum0 type dummy
ip netns exec $netnsleft ip addr add 10.10.10.10/24 dev dum0
ip netns exec $netnsleft ip link set up dev dum0
ip netns exec $netnsleft ip route add default dev wg0
ip netns exec $netnsleft wg set wg0 listen-port 51820 peer $pbl_right allowed-ips 0.0.0.0/0 endpoint $rightip:51820


ip link set dev $rightveth netns $netnsright
ip netns exec $netnsright ip addr add $rightip/30 dev $rightveth
ip netns exec $netnsright ip link set up dev $rightveth
ethtool $rightveth
ifconfig $rightveth
cat /sys/class/net/$rightveth/speed

ip netns exec $netnsright ip link add dev wg0 numtxqueues $numtxqueues numrxqueues $numrxqueues type wireguard
#ip netns exec $netnsright ../wireguard-go/wireguard-go wg0
for ((i=0; i < $numtxqueues; i++)); do
    echo "ffffff,ffffffff,ffffffff" > /sys/class/net/wg0/queues/tx-$i/xps_cpus
done
for ((i=0; i < $numrxqueues; i++)); do
    echo "ffffff,ffffffff,ffffffff" > /sys/class/net/wg0/queues/rx-$i/rps_cpus
done
#
#ip netns exec $netnsright  ./xdp_redirect_cpu -d wg0 -c 0 -c 1  -c 2   -c 3 -S -v -p $xdpprogram &
#pidright=$!

#ip netns exec $netnsright  tc qdisc add dev wg0 parent root handle 1: hfsc default 1
#ip netns exec $netnsright  tc class add dev wg0 parent 1: classid 1:1 hfsc sc rate 10000mbit ul rate 10000mbit


ip netns exec $netnsright ip address add dev wg0 192.168.2.1/24
ip netns exec $netnsright ip link set up dev wg0
ip netns exec $netnsright wg set wg0 private-key ./private_right$cnt
ip netns exec $netnsright ip link add dum0 type dummy
ip netns exec $netnsright ip addr add 10.20.20.10/24 dev dum0
ip netns exec $netnsright ip link set up dev dum0
ip netns exec $netnsright ip route add default dev wg0
ip netns exec $netnsright wg set wg0 listen-port 51820 peer $pbl_left allowed-ips 0.0.0.0/0 endpoint $leftip:51820



ip netns exec $netnsright ping -c 5 10.10.10.10 -I 10.20.20.10


ip netns exec $netnsleft iperf3 -s -B 10.10.10.10 | grep 'SUM' &
waitiperf $netnsleft 
ip netns exec $netnsright iperf3 -c 10.10.10.10 -B 10.20.20.10 -t 50 -P 128 -M 1360  | grep 'SUM'

