#!/bin/bash

# ifconfig eth0 172.16.25.125 netmask 255.255.255.224 broadcast 172.16.25.63
set -x
cnt=$1
netnsleft="leftns${cnt}"
netnsright="rightns${cnt}"
leftip=192.168.${cnt}.1 #+2 bir sonrakinde
rightip=192.168.${cnt}.2 #+2 bir sonrakinde
leftveth="veth${cnt}_1" #+2 bir sonrakinde
rightveth="veth${cnt}_2" #+2 bir sonrakinde
#numrxqueues=50
#numtxqueues=50
#xdpprogram=xdp_prognum5_lb_hash_ip_pairs
#xdpprogram=xdp_prognum3_proto_separate
#xdpprogram=xdp_prognum2_round_robin

pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
sleep() { read -t "$1" -N 0 || true; }
waitiperf() { while [[ $(ss -N "$1" -tlp 'sport = 5201') != *iperf3* ]]; do sleep 0.1; done; }

cleanup() {
#    ip netns exec $netnsleft pkill  boringtun-cli
#    ip netns exec $netnsright pkill  boringtun-cli
    ip netns del $netnsleft
    ip netns del $netnsright
    exit
}

trap cleanup EXIT

ip netns add $netnsleft
ip netns add $netnsright
umask 077
wg genkey > private_left${cnt}
wg genkey > private_right${cnt}
wg pubkey <private_left${cnt}> publeft${cnt}
wg pubkey <private_right${cnt}> pubright${cnt}
pbl_left=''$(cat publeft${cnt})
pbl_right=$(cat pubright${cnt})

ip link add $leftveth type veth peer $rightveth
ip link set dev $leftveth netns $netnsleft
ip netns exec $netnsleft ip addr add $leftip/30 dev $leftveth
ip netns exec $netnsleft ip link set up dev $leftveth
#ethtool $leftveth
#ifconfig $leftveth
#cat /sys/class/net/$leftveth/speed

#ip netns exec $netnsleft ip link add dev wg0 numtxqueues $numtxqueues numrxqueues $numrxqueues type wireguard
ip netns exec $netnsleft ip link add dev wg$((${cnt} +1))l  type wireguard
#for ((i=0; i < $numtxqueues; i++)); do
#    echo "ffffff,ffffffff,ffffffff" > /sys/class/net/wg$((${cnt} +1))l/queues/tx-$i/xps_cpus
#    cat /sys/class/net/wg$((${cnt} +1))l/queues/tx-$i/xps_cpus
#done
#for ((i=0; i < $numrxqueues; i++)); do
#    echo "ffffff,ffffffff,ffffffff" > /sys/class/net/wg$((${cnt} +1))l/queues/rx-$i/rps_cpus
#    cat /sys/class/net/wg$((${cnt} +1))l/queues/rx-$i/rps_cpus
#done

#ip netns exec $netnsleft ip link add dev wg$((${cnt} +1))l type wireguard
#ip netns exec $netnsleft  ./6.26/xdp_redirect_cpu -d wg0 -c 0 -c 1  -S -v -p $xdpprogram &
#pidleft=$!
#ip netns exec $netnsleft taskset --cpu-list 1,2 /home/ulak/aes/boringtune/target/release/boringtun-cli -t 1 -v trace -l /home/ulak/aes/boringtune/wg1_${cnt}.log  wg$((${cnt} +1))l
#ip netns exec $netnsleft taskset --cpu-list $((2*${cnt})) /home/fatihyuce/work/projects/maya3/ng_sdn/wireguard/boringtun/target/release/boringtun-cli --disable-multi-queue --disable-connected-udp   --disable-drop-privileges  -t 1 -v trace -l /home/fatihyuce/work/projects/maya3/ng_sdn/wireguard/boringtun/wg1_${cnt}.log  wg$((${cnt} +1))
ip netns exec $netnsleft ip address add dev wg$((${cnt} +1))l 192.168.$((${cnt} + 1)).$((${cnt} + 1))/24
ip netns exec $netnsleft ip link set up dev wg$((${cnt} +1))l
ip netns exec $netnsleft wg set wg$((${cnt} +1))l private-key ./private_left${cnt}
ip netns exec $netnsleft ip link add dum0 type dummy
ip netns exec $netnsleft ip addr add 10.10.$((${cnt} + 10)).10/24 dev dum0
ip netns exec $netnsleft ip link set up dev dum0
ip netns exec $netnsleft ip route add default dev wg$((${cnt} +1))l
ip netns exec $netnsleft wg set wg$((${cnt} +1))l listen-port 518$((20 + ${cnt} +1)) peer "$pbl_right" allowed-ips 0.0.0.0/0 endpoint $rightip:518$((20 + ${cnt} +1))


ip link set dev $rightveth netns $netnsright
ip netns exec $netnsright ip addr add $rightip/30 dev $rightveth
ip netns exec $netnsright ip link set up dev $rightveth
#ethtool $rightveth
#ifconfig $rightveth
#cat /sys/class/net/$rightveth/speed

#ip netns exec $netnsright ip link add dev wg$((${cnt} +1))r numtxqueues $numtxqueues numrxqueues $numrxqueues type wireguard
ip netns exec $netnsright ip link add dev wg$((${cnt} +1))r  type wireguard
#for ((i=0; i < $numtxqueues; i++)); do
#    echo "ffffff,ffffffff,ffffffff" > /sys/class/net/wg$((${cnt} +1))r/queues/tx-$i/xps_cpus
#done
#for ((i=0; i < $numrxqueues; i++)); do
#    echo "ffffff,ffffffff,ffffffff" > /sys/class/net/wg$((${cnt} +1))r/queues/rx-$i/rps_cpus
#done

#ip netns exec $netnsright  ./xdp_redirect_cpu -d wg0  -c 0 -c 1  -c 2 -S -v -p $xdpprogram &
#pidright=$!

#ip netns exec $netnsright ip link add dev wg$((${cnt} +1))r type wireguard
#ip netns exec $netnsright taskset --cpu-list 1,2 /home/ulak/aes/boringtune/target/release/boringtun-cli -t 1 -v trace -l /home/ulak/aes/boringtune/wg2_${cnt}.log  wg$((${cnt} +1))r
#ip netns exec $netnsright taskset --cpu-list $((2*${cnt} + 1)) /home/fatihyuce/work/projects/maya3/ng_sdn/wireguard/boringtun/target/release/boringtun-cli --disable-multi-queue --disable-connected-udp   --disable-drop-privileges   -t 1 -v trace -l /home/fatihyuce/work/projects/maya3/ng_sdn/wireguard/boringtun/wg2_${cnt}.log  wg$((${cnt} +1))r
ip netns exec $netnsright ip address add dev wg$((${cnt} +1))r 192.168.$((${cnt} + 1)).$((${cnt} + 2))/24
ip netns exec $netnsright ip link set up dev wg$((${cnt} +1))r
ip netns exec $netnsright wg set wg$((${cnt} +1))r private-key ./private_right${cnt}
ip netns exec $netnsright ip link add dum0 type dummy
ip netns exec $netnsright ip addr add 10.20.$((${cnt} + 10)).10/24 dev dum0
ip netns exec $netnsright ip link set up dev dum0
ip netns exec $netnsright ip route add default dev wg$((${cnt} +1))r
ip netns exec $netnsright wg set wg$((${cnt} +1))r listen-port 518$((20 + ${cnt} +1)) peer "$pbl_left" allowed-ips 0.0.0.0/0 endpoint $leftip:518$((20 + ${cnt} +1))



sleep $((${cnt} + 5))
ip netns exec $netnsright ping -c 1 10.10.$((${cnt} + 10)).10 -I 10.20.$((${cnt} + 10)).10
echo Test ${cnt}
ip netns exec $netnsleft iperf3 -s -B 10.10.$((${cnt} + 10)).10 --forceflush   --interval 1   2>&1 | tee output_receive_${cnt}.txt  & #>/dev/null
waitiperf $netnsleft 
ip netns exec $netnsright iperf3 -c 10.10.$((${cnt} + 10)).10 -B 10.20.$((${cnt} + 10)).10 -t 10 -P 1 -M 1310    --interval 1   2>&1 | tee output_send_${cnt}.txt #>/dev/null

