iperf3 --server
iperf3 --udp --client 127.0.0.1 --bitrate 1000M -t 1000 -P 128 -M 1310
 
modinfo wireguard
sudo cp ./wireguard_5.4_plain.ko /lib/modules/5.4.0-166-generic/kernel/wireguard/wireguard.ko
modinfo wireguard
sudo rmmod wireguard
sudo modprobe wireguard
modinfo wireguard

 
modinfo wireguard
sudo cp ./wireguard_5.4_aes.ko /lib/modules/5.4.0-166-generic/kernel/wireguard/wireguard.ko
modinfo wireguard
sudo rmmod wireguard
sudo modprobe wireguard
modinfo wireguard




sudo ./test_generic_single.sh 25
sudo ./test_generic_single.sh 25 udp


tar cvzf output.tarr.gz output_*.txt
tar xvzf output.tar.gz -C .

CREATE EXTENSION pgcrypto;
http://192.168.134.34/

update send set bitrate = 1000*1000*1000 where is_tcp = 0 and try = 1
update send set bitrate = 1000*1000 where is_tcp = 0 and try = 2
update send set bitrate = 10*1000*1000 where is_tcp = 0 and try = 3
update send set bitrate = 1000*1000 where is_tcp = 0 and try = 4
update send set bitrate = 5*1000*1000 where is_tcp = 0 and try = 5
update send set bitrate = 3*1000*1000 where is_tcp = 0 and try = 6
update send set bitrate = 2*1000*1000 where is_tcp = 0 and try = 7

udp 
1-> 1Gb/s
2-> 1Mb/s
3-> 10Mb/s
4-> 1Mb/s
5-> 5Mb/s
6-> 3Mb/s
7-> 2Mb/s
8-> 4Mb/s
