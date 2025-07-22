#./build.sh
scp fatihyuce@10.20.206.142:/home/fatihyuce/work/projects/tmp/wireguard-mayaos/wireguard-5.10.55/wireguard.ko ./
sudo cp ./wireguard.ko /lib/modules/$(uname -r)/kernel/drivers/net/wireguard
sudo rmmod wireguard
sudo modprobe wireguard
sudo echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control
sudo modinfo wireguard