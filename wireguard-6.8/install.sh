./build.sh
sudo cp ./wireguard.ko /lib/modules/$(uname -r)/kernel/drivers/net/wireguard
sudo rmmod wireguard
sudo modprobe wireguard
sudo echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control
cd