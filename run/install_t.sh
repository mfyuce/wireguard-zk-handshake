#./build.sh
sudo pkill iperf
sudo cp ../send/wireguard_higpri_noenc_lockless.ko /lib/modules/$(uname -r)/kernel/drivers/net/wireguard
sudo rmmod wireguard
sudo modprobe wireguard
sudo echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control
sudo modinfo wireguard
./test.sh &
./test2.sh &
./test3.sh &
./test4.sh &