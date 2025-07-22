#!/bin/bash
set -x
sudo pkill iperf3
sudo ps aux | grep wg0 | awk '{print $2}' | sudo xargs sudo kill -9
sudo ps aux | grep iperf3 | awk '{print $2}' | sudo xargs sudo kill -9
sudo ip netns list  | awk '{print $1}' | sudo xargs sudo ip netns del
sudo rm out/output_*.txt out/private_left* out/private_right* out/publeft* out/pubright* out/wg*_*.log
