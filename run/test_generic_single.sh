#!/bin/bash

set -x


pkill iperf3

howmany=$1

pids=()

# run processes and store pids in array
for ((i=0; i < $howmany; i++)); do
    ./test_generic.sh ${i}   &
    pids+=($!)
    sleep 5
done
sleep 10
# wait for all pids
for pid in ${pids[*]}; do
    wait $pid
done
