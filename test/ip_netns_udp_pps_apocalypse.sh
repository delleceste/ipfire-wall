#!/usr/bin/env bash



ip netns exec ns1 iperf3 -c 10.0.2.2 -u -b 1G -l 64 -t 300
