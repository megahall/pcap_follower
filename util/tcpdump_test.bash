#!/bin/bash

sudo tcpdump -n -i lo -C 100 -W 10 -w capture.pcap udp port 10000
