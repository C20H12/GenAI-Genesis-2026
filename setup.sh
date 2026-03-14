#!/bin/bash

sudo sysctl -w net.ipv4.ip_forward=1

sudo setcap 'cap_net_admin,cap_net_raw+ep' ./mitm

sudo ip rule  del fwmark 0x1 lookup 100 || true
sudo ip route del local 0.0.0.0/0 dev lo table 100 || true

sudo ip rule  add fwmark 0x1 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100

sudo iptables -t mangle -F PREROUTING
sudo iptables -t filter -F FORWARD

sudo iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY --on-port 8000 --tproxy-mark 0x1/0x1
sudo iptables -t filter -A FORWARD -p udp --dport 443 -j DROP

