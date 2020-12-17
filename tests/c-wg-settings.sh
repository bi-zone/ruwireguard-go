#!/usr/bin/env bash

host_private_key="YUcpBQ7Wp58OHZWyfGkuKQEUhAA65excyzFLhi/cuiA="
peer_public_key="AgYLfk3J1RqpUbG7X/kQ2KHymBMdxzmhsgtRMBEEf7wN"

echo "$host_private_key" > /tmp/host_private_key

sudo ip link set wg0 up

sudo ./wg set wg0 \
  listen-port 5800 \
  private-key /tmp/host_private_key \
  peer "$peer_public_key" \
  endpoint 10.10.10.1:5800 \
  persistent-keepalive 3 \
  allowed-ips 0.0.0.0/0

sudo ip addr add 7.7.7.1/24 dev wg0
sudo ip addr add 10.10.10.2/24 dev wan_tun
sudo ip ro add 6.6.6.0/24 dev wg0

# add netns for lan_tun
sudo ip netns del lan_tun_demo
sudo ip netns add lan_tun_demo
sudo ip link set dev lan_tun netns lan_tun_demo
sudo ip netns exec lan_tun_demo ip link set lan_tun up
sudo ip netns exec lan_tun_demo ip addr add 6.6.6.1/24 dev lan_tun
sudo ip netns exec lan_tun_demo ip ro add default dev lan_tun
