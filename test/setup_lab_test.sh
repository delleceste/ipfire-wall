#!/usr/bin/env bash
set -e

NS1="ns1"
NS2="ns2"

VETH1="veth1"
VETH1_NS="veth1-ns"
VETH2="veth2"
VETH2_NS="veth2-ns"

IP1_HOST="10.0.1.1/24"
IP1_NS="10.0.1.2/24"

IP2_HOST="10.0.2.1/24"
IP2_NS="10.0.2.2/24"

echo "[*] Cleaning old setup..."

# Delete namespaces if they exist
ip netns del $NS1 2>/dev/null || true
ip netns del $NS2 2>/dev/null || true

# Delete leftover veth interfaces if present
ip link del $VETH1 2>/dev/null || true
ip link del $VETH2 2>/dev/null || true

echo "[*] Creating namespaces..."
ip netns add $NS1
ip netns add $NS2

echo "[*] Creating veth pairs..."
ip link add $VETH1 type veth peer name $VETH1_NS
ip link add $VETH2 type veth peer name $VETH2_NS

echo "[*] Moving peers into namespaces..."
ip link set $VETH1_NS netns $NS1
ip link set $VETH2_NS netns $NS2

echo "[*] Configuring host side interfaces..."
ip addr add $IP1_HOST dev $VETH1
ip addr add $IP2_HOST dev $VETH2
ip link set $VETH1 up
ip link set $VETH2 up

echo "[*] Configuring namespace $NS1..."
ip netns exec $NS1 ip addr add $IP1_NS dev $VETH1_NS
ip netns exec $NS1 ip link set lo up
ip netns exec $NS1 ip link set $VETH1_NS up
ip netns exec $NS1 ip route add default via 10.0.1.1

echo "[*] Configuring namespace $NS2..."
ip netns exec $NS2 ip addr add $IP2_NS dev $VETH2_NS
ip netns exec $NS2 ip link set lo up
ip netns exec $NS2 ip link set $VETH2_NS up
ip netns exec $NS2 ip route add default via 10.0.2.1

echo "[*] Enabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo
echo "[✓] Topology ready."
echo
echo "ns1 (10.0.1.2) --> init_net firewall --> ns2 (10.0.2.2)"
echo
echo "Start server:"
echo "  ip netns exec $NS2 iperf3 -s"
echo
echo "Run client:"
echo "  ip netns exec $NS1 iperf3 -c 10.0.2.2 -u -b 500M"
echo
