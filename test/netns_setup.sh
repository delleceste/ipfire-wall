#!/bin/bash
# setup-test-env.sh

set -e

echo "Creating network namespaces..."

# Create namespaces
ip netns add hostA
ip netns add hostB
ip netns add hostC

# Create veth pairs
# Pair 1: hostA <-> hostB (internal network)
ip link add veth0 type veth peer name veth1
# Pair 2: hostB <-> hostC (external network)
ip link add veth2 type veth peer name veth3

# Move interfaces to namespaces
ip link set veth0 netns hostA
ip link set veth1 netns hostB
ip link set veth2 netns hostB
ip link set veth3 netns hostC

# Configure Host A (Client)
echo "Configuring Host A (Client)..."
ip netns exec hostA ip addr add 192.168.1.10/24 dev veth0
ip netns exec hostA ip link set veth0 up
ip netns exec hostA ip link set lo up
ip netns exec hostA ip route add default via 192.168.1.1

# Configure Host B (Router/Firewall)
echo "Configuring Host B (Router/Firewall)..."
ip netns exec hostB ip addr add 192.168.1.1/24 dev veth1
ip netns exec hostB ip addr add 10.0.0.1/24 dev veth2
ip netns exec hostB ip link set veth1 up
ip netns exec hostB ip link set veth2 up
ip netns exec hostB ip link set lo up
# Enable IP forwarding
ip netns exec hostB sysctl -w net.ipv4.ip_forward=1

# Configure Host C (Server)
echo "Configuring Host C (Server)..."
ip netns exec hostC ip addr add 10.0.0.10/24 dev veth3
ip netns exec hostC ip link set veth3 up
ip netns exec hostC ip link set lo up
ip netns exec hostC ip route add default via 10.0.0.1

echo "Test environment created successfully!"
echo ""
echo "Usage:"
echo "  Host A: ip netns exec hostA bash"
echo "  Host B: ip netns exec hostB bash"
echo "  Host C: ip netns exec hostC bash"

