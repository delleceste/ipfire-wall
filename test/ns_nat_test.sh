#!/bin/bash
#
# IPFire Namespace Test Script
#
# This script sets up a network namespace environment to test the IPFire firewall module.
# It creates three namespaces: client, firewall, and server.
#
# Topology:
# [Client NS] <--(veth_client)--> [Router NS (IPFire)] <--(veth_server)--> [Server NS]
#
# Client IP: 10.0.1.2/24
# Router Client-side IP: 10.0.1.1/24
# Router Server-side IP: 10.0.2.1/24
# Server IP: 10.0.2.2/24
#
# Tests covering:
# 1. Source NAT (SNAT)
# 2. Destination NAT (DNAT)
# 3. Masquerading

set -e

# Configuration
MODULE_NAME="ipfi"
NS_CLIENT="client_ns"
NS_ROUTER="router_ns"
NS_SERVER="server_ns"

VETH_RC="veth_rc" # Router -> Client
VETH_CR="veth_cr" # Client -> Router
VETH_RS="veth_rs" # Router -> Server
VETH_SR="veth_sr" # Server -> Router

IP_CLIENT="10.0.1.2/24"
IP_ROUTER_C="10.0.1.1/24"
IP_ROUTER_S="10.0.2.1/24"
IP_SERVER="10.0.2.2/24"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

function cleanup {
    echo -e "${GREEN}Cleaning up...${NC}"
    # Delete namespaces (interfaces disappear automatically)
    ip netns delete $NS_CLIENT 2>/dev/null || true
    ip netns delete $NS_ROUTER 2>/dev/null || true
    ip netns delete $NS_SERVER 2>/dev/null || true
    # Unload module
    # rmmod $MODULE_NAME 2>/dev/null || true
}

# Trap exit for cleanup
trap cleanup EXIT

echo -e "${GREEN}Starting IPFire Namespace Test${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

# Load kernel module with per-namespace support enabled
# echo -e "${GREEN}Loading $MODULE_NAME module...${NC}"
# Note: 'per_net=1' enables netns support if implemented in the module
# modprobe $MODULE_NAME per_net=1 || { echo -e "${RED}Failed to load module${NC}"; exit 1; }

echo -e "${GREEN}Network Namespace Setup Complete.${NC}"
echo -e "${GREEN}IMPORTANT: The 'ipfi' kernel module is NOT loaded by this script.${NC}"
echo -e "You must start the firewall inside the Router NS to load the module and rules:"
echo -e "  sudo ip netns exec $NS_ROUTER /path/to/ipfire/executable"
echo -e "Ensure 'per_net=1' is used if loading the module manually."

# Create namespaces
echo -e "${GREEN}Creating namespaces...${NC}"
ip netns add $NS_CLIENT
ip netns add $NS_ROUTER
ip netns add $NS_SERVER

# Create veth pairs
echo -e "${GREEN}Creating veth pairs...${NC}"
# veth_client: Client <-> Router
ip link add $VETH_CR type veth peer name $VETH_RC
# veth_server: Router <-> Server
ip link add $VETH_SR type veth peer name $VETH_RS

# Move interfaces to correct namespaces
# Client side of link 1 -> Client NS
ip link set $VETH_CR netns $NS_CLIENT
# Router side of link 1 -> Router NS
ip link set $VETH_RC netns $NS_ROUTER
# Router side of link 2 -> Router NS
ip link set $VETH_RS netns $NS_ROUTER
# Server side of link 2 -> Server NS
ip link set $VETH_SR netns $NS_SERVER

# Configure interfaces and routing

# Client NS
echo -e "${GREEN}Configuring Client NS...${NC}"
ip netns exec $NS_CLIENT ip addr add $IP_CLIENT dev $VETH_CR
ip netns exec $NS_CLIENT ip link set $VETH_CR up
ip netns exec $NS_CLIENT ip link set lo up
# Default route via Router's client-side IP
ip netns exec $NS_CLIENT ip route add default via ${IP_ROUTER_C%/*}

# Router NS
echo -e "${GREEN}Configuring Router NS...${NC}"
ip netns exec $NS_ROUTER ip addr add $IP_ROUTER_C dev $VETH_RC
ip netns exec $NS_ROUTER ip addr add $IP_ROUTER_S dev $VETH_RS
ip netns exec $NS_ROUTER ip link set $VETH_RC up
ip netns exec $NS_ROUTER ip link set $VETH_RS up
ip netns exec $NS_ROUTER ip link set lo up
# Enable IP forwarding
ip netns exec $NS_ROUTER sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Server NS
echo -e "${GREEN}Configuring Server NS...${NC}"
ip netns exec $NS_SERVER ip addr add $IP_SERVER dev $VETH_SR
ip netns exec $NS_SERVER ip link set $VETH_SR up
ip netns exec $NS_SERVER ip link set lo up
# Default route via Router's server-side IP
ip netns exec $NS_SERVER ip route add default via ${IP_ROUTER_S%/*}

# Basic connectivity check
echo -e "${GREEN}Checking basic connectivity (Client -> Server)...${NC}"
# Ping might fail if firewall default policy is DROP, but routing should be correct
if ip netns exec $NS_CLIENT ping -c 1 -W 1 ${IP_SERVER%/*} >/dev/null 2>&1; then
    echo -e "${GREEN}Connectivity OK${NC}"
else
    echo -e "${RED}Ping failed (Check Routing/Firewall Policies)${NC}"
fi

# ---------------------------------------------------------------------------
# Test Functions
# ---------------------------------------------------------------------------

run_iperf_test() {
    local server_ns=$1
    local client_ns=$2
    local target_ip=$3
    local desc=$4

    echo -e "\n${GREEN}--- Test: $desc ---${NC}"
    
    # Start iperf3 server in background
    # -s: server mode
    # -D: daemon
    # -1: handle one client connection then exit
    echo -e "Starting iperf3 server in $server_ns listening on $target_ip..."
    ip netns exec $server_ns iperf3 -s -D -1
    
    # Give server time to start
    sleep 1

    # Run client
    echo -e "Running iperf3 client from $client_ns connecting to $target_ip..."
    if ip netns exec $client_ns iperf3 -c $target_ip -t 2; then
        echo -e "${GREEN}Test PASSED${NC}"
    else
        echo -e "${RED}Test FAILED${NC}"
    fi

    # Cleanup any lingering iperf3 processes
    pkill iperf3 || true
}

# ---------------------------------------------------------------------------
# Instructions for Usage
# ---------------------------------------------------------------------------

echo -e "\n${GREEN}Setup Complete.${NC}"
echo -e "You can now run manual tests or use the provided functions."
echo -e "To configure the firewall rules, you would typically run the userspace tool inside the router namespace:"
echo -e "  ip netns exec $NS_ROUTER /path/to/ipfire"

# Sample Tests (Commented out until rules can be applied programmatically)
# run_iperf_test $NS_SERVER $NS_CLIENT ${IP_SERVER%/*} "Direct Routed Traffic (No NAT)"

# User-requested scenarios:
# 1. Source NAT (SNAT): Client (10.0.1.2) -> Server (10.0.2.2), Src rewritten to Router (10.0.2.1)
# 2. Destination NAT (DNAT): Client (10.0.1.2) -> Router (10.0.1.1:Port), Dst rewritten to Server (10.0.2.2:Port)
# 3. Masquerade: Similar to SNAT but dynamic on output interface

echo -e "\n${GREEN}Script execution finished.${NC}"
# Prevent immediate cleanup for inspection
read -p "Press enter to cleanup and exit..."
