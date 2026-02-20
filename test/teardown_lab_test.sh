#!/usr/bin/env bash
set -e

NS1="ns1"
NS2="ns2"

VETH1="veth1"
VETH2="veth2"

echo "[*] Removing namespaces..."
ip netns del $NS1 2>/dev/null || true
ip netns del $NS2 2>/dev/null || true

echo "[*] Deleting host-side veth interfaces..."
ip link del $VETH1 2>/dev/null || true
ip link del $VETH2 2>/dev/null || true

echo "[*] Optional: disabling IPv4 forwarding (if you want)"
# sysctl -w net.ipv4.ip_forward=0 >/dev/null

echo "[✓] Teardown complete. All test topology removed."
