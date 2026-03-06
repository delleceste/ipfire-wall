# Chapter 11: Network Namespace Support

This chapter details the current implementation of Network Namespace (netns) support and its intended use cases.

## 11.1. Host-Centric Design
By default, IPFire-Wall is designed as a **Host-Based Firewall**. 

- **Target**: Protect the host's primary network stack.
- **Scope**: Hooks are registered only in the initial namespace (`init_net`).
- **Performance**: Minimal overhead for systems using containers or namespaces that don't require firewalling.

## 11.2. The `per_net` Module Parameter
Administrators can control how the module interacts with namespaces via the `per_net` parameter:

| Mode | Behavior |
|------|----------|
| `per_net=0` (Default) | Hooks registered only in `init_net`. Traffic in other namespaces (including loopback inside containers) is invisible to IPFire. |
| `per_net=1` | Hooks are registered in **every** namespace (via `register_pernet_subsys`). |

## 11.3. Known Limitations (Current Version)

### Shared Global Tables
Even with `per_net=1`, the internal tables (State, NAT, and Logs) are **global and shared**. 
- A state entry created in Namespace A can be matched by traffic in Namespace B if the IPs/Ports happen to collide.
- This is intentional for the current primary use case (local performance testing) but lacks strict isolation between tenants.

### The `MYADDR` Issue
The `MYADDR` keyword in rules (e.g., `ACCEPT src=MYADDR`) currently relies on a lookup function that is **hardcoded to search `init_net`**.
- **Symptom**: "IPFIRE: no interface matching name" messages in the kernel log.
- **Cause**: If a rule uses `MYADDR` in a non-init namespace, the lookup fails because that interface name does not exist in the initial namespace's device list.
- **Recommendation**: Avoid `MYADDR` in rules when using `per_net=1` for namespace-to-namespace traffic.

## 11.4. Primary Use Case: Local Performance Lab
The `per_net=1` mode is optimized for local benchmarking:
1.  Create two namespaces connected via a `veth` pair.
2.  Enable IPFire in all namespaces.
3.  Flood packets between the namespaces using tools like `hping3` or `iperf`.
4.  Measure firewall overhead without involving physical network hardware or saturating the host's external NIC.
