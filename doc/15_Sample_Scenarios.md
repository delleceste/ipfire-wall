# Chapter 15: Sample Network Scenarios

This chapter aggregates practical configuration scenarios for IPFire-Wall, focusing specifically on Network Address Translation (NAT) and redirection flows. These examples illustrate the flexibility of the DNAT and SNAT engines.

## 15.1. Port Redirection (Local Host)
**Goal:** Redirect traffic from an external standard port (e.g., HTTP 80) to a different local service port (e.g., 8080).
- **Hook Used**: `PRE_ROUTING` (DNAT)
- **Mechanism**: The incoming packet's destination port is swapped before routing. The local IP stack then perceives the packet as destined for port 8080 and delivers it to the application listening there.

## 15.2. Transparent Proxying (Virus Scanning)
**Goal:** Redirect outbound user POP3 mail traffic (port 110) transparently to a local virus scanning proxy (`p3scan` on port 8110) before it reaches the Internet.
- **Hook Used**: `OUTPUT` (DNAT)
- **Mechanism**: Normal users initiate a connection to an external email server. Due to an Output DNAT rule, the packet's destination is changed to the local proxy (127.0.0.1:8110). 
- **API Extraction**: The proxy intercepts the packet and uses the `getsockopt` API (`SO_IPFI_GETORIG_DST`) to query IPFire-Wall for the original external server IP. The proxy retrieves the emails safely, scans them, and hands them to the email client.

## 15.3. External SSH Server Forwarding
**Goal:** A client connects to the IPFire-Wall router requesting SSH. The firewall redirects the connection to an internal SSH server (Host Y).
- **Hook Used**: `PRE_ROUTING` (DNAT) -> `FORWARD` -> `POST_ROUTING` (SNAT/Masquerade)
- **Mechanism**: 
  - In `PRE_ROUTING`, the firewall rewrites the packet's destination IP to the internal Server Y.
  - The routing table forwards the packet.
  - In `POST_ROUTING`, if the internal server Y doesn't have a default route back through the firewall, a Source NAT (Masquerade) is applied to ensure the replies return through the firewall before proceeding to the original client.

## 15.4. DNS Interception
**Goal:** Prevent users from bypassing parental controls or organizational policies by hardcoding an external DNS server (e.g., 8.8.8.8).
- **Hook Used**: `PRE_ROUTING` / `OUTPUT`
- **Mechanism**: A destination NAT rule intercepts all UDP traffic destined for port 53. Regardless of the intended external server, the address is rewritten to point to the local network's strictly-managed DNS caching server.
