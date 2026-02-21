# Chapter 14: Port Scanning Test Analysis

IPFire-Wall's stateful inspection and default DROP policies have been rigorously tested against industry-standard network scanners like **NMAP**. This chapter outlines how the kernel filtering engine responds to various stealth scanning techniques.

## 14.1. Stealth TCP Scans

Because IPFire-Wall automatically drops unapproved traffic, the firewall achieves high stealth by refusing to send `RST` (Reset) or `ICMP Unreachable` packets back to the scanner. This typically results in NMAP classifying ports as `filtered` rather than `closed`, obscuring the network topology.

### SYN Scanning
In a standard SYN scan, NMAP sends a `SYN` packet. 
- **Expected Open**: `SYN/ACK`
- **Expected Closed**: `RST`
- **IPFire-Wall Response**: If no explicit rule or state exists, IPFire-Wall drops the packet silently without sending a `RST`. This causes NMAP to eventually time out and classify the port as `filtered` rather than `closed`.

### ACK Scanning
ACK scanning is used to determine if a firewall is stateful or simply a rudimentary SYN-blocker. It sends an `ACK` packet simulating an established connection.
- **IPFire-Wall Response**: Because IPFire-Wall tracks connections statefully, an unexpected `ACK` packet without a preceding `SYN_SENT`/`SYN_RECV` state is immediately identified as invalid by the `check_state()` engine. The packet is dropped silently, yielding a `filtered` result in NMAP.

## 14.2. Advanced Flag Manipulation Scans

Attackers often manipulate TCP flags to bypass poorly configured firewalls that only examine the `SYN` flag. IPFire-Wall's protocol tracking ensures these are caught.

### FIN Scanning
A naked `FIN` packet is sent to the target. In older RFC implementations, closed ports reply with `RST`, while open ports ignore it.
- **How IPFire-Wall Blocks It**: A user might wonder why legitimate closing connections (which use `FIN` flags) work, but bare `FIN` scans fail. Stateful connections are verified *before* the rule list is checked. A valid `FIN` belongs to an `ESTABLISHED` state. A bare `FIN` scan has no state table entry, falls through to the rule definitions (which default to DROP), and is silently discarded.

### NULL and XMAS Tree Scanning
- **NULL Scan**: All TCP flags (SYN, ACK, FIN, RST, URG, PSH) are turned off.
- **XMAS Scan**: The FIN, PSH, and URG flags are simultaneously turned on.
- **IPFire-Wall Response**: Similar to the FIN scan, these packets have no corresponding state in the tracking table. Because they do not match the strict state transition mapping of a legitimate flow, they are dropped. NMAP receives no response and classifies them as `open|filtered`.

## 14.3. Connectionless Scans

### UDP Scanning
UDP scanning attempts to find open UDP services by sending a 0-byte UDP packet. 
- **Expected Closed**: `ICMP Port Unreachable`.
- **IPFire-Wall Response**: Without an explicit `ALLOW` rule, the UDP packet is dropped. IPFire-Wall does *not* generate an `ICMP Port Unreachable` response, causing NMAP to mark the port as `open|filtered`.

### IP Protocol Scanning
This scan sends raw IP packets without a transport layer header (TCP/UDP). 
- **Expected Closed**: `ICMP Protocol Unreachable`.
- **IPFire-Wall Response**: The unsupported protocol falls through the parsing engine to the default rejection policy. It is dropped silently, resulting in an `open|filtered` scan result.
