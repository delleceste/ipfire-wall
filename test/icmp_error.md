# Testing ICMP Error Messages on NAT

This test verifies that ICMP error messages (such as Port Unreachable) are correctly translated and routed back to the originator when traversing a Network Address Translation (NAT) boundary.

## Scenario Setup

We have three hosts involved:
1. `taeyang` (The client originating the traffic)
2. `dal` (192.168.205.245) - The firewall running `ipfire-wall`.
3. `gaia` (192.168.205.49) - The internal destination server.

On the firewall host (`dal`), the following DNAT translation rule is configured to forward UDP traffic on port `64999` to `gaia` on port `65000`:

```ini
RULE
NAME=DNAT UDP dal:64999->gaia 65000
DIRECTION=PRE
DSTADDR=192.168.205.245
PROTOCOL=17
DSTPORT=64999
NAT=YES
NEWADDR=192.168.205.49
NEWPORT=65000
```

Crucially, **port 65000 is NOT open** on the destination host `gaia`. Therefore, when `gaia` receives the UDP packet, its OS will reply with an ICMP "Port Unreachable" message.

## Execution

From the client host (`taeyang`), execute a UDP ping targeting the firewall (`dal`):

```bash
sudo hping3 --udp -p 64999 dal
```

## Expected Output

The expected output proves that the ICMP error handling and reverse NAT translation are functioning correctly. `taeyang` should receive the ICMP unreachable message appearing as if it came from `dal` (the original destination), not `gaia`:

```text
[root@taeyang giacomo]# sudo hping3 --udp -p 64999 dal
HPING dal (eno1 192.168.205.245): udp mode set, 28 headers + 0 data bytes
ICMP Port Unreachable from ip=192.168.205.245 name=dal.elettra.trieste.it
ICMP Port Unreachable from ip=192.168.205.245 name=dal.elettra.trieste.it
```

*Note: Unlike the FTP PASSIVE support for dynamic tables, no `{RELATED}` indication is given on the client application console for these ICMP error logs: it is currently not implemented.*
