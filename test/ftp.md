# Testing FTP Passive Connections

This test verifies the firewall's ability to seamlessly track and permit FTP Passive mode data connections via dynamic state tracking (`{RELATED}` connections).

## Execution

Execute the following automated FTP session against a public FTP server (e.g., `ftp.scene.org`):

```bash
ftp -inv ftp.scene.org <<EOF
user anonymous anonymous@
passive
binary
cd pub
ls
bye
EOF
```

## Expected Output

You should monitor the `ipfire` daemon output. The expected console output displays the traffic flow, explicitly highlighting when the "related" PASSIVE FTP transfer data connection can be seen. 

Notice the `{RELATED}` tag automatically appended by the userspace application for the dynamically permitted high-port connections triggered by the FTP control session's `PASV` command:

```text
[OK] OUT: [eno1] |TCP| 192.168.205.245:35784-->85.188.1.133:50926 |S|SETUP [me -> ftp control] {RELATED}
[OK] IN:  [eno1] |TCP| 85.188.1.133:50926-->192.168.205.245:35784 |S|A|SETUP OK [me -> ftp control] {RELATED}
[OK] OUT: [eno1] |TCP| 192.168.205.245:35784-->85.188.1.133:50926 |A|EST [me -> ftp control] {RELATED}
[IMPL] IN:  [eno1] |IGMP| SRC:192.168.205.252 --> DST:224.0.0.1 |GROUP: 0.0.0.0|{Membership query/Max response time: 100}|  
[OK] IN:  [eno1] |TCP| 85.188.1.133:50926-->192.168.205.245:35784 |F|P|A|FIN WAIT [me -> ftp control] {RELATED}
[OK] OUT: [eno1] |TCP| 192.168.205.245:35784-->85.188.1.133:50926 |A|CLOSE WAIT [me -> ftp control] {RELATED}
[OK] OUT: [eno1] |TCP| 192.168.205.245:35784-->85.188.1.133:50926 |F|A|LAST ACK [me -> ftp control] {RELATED}
[OK] IN:  [eno1] |TCP| 85.188.1.133:50926-->192.168.205.245:35784 |A|TIME WAIT [me -> ftp control] {RELATED}
[OK] IN:  [eno1] |TCP| 85.188.1.133:ftp-->192.168.205.245:49370 |F|A|FIN WAIT [me -> ftp control]
[OK] OUT: [eno1] |TCP| 192.168.205.245:49370-->85.188.1.133:ftp |F|A|CLOSE WAIT [me -> ftp control]
[IMPL] IN:  [eno1] |UDP| 192.168.205.25:33301-->239.255.255.250:ssdp   
[OK] IN:  [eno1] |TCP| 85.188.1.133:ftp-->192.168.205.245:49370 |A|CLOSE WAIT [me -> ftp control]
[IMPL] OUT: [eno1] |TCP| 192.168.205.245:33396-->140.105.206.204:imaps |A|  
[OK] OUT: [eno1] |UDP| 192.168.205.245:60492-->172.217.23.74:https STREAM [me -> the UDP world]
```
