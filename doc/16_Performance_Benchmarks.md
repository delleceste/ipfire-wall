# Chapter 16: Performance Benchmarks

IPFire-Wall was designed with minimal latency and high-throughput environments in mind. To ensure that the stateful tracking and packet inspection engines do not degrade network performance, benchmark testing was conducted against standard bare-metal routing and traditional Linux netfilter configurations.

## 16.1. Throughput Testing Methodology
A common scenario involves large file transfers over a network. The benchmark consisted of measuring the time taken to recursively copy a 215.7 MB directory composed of numerous objects over a Samba (SMB) network share. 

Three environmental configurations were tested comprehensively with multiple iterations to establish mean values:
1. **Without Firewall**: A vanilla Linux kernel relying solely on its internal routing stack with no Netfilter hooks registered.
2. **With IPFire-Wall**: The server had the IPFire kernel module actively inspecting packets and maintaining state tables.
3. **With `iptables`**: The server used standard `iptables` rules executing analogous stateful and filtering capabilities.

## 16.2. Benchmark Results

| Configuration | Mean Transfer Time (seconds) |
|---------------|------------------------------|
| **Without Firewall** | 37.84s |
| **With IPFire-Wall** | 37.64s |
| **With iptables** | 38.28s |

*Note: The slight reduction in time with IPFire over the non-firewall setup in this specific environment is statistically negligible and well within standard network fluctuation margins.*

## 16.3. Conclusion
The testing definitively highlights that **IPFire-Wall does not introduce measurable latency overhead to data transfers**. Its performance is comparable, and occasionally superior in specific edge cases, to the heavily-optimized legacy `iptables` implementation. 

The $O(1)$ fast-path execution (via `jhash_3words`) ensures that high-volume established connections bypass the linear rule-checking loops immediately—protecting both data throughput and CPU cycles.
