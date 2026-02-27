# IPFire-Wall

**[Installation Instructions & Command-Line Usage](INSTALL.md)**

IPFire-Wall is a high-performance, stateful packet filtering and Network Address Translation (NAT) engine implemented as a Linux kernel module (`ipfi.ko`), paired with a robust userspace tool (`ipfire`). 

*Note: The legacy graphical interface `iqfire` (Qt application) has not been ported to this modern iteration yet.*

## Core Philosophy & Rule Hierarchy

IPFire-Wall is designed around an asynchronous, multi-user privilege model. This represents a fundamental paradigm shift compared to traditional firewalls.

### Differences vs. NFTABLES
While **NFTABLES** provides a highly sophisticated, statically managed ruleset that is exclusively controlled by the system administrator (`root`), IPFire-Wall introduces a personalized, granular approach. While the `root` administrator maintains absolute foundational security (like NAT and global logging limits), unprivileged network users can define their own local rulesets (in `~/.IPFIRE/`) to dynamically personalize their traffic—provided the administrator has explicitly permitted it via the `-user` daemon flag.

### Privilege and Evaluation Logic
The kernel packet filtering engine evaluates rules sequentially, stopping at the first match. Prioritization is established securely through chronological list insertion:

1. **Root Denial Rules First**: The engine evaluates the Blacklist (dropped rules). Since the `ipfire` daemon loads Root rules first on system boot, the administrator's broad security blocks are evaluated before anything else.
2. **Root Permission Rules Next**: The engine then evaluates the Administrator's allowed list. Fundamental local services and essential routing are permitted here.
3. **Single User's Rules**: Finally, if the packet bypasses the root rules, it is evaluated against the rules loaded by individual logged-in users. 

This guarantees that a localized user rule can never override or bypass an administrator's fundamental drop policy.

## Technical Concepts and Peculiarities

Extensive architectural improvements ensure IPFire-Wall scales seamlessly on modern multi-core systems:

- **Stateful Connection Management**: The firewall tracks TCP, UDP, FTP (expectations), and ICMP flows dynamically. Lookups are accelerated using RCU-protected hash tables, achieving $O(1)$ performance even under severe connection pressure.
- **High Concurrency Architecture**: Legacy lock contention (such as traversing single linked lists) has been entirely eradicated. The engine uses **per-bucket spinlocks**, **per-CPU counters**, and atomic bit operations to eliminate cache-line bouncing, meaning throughput remains extremely high during DDoS or port-scanning events.
- **Robust NAT Routing**: Network Address Translation operates on a sophisticated dual-hashing strategy, securely handling `SNAT`, `DNAT`, and `MASQUERADE`. It accurately reconstructs Reverse Paths and natively supports complex ICMP error translations spanning localized and routed namespaces.
- **Resilient Userspace Communication**: The communication layer between the kernel and the `ipfire` daemon relies on asynchronous Netlink sockets. Heavy tasks, like dumping massive state tables to userspace, are offloaded to kernel workqueues. This batching and scheduling mechanism prevents `ENOBUFS` desynchronizations and socket deadlocks.

For deep-dive technical explorations covering memory lifecycles, hash algorithms, and API integrations, consult the markdown files located in the `doc/` directory.
