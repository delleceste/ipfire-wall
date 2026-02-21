# Chapter 13: Privileges and Policies

IPFire-Wall is designed to allow both system administrators and standard, unprivileged users to filter traffic and personalize their network experience asynchronously. This chapter outlines the strict separation of capabilities between the Root user and normal users.

## 13.1. The Root Administrator `(uid = 0)`

The system administrator is ultimately responsible for the health, routing, and fundamental security of the machine. Only the root user inherently possesses the exact rights necessary to:

1. **Alter Firewall Options**:
   - Change the kernel-space log level (`-kloglevel`).
   - Modify the default firewall policy (`ACCEPT` or `DROP`).
   - Change the timeout values for state connections (`-time`).
   - Modify the maximum allowed sizing of dynamic lists, such as the Network Address Translation tables or State tables (`-max_nat_entries`, `-max_state_entries`).
2. **Perform Network Address Translation (NAT)**:
   - Defining `SNAT`, `DNAT`, or `MASQUERADE` rules is strictly forbidden for normal users, as it influences routing directly and poses severe security implications if exposed to unprivileged users.
3. **Control Resolvers**:
   - Resolve "Blacklisted Sites" into dynamic denial rules via the daemon's background DNS resolver thread.

### The `-user` Option
The administrator explicitly grants the capability for normal users to connect their own client instances to the active firewall by starting the main daemon with the `-user` flag (e.g., `ipfire -daemon -user`). If `-nouser` is provided, all subsequent unprivileged user requests to the kernel are rejected with `RULE_NOT_ADDED_NO_PERM`.

## 13.2. Unprivileged Users `(uid > 0)`

When `-user` is permitted, unprivileged users can start their own `ipfire` client.

### Permitted Operations
- **Personalized Filtering**: Users can define their own Denial (drop) and Permission (accept) rules, which are saved in their home directory `~/.IPFIRE/`.
- **Packet Monitoring**: Users can observe packet flows in real-time, receiving Netlink messages for packets that trigger `NOTIFY` rules.

### Restricted Operations
- **System Alterations**: Unprivileged users cannot modify global tracking timers, max threshold limits, or initiate NAT translation rules. 
- **Flushing Behavior**: When a normal user instructs the firewall to flush rules (e.g., selecting "Flush all rules" or shutting down their interface), the kernel iterates over the lists and *only* deletes rules where the `owner` matches the user's `uid`. The administrator's rules (`uid = 0`) remain entirely unaffected.

## 13.3. Rule Priority and Chronological Loading

While there is a clear distinction in capabilities, the kernel's packet filtering engine itself does not enforce a rigid hierarchical sorting mechanism (i.e., Root rules are not inherently prioritized simply because they belong to root). 

Instead, prioritization is established through chronological list insertion:
1. Rules are evaluated sequentially using `list_for_each_entry_rcu`.
2. New rules sent via Netlink are always appended to the tail of the lists (`list_add_tail_rcu`).
3. Since the system `ipfire` service initiates on boot as Root loading the `/etc/ipfire/` files, the Root rules are inserted first.
4. When a user subsequently logs in and loads their rules via `~/.IPFIRE/`, their rules are organically appended *after* the Root rules.

This ensures that the administrator's broad security sweeps (evaluated first) will catch packets before they can ever reach a user's local override rule. 
