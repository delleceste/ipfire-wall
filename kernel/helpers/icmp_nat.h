#ifndef IPFI_ICMP_NAT_H
#define IPFI_ICMP_NAT_H

#include "../filter/state/state_table.h"
#include <linux/skbuff.h>

/* Handle internal rewriting of ICMP errors that reference heavily-NATed
 * connections. hooknum expected: NF_INET_PRE_ROUTING or NF_INET_POST_ROUTING.
 * Returns 1 on success, -1 otherwise.
 */
int icmp_nat_process(struct sk_buff *skb, unsigned int hooknum);

/* Matches ICMP error payload against a state entry */
int match_icmp_error_payload(const struct sk_buff *skb,
                             const struct state_table *entry, short *reverse);

/* Hashes the inner IP payload of an ICMP error for state table lookups */
int get_icmp_inner_hash(const struct sk_buff *skb, __u32 *hash_key);

#endif /* IPFI_ICMP_NAT_H */
