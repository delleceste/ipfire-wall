/* nat/nat_table.h — Unified NAT table structure
 *
 * Replaces the separate snatted_table and dnatted_table structs.
 * Every NAT entry (SNAT or DNAT) is represented as a struct nat_table
 * with a type flag.
 */
#ifndef IPFI_NAT_TABLE_H
#define IPFI_NAT_TABLE_H

#include "ipfi_entry.h"
#include "nat.h"
#include <common/ipfi_structures.h>
#include <linux/netdevice.h>

enum nat_type { NAT_SNAT = 0, NAT_DNAT = 1 };

struct nat_table {
	struct ipfi_entry_head h;   /* MUST be first */

	/* Original packet fields */
	__u32 old_saddr, old_daddr;
	__u16 old_sport, old_dport;

	/* Translated fields:
	 *   SNAT: new_addr = new source addr, new_port = new source port
	 *   DNAT: new_addr = new dest addr,   new_port = new dest port
	 */
	__u32 new_addr;
	__u16 new_port;

	__u32 our_ifaddr;   /* DNAT dynamic SNAT reverse, 0 for SNAT */

	__u8 direction : 4, external : 3, nolog : 1;
	__u8 protocol;
	__u8 state;
	enum nat_type type;

	uint32_t rule_id;
	unsigned int position;

	int in_ifindex, out_ifindex;
	char in_devname[IFNAMSIZ];
	char out_devname[IFNAMSIZ];
	char rulename[RULENAMELEN]; /* DNAT only, empty for SNAT */
};

/* ---- Inline hold/put delegating to lifecycle ---- */

static inline void nat_hold(struct nat_table *nt)
{
	ipfi_entry_hold(&nt->h);
}

static inline bool nat_hold_rcu(struct nat_table *nt)
{
	return ipfi_entry_hold_rcu(&nt->h);
}

static inline void nat_put(struct nat_table *nt)
{
	ipfi_entry_put(&nt->h);
}

/* ---- NAT table functions (nat_table.c) ---- */

/* Hash functions */
u32 get_snat_hash(__u32 new_saddr, __u16 new_sport, __u32 old_daddr,
		  __u16 old_dport, __u8 proto);
u32 get_dnat_hash(__u32 old_saddr, __u16 old_sport, __u32 new_daddr,
		  __u16 new_dport, __u8 proto);

/* Lookup */

struct nat_table *lookup_nat_forward(const struct sk_buff *skb,
				     enum nat_type type);

/* Fill fields */
int fill_nat_entry_fields(struct nat_table *entry, const struct sk_buff *skb,
			  const ipfi_flow *flow, const struct response *resp,
			  const struct info_flags *flags,
			  const ipfire_rule *rule, enum nat_type type);

/* Compare */
int compare_nat_entries(const struct nat_table *a, const struct nat_table *b);

/* Timer callback */
void handle_nat_entry_timeout(struct timer_list *t);

/* Flush */
int free_nat_tables(enum nat_type type);

/* Init/Fini */
int init_nat_tables(void);
void fini_nat_tables(void);

/* Access to per-type globals — implemented as arrays indexed by nat_type */
extern struct list_head nat_lists[2];
extern spinlock_t nat_locks[2];
extern unsigned int nat_counters[2];

#endif /* IPFI_NAT_TABLE_H */
