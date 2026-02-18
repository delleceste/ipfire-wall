#ifndef IPFI_STATE_TABLE_H
#define IPFI_STATE_TABLE_H

#include "ipfi_entry.h"
#include <linux/types.h>
#include <linux/netdevice.h>
#include <common/ipfi_structures.h>

struct state_table {
  struct ipfi_entry_head h;   /* MUST be first — common lifecycle */

  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u8 direction : 3, ftp : 3, /* passive ftp support */
      notify : 1, admin : 1;
  __u8 nolog : 1;
  __u32 rule_id; /* ID of the rule that originated this state */
  __u8 protocol;
  char in_devname[IFNAMSIZ];
  char out_devname[IFNAMSIZ];
  struct state_t state;
};

/* Helper for refcounting — delegates to ipfi_entry lifecycle */
static inline void state_hold(struct state_table *st) {
	ipfi_entry_hold(&st->h);
}

static inline void state_put(struct state_table *st) {
	ipfi_entry_put(&st->h);
}

/* Function Prototypes from state_table.c */
int direct_state_match(const struct sk_buff *skb, const struct state_table *entry, const ipfi_flow *flow);
int reverse_state_match(const struct sk_buff *skb, const struct state_table *entry, const ipfi_flow *flow);
int skb_matches_state_table(const struct sk_buff *skb, const struct state_table *entry, short *reverse, const ipfi_flow *flow);
int fill_net_table_fields(struct state_table *state_t, const struct sk_buff *skb, const ipfi_flow *flow);
int compare_state_entries(const struct state_table *s1, const struct state_table *s2);
int lookup_state_table_n_update_timer(const struct state_table *stt);
int add_state_table_to_list(struct state_table *newtable);
void handle_keep_state_timeout(struct timer_list *t);
void handle_keep_state_timeout(struct timer_list *t);

int free_state_tables(void);
void update_timer_of_state_entry(struct state_table *sttable);
int init_machine(void);
void fini_machine(void);

/* Prototypes for functions in filter_engine.c related to state setup */
struct state_table *keep_state(const struct sk_buff *skb, const ipfire_rule *p_rule, const ipfi_flow *flow);
void fill_state_info(struct state_info *stinfo, const struct state_table *stt);
int add_ftp_dynamic_rule(struct state_table *ftpt);

/* Generic helpers */
int get_dev_ifaddr(__u32 *addr, int direction, const struct net_device *in, const struct net_device *out);
int get_ifaddr_by_name(const char *ifname, __u32 *addr);

extern struct kmem_cache *state_cache;

#endif /* IPFI_STATE_TABLE_H */
