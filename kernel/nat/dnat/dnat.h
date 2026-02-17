#ifndef IPFI_DNAT_H
#define IPFI_DNAT_H

#include "../nat.h"

/* the table contains information about destination adddress
 * translated connections. The list of dnatted tables must be
 * checked on arrival of a packet on the interface interested.
 */
struct dnatted_table {
  __u32 old_saddr;
  __u16 old_sport;
  __u32 old_daddr;
  __u16 old_dport;
  __u32 new_daddr;
  __u16 new_dport;

  __u32 our_ifaddr;

  __u8 direction : 4, external : 4;
  __u8 protocol;

  /* From version 0.98.2 on, we keep the state of the NAT tables, just to
   * apply the correct timeouts on them.
   */
  __u8 state;
  unsigned long status;

  uint32_t rule_id; /* rule ID that originated this NAT entry */
  unsigned int position;

  int in_ifindex;
  int out_ifindex;
  char in_devname[IFNAMSIZ];
  char out_devname[IFNAMSIZ];
  char rulename[RULENAMELEN];
  struct timer_list timer_dnattedlist;
  struct work_struct cleanup_work;
  unsigned long last_timer_update;
  /* RCU */
  struct rcu_head dnat_rcuh;
  struct list_head lnode; /* list-based lookup  */

  refcount_t refcnt;
};

/* Helper for refcounting */
static inline void dnatted_hold(struct dnatted_table *dt) {
	refcount_inc(&dt->refcnt);
}

static inline void dnatted_put(struct dnatted_table *dt)
{
		if (!refcount_dec_and_test(&dt->refcnt))
				return;

		/*
		 * Always defer final cleanup via workqueue so we do not risk
		 * kfree'ing while other contexts (RCU readers, spinlocks, timers)
		 * may still access the object.
		 *
		 * If ipfire_wq is missing, fall back to system_wq but WARN so the
		 * bug is visible (module init/teardown ordering problem).
		 */
		if (!ipfire_wq) {
				WARN_ON(1);
				/* last-resort: queue on the system workqueue rather than kfree */
				queue_work(system_wq, &dt->cleanup_work);
		} else {
				queue_work(ipfire_wq, &dt->cleanup_work);
		}
}

u32 get_dnat_hash(__u32 old_saddr, __u16 old_sport, __u32 new_daddr,
                  __u16 new_dport, __u8 proto);

int dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                     struct response *resp, struct info_flags *flags);

struct dnatted_table *add_dnatted_entry(const struct sk_buff *skb,
                                        const ipfi_flow *flow,
                                        struct response *resp,
                                        struct info_flags *flags,
                                        const ipfire_rule *dnat_rule);

int dest_translate(struct sk_buff *skb, const struct dnatted_table *dnt);

int fill_entry_net_fields(struct dnatted_table *dnentry,
                          const struct sk_buff *skb, const ipfi_flow *flow,
                          const struct response *resp,
                          const struct info_flags *flags,
                          const ipfire_rule *nat_rule);

void fill_timer_dnat_entry(struct dnatted_table *dnt);
void update_dnat_timer(struct dnatted_table *dnt);
void handle_dnatted_entry_timeout(struct timer_list *t);
void free_dnat_entry_rcu_call(struct rcu_head *head);
int free_dnatted_table(void);

int compare_entries(const struct dnatted_table *dne1,
                    const struct dnatted_table *dne2);
int compare_dnat_entries(const struct dnatted_table *dne1,
                         const struct dnatted_table *dne2);

/* Looks up dnatted table, comparing each entry with the entry
 * passed as argument.
 */
struct dnatted_table *lookup_dnatted_table_n_update_timer(
    const struct dnatted_table *dne, const struct sk_buff *skb,
    const ipfi_flow *flow, struct response *resp, struct info_flags *flags);

struct dnatted_table *lookup_dnat_forward(const struct sk_buff *skb,
                                          const ipfi_flow *flow,
                                          struct response *resp,
                                          struct info_flags *flags);

int get_orig_from_dnat_entry(const struct dnatted_table *dnt,
                             const net_quadruplet *n4, struct sockaddr_in *sin);

int lookup_dnat_table_and_getorigdst(const net_quadruplet *n4,
                                     struct sockaddr_in *sin);

int get_original_dest(struct sock *sk, int optval, void __user *user, int *len);


int de_dnat(struct sk_buff *skb, const struct dnatted_table *dnatt);
int de_dnat_table_match(const struct dnatted_table *dnt,
                        const struct sk_buff *skb);
int de_dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                        struct response *resp, struct info_flags *flags);

int pre_de_dnat_translate(struct sk_buff *skb, const struct dnatted_table *dnt);
int pre_denat_table_match(const struct dnatted_table *dnt,
                          const struct sk_buff *skb);
int pre_de_dnat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags);

#endif /* IPFI_DNAT_H */
