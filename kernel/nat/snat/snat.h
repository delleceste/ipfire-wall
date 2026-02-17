#ifndef IPFI_SNAT_H
#define IPFI_SNAT_H

#include "../nat.h"

struct dnatted_table; /* Forward declaration */

/* the table contains information about source adddress
 * translated connections. The list of snatted tables must be
 * checked on arrival of a packet on the interface interested.
 */
struct snatted_table {
  __u32 old_saddr;
  __u16 old_sport;
  __u32 old_daddr;
  __u16 old_dport;
  __u32 new_saddr;
  __u16 new_sport;

  __u8 direction : 4, external : 4;
  __u8 protocol;
  __u8 state;
  unsigned long status;

  uint32_t rule_id; /* rule ID that originated this NAT entry */
  unsigned int position;

  int in_ifindex;
  int out_ifindex;
  char in_devname[IFNAMSIZ];
  char out_devname[IFNAMSIZ];

  struct timer_list timer_snattedlist;
  struct work_struct cleanup_work;
  unsigned long last_timer_update;
  /* RCU */
  struct rcu_head snat_rcuh;
  struct list_head lnode; /* list-based lookup */

  refcount_t refcnt;
};

/* Helper for refcounting */
static inline void snatted_hold(struct snatted_table *st) {
	refcount_inc(&st->refcnt);
}

static inline void snatted_put(struct snatted_table *st) {
	if (!refcount_dec_and_test(&st->refcnt))
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
			queue_work(system_wq, &st->cleanup_work);
	} else {
			queue_work(ipfire_wq, &st->cleanup_work);
	}
}

u32 get_snat_hash(__u32 new_saddr, __u16 new_sport, __u32 old_daddr,
                  __u16 old_dport, __u8 proto);

int snat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                     struct response *resp, struct info_flags *flags);

struct snatted_table *add_snatted_entry(const struct sk_buff *skb,
                                        const ipfi_flow *flow,
                                        struct response *resp,
                                        struct info_flags *flags,
                                        const ipfire_rule *snat_rule);

int snat_packet(struct sk_buff *skb, const struct snatted_table *snt);

int fill_snat_entry_net_fields(struct snatted_table *snentry,
                               const struct sk_buff *skb, const ipfi_flow *flow,
                               const struct response *resp,
                               const struct info_flags *flags,
                               const ipfire_rule *snat_rule);

void fill_timer_snat_entry(struct snatted_table *snt);
void update_snat_timer(struct snatted_table *snt);
void handle_snatted_entry_timeout(struct timer_list *t);
void free_snat_entry_rcu_call(struct rcu_head *head);
int free_snatted_table(void);

int compare_snat_entries(const struct snatted_table *sne1,
                         const struct snatted_table *sne2);

/* Looks up in source address translated tables and if
 * an entry is equal to the entry passed as parameter
 * its timer is updated and a pointer to it is returned.
 */
struct snatted_table *lookup_snatted_table_n_update_timer(
    const struct snatted_table *sne, const struct sk_buff *skb,
    const ipfi_flow *flow, struct response *resp, struct info_flags *flags);

struct snatted_table *lookup_snat_forward(const struct sk_buff *skb,
                                          const ipfi_flow *flow,
                                          struct response *resp,
                                          struct info_flags *flags);


int de_snat(struct sk_buff *skb, struct snatted_table *snt);
int de_snat_table_match(struct snatted_table *snt, struct sk_buff *skb);
int pre_de_snat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags);


int snat_dynamic_translate(struct sk_buff *skb, struct dnatted_table *dnt);
int snat_dynamic_table_match(const struct dnatted_table *dnt,
                             const struct sk_buff *skb);
int post_snat_dynamic(struct sk_buff *skb, const ipfi_flow *flow,
                      struct response *resp, struct info_flags *flags);

/* Masquerade */
int masquerade_translation(struct sk_buff *skb, const ipfi_flow *flow,
                           struct response *resp, struct info_flags *flags);
int masquerade_packet(struct sk_buff *skb, const struct snatted_table *snt);
void fill_masquerade_rule_fields(ipfire_rule *ipfr, __u32 newsaddr);
void clear_masquerade_rule_fields(ipfire_rule *);

#endif /* IPFI_SNAT_H */
