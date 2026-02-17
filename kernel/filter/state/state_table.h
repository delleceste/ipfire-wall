#ifndef IPFI_STATE_TABLE_H
#define IPFI_STATE_TABLE_H

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/netdevice.h>
#include <linux/bug.h>
#include <common/ipfi_structures.h>

extern struct workqueue_struct *ipfire_wq;

#define IPFI_ST_REMOVED 0

struct state_table {
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u8 direction : 3, ftp : 3, /* passive ftp support */
      notify : 1, admin : 1;
  __u32 rule_id; /* ID of the rule that originated this state */
  __u8 protocol;
  unsigned long status;
  char in_devname[IFNAMSIZ];
  char out_devname[IFNAMSIZ];
	unsigned long last_timer_update;
	struct state_t state;

  /* Note: pkmanip removed - MSS mangling applied directly on rule match,
   * no need to store in state tables */

  struct timer_list timer_statelist;
	struct work_struct cleanup_work;

  /* RCU */
  struct rcu_head state_rcuh;
  struct list_head lnode;


	refcount_t refcnt;
};

/* Helper for refcounting */
static inline void state_hold(struct state_table *st) {
	refcount_inc(&st->refcnt);
}

static inline void state_put(struct state_table *st) {
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

/* Function Prototypes from state_table.c */
int direct_state_match(const struct sk_buff *skb, const struct state_table *entry, const ipfi_flow *flow);
int reverse_state_match(const struct sk_buff *skb, const struct state_table *entry, const ipfi_flow *flow);
int skb_matches_state_table(const struct sk_buff *skb, const struct state_table *entry, short *reverse, const ipfi_flow *flow);
void free_state_entry_rcu_call(struct rcu_head *head);
int fill_net_table_fields(struct state_table *state_t, const struct sk_buff *skb, const ipfi_flow *flow);
int compare_state_entries(const struct state_table *s1, const struct state_table *s2);
int lookup_state_table_n_update_timer(const struct state_table *stt);
int add_state_table_to_list(struct state_table *newtable);
void handle_keep_state_timeout(struct timer_list *t);
void fill_timer_table_fields(struct state_table *state_t);
void register_ipfire_netdev_notifier(void);
void unregister_ipfire_netdev_notifier(void);
void update_ifindex_in_state_tables(const char *name, int new_index);
int free_state_tables(void);
void update_timer_of_state_entry(struct state_table *sttable);
int init_machine(void);
void fini_machine(void); /* Typically used to free tables at module unload */

/* Prototypes for functions formerly in ipfi_machine.h managed in filter_engine.c but related to state setup */
struct state_table *keep_state(const struct sk_buff *skb, const ipfire_rule *p_rule, const ipfi_flow *flow);
void fill_state_info(struct state_info *stinfo, const struct state_table *stt);
int add_ftp_dynamic_rule(struct state_table *ftpt);

/* Generic helpers sometimes used in state context */
int get_dev_ifaddr(__u32 *addr, int direction, const struct net_device *in, const struct net_device *out);
int get_ifaddr_by_name(const char *ifname, __u32 *addr);

#endif /* IPFI_STATE_TABLE_H */
