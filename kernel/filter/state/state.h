#ifndef IPFI_STATE_H
#define IPFI_STATE_H

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

#endif /* IPFI_STATE_H */
