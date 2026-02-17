/* ipfi_entry.h — Common lifecycle header for all ipfire table entries
 *
 * Every table entry struct (state_table, nat_table) embeds an
 * ipfi_entry_head as its FIRST member. The lifecycle functions in
 * table_lifecycle.c operate on this embedded header.
 */
#ifndef IPFI_ENTRY_H
#define IPFI_ENTRY_H

#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>

/* Bit index for the "entry has been removed from its list" flag */
#define IPFI_ENTRY_REMOVED 0

extern struct workqueue_struct *ipfire_wq;

/**
 * struct ipfi_entry_head - common header embedded in every table entry
 *
 * This must be the FIRST member of any table entry struct, so that
 * container_of(head, struct whatever, h) works uniformly and the
 * pointer to the head IS the pointer to the entry.
 */
struct ipfi_entry_head {
	struct timer_list    timer;
	struct work_struct   cleanup_work;
	struct rcu_head      rcuh;
	struct list_head     lnode;
	refcount_t           refcnt;
	unsigned long        status;
	unsigned long        last_timer_update;
};

/* ===== Lifecycle functions (table_lifecycle.c) ===== */

/**
 * ipfi_entry_init - Initialise lifecycle fields of a new entry.
 * @h:         pointer to the embedded head
 * @timeout_s: initial timeout in seconds
 *
 * Sets up the timer, work struct, refcount (at 0 — caller must set it),
 * status (cleared), and initial expiry.
 */
void ipfi_entry_init(struct ipfi_entry_head *h, unsigned int timeout_s,
		     void (*timeout_fn)(struct timer_list *));

/**
 * ipfi_entry_arm_timer - Start the timer after entry has been added to its list.
 */
static inline void ipfi_entry_arm_timer(struct ipfi_entry_head *h)
{
	mod_timer(&h->timer, h->timer.expires);
}

/**
 * ipfi_entry_hold / ipfi_entry_put - refcount management.
 *
 * When refcount drops to zero, _put queues the cleanup work which
 * syncs the timer and then schedules RCU-delayed kfree.
 */
static inline void ipfi_entry_hold(struct ipfi_entry_head *h)
{
	refcount_inc(&h->refcnt);
}

/**
 * ipfi_entry_hold_rcu - Try to acquire a reference in RCU context.
 * Returns true if successful, false if the entry is already dead (0 refcnt).
 */
static inline bool ipfi_entry_hold_rcu(struct ipfi_entry_head *h)
{
	return refcount_inc_not_zero(&h->refcnt);
}

void ipfi_entry_put(struct ipfi_entry_head *h);

/**
 * ipfi_entry_update_timer - Throttled timer refresh.
 * @h:        entry head
 * @proto:    protocol (IPPROTO_*)
 * @state:    current connection state (int, passed to get_timeout_by_state)
 *
 * Skips if REMOVED is set or if last update was <5 s ago.
 */
void ipfi_entry_update_timer(struct ipfi_entry_head *h,
			     int proto, int state);

/**
 * ipfi_entry_remove - Unlink an entry from its list (under caller's lock).
 * @h:       entry head
 * @counter: pointer to the list's entry counter (decremented)
 *
 * The caller MUST hold the list's spinlock when calling this.
 * This does list_del_rcu + set_bit(REMOVED) + counter--.
 */
void ipfi_entry_remove(struct ipfi_entry_head *h, unsigned int *counter);

/**
 * ipfi_table_flush_all - Remove and put all entries on a list.
 * @list:    the list_head to flush
 * @lock:    the spinlock protecting the list
 * @counter: pointer to the counter (zeroed)
 *
 * Process-context only (sleepable).
 */
int ipfi_table_flush_all(struct list_head *list, spinlock_t *lock,
		     unsigned int *counter);

#endif /* IPFI_ENTRY_H */
