/* table_lifecycle.c — Unified lifecycle management for ipfire table entries
 *
 * Provides refcounting, timer management, RCU-safe destruction, and
 * bulk flush for any struct that embeds an ipfi_entry_head as its
 * first member (state_table, nat_table, ...).
 */

#include "ipfi_entry.h"
#include <linux/bitops.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/* Forward declaration: timeout helper from state_timeout.c */
unsigned int get_timeout_by_state(int protocol, int state);

/* ---- RCU callback: final kfree ---- */

static void free_entry_rcu(struct rcu_head *rcu)
{
	struct ipfi_entry_head *h =
		container_of(rcu, struct ipfi_entry_head, rcuh);
	/*
	 * The entry was allocated with kmalloc; the ipfi_entry_head is
	 * at offset 0, so kfree(h) frees the whole containing struct.
	 */
	kfree(h);
}

/* ---- Work handler: process-context cleanup ---- */

static void free_entry_work(struct work_struct *work)
{
	struct ipfi_entry_head *h =
		container_of(work, struct ipfi_entry_head, cleanup_work);

	/* Safe in process context */
	timer_delete_sync(&h->timer);

	/* After RCU grace period, kfree the entry */
	call_rcu(&h->rcuh, free_entry_rcu);
}

/* ---- Public API ---- */

void ipfi_entry_init(struct ipfi_entry_head *h, unsigned int timeout_s,
		     void (*timeout_fn)(struct timer_list *))
{
	INIT_WORK(&h->cleanup_work, free_entry_work);
	timer_setup(&h->timer, timeout_fn, 0);
	h->timer.expires = jiffies + HZ * timeout_s;
	h->status = 0;
	h->last_timer_update = jiffies;
	/* refcnt is NOT set here — caller is responsible
	 * (refcount_set before or after init as appropriate). */
}

void ipfi_entry_put(struct ipfi_entry_head *h)
{
	if (!refcount_dec_and_test(&h->refcnt))
		return;

	/*
	 * Defer final cleanup via workqueue so we don't risk kfree'ing
	 * while other contexts (RCU readers, timers) may touch the object.
	 */
	if (!ipfire_wq) {
		WARN_ON(1);
		queue_work(system_wq, &h->cleanup_work);
	} else {
		queue_work(ipfire_wq, &h->cleanup_work);
	}
}

void ipfi_entry_update_timer(struct ipfi_entry_head *h,
			     int proto, int state)
{
	unsigned int timeout;

	if (unlikely(test_bit(IPFI_ENTRY_REMOVED, &h->status)))
		return;

	timeout = get_timeout_by_state(proto, state);

	if (time_after(jiffies, READ_ONCE(h->last_timer_update) + (5 * HZ))) {
		/* Re-check after computing condition */
		if (unlikely(test_bit(IPFI_ENTRY_REMOVED, &h->status)))
			return;

		mod_timer(&h->timer, jiffies + HZ * timeout);
		WRITE_ONCE(h->last_timer_update, jiffies);
	}
}

/**
 * ipfi_entry_remove - Unlink an entry from its list (atomic vs flush).
 * @h:       entry head
 * @counter: pointer to the list's entry counter (decremented)
 *
 * This function is called from timer expiration or other specific removal
 * events. It races with ipfi_table_flush_all().
 *
 * CRITICAL: We MUST use test_and_set_bit() BEFORE list_del_rcu().
 * Only the thread that successfully sets the REMOVED bit is allowed
 * to unlink the entry. If the bit is already set (e.g., by flush),
 * we return immediately to avoid corrupting the flush thread's
 * private list (where this entry might already reside).
 */
void ipfi_entry_remove(struct ipfi_entry_head *h, unsigned int *counter)
{
	if (test_and_set_bit(IPFI_ENTRY_REMOVED, &h->status))
		return;

	list_del_rcu(&h->lnode);
	(*counter)--;
}

int ipfi_table_flush_all(struct list_head *list, spinlock_t *lock,
		     unsigned int *counter)
{
	struct ipfi_entry_head *h, *tmp;
	int count;
	LIST_HEAD(to_free);

	spin_lock_bh(lock);
	list_splice_init(list, &to_free);
	list_for_each_entry(h, &to_free, lnode)
		set_bit(IPFI_ENTRY_REMOVED, &h->status);
	count = *counter;
	*counter = 0;
	spin_unlock_bh(lock);

	list_for_each_entry_safe(h, tmp, &to_free, lnode) {
		list_del(&h->lnode);
		ipfi_entry_put(h);
	}

	return count;
}
