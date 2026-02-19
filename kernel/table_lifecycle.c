/* table_lifecycle.c — Unified lifecycle management for ipfire table entries
 *
 * Provides refcounting, timer management, RCU-safe destruction, and
 * bulk flush for any struct that embeds an ipfi_entry_head as its
 * first member (state_table, nat_table, ipfire_loginfo).
 *
 * Compiled in two variants selected at build time via USE_HASH=y|n:
 *   - List build  (default off): uses list_head / lnode for O(N) traversal
 *   - Hash build  (default on):  uses hlist_node / hnode for O(1) lookups
 *
 * ═══════════════════════════════════════════════════════════
 * OWNERSHIP AND DELETION CHAIN
 * ═══════════════════════════════════════════════════════════
 *
 * Every entry starts with refcount = 1 (the "container reference").
 * The lifecycle is:
 *
 *   CREATED (refcnt=1)
 *       │
 *       ▼
 *   LINKED into list/hash + timer armed
 *       │
 *       ▼  timer fires  ──or──  eviction (loginfo only)
 *   ipfi_entry_remove()          [under table spinlock]
 *     ├─ test_and_set_bit(REMOVED)   ← atomic "winner" gate
 *     ├─ hlist_del_rcu / list_del_rcu
 *     ├─ counter--
 *     └─ ipfi_entry_put()            ← winner puts, loser is no-op
 *           └─ refcount → 0
 *                 └─ queue_work(ipfire_wq, cleanup_work)
 *                       └─ [workqueue / process context]
 *                             timer_delete_sync()
 *                             call_rcu(free_entry_rcu)
 *                                   └─ [RCU callback]
 *                                         kfree(h)
 *
 * KEY INVARIANTS
 * ─────────────────────────────────────────────────────────
 * 1. REMOVED bit is set exactly once (test_and_set_bit).
 * 2. ipfi_entry_put is called exactly once (by the winner of the bit race).
 * 3. kfree happens only after: timer is dead AND RCU grace period has
 *    elapsed, guaranteeing no CPU is still touching the object.
 * 4. queue_work() is safe from BH-disabled spinlock context because it
 *    uses spin_lock_irqsave internally and never sleeps.
 *
 * LOGINFO SPECIAL CASE (see log.c)
 * ─────────────────────────────────────────────────────────
 * loginfo entries maintain TWO simultaneous links in hash mode:
 *   lnode → active_logi_list   (LRU eviction, O(1) tail access)
 *   hnode → loginfo_hashtable  (deduplication lookup, O(1))
 *
 * ipfi_entry_remove only handles hnode. The lnode is managed explicitly
 * by the loginfo timer callback and eviction path, both under
 * loginfo_list_lock, guarded by a REMOVED pre-check to prevent
 * double list_del_rcu (which would write to LIST_POISON addresses).
 * ═══════════════════════════════════════════════════════════
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

static void free_entry_rcu(struct rcu_head *rcu) {
  struct ipfi_entry_head *h = container_of(rcu, struct ipfi_entry_head, rcuh);
  /*
   * All entries are allocated via kmem_cache_alloc.
   * kfree() handles kmem_cache objects correctly on
   * modern kernels (6.x) via virt_to_slab().
   */
  kfree(h);
}

/* ---- Work handler: process-context cleanup ---- */

static void free_entry_work(struct work_struct *work) {
  struct ipfi_entry_head *h =
      container_of(work, struct ipfi_entry_head, cleanup_work);

  /* Safe in process context */
  timer_delete_sync(&h->timer);

  /* After RCU grace period, kfree the entry */
  call_rcu(&h->rcuh, free_entry_rcu);
}

/* ---- Public API ---- */

void ipfi_entry_init(struct ipfi_entry_head *h, unsigned int timeout_s,
                     void (*timeout_fn)(struct timer_list *)) {
  INIT_WORK(&h->cleanup_work, free_entry_work);
  timer_setup(&h->timer, timeout_fn, 0);
  h->timer.expires = jiffies + HZ * timeout_s;
  h->status = 0;
  h->last_timer_update = jiffies;
  /* refcnt is NOT set here — caller is responsible
   * (refcount_set before or after init as appropriate). */
}

void ipfi_entry_put(struct ipfi_entry_head *h) {
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

void ipfi_entry_update_timer(struct ipfi_entry_head *h, int proto, int state) {
  if (unlikely(test_bit(IPFI_ENTRY_REMOVED, &h->status)))
    return;

  if (time_after(jiffies, READ_ONCE(h->last_timer_update) + (5 * HZ))) {
    unsigned int timeout;

    /* Safely get a reference while under RCU/pointer validity */
    if (!ipfi_entry_hold_rcu(h))
      return;

    /* Re-check removal bit under the reference */
    if (unlikely(test_bit(IPFI_ENTRY_REMOVED, &h->status))) {
      ipfi_entry_put(h);
      return;
    }

    timeout = get_timeout_by_state(proto, state);
    mod_timer(&h->timer, jiffies + HZ * timeout);
    WRITE_ONCE(h->last_timer_update, jiffies);

    ipfi_entry_put(h);
  }
}

/**
 * ipfi_entry_remove - Unlink an entry from its container (under caller's lock).
 *
 * CRITICAL: test_and_set_bit(REMOVED) MUST happen BEFORE the del_rcu call.
 * Only the thread that successfully sets the bit unlinks the entry.
 */
void ipfi_entry_remove(struct ipfi_entry_head *h, unsigned int *counter) {
  if (test_and_set_bit(IPFI_ENTRY_REMOVED, &h->status))
    return; /* loser: complete no-op */

#ifdef IPFI_USE_HASH
  /* State table entries are tracked by hnode in hash mode */
  hlist_del_rcu(&h->hnode);
#else
  list_del_rcu(&h->lnode);
#endif
  (*counter)--;

  /*
   * Winner always puts. queue_work() is safe from BH-disabled spinlock
   * context: it uses spin_lock_irqsave internally and never sleeps.
   */
  ipfi_entry_put(h);
}

/* ============================================================
 * List-mode bulk flush (always compiled — used by NAT tables
 * regardless of whether hash mode is active for the state table)
 * ============================================================ */

int ipfi_table_flush_all(struct list_head *list, spinlock_t *lock,
                         unsigned int *counter) {
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

/* ============================================================
 * Hash-mode bulk flush (compiled only when IPFI_USE_HASH is set)
 * ============================================================ */
#ifdef IPFI_USE_HASH

/**
 * ipfi_table_flush_hash - drain all entries from a hash table.
 * @ht:       the hlist_head array (e.g. state_hashtable)
 * @nbuckets: number of buckets (ARRAY_SIZE of the hash table)
 * @lock:     the spinlock protecting the table
 * @counter:  pointer to the entry counter (zeroed)
 *
 * Mirrors ipfi_table_flush_all() for the hash case.
 * Process-context only (sleepable, calls queue_work via ipfi_entry_put).
 */
int ipfi_table_flush_hash(struct hlist_head *ht, unsigned int nbuckets,
                          spinlock_t *lock, unsigned int *counter) {
  struct ipfi_entry_head *h;
  struct hlist_node *tmp;
  unsigned int bkt;
  int count;

  spin_lock_bh(lock);
  for (bkt = 0; bkt < nbuckets; bkt++) {
    hlist_for_each_entry_safe(h, tmp, &ht[bkt], hnode) {
      hlist_del_rcu(&h->hnode);
      set_bit(IPFI_ENTRY_REMOVED, &h->status);
      /*
       * ipfi_entry_put only calls queue_work(), which is
       * safe from BH/spinlock context.
       */
      ipfi_entry_put(h);
    }
  }
  count = *counter;
  *counter = 0;
  spin_unlock_bh(lock);

  return count;
}

#endif /* IPFI_USE_HASH */
