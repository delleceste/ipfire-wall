# Chapter 10: Lifecycle & Synchronization

This chapter describes how IPFire-Wall manages memory and concurrency for its
internal tables using the unified `ipfi_entry` framework.

---

## 10.1. The Unified Entry Header

All dynamic table entries (State, NAT, LogInfo) embed `ipfi_entry_head` as
their **first** member. This layout is mandated: `container_of` relies on the
head being at offset 0 so that `kfree(h)` frees the whole object.

```c
struct ipfi_entry_head {
    struct timer_list    timer;          /* per-entry expiry timer */
    struct work_struct   cleanup_work;   /* deferred-delete work item */
    struct rcu_head      rcuh;           /* RCU callback node */
    struct list_head     lnode;          /* list linkage (NAT; loginfo LRU) */
    struct hlist_node    hnode;          /* hash linkage (IPFI_USE_HASH) */
    refcount_t           refcnt;         /* reference counter */
    unsigned long        status;         /* IPFI_ENTRY_REMOVED bit */
    unsigned long        last_timer_update; /* throttle timestamp */
};
```

---

## 10.2. Entry Lifecycle — Full Chain

Every entry starts with `refcount = 1` (the **container reference**).

```
ALLOCATED (refcnt = 1)
    │
    ▼  added to list/hash + timer armed
LIVE
    │
    ├─── timer fires ──────────────────────────────────────────┐
    │                                                          │
    └─── eviction (loginfo only, capacity-based) ─────────────┤
                                                               │
                                                               ▼
                                               [under table spinlock]
                                                ipfi_entry_remove(h, &counter)
                                                  │
                                                  ├─ test_and_set_bit(REMOVED)
                                                  │     WINNER proceeds ──────▶ hlist/list del_rcu
                                                  │     LOSER returns (no-op)        counter−−
                                                  │                                  ipfi_entry_put(h)
                                                  │                                        │
                                                  │                              refcount → 0
                                                  │                                        │
                                                  │                              queue_work(ipfire_wq)
                                                  │
                                                  ▼    [workqueue / process context]
                                              free_entry_work()
                                                  ├─ timer_delete_sync()      ← wait for timer
                                                  └─ call_rcu(free_entry_rcu) ← wait for readers
                                                              │
                                                              ▼  [RCU callback]
                                                          kfree(h)              ← object freed
```

### Key invariants

| Invariant | Enforcement |
|-----------|-------------|
| REMOVED set **exactly once** | `test_and_set_bit` atomicity |
| `ipfi_entry_put` called **exactly once** | only the bit winner calls it |
| `kfree` happens after timer is **fully dead** | `timer_delete_sync` before `call_rcu` |
| `kfree` happens after all **RCU readers** are done | `call_rcu` grace period |
| `queue_work` is safe under `spin_lock_bh` | `queue_work` uses `spin_lock_irqsave`, never sleeps |

---

## 10.3. loginfo — The Dual-Link Special Case

`ipfire_loginfo` is the **only** entry type carrying two simultaneous links
in hash mode:

```
active_logi_list  ◄─── lnode ───► ipfire_loginfo ◄─── hnode ───► loginfo_hashtable
     (LRU eviction, O(1) tail)              (dedup lookup, O(1))
```

This is necessary because:
- `active_logi_list` (lnode) enables O(1) LRU eviction: oldest entry is
  always at the tail, removed when the table reaches `max_loginfo_entries`.
- `loginfo_hashtable` (hnode) enables O(1) duplicate detection lookups.

`ipfi_entry_remove` handles **only hnode** (hash mode) or **only lnode**
(list mode). The loginfo lnode in hash mode must be managed separately,
under `loginfo_list_lock`, by **both** the timer callback and the eviction
path.

### The evict-vs-timer race and its fix

Two paths can try to remove the same lnode from `active_logi_list`:

```
Path A (timer callback)         Path B (loginfo_evict_oldest)
─────────────────────           ────────────────────────────
spin_lock_bh(lock)              spin_lock_bh(lock)   ← serialised by lock
if (!REMOVED)                   list_del_rcu(lnode)
  list_del_rcu(lnode)           ipfi_entry_remove()  ← sets REMOVED, puts
ipfi_entry_remove()             timer_delete()
spin_unlock_bh(lock)            spin_unlock_bh(lock)
```

Because both paths hold `loginfo_list_lock`, they are **serialised**.
The REMOVED pre-check in path A ensures that if eviction already ran,
the timer callback skips `list_del_rcu` (which would otherwise write to
`LIST_POISON` addresses → silent hard panic).

`timer_delete()` in path B deflects any **pending** timer fire. If the
timer is already running (blocked on the lock), the REMOVED check will
cause it to skip lnode removal and be a no-op in `ipfi_entry_remove`.

---

## 10.4. Safe Module Shutdown (7-Step Sequence)

Unloading a stateful kernel module requires draining all pending timers,
work items, and RCU callbacks before freeing the slab caches.

```
Step 1  we_are_exiting = true         ← no new allocations
Step 2  synchronize_net()             ← wait for in-flight packets
Step 3  unregister_hooks()            ← no new packets enter
Step 4  fini_machine / fini_log /     ← flush tables:
        fini_translation                ipfi_entry_put chains → queue_work
Step 5  destroy_workqueue(ipfire_wq)  ← drain work items:
                                        each runs timer_delete_sync + call_rcu
Step 6  rcu_barrier()                 ← wait for all call_rcu callbacks
                                        (i.e., all kfree calls) to complete
Step 7  kmem_cache_destroy()          ← safe: all objects are freed
```

> [!WARNING]
> If steps 5 and 6 were swapped, or if step 6 were omitted, `kfree` could
> fire **after** `kmem_cache_destroy` — an immediate kernel panic.

---

## 10.5. Timer Update Path — TOCTOU Mitigation

`ipfi_entry_update_timer` must not call `mod_timer` on an entry that is
being freed. The function is **self-contained**: it takes its own
`ipfi_entry_hold_rcu` before touching the timer, so callers do not need
an extra hold. Flow:

```
ipfi_entry_update_timer(h, proto, state)
    │
    ├─ test_bit(REMOVED) → early exit if dying
    │
    └─ if last update was > 5s ago:
           ipfi_entry_hold_rcu(h)    ← atomic inc-not-zero
           test_bit(REMOVED) again   ← re-check under hold
           mod_timer(...)            ← safe: hold prevents free
           ipfi_entry_put(h)         ← release temporary hold
```

The 5-second throttle prevents O(N_packets) timer modifications under
high load while keeping entries alive under sustained traffic.
