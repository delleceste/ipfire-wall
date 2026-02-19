# Chapter 12: Concurrency & Safety Analysis

This chapter documents the synchronization mechanisms used in IPFire-Wall to
prevent race conditions, Use-After-Free (UAF), double-free, and
Time-of-Check-to-Time-of-Use (TOCTOU) vulnerabilities, including the bugs
discovered and fixed during high-load UDP flood testing.

---

## 12.1. The Three-Layer Safety Model

### Layer 1 — RCU (lockless hot-path reads)

Packet processing lookups use `rcu_read_lock_bh()` to traverse lists and
hash tables without taking a lock. RCU guarantees that linked objects remain
pointer-valid for the duration of the read-side critical section, **even if
another CPU unlinks them concurrently**.

```c
rcu_read_lock_bh();
hash_for_each_possible_rcu(..., entry, hnode, key) {
    if (matches(entry)) {
        ipfi_entry_update_timer(&entry->h, ...);  /* self-contained, safe */
        break;
    }
}
rcu_read_unlock_bh();
```

> [!IMPORTANT]
> RCU only guarantees **pointer validity** during the critical section, NOT
> **object liveness** beyond it. For operations that need the object to
> survive past the RCU lock, a refcount hold is required.

### Layer 2 — Reference counting (object liveness)

`refcount_t` ensures objects are freed only when **all** users have released
them. `ipfi_entry_hold_rcu` uses `refcount_inc_not_zero`: it atomically
increments the counter OR refuses if it is already at zero (dying object).

`ipfi_entry_update_timer` is self-contained: it acquires hold, updates the
timer, and puts — callers do not need an external hold.

### Layer 3 — Spinlocks (writer serialisation)

Writers (add, remove, evict) hold the table spinlock:
- prevents concurrent `hlist_del_rcu` / `list_del_rcu` on the same bucket
- protects plain-`unsigned int` counters from data races
- serialises the loginfo lnode pre-check + `list_del_rcu` sequence

---

## 12.2. Lock Disciplines

| Operation | Lock held | Locking function |
|-----------|-----------|-----------------|
| Add state entry | `state_list_lock` | `spin_lock_bh` |
| Remove (timer) state | `state_list_lock` | `spin_lock_bh` |
| Add NAT entry | `nat_locks[type]` | `spin_lock_bh` |
| Remove (timer) NAT | `nat_locks[type]` | `spin_lock_bh` |
| Add loginfo entry | `loginfo_list_lock` | `spin_lock_bh` |
| Remove (timer) loginfo | `loginfo_list_lock` | `spin_lock_bh` |
| Evict loginfo (capacity) | `loginfo_list_lock` | `spin_lock_bh` |
| Lookup (state/NAT/log) | none (RCU) | `rcu_read_lock_bh` |
| Timer update | none (internal hold) | `ipfi_entry_hold_rcu` |
| Flush (module unload) | table spinlock | `spin_lock_bh` (brief) |

`spin_lock_bh` disables BH (softirqs), preventing timer callbacks from
running on the same CPU while a lock is held. This avoids the need for
`spin_lock_irqsave` in most paths (timers run in softirq, not hard IRQ).

---

## 12.3. ipfi_entry_remove — Ownership Model

`ipfi_entry_remove` owns the final `ipfi_entry_put`. The **winner** of the
`test_and_set_bit(REMOVED)` race performs unlink + put; the **loser** is a
complete no-op.

```c
void ipfi_entry_remove(struct ipfi_entry_head *h, unsigned int *counter) {
    if (test_and_set_bit(IPFI_ENTRY_REMOVED, &h->status))
        return;           /* loser: no-op */

    hlist_del_rcu(&h->hnode);   /* or list_del_rcu in list mode */
    (*counter)--;
    ipfi_entry_put(h);           /* winner: sole caller of put */
}
```

Callers must **not** call `ipfi_entry_put` after `ipfi_entry_remove`.
`queue_work` (inside `ipfi_entry_put`) is safe from BH-disabled spinlock
context: it uses `spin_lock_irqsave` internally and never sleeps.

---

## 12.4. Post-Mortem: Silent Kernel Crash Under UDP Flood

### Symptom

`iperf3 -u -b 1G -P 120` crashed the machine **immediately** with no kernel
oops, no kdump trace — a completely silent hard reset. Even a single stream
crashed with high probability.

**Root cause: fault in softirq context before the oops path could execute.**

---

### Bug 1 — `handle_loginfo_timeout`: `list_del_rcu` on LIST_POISON (CRITICAL)

**File:** `logging/log.c` — `handle_loginfo_timeout` (hash mode)

```
CPU 0 (eviction, holds loginfo_list_lock)     CPU 1 (timer fires, waits for lock)
──────────────────────────────────────────    ────────────────────────────────────
list_del_rcu(X.lnode)                         [blocked on lock]
ipfi_entry_remove(X) ← sets REMOVED
  └─ ipfi_entry_put → queue_work
spin_unlock_bh()
                                              spin_lock_bh() ← acquired
                                              list_del_rcu(X.lnode)  ← X.lnode.prev
                                                                         = LIST_POISON!
                                              WRITE to 0x100 → page fault in softirq
                                              → no oops printed → hard reset
```

**Fix:** Check `REMOVED` before `list_del_rcu` in the timer callback:

```c
if (!test_bit(IPFI_ENTRY_REMOVED, &h->status))
    list_del_rcu(&h->lnode);
ipfi_entry_remove(h, &loginfo_entry_counter); /* winner puts; loser no-op */
```

---

### Bug 2 — `loginfo_evict_oldest`: no timer cancellation

**File:** `logging/log.c` — `loginfo_evict_oldest`

After eviction sets REMOVED and calls `ipfi_entry_put` (refcount → 0,
work queued), the timer can still fire on another CPU before the workqueue
runs `timer_delete_sync`. The timer callback then acquires the lock and
reaches `list_del_rcu` with a poisoned lnode.

**Fix:** `timer_delete()` after `ipfi_entry_remove`. Non-sync is safe: if
the timer is running it's blocked on the lock we hold; REMOVED is set so
it becomes a no-op when it eventually acquires the lock.

```c
ipfi_entry_remove(&oldest->h, &loginfo_entry_counter);
timer_delete(&oldest->h.timer);   /* deflect pending timer fire */
```

---

### Bug 3 — `add_packet_to_infolist`: arm-timer after lock release (UAF)

**File:** `logging/log.c` — `add_packet_to_infolist`

```
CPU 0                           CPU 1
─────────────────────           ─────────────────────
list_add_rcu(lnode)
loginfo_entry_counter++
spin_unlock_bh()                [eviction: list is at capacity]
                                ipfi_entry_remove(new_entry) → put → work queued
                                timer_delete_sync() → kfree(new_entry)
ipfi_entry_arm_timer()          ← mod_timer on freed object!  UAF!
```

**Fix:** Hold an extra refcount reference spanning the lock-release →
arm-timer gap:

```c
ipfi_entry_hold(&ipli->h);   /* arm-guard: refcount → 2 */
spin_unlock_bh(&loginfo_list_lock);
ipfi_entry_arm_timer(&ipli->h);  /* safe: refcount ≥ 2 */
ipfi_entry_put(&ipli->h);    /* release arm-guard */
```

---

### Bug 4 — `fini_log` (hash mode): lnode left dangling

**File:** `logging/log.c` — `fini_log`

`ipfi_table_flush_hash` unlinks `hnode` only. In hash mode, loginfo lnodes
remained in `active_logi_list` after flush → UAF on any subsequent traversal.

**Fix:** Always drain via `active_logi_list` (lnode-based flush works for
both links because REMOVED prevents timer callbacks from re-entering):

```c
ipfi_table_flush_all(&active_logi_list, &loginfo_list_lock,
                     &loginfo_entry_counter);
```

---

## 12.5. Final UAF / TOCTOU / Double-Free Audit

### State table

| Path | Lock | Race risk | Status |
|------|------|-----------|--------|
| `check_state` timer update | RCU | `update_timer` is self-contained (internal hold) | ✅ safe |
| `handle_keep_state_timeout` remove | `state_list_lock` | single removal path, no eviction | ✅ safe |
| `lookup_state_table_n_update_timer` | RCU + `state_hold_rcu` | redundant outer hold, harmless | ✅ safe |
| `add_state_table_to_list` | `state_list_lock` | `we_are_exiting` double-check inside lock | ✅ safe |

### NAT table

| Path | Lock | Race risk | Status |
|------|------|-----------|--------|
| `lookup_nat_forward` timer update | RCU + `nat_hold_rcu` | correct hold before `update_timer` | ✅ safe |
| `handle_nat_entry_timeout` remove | `nat_locks[type]` | single removal path | ✅ safe |

### LogInfo

| Path | Lock | Race risk | Status |
|------|------|-----------|--------|
| `handle_loginfo_timeout` lnode | `loginfo_list_lock` | REMOVED pre-check added | ✅ fixed |
| `loginfo_evict_oldest` timer | `loginfo_list_lock` | `timer_delete()` added | ✅ fixed |
| `add_packet_to_infolist` arm | — | extra hold spanning gap | ✅ fixed |
| `fini_log` lnode flush | `loginfo_list_lock` | lnode-based flush | ✅ fixed |
| `packet_not_seen` (hash) update | RCU | `update_timer` self-contained | ✅ safe |
| `packet_not_seen` (list) update | RCU + `ipfi_entry_hold_rcu` | outer hold redundant but safe | ✅ safe |

### Module unload

| Step | Safety concern | Status |
|------|----------------|--------|
| `fini_machine` → `free_state_tables` | entries in-flight in timers | REMOVED set, timer callback no-ops | ✅ safe |
| `destroy_workqueue` | work items post `call_rcu` | `destroy_workqueue` drains all | ✅ safe |
| `rcu_barrier` | `kfree` callbacks in flight | barrier waits for all | ✅ safe |
| `kmem_cache_destroy` after `rcu_barrier` | use-after-destroy | ordering guarantees objects freed | ✅ safe |

---

## 12.6. Debugging Silent Panics

A fault in softirq context (`list_del_rcu` → page fault at LIST_POISON)
crashes the machine before the oops message can be serialised to any
output. To capture such events:

```bash
# Serial console (capture before framebuffer flush):
GRUB_CMDLINE_LINUX="... console=ttyS0,115200 earlyprintk=serial,ttyS0,115200"

# Verify kdump crash kernel is loaded:
cat /sys/kernel/kexec_crash_loaded   # must be 1

# Force panic on oops + immediate reboot (trips kdump):
echo 1 > /proc/sys/kernel/panic_on_oops
echo 1 > /proc/sys/kernel/panic

# Compile with KASAN for in-kernel UAF detection (requires source rebuild):
# CONFIG_KASAN=y
# CONFIG_KASAN_INLINE=y
```

With `crashkernel=256M` already set, kdump should produce a vmcore after
the next crash. Analyse with:

```bash
crash /usr/lib/debug/boot/vmlinux-$(uname -r) /var/crash/*/vmcore
```
