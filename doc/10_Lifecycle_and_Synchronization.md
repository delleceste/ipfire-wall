# Chapter 10: Lifecycle & Synchronization

This chapter describes how the IPFire-Wall manages the memory and concurrency of its internal tables using the unified `ipfi_entry` framework.

## 10.1. The Unified Entry Framework
To avoid fragmented logic and potential race conditions, all dynamic table entries (State, NAT, and LogInfo) share a common header:

```c
struct ipfi_entry_head {
    struct list_head lnode;      /* RCU-safe linked list node */
    struct timer_list timer;     /* Entry expiration timer */
    struct work_struct cleanup_work; /* Deferred deletion work */
    struct rcu_head rcuh;        /* RCU callback node */
    refcount_t refcnt;           /* Reference counter */
    unsigned long status;        /* Removal status bits */
    unsigned long last_timer_update; /* Throttling timestamp */
};
```

## 10.2. The Deletion Chain
IPFire-Wall uses a multi-stage deferred-free mechanism to ensure that memory is only released when it is no longer being accessed by any CPU.

1.  **Logical Removal**: `ipfi_entry_remove()` marks the entry as removed and unlinks it from the RCU list. No new lookups will find it.
2.  **Reference Drop**: `ipfi_entry_put()` reduces the reference count. If it reach zero, it queues the `cleanup_work`.
3.  **Synchronization**: The worker runs `timer_delete_sync()` to ensure the entry's timer is not running on any other CPU.
4.  **RCU Barrier**: `call_rcu()` is invoked to wait for a quiet period (ensuring no RCU readers are active).
5.  **Physical Free**: `free_entry_rcu()` finally calls `kfree()`, which releases the memory to its specific slab cache.

## 10.3. Safe Module Shutdown
Unloading a stateful kernel module is risky due to pending timers and RCU callbacks. IPFire-Wall implements a strict 7-step sequence:

1.  **Exit Signal**: `we_are_exiting = true` prevents new entries from being created.
2.  **Hook Synchronization**: `synchronize_net()` waits for in-flight packets to finish.
3.  **Unregistration**: Netfilter hooks are removed.
4.  **Table Flush**: Every entry is logically removed and its reference count dropped.
5.  **Workqueue Drain**: `destroy_workqueue()` waits for all `cleanup_work` items (step 3 of the deletion chain).
6.  **Callback Barrier**: `rcu_barrier()` waits for all `kfree` callbacks to finish.
7.  **Cache Destruction**: `kmem_cache_destroy()` safely tears down the slabs.
