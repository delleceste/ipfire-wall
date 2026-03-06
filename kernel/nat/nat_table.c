/* nat/nat_table.c — Unified NAT table management for ipfire-wall
 *
 * Merges the former snat_table.c and dnat_table.c into a single
 * implementation. All SNAT and DNAT entries share the same struct
 * nat_table and lifecycle functions from table_lifecycle.c.
 */

#include "nat_table.h"
#include "../filter/state/state_machine.h"
#include "../globals.h"
#include "ipfi_machine.h"
#include "ipfire.h"
#include "nat.h"
#include <linux/bitops.h>
#include <linux/gfp.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timer.h>

/* ---- Per-type globals ---- */

/* Hash tables: two arrays of hlist_head, one per nat_type */
/* (defined in common/globals.c via globals.h extern) */
/* (defined in common/globals.c via globals.h extern) */
extern struct percpu_counter nat_counters[2];
extern struct kmem_cache *nat_cache;

void fini_nat_tables(void) {
  int s, d;
  s = free_nat_tables(NAT_SNAT);
  d = free_nat_tables(NAT_DNAT);
  percpu_counter_destroy(&nat_counters[NAT_SNAT]);
  percpu_counter_destroy(&nat_counters[NAT_DNAT]);
  IPFI_PRINTK("IPFIRE: NAT tables freed: snat=%d dnat=%d\n", s, d);
  /* kmem_cache_destroy deferred to ipfire.c::fini() after
   * destroy_workqueue + rcu_barrier ensure all kfree callbacks ran. */
}

int init_nat_tables(void) {
  nat_cache = kmem_cache_create("ipfi_nat", sizeof(struct nat_table), 0,
                                SLAB_HWCACHE_ALIGN, NULL);
  if (!nat_cache) {
    IPFI_PRINTK("IPFIRE: failed to create NAT slab cache\n");
    return -ENOMEM;
  }
  {
    unsigned int i, j;
    for (i = 0; i < (1 << NAT_HASH_BITS); i++) {
      for (j = 0; j < NAT_IDX_COUNT; j++) {
        INIT_HLIST_HEAD(&nat_hashtables[NAT_SNAT][j][i]);
        INIT_HLIST_HEAD(&nat_hashtables[NAT_DNAT][j][i]);
        spin_lock_init(&nat_bucket_locks[NAT_SNAT][j][i]);
        spin_lock_init(&nat_bucket_locks[NAT_DNAT][j][i]);
      }
    }
  }
  percpu_counter_init(&nat_counters[NAT_SNAT], 0, GFP_KERNEL);
  percpu_counter_init(&nat_counters[NAT_DNAT], 0, GFP_KERNEL);
  return 0;
}

/* ---- Hash functions ---- */

u32 get_snat_hash(__u32 new_saddr, __u16 new_sport, __u32 old_daddr,
                  __u16 old_dport, __u8 proto) {
  __u32 a1 = new_saddr, a2 = old_daddr;
  __u16 p1 = new_sport, p2 = old_dport;
  if (a1 > a2 || (a1 == a2 && p1 > p2)) {
    swap(a1, a2);
    swap(p1, p2);
  }
  if (proto == IPPROTO_ICMP)
    return jhash_3words(a1, a2, 0, proto);
  return jhash_3words(a1, a2, ((u32)p1 << 16) | p2, proto);
}

u32 get_nat_tuple_hash(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport,
                       __u8 proto) {
  __u32 a1 = saddr, a2 = daddr;
  __u16 p1 = sport, p2 = dport;
  if (a1 > a2 || (a1 == a2 && p1 > p2)) {
    swap(a1, a2);
    swap(p1, p2);
  }
  if (proto == IPPROTO_ICMP)
    return jhash_3words(a1, a2, 0, proto);
  return jhash_3words(a1, a2, ((u32)p1 << 16) | p2, proto);
}

u32 get_dnat_hash(__u32 old_saddr, __u16 old_sport, __u32 new_daddr,
                  __u16 new_dport, __u8 proto) {
  return get_nat_tuple_hash(old_saddr, old_sport, new_daddr, new_dport, proto);
}

/* Supplemental index management */
void nat_add_index(struct nat_table *nt, enum nat_index idx, __u32 key) {
  unsigned int new_bkt, old_bkt;

  if (idx <= NAT_IDX_ORIG || idx >= NAT_IDX_COUNT)
    return;

  new_bkt = key & ((1 << NAT_HASH_BITS) - 1);

  /* Case 1: Entry already has this index. Check if it needs moving. */
  if (nt->active_indices & (1 << idx)) {
    if (nt->keys[idx] == key)
      return; /* Bucket same, nothing to do (idempotency) */

    /* Identity changed (e.g. masquerading updated our_ifaddr).
     * Move entry to the new bucket. */
    old_bkt = nt->bkts[idx];

    /* Unlink from old bucket */
    spin_lock_bh(&nat_bucket_locks[nt->type][idx][old_bkt]);
    hlist_del_rcu(&nt->h_indices[idx - 1]);
    nt->active_indices &= ~(1 << idx);
    spin_unlock_bh(&nat_bucket_locks[nt->type][idx][old_bkt]);
  }

  /* Case 2: Add to new bucket (or relocated bucket) */
  spin_lock_bh(&nat_bucket_locks[nt->type][idx][new_bkt]);
  nt->keys[idx] = key;
  nt->bkts[idx] = new_bkt;
  nt->active_indices |= (1 << idx);

  hlist_add_head_rcu(&nt->h_indices[idx - 1],
                     &nat_hashtables[nt->type][idx][new_bkt]);
  spin_unlock_bh(&nat_bucket_locks[nt->type][idx][new_bkt]);
}

/* ---- Compare ---- */

int compare_nat_entries(const struct nat_table *a, const struct nat_table *b) {
  return (a->type == b->type) && (a->protocol == b->protocol) &&
         (a->old_saddr == b->old_saddr) && (a->old_daddr == b->old_daddr) &&
         (a->old_sport == b->old_sport) && (a->old_dport == b->old_dport) &&
         (a->new_addr == b->new_addr) && (a->new_port == b->new_port) &&
         (a->direction == b->direction);
}

/* ---- Fill network fields ---- */

int fill_nat_entry_fields(struct nat_table *entry, const struct sk_buff *skb,
                          const ipfi_flow *flow, const struct response *resp,
                          const struct info_flags *flags,
                          const ipfire_rule *rule, enum nat_type type) {
  struct iphdr *iph = ip_hdr(skb);

  memset(entry, 0, sizeof(struct nat_table));
  entry->type = type;
  entry->protocol = iph->protocol;
  entry->old_saddr = iph->saddr;
  entry->old_daddr = iph->daddr;
  entry->direction = flags->direction;
  entry->nolog = rule->nflags.nolog;
  entry->external = flags->external;
  entry->rule_id = resp->rule_id;
  entry->position = percpu_counter_read(&nat_counters[type]);

  /* Initialize index metadata for NAT_IDX_ORIG */
  entry->active_indices = (1 << NAT_IDX_ORIG);
  entry->keys[NAT_IDX_ORIG] = get_nat_tuple_hash(
      iph->saddr,
      (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
          ? ((struct tcphdr *)((void *)iph + iph->ihl * 4))->source
          : 0,
      iph->daddr,
      (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
          ? ((struct tcphdr *)((void *)iph + iph->ihl * 4))->dest
          : 0,
      iph->protocol);
  entry->bkts[NAT_IDX_ORIG] =
      entry->keys[NAT_IDX_ORIG] & ((1 << NAT_HASH_BITS) - 1);

  if (flow->in)
    strncpy(entry->in_devname, flow->in->name, IFNAMSIZ);
  if (flow->out)
    strncpy(entry->out_devname, flow->out->name, IFNAMSIZ);

  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    entry->old_sport = th->source;
    entry->old_dport = th->dest;
  } else if (iph->protocol == IPPROTO_ICMP) {
    entry->old_sport = 0;
    entry->old_dport = 0;
  }

  if (type == NAT_SNAT) {
    /* Default: keep original source */
    entry->new_addr = iph->saddr;
    entry->new_port =
        (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
            ? entry->old_sport
            : 0;
    if (rule->nflags.newaddr)
      entry->new_addr = rule->newaddr;
    if (rule->nflags.newport)
      entry->new_port = rule->newport;
  } else { /* NAT_DNAT */
    /* Default: keep original dest */
    entry->new_addr = iph->daddr;
    entry->new_port =
        (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
            ? entry->old_dport
            : 0;
    if (rule->nflags.newaddr)
      entry->new_addr = rule->newaddr;
    if (rule->nflags.newport)
      entry->new_port = rule->newport;
  }

  return 0;
}

/* ---- Timer callback ---- */

void handle_nat_entry_timeout(struct timer_list *t) {
  struct nat_table *nt = timer_container_of(nt, t, h.timer);
  enum nat_type type = nt->type;
  int i;
  struct {
    unsigned int bkt;
    enum nat_index idx;
  } locks[NAT_IDX_COUNT];
  int lock_count = 0;

  /* Identify active locks and order them to avoid deadlock */
  for (i = 0; i < NAT_IDX_COUNT; i++) {
    if (nt->active_indices & (1 << i)) {
      locks[lock_count].bkt = nt->bkts[i];
      locks[lock_count].idx = i;
      lock_count++;
    }
  }

  /* Bubble sort by (idx, bkt) for consistent locking order */
  for (i = 0; i < lock_count - 1; i++) {
    for (int j = 0; j < lock_count - i - 1; j++) {
      if (locks[j].idx > locks[j + 1].idx ||
          (locks[j].idx == locks[j + 1].idx &&
           locks[j].bkt > locks[j + 1].bkt)) {
        swap(locks[j], locks[j + 1]);
      }
    }
  }

  /* Acquire locks */
  for (i = 0; i < lock_count; i++) {
    spin_lock_bh(&nat_bucket_locks[type][locks[i].idx][locks[i].bkt]);
  }

  /* Unlink from all indices */
  if (test_and_set_bit(IPFI_ENTRY_REMOVED, &nt->h.status))
    goto unlock;

  hlist_del_rcu(&nt->h.hnode); /* ORIG */
  for (i = 0; i < NAT_IDX_COUNT - 1; i++) {
    if (nt->active_indices & (1 << (i + 1))) {
      hlist_del_rcu(&nt->h_indices[i]);
    }
  }

  percpu_counter_add_batch(&nat_counters[type], -1, 1);
  ipfi_entry_put(&nt->h);

unlock:
  for (i = lock_count - 1; i >= 0; i--) {
    spin_unlock_bh(&nat_bucket_locks[type][locks[i].idx][locks[i].bkt]);
  }
}

/* ---- Forward match (for early lookup in existing sessions) ---- */

/* ---- Lookup: by specific index (O(1)) ----
 *
 * This function handles RCU read-side protection internally.
 * It searches the specified index and returns a pointer to the entry
 * with a reference count hold (using nat_hold_rcu).
 *
 * The caller MUST call nat_put() when the entry is no longer needed.
 */
struct nat_table *lookup_nat_idx(enum nat_type type, enum nat_index idx,
                                 const struct sk_buff *skb) {
  struct nat_table *tmp;
  struct iphdr *iph = ip_hdr(skb);
  net_quadruplet nq;
  u32 key;
  unsigned int bkt;

  if (unlikely(!iph))
    return NULL;

  nq = get_quad_from_skb(skb);
  if (unlikely(!nq.valid))
    return NULL;

  key =
      get_nat_tuple_hash(nq.saddr, nq.sport, nq.daddr, nq.dport, iph->protocol);
  bkt = key & ((1 << NAT_HASH_BITS) - 1);

  rcu_read_lock_bh();
  if (idx == NAT_IDX_ORIG) {
    hlist_for_each_entry_rcu(tmp, &nat_hashtables[type][idx][bkt], h.hnode) {
      if (iph->protocol == tmp->protocol) {
        if (nq.saddr == tmp->old_saddr && nq.sport == tmp->old_sport &&
            nq.daddr == tmp->old_daddr && nq.dport == tmp->old_dport) {
          if (nat_hold_rcu(tmp)) {
            rcu_read_unlock_bh();
            return tmp;
          }
        }
      }
    }
  } else {
    /* Use the appropriate index in h_indices */
    int h_idx = (int)idx - 1;
    if (h_idx == 0) { /* POSTNAT */
      hlist_for_each_entry_rcu(tmp, &nat_hashtables[type][idx][bkt],
                               h_indices[0]) {
        if (iph->protocol == tmp->protocol) {
          if (tmp->type == NAT_DNAT) {
            /* DNAT POSTNAT: A -> C (Destination is new) */
            if (nq.saddr == tmp->old_saddr && nq.sport == tmp->old_sport &&
                nq.daddr == tmp->new_addr && nq.dport == tmp->new_port) {
              if (nat_hold_rcu(tmp)) {
                rcu_read_unlock_bh();
                return tmp;
              }
            }
            /* DNAT POSTNAT Reverse: C -> A (Reply from DNAT target to original
             * source) */
            if (nq.saddr == tmp->new_addr && nq.sport == tmp->new_port &&
                nq.daddr == tmp->old_saddr && nq.dport == tmp->old_sport) {
              if (nat_hold_rcu(tmp)) {
                rcu_read_unlock_bh();
                return tmp;
              }
            }
          } else {
            /* SNAT POSTNAT: C -> B (Source is new) */
            if (nq.saddr == tmp->new_addr && nq.sport == tmp->new_port &&
                nq.daddr == tmp->old_daddr && nq.dport == tmp->old_dport) {
              if (nat_hold_rcu(tmp)) {
                rcu_read_unlock_bh();
                return tmp;
              }
            }
          }
        }
      }
    } else { /* REPLY */
      hlist_for_each_entry_rcu(tmp, &nat_hashtables[type][idx][bkt],
                               h_indices[1]) {
        if (iph->protocol == tmp->protocol) {
          if (tmp->type == NAT_DNAT) {
            /* DNAT REPLY: C -> B (Reply to DNATed destination)
             * Match criteria for packets returning from a DNAT target server
             * (C). Used in:
             * - PREROUTING (pre_de_dnat): Identifies replies to keep state.
             * - POSTROUTING (de_dnat_translation): Restores the original
             *   destination address of the forward packet as the source of this
             *   reply, so the client (B) sees the gateway's IP.
             */
            if (tmp->direction == IPFI_OUTPUT) {
              /* OUTPUT DNAT REPLY: C -> A
               * Packet generated locally (A -> B), translated to A -> C.
               * Reply is C -> A. It comes back to the local host's old_saddr.
               */
              if (nq.saddr == tmp->new_addr && nq.sport == tmp->new_port &&
                  nq.daddr == tmp->old_saddr && nq.dport == tmp->old_sport) {
                if (nat_hold_rcu(tmp)) {
                  rcu_read_unlock_bh();
                  return tmp;
                }
              }
            } else {
              if (nq.saddr == tmp->new_addr && nq.sport == tmp->new_port &&
                  (nq.daddr == tmp->old_daddr ||
                   (tmp->our_ifaddr && nq.daddr == tmp->our_ifaddr))) {
                if (nat_hold_rcu(tmp)) {
                  rcu_read_unlock_bh();
                  return tmp;
                }
              }
            }
          } else {
            /* SNAT REPLY: B -> C (Reply to SNATed source)
             * Match criteria for packets returning to an SNATed source (C).
             * Used in:
             * - PREROUTING (pre_de_snat): The FIRST step in reverse processing.
             *   Correctly identifies the reply packet and restores the original
             *   client IP as the destination, before any DNAT reverse
             * processing.
             */
            if (nq.saddr == tmp->old_daddr && nq.sport == tmp->old_dport &&
                nq.daddr == tmp->new_addr && nq.dport == tmp->new_port) {
              if (nat_hold_rcu(tmp)) {
                rcu_read_unlock_bh();
                return tmp;
              }
            }
          }
        }
      }
    }
  }
  rcu_read_unlock_bh();
  return NULL;
}

/* ---- Forward match (for original direction) ---- */

/* ---- Lookup: by entry comparison (for duplicate detection) ---- */

/* ---- Lookup: by forward 5-tuple (for existing session reuse) ----
 *
 * Wraps lookup_nat_idx for the original direction.
 * Internally handles RCU protection and state/timer updates.
 *
 * Returns entry with reference hold.
 */
struct nat_table *lookup_nat_forward(const struct sk_buff *skb,
                                     enum nat_type type) {
  struct nat_table *nt = lookup_nat_idx(type, NAT_IDX_ORIG, skb);
  if (nt) {
    nt->state = state_machine(skb, nt->state, 0);
    ipfi_entry_update_timer(&nt->h, nt->protocol, nt->state);
  }
  return nt;
}

/* ---- Flush ---- */

int free_nat_tables(enum nat_type type) {
  struct nat_table *nt;
  struct hlist_node *tmp;
  unsigned int bkt;

  /* Supplemental indices must be cleared first.
   * We don't call ipfi_entry_put here because the final ORIG flush
   * will handle entry destruction.
   */
  for (bkt = 0; bkt < (1 << NAT_HASH_BITS); bkt++) {
    /* 1. Flush POSTNAT index */
    spin_lock_bh(&nat_bucket_locks[type][NAT_IDX_POSTNAT][bkt]);
    hlist_for_each_entry_safe(nt, tmp,
                              &nat_hashtables[type][NAT_IDX_POSTNAT][bkt],
                              h_indices[NAT_IDX_POSTNAT - 1]) {
      /* Only the thread that marks the entry as REMOVED (either the
       * final ORIG flush or a timer) should handle supplemental unlinking.
       * However, during module unload we clear everything. We check the
       * status to avoid double-deletion if a timer is firing. */
      if (!test_bit(IPFI_ENTRY_REMOVED, &nt->h.status)) {
        hlist_del_rcu(&nt->h_indices[NAT_IDX_POSTNAT - 1]);
        nt->active_indices &= ~(1 << NAT_IDX_POSTNAT);
      }
    }
    spin_unlock_bh(&nat_bucket_locks[type][NAT_IDX_POSTNAT][bkt]);

    /* 2. Flush REPLY index */
    spin_lock_bh(&nat_bucket_locks[type][NAT_IDX_REPLY][bkt]);
    hlist_for_each_entry_safe(nt, tmp,
                              &nat_hashtables[type][NAT_IDX_REPLY][bkt],
                              h_indices[NAT_IDX_REPLY - 1]) {
      if (!test_bit(IPFI_ENTRY_REMOVED, &nt->h.status)) {
        hlist_del_rcu(&nt->h_indices[NAT_IDX_REPLY - 1]);
        nt->active_indices &= ~(1 << NAT_IDX_REPLY);
      }
    }
    spin_unlock_bh(&nat_bucket_locks[type][NAT_IDX_REPLY][bkt]);
  }

  /* 3. Flush ORIG index (standard traversal of h.hnode) */
  return ipfi_table_flush_hash_bucketed(
      nat_hashtables[type][NAT_IDX_ORIG], 1 << NAT_HASH_BITS,
      nat_bucket_locks[type][NAT_IDX_ORIG], &nat_counters[type]);
}
