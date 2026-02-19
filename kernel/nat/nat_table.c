/* nat/nat_table.c — Unified NAT table management for ipfire-wall
 *
 * Merges the former snat_table.c and dnat_table.c into a single
 * implementation. All SNAT and DNAT entries share the same struct
 * nat_table and lifecycle functions from table_lifecycle.c.
 */

#include "nat_table.h"
#include "../filter/state/state_machine.h"
#include "globals.h"
#include "ipfi_machine.h"
#include "ipfire.h"
#include "nat.h"
#include <linux/jhash.h>
#ifdef IPFI_USE_HASH
#include <linux/hashtable.h>
#endif
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timer.h>

/* ---- Per-type globals ---- */

#ifdef IPFI_USE_HASH
/* Hash tables: two arrays of hlist_head, one per nat_type */
/* (defined in common/globals.c via globals.h extern) */
#else
struct list_head nat_lists[2];
#endif
spinlock_t nat_locks[2];
unsigned int nat_counters[2];
struct kmem_cache *nat_cache;

void fini_nat_tables(void) {
  int s, d;
  s = free_nat_tables(NAT_SNAT);
  d = free_nat_tables(NAT_DNAT);
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
#ifdef IPFI_USE_HASH
  {
    unsigned int i;
    for (i = 0; i < (1 << NAT_HASH_BITS); i++) {
      INIT_HLIST_HEAD(&nat_hashtables[NAT_SNAT][i]);
      INIT_HLIST_HEAD(&nat_hashtables[NAT_DNAT][i]);
    }
  }
#else
  INIT_LIST_HEAD(&nat_lists[NAT_SNAT]);
  INIT_LIST_HEAD(&nat_lists[NAT_DNAT]);
#endif
  spin_lock_init(&nat_locks[NAT_SNAT]);
  spin_lock_init(&nat_locks[NAT_DNAT]);
  nat_counters[NAT_SNAT] = 0;
  nat_counters[NAT_DNAT] = 0;
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

u32 get_dnat_hash(__u32 old_saddr, __u16 old_sport, __u32 new_daddr,
                  __u16 new_dport, __u8 proto) {
  __u32 a1 = old_saddr, a2 = new_daddr;
  __u16 p1 = old_sport, p2 = new_dport;
  if (a1 > a2 || (a1 == a2 && p1 > p2)) {
    swap(a1, a2);
    swap(p1, p2);
  }
  if (proto == IPPROTO_ICMP)
    return jhash_3words(a1, a2, 0, proto);
  return jhash_3words(a1, a2, ((u32)p1 << 16) | p2, proto);
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
  entry->position = nat_counters[type];

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
  struct ipfi_entry_head *h = &nt->h;
  enum nat_type type = nt->type;

  spin_lock_bh(&nat_locks[type]);
  ipfi_entry_remove(h, &nat_counters[type]); /* puts internally if winner */
  spin_unlock_bh(&nat_locks[type]);
}

/* ---- Forward match (for early lookup in existing sessions) ---- */

static int forward_nat_match(const struct nat_table *nt,
                             const struct sk_buff *skb) {
  struct iphdr *iph = ip_hdr(skb);
  net_quadruplet nq = get_quad_from_skb(skb);

  if (!nq.valid)
    return -1;
  if (iph->protocol != nt->protocol)
    return -1;

  if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
    if (iph->saddr == nt->old_saddr && nq.sport == nt->old_sport &&
        iph->daddr == nt->old_daddr && nq.dport == nt->old_dport)
      return 1;
  } else {
    if (iph->saddr == nt->old_saddr && iph->daddr == nt->old_daddr)
      return 1;
  }
  return -1;
}

/* ---- Lookup: by entry comparison (for duplicate detection) ---- */

/* ---- Lookup: by forward 5-tuple (for existing session reuse) ---- */

struct nat_table *lookup_nat_forward(const struct sk_buff *skb,
                                     enum nat_type type) {
  struct nat_table *tmp;

  rcu_read_lock_bh();
#ifdef IPFI_USE_HASH
  {
    struct iphdr *iph = ip_hdr(skb);
    u32 key;
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
      net_quadruplet nq = get_quad_from_skb(skb);
      if (!nq.valid) {
        rcu_read_unlock_bh();
        return NULL;
      }
      if (type == NAT_SNAT)
        key = get_snat_hash(nq.saddr, nq.sport, nq.daddr, nq.dport,
                            iph->protocol);
      else
        key = get_dnat_hash(nq.saddr, nq.sport, nq.daddr, nq.dport,
                            iph->protocol);
    } else {
      key = jhash_2words(iph->saddr, iph->daddr, iph->protocol);
    }
    hash_for_each_possible_rcu(nat_hashtables[type], tmp, h.hnode, key) {
      if (forward_nat_match(tmp, skb) > 0) {
        if (nat_hold_rcu(tmp)) {
          tmp->state = state_machine(skb, tmp->state, 0);
          ipfi_entry_update_timer(&tmp->h, tmp->protocol, tmp->state);
          rcu_read_unlock_bh();
          return tmp;
        }
      }
    }
  }
#else
  list_for_each_entry_rcu(tmp, &nat_lists[type], h.lnode) {
    if (forward_nat_match(tmp, skb) > 0) {
      if (nat_hold_rcu(tmp)) { // hold the entry (released by the caller)
        tmp->state = state_machine(skb, tmp->state, 0);
        ipfi_entry_update_timer(&tmp->h, tmp->protocol, tmp->state);
        rcu_read_unlock_bh();
        return tmp;
      }
    }
  }
#endif
  rcu_read_unlock_bh();
  return NULL;
}

/* ---- Flush ---- */

int free_nat_tables(enum nat_type type) {
#ifdef IPFI_USE_HASH
  return ipfi_table_flush_hash(nat_hashtables[type], 1 << NAT_HASH_BITS,
                               &nat_locks[type], &nat_counters[type]);
#else
  return ipfi_table_flush_all(&nat_lists[type], &nat_locks[type],
                              &nat_counters[type]);
#endif
}
