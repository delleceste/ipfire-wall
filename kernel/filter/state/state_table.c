/* filter/state/state_table.c: State table management for ipfire-wall */

#include "globals.h"
#include "ipfi_machine.h"
#include "ipfire.h"
#include "state_machine.h"
#include <linux/bitops.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>

struct kmem_cache *state_cache;

int direct_state_match(const struct sk_buff *skb,
                       const struct state_table *entry, const ipfi_flow *flow) {
  const struct iphdr *iph = ip_hdr(skb);
  if (!iph || entry->protocol != iph->protocol)
    return -1;
  if (iph->saddr != entry->saddr || iph->daddr != entry->daddr)
    return -1;
  switch (iph->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    if (entry->ftp == FTP_DEFINED) { /* ftp support: discard source port */
      if (th->dest == entry->dport)
        return 1;
    }
    if (th->source != entry->sport || th->dest != entry->dport)
      return -1;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
    if (uh->source != entry->sport || uh->dest != entry->dport)
      return -1;
  } break;
  }
  /* ICMP and IGMP treated in l2l3match() */
  return 1;
}

int reverse_state_match(const struct sk_buff *skb,
                        const struct state_table *entry,
                        const ipfi_flow *flow) {
  const struct iphdr *iph = ip_hdr(skb);
  if (!iph || entry->protocol != iph->protocol)
    return -1;
  if (iph->saddr != entry->daddr || iph->daddr != entry->saddr)
    return -1;
  switch (iph->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    if (th->source != entry->dport || th->dest != entry->sport)
      return -1;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
    if (uh->source != entry->dport || uh->dest != entry->sport)
      return -1;
  } break;
  }
  return 1;
}

inline int l2l3match(const struct sk_buff *skb, const struct state_table *entry,
                     short *reverse, const ipfi_flow *flow) {
  const struct iphdr *iph = ip_hdr(skb);

  if (iph->protocol != entry->protocol)
    return -1;
  /* Direct Match */
  if (iph->saddr == entry->saddr && iph->daddr == entry->daddr) {
    *reverse = 0;
    return 1;
  }

  /* Reverse Match */
  if (iph->saddr == entry->daddr && iph->daddr == entry->saddr) {
    *reverse = 1;
    return 1;
  }
  return -1;
}

/**
 * skb_matches_state_table - check if skb matches a state table entry
 * @skb: packet to check
 * @entry: state table entry
 * @reverse: output flag
 *           0  = direct match
 *           1  = reverse match
 *          -1  = no match
 * @flow: packet metadata (direction, etc.)
 *
 * Returns:
 *   >0  if matched
 *   -1  if no match
 *
 * Security model:
 *
 * 1) Direct match (same 5-tuple):
 *    This is safe to allow across INPUT <-> OUTPUT symmetry.
 *    Reason: an external attacker cannot realistically inject a packet
 *    with the exact same 5-tuple in direct form because routing would not
 *    deliver such a packet to us. A real external reply always appears
 *    as a reverse 5-tuple, not direct.
 *
 *    Therefore allowing direct INPUT/OUTPUT symmetry fixes netns traversal
 *    without creating a spoofing hole.
 *
 * 2) Reverse match (swapped 5-tuple):
 *    This is what real replies look like.
 *    This must be controlled carefully to prevent spoofed replies.
 *
 *    Allowed:
 *      - OUTPUT entry -> INPUT reply
 *      - INPUT entry  -> OUTPUT reply
 *      - OUTPUT entry -> OUTPUT (lenient netns case)
 *
 *    Not allowed:
 *      - Reverse matches in arbitrary directions.
 */
int skb_matches_state_table(const struct sk_buff *skb,
                            const struct state_table *entry, short *reverse,
                            const ipfi_flow *flow) {
  const struct iphdr *iph = ip_hdr(skb);
  short tr_match = 0;

  *reverse = -1;

  if (iph->protocol != entry->protocol)
    return -1;

  /* Special protocols */
  if (iph->protocol == IPPROTO_ICMP || iph->protocol == IPPROTO_IGMP ||
      iph->protocol == IPPROTO_GRE || iph->protocol == IPPROTO_PIM) {
    return l2l3match(skb, entry, reverse, flow);
  }

  /* Try direct 5-tuple match */
  if ((tr_match = direct_state_match(skb, entry, flow)) > 0) {
    *reverse = 0;
  }
  /* Try reverse 5-tuple match */
  else if ((tr_match = reverse_state_match(skb, entry, flow)) > 0) {
    *reverse = 1;
  } else {
    return -1;
  }

  /* FWD flows: only match FWD entries */
  if (entry->direction == IPFI_FWD && flow->direction == IPFI_FWD)
    return tr_match;

  /* DIRECT MATCH HANDLING */
  if (*reverse == 0) {
    if (flow->direction == entry->direction)
      return tr_match;

    /*
     * Allow INPUT <-> OUTPUT symmetry for direct matches.
     *
     * Why this is safe:
     * A true external reply does NOT appear as a direct 5-tuple.
     * It appears as a reverse 5-tuple.
     *
     * Therefore allowing direct symmetry does not allow spoofed
     * replies from outside. It only allows the same packet to
     * traverse multiple hooks (netns case).
     */
    if ((entry->direction == IPFI_OUTPUT && flow->direction == IPFI_INPUT) ||
        (entry->direction == IPFI_INPUT && flow->direction == IPFI_OUTPUT)) {
      *reverse = 2; /* mark special namespace reverse */
      return tr_match;
    }
    return -1;
  }

  /* ----------------------------
   * REVERSE MATCH HANDLING
   * ---------------------------- */
  if (*reverse == 1) {

    /*
     * First of two legitimate and natural reply case:
     * OUTPUT entry -> INPUT reply
     */
    if (entry->direction == IPFI_OUTPUT && flow->direction == IPFI_INPUT)
      return tr_match;

    /*
     * Second of two legitimate and natural reply case:
     * INPUT entry -> OUTPUT reply
     */
    if (entry->direction == IPFI_INPUT && flow->direction == IPFI_OUTPUT)
      return tr_match;

    /*
     * Lenient namespace case:
     * reverse 5-tuple still seen in OUTPUT hook.
     *
     * This happens when traffic crosses veth/netns boundaries
     * and appears again in OUTPUT context.
     */
    if (entry->direction == IPFI_OUTPUT && flow->direction == IPFI_OUTPUT) {
      *reverse = 2; /* mark special namespace reverse */
      return tr_match;
    }

    /*
     * All other reverse combinations are rejected.
     *
     * This is critical for spoofing protection:
     * A malicious external host can attempt to inject
     * reverse 5-tuples to hijack state. We only allow
     * directionally correct reply paths.
     */
    return -1;
  }

  return -1;
}

int fill_net_table_fields(struct state_table *state_t,
                          const struct sk_buff *skb, const ipfi_flow *flow) {
  struct iphdr *iph = ip_hdr(skb);
  if (iph) {
    state_t->protocol = iph->protocol;
    state_t->saddr = iph->saddr;
    state_t->daddr = iph->daddr;
    switch (iph->protocol) {
    case IPPROTO_TCP: {
      struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
      state_t->sport = th->source;
      state_t->dport = th->dest;
      break;
    }
    case IPPROTO_UDP: {
      struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
      state_t->sport = uh->source;
      state_t->dport = uh->dest;
      break;
    }
    case IPPROTO_ICMP:
    case IPPROTO_IGMP:
    case IPPROTO_GRE:
    case IPPROTO_PIM:
      state_t->sport = 0;
      state_t->dport = 0;
      break;
    default:
      printk("IPFIRE: fill_net_table_fields (stateful connection): invalid "
             "protocol %d!\n",
             iph->protocol);
      return -1;
    }
    state_t->direction = flow->direction;
    if (flow->in) {
      strncpy(state_t->in_devname, flow->in->name, IFNAMSIZ);
      state_t->in_devname[IFNAMSIZ - 1] = '\0';
    }
    if (flow->out) {
      strncpy(state_t->out_devname, flow->out->name, IFNAMSIZ);
      state_t->out_devname[IFNAMSIZ - 1] = '\0';
    }
    return 0;
  }
  return -1;
}

int compare_state_entries(const struct state_table *s1,
                          const struct state_table *s2) {
  return (s1->saddr == s2->saddr) && (s1->daddr == s2->daddr) &&
         (s1->sport == s2->sport) && (s1->dport == s2->dport) &&
         (s1->direction == s2->direction) && (s1->protocol == s2->protocol);
}

/* IMPORTANT: Must be called under rcu_read_lock_bh() */
int lookup_state_table_n_update_timer(const struct state_table *stt) {
  struct state_table *statet;

#ifdef IPFI_USE_HASH
  __u32 key = get_state_hash(stt->saddr, stt->daddr, stt->sport, stt->dport,
                             stt->protocol);
  hash_for_each_possible_rcu(state_hashtable, statet, h.hnode, key) {
#else
  list_for_each_entry_rcu(statet, &state_list, h.lnode) {
#endif
    if (compare_state_entries(statet, stt) == 1) {
      if (state_hold_rcu(statet)) {
        update_timer_of_state_entry(statet);
        state_put(statet);
        return 1;
      }
      /* If we can't get a reference, the entry is dying.
       * Treat it as not found so we don't try to mod_timer on
       * a doomed entry. Only return 1 if we successfully held & updated */
    }
  }
  return 0;
}

int add_state_table_to_list(struct state_table *newtable) {
  unsigned int timeout;

  if (unlikely(READ_ONCE(we_are_exiting)))
    return -EBUSY;

  spin_lock_bh(&state_list_lock);

  if (unlikely(we_are_exiting)) {
    spin_unlock_bh(&state_list_lock);
    return -EBUSY;
  }

  timeout = get_timeout_by_state(newtable->protocol, newtable->state.state);
  ipfi_entry_init(&newtable->h, timeout, handle_keep_state_timeout);

  state_hold(newtable); /* container ref */

#ifdef IPFI_USE_HASH
  hash_add_rcu(state_hashtable, &newtable->h.hnode,
               get_state_hash(newtable->saddr, newtable->daddr, newtable->sport,
                              newtable->dport, newtable->protocol));
#else
  list_add_rcu(&newtable->h.lnode, &state_list);
#endif

  state_tables_counter++;
  table_id++;
  spin_unlock_bh(&state_list_lock);

  /* arm timer after releasing lock to reduce lock hold time */
  ipfi_entry_arm_timer(&newtable->h);
  return 0;
}

void handle_keep_state_timeout(struct timer_list *t) {
  struct state_table *st = timer_container_of(st, t, h.timer);
  struct ipfi_entry_head *h = &st->h;

  spin_lock_bh(&state_list_lock);
  ipfi_entry_remove(h, &state_tables_counter); /* puts internally if winner */
  spin_unlock_bh(&state_list_lock);
}

int free_state_tables(void) {
#ifdef IPFI_USE_HASH
  return ipfi_table_flush_hash(state_hashtable, ARRAY_SIZE(state_hashtable),
                               &state_list_lock, &state_tables_counter);
#else
  return ipfi_table_flush_all(&state_list, &state_list_lock,
                              &state_tables_counter);
#endif
}

inline void update_timer_of_state_entry(struct state_table *sttable) {
  ipfi_entry_update_timer(&sttable->h, sttable->protocol, sttable->state.state);
}

int init_machine(void) {
  state_cache = kmem_cache_create("ipfi_state", sizeof(struct state_table), 0,
                                  SLAB_HWCACHE_ALIGN, NULL);
  if (!state_cache) {
    IPFI_PRINTK("IPFIRE: failed to create state slab cache\n");
    return -ENOMEM;
  }
#ifdef IPFI_USE_HASH
  hash_init(state_hashtable);
#endif
  return 0;
}

void fini_machine(void) {
  int ret;
  ret = free_state_tables();
  IPFI_PRINTK("IPFIRE: state tables freed: %d.\n", ret);
  /* kmem_cache_destroy deferred to ipfire.c::fini() after
   * destroy_workqueue + rcu_barrier ensure all kfree callbacks ran. */
  might_sleep();
}
