/* filter/state/state_table.c: State table management for ipfire-wall */

#include "globals.h"
#include "ipfi.h"
#include "ipfi_machine.h"
#include "ipfi_state_machine.h"
#include <linux/bitops.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>

void update_timer_of_state_entry(struct state_table *sttable);

/*jhash_3words is an optimized implementation of Bob Jenkins' lookup3 hash
 algorithm, specifically designed to hash exactly three 32-bit words into a
 single 32-bit hash value. In the Linux kernel, it is defined in <linux/jhash.h>
 and is the standard way to hash network flow identifiers (like IP addresses and
 ports) because it is extremely fast and provides excellent bit distribution.
*/
/* TODO: restore hash
__u32 get_state_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
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
*/

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

    /* Lenient check: Only mismatch if flow has interface AND entry has specific
   * interface AND they differ */
    /* Lenient check: Only mismatch if flow has interface AND entry has specific
   * interface AND they differ */
    /*
  if (flow->in && entry->in_devname[0] &&
      strncmp(flow->in->name, entry->in_devname, IFNAMSIZ) != 0) {
    return -1;
  }
  if (flow->out && entry->out_devname[0] &&
      strncmp(flow->out->name, entry->out_devname, IFNAMSIZ) != 0) {
    return -1;
  }
  */
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
    /* Lenient check: Reverse direction swaps in/out */
    /*
  if (flow->in && entry->out_devname[0] &&
      strncmp(flow->in->name, entry->out_devname, IFNAMSIZ) != 0) {
    return -1;
  }
  if (flow->out && entry->in_devname[0] &&
      strncmp(flow->out->name, entry->in_devname, IFNAMSIZ) != 0) {
    return -1;
  }
  */
    return 1;
}

inline int l2l3match(const struct sk_buff *skb, const struct state_table *entry,
                     short *reverse, const ipfi_flow *flow) {
    const struct iphdr *iph = ip_hdr(skb);

    /* Protocol safety: Ensure packet protocol matches entry protocol */
    if (iph->protocol != entry->protocol)
        return -1;
    /* Direct Match */
    if (iph->saddr == entry->saddr && iph->daddr == entry->daddr) {
        /* Lenient interface check */
        /*
    if ((!flow->in || strncmp(flow->in->name, entry->in_devname, IFNAMSIZ) == 0
    || entry->in_devname[0] == '\0') &&
        (!flow->out || strncmp(flow->out->name, entry->out_devname, IFNAMSIZ) ==
    0 || entry->out_devname[0] == '\0')) {
    */
        *reverse = 0;
        return 1;
        // }
    }

    /* Reverse Match */
    if (iph->saddr == entry->daddr && iph->daddr == entry->saddr) {
        /* Cross-check interfaces: incoming response should match outgoing request
     * interface (and vice-versa) */
        /*
    if ((!flow->in || strncmp(flow->in->name, entry->out_devname, IFNAMSIZ) == 0
    || entry->out_devname[0] == '\0') &&
        (!flow->out || strncmp(flow->out->name, entry->in_devname, IFNAMSIZ) ==
    0 || entry->in_devname[0] == '\0')) {
    */
        *reverse = 1;
        return 1;
        // }
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

    *reverse = -1; /* default: no match */

    /* Protocol must match */
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
        return -1; /* no tuple match at all */
    }

    /* ----------------------------
   * Direction validation
   * ---------------------------- */

    /* FWD flows: only match FWD entries */
    if (entry->direction == IPFI_FWD && flow->direction == IPFI_FWD) {
        return tr_match;
    }

    /* ----------------------------
   * DIRECT MATCH HANDLING
   * ---------------------------- */
    if (*reverse == 0) {

        /*
     * Standard direct match:
     * same direction as state creation.
     */
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
     * Legitimate reply case:
     * OUTPUT entry -> INPUT reply
     */
        if (entry->direction == IPFI_OUTPUT && flow->direction == IPFI_INPUT)
            return tr_match;

        /*
     * Legitimate reply case:
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

void free_state_entry_rcu_call(struct rcu_head *head) {
    struct state_table *ipst = NULL;
    if (head == NULL) {
        IPFI_PRINTK("Callback: head is null.\n");
        return;
    }
    ipst = container_of(head, struct state_table, state_rcuh);
    if (ipst != NULL) {
        kfree(ipst);
    }
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
        case IPPROTO_ICMP: {
            state_t->sport = 0;
            state_t->dport = 0;
            break;
        }
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
            break;
        }
        state_t->direction = flow->direction;
        state_t->protocol = iph->protocol;
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
    /* ifindex comparison removed */
    // (s1->in_ifindex == s2->in_ifindex) &&
    // (s1->out_ifindex == s2->out_ifindex);
}

/* IMPORTANT: Must be called under rcu_read_lock_bh()
 *
 */
int lookup_state_table_n_update_timer(const struct state_table *stt) {
    struct state_table *statet;
    list_for_each_entry_rcu(statet, &state_list, lnode) {
        if (compare_state_entries(statet, stt) == 1) {
            update_timer_of_state_entry(statet);
            return 1;
        }
    }
    return 0;
}

int add_state_table_to_list(struct state_table *newtable) {
    if (unlikely(READ_ONCE(we_are_exiting))) {
        return -EBUSY;
    }

    /* TODO: restore hash
  u32 key = get_state_hash(newtable->saddr, newtable->daddr, newtable->sport,
                           newtable->dport, newtable->protocol);
  */

    spin_lock_bh(&state_list_lock);

    if (unlikely(we_are_exiting)) {
        spin_unlock_bh(&state_list_lock);
        return -EBUSY;
    }

    fill_timer_table_fields(newtable);
    state_hold(newtable);
    list_add_rcu(&newtable->lnode, &state_list);
    state_tables_counter++;
    table_id++;
    spin_unlock_bh(&state_list_lock);

    /* arm timer after releasing lock to reduce lock hold time */
    add_timer(&newtable->timer_statelist);
    return 0;
}

static void free_state_work(struct work_struct *work) {
    struct state_table *st = container_of(work, struct state_table, cleanup_work);
    /* Wait for any RCU readers that might still be in update_timer_of_state_entry()
   * to finish. This guarantees no one can rearm the timer after we delete it.
   */
    synchronize_rcu();
    /* Safe to synchronously delete the timer now; we are in process context. */
    timer_delete_sync(&st->timer_statelist);
    /* Now free memory — no RCU readers can touch the object (we synchronized). */
    kfree(st);
}

void handle_keep_state_timeout(struct timer_list *t) {
    struct state_table *st = timer_container_of(st, t, timer_statelist);

    spin_lock_bh(&state_list_lock);
    /* TODO: restore hash
  if (hlist_unhashed(&st->hnode)) {
    spin_unlock_bh(&state_list_lock);
    return;
  }
  hash_del_rcu(&st->hnode);
  */
    list_del_rcu(&st->lnode);
    set_bit(IPFI_ST_REMOVED, &st->status);
    state_tables_counter--;
    spin_unlock_bh(&state_list_lock);

    state_put(st);
}

void fill_timer_table_fields(struct state_table *state_t) {
    long int expi;
    expi = get_timeout_by_state(state_t->protocol, state_t->state.state);

    INIT_WORK(&state_t->cleanup_work, free_state_work);
    timer_setup(&state_t->timer_statelist, handle_keep_state_timeout, 0);
    state_t->timer_statelist.expires = jiffies + expi * HZ;
    state_t->status = 0;
    state_t->last_timer_update = jiffies;
}

/* update_ifindex_in_state_tables removed */

/* ipfire_netdev_event removed */

/* ipfire_netdev_notifier removed */

void register_ipfire_netdev_notifier(void) {
    /* No-op */
    // register_netdevice_notifier(&ipfire_netdev_notifier);
}

void unregister_ipfire_netdev_notifier(void) {
    /* No-op */
    // unregister_netdevice_notifier(&ipfire_netdev_notifier);
}

int free_state_tables(void) {
    struct state_table *tl;
    struct state_table *tmp;
    int counter = 0;
    spin_lock_bh(&state_list_lock);
    list_for_each_entry_safe(tl, tmp, &state_list, lnode) {
        list_del_rcu(&tl->lnode);
        set_bit(IPFI_ST_REMOVED, &tl->status);
        state_tables_counter--;
        counter++;

        state_put(tl);
    }
    spin_unlock_bh(&state_list_lock);
    return counter;
}

inline void update_timer_of_state_entry(struct state_table *sttable) {
    unsigned int timeout;
    if (unlikely(test_bit(IPFI_ST_REMOVED, &sttable->status)))
        return;
    timeout = get_timeout_by_state(sttable->protocol, sttable->state.state);
    /* Use READ_ONCE/WRITE_ONCE for last_timer_update to avoid tearing */
    if (time_after(jiffies, READ_ONCE(sttable->last_timer_update) + (5 * HZ))) {
        /* Double-check REMOVED after computing condition to avoid TOCTOU as much as possible */
        if (unlikely(test_bit(IPFI_ST_REMOVED, &sttable->status)))
            return;

        mod_timer(&sttable->timer_statelist, jiffies + HZ * timeout);
        WRITE_ONCE(sttable->last_timer_update, jiffies);
    }
}

int init_machine(void) {
    /* TODO: restore hash
  hash_init(state_hashtable);
  */
    register_ipfire_netdev_notifier();
    return 0;
}

void fini_machine(void) {
    unregister_ipfire_netdev_notifier();
    int ret;
    ret = free_state_tables();
    IPFI_PRINTK("IPFIRE: state tables freed: %d.\n", ret);
    might_sleep();
}
