/* filter/state/state_table.c: State table management for ipfire-wall */

#include "globals.h"
#include "ipfi.h"
#include "ipfi_machine.h"
#include "ipfi_state_machine.h"
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
  if (flow->in && entry->in_ifindex > 0 &&
      flow->in->ifindex != entry->in_ifindex) {
    return -1;
  }
  if (flow->out && entry->out_ifindex > 0 &&
      flow->out->ifindex != entry->out_ifindex) {
    return -1;
  }
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
  if (flow->in && entry->out_ifindex > 0 &&
      flow->in->ifindex != entry->out_ifindex) {
    return -1;
  }
  if (flow->out && entry->in_ifindex > 0 &&
      flow->out->ifindex != entry->in_ifindex) {
    return -1;
  }
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
    /* Lenient interface check: match if interface is identical OR if entry
     * index is UNSET (<=0) OR if flow interface is NULL */
    if ((!flow->in || flow->in->ifindex == entry->in_ifindex ||
         entry->in_ifindex <= 0) &&
        (!flow->out || flow->out->ifindex == entry->out_ifindex ||
         entry->out_ifindex <= 0)) {
      *reverse = 0;
      return 1;
    }
  }

  /* Reverse Match */
  if (iph->saddr == entry->daddr && iph->daddr == entry->saddr) {
    /* Cross-check interfaces: incoming response should match outgoing request
     * interface (and vice-versa) */
    if ((!flow->in || flow->in->ifindex == entry->out_ifindex ||
         entry->out_ifindex <= 0) &&
        (!flow->out || flow->out->ifindex == entry->in_ifindex ||
         entry->in_ifindex <= 0)) {
      *reverse = 1;
      return 1;
    }
  }
  return -1;
}

int skb_matches_state_table(const struct sk_buff *skb,
                            const struct state_table *entry, short *reverse,
                            const ipfi_flow *flow) {
  short tr_match = 0;
  const struct iphdr *iph = ip_hdr(skb);
  *reverse = -1; /* negative means no match */

  if (iph->protocol != entry->protocol)
    return -1;

  if (iph->protocol == IPPROTO_ICMP || iph->protocol == IPPROTO_IGMP ||
      iph->protocol == IPPROTO_GRE || iph->protocol == IPPROTO_PIM) {
    /* l2l3match now handles setting the reverse flag */
    return l2l3match(skb, entry, reverse, flow);
  }

  if ((tr_match = direct_state_match(skb, entry, flow)) > 0)
    *reverse = 0;
  else if ((tr_match = reverse_state_match(skb, entry, flow)) > 0)
    *reverse = 1;

  if (flow->direction == IPFI_FWD)
    return tr_match;

  if (flow->direction == entry->direction && *reverse == 0)
    return tr_match;
  else if (flow->direction != entry->direction && *reverse == 1)
    return tr_match;

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
      state_t->in_ifindex = flow->in->ifindex;
      strncpy(state_t->in_devname, flow->in->name, IFNAMSIZ);
    }
    if (flow->out) {
      state_t->out_ifindex = flow->out->ifindex;
      strncpy(state_t->out_devname, flow->out->name, IFNAMSIZ);
    }
    return 0;
  }
  return -1;
}

int compare_state_entries(const struct state_table *s1,
                          const struct state_table *s2) {
  return (s1->saddr == s2->saddr) && (s1->daddr == s2->daddr) &&
         (s1->sport == s2->sport) && (s1->dport == s2->dport) &&
         (s1->direction == s2->direction) && (s1->protocol == s2->protocol) &&
         (s1->in_ifindex == s2->in_ifindex) &&
         (s1->out_ifindex == s2->out_ifindex);
}

struct state_table *
lookup_state_table_n_update_timer(const struct state_table *stt, int lock) {
  int counter = 0;
  struct state_table *statet;
  u32 key = get_state_hash(stt->saddr, stt->daddr, stt->sport, stt->dport,
                           stt->protocol);

  if (lock == ACQUIRE_LOCK)
    rcu_read_lock_bh();

  hash_for_each_possible_rcu(state_hashtable, statet, hnode, key) {
    counter++;
    if (compare_state_entries(statet, stt) == 1) {
      update_timer_of_state_entry(statet);
      if (lock == ACQUIRE_LOCK)
        rcu_read_unlock_bh();
      return statet;
    }
  }
  if (lock == ACQUIRE_LOCK)
    rcu_read_unlock_bh();
  return NULL;
}

int add_state_table_to_list(struct state_table *newtable) {
  u32 key = get_state_hash(newtable->saddr, newtable->daddr, newtable->sport,
                           newtable->dport, newtable->protocol);

  spin_lock_bh(&state_list_lock);

  fill_timer_table_fields(newtable);
  add_timer(&newtable->timer_statelist);
  hash_add_rcu(state_hashtable, &newtable->hnode, key);

  state_tables_counter++;
  table_id++;
  spin_unlock_bh(&state_list_lock);
  return 0;
}

void free_state_work(struct work_struct *work) {
  struct state_table *st = container_of(work, struct state_table, cleanup_work);

  /* Safe to sync because we are in process context (workqueue worker) */
  timer_delete_sync(&st->timer_statelist);

  /* Readers are finished, timer is synced, now we can free after RCU grace. */
  call_rcu(&st->state_rcuh, free_state_entry_rcu_call);
}

void handle_keep_state_timeout(struct timer_list *t) {
  struct state_table *st = timer_container_of(st, t, timer_statelist);

  spin_lock_bh(&state_list_lock);
  if (hlist_unhashed(&st->hnode)) {
    spin_unlock_bh(&state_list_lock);
    return;
  }
  hash_del_rcu(&st->hnode);
  state_tables_counter--;
  spin_unlock_bh(&state_list_lock);

  if (ipfire_wq)
    queue_work(ipfire_wq, &st->cleanup_work);
}

void fill_timer_table_fields(struct state_table *state_t) {
  long int expi;
  expi = get_timeout_by_state(state_t->protocol, state_t->state.state);

  INIT_WORK(&state_t->cleanup_work, free_state_work);
  timer_setup(&state_t->timer_statelist, handle_keep_state_timeout, 0);
  state_t->timer_statelist.expires = jiffies + expi * HZ;
  state_t->last_timer_update = jiffies;
}

void update_ifindex_in_state_tables(const char *name, int new_index) {
  struct state_table *entry;
  int bkt;

  spin_lock_bh(&state_list_lock);
  hash_for_each(state_hashtable, bkt, entry, hnode) {
    if (entry->in_devname[0] && strcmp(entry->in_devname, name) == 0)
      entry->in_ifindex = new_index;
    if (entry->out_devname[0] && strcmp(entry->out_devname, name) == 0)
      entry->out_ifindex = new_index;
  }
  spin_unlock_bh(&state_list_lock);
}

static int ipfire_netdev_event(struct notifier_block *this, unsigned long event,
                               void *ptr) {
  struct net_device *dev = netdev_notifier_info_to_dev(ptr);

  if (event == NETDEV_UP || event == NETDEV_CHANGENAME ||
      event == NETDEV_REGISTER) {
    update_ifindex_in_rules(dev->name, dev->ifindex);
    update_ifindex_in_state_tables(dev->name, dev->ifindex);
  } else if (event == NETDEV_UNREGISTER) {
    update_ifindex_in_rules(dev->name, -1);
    update_ifindex_in_state_tables(dev->name, -1);
  }
  return NOTIFY_DONE;
}

static struct notifier_block ipfire_netdev_notifier = {
    .notifier_call = ipfire_netdev_event,
};

void register_ipfire_netdev_notifier(void) {
  register_netdevice_notifier(&ipfire_netdev_notifier);
}

void unregister_ipfire_netdev_notifier(void) {
  unregister_netdevice_notifier(&ipfire_netdev_notifier);
}

int free_state_tables(void) {
  struct state_table *tl;
  struct hlist_node *tmp;
  int counter = 0;
  int bkt;

  spin_lock_bh(&state_list_lock);
  hash_for_each_safe(state_hashtable, bkt, tmp, tl, hnode) {
    /* Removal under lock - this ensures we win against the timer handler. */
    hash_del_rcu(&tl->hnode);
    state_tables_counter--;

    /* Now queue work to safely timer_delete_sync and call_rcu
     * outside of the spinlock block.
     */
    if (ipfire_wq)
      queue_work(ipfire_wq, &tl->cleanup_work);
    counter++;
  }
  spin_unlock_bh(&state_list_lock);
  return counter;
}

int init_machine(void) {
  hash_init(state_hashtable);
  register_ipfire_netdev_notifier();
  return 0;
}

void fini_machine(void) {
  unregister_ipfire_netdev_notifier();
  int ret;
  ret = free_state_tables();
  IPFI_PRINTK("IPFIRE: state tables freed: %d.\n", ret);
  might_sleep();
  rcu_barrier();
}
