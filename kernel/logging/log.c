/* ipfi_log.c: a packet to be logged is really sent to userspace only if
 * it is not identical to a one previously sent. This reduces kernel/user
 * communication load */

/***************************************************************************
 *  Copyright  2005  Giacomo
 *  jacum@libero.it
 ****************************************************************************/

#include "globals.h"
#include "ipfi_log.h"
#include <linux/slab.h>
#include <linux/workqueue.h>

/*
 * LOCKING ARCHITECTURE & DESIGN:
 *
 * 1. UNIFIED LOCK ORDER:
 *    To prevent deadlocks, a strict hierarchy is established:
 *    loginfo_list_lock (Active List) -> loginfo_pool.lock (Memory Pool).
 *    This order is consistently followed in both the packet logging path
 *    and the periodic expiration worker.
 *
 * 2. SIMPLIFIED ALLOCATION:
 *    pool_alloc() only handles scanning of the static pool state array.
 *    It is protected by loginfo_pool.lock and does not nest any other locks.
 *
 * 3. SAFE RECYCLING:
 *    If the pool is completely full, add_packet_to_infolist() handles
 *    the recycling of the oldest entry (the tail of the active list).
 *    This ensures that unlinking and reallocation are atomic relative to
 *    active readers and follows the unified lock order.
 *
 * 4. PERFORMANCE:
 *    Duplicate detection (packet_not_seen) only scans the Active List.
 *    For N_active << MAX_LOG_ENTRIES, performance is O(N_active).
 */

/* The pool and its management */
static struct ipfire_loginfo_pool loginfo_pool;

/* Periodic cleanup */
static struct delayed_work loginfo_cleanup_work;

static void loginfo_cleanup_worker(struct work_struct *work) {
  if (unlikely(READ_ONCE(we_are_exiting)))
    return;

  loginfo_expire_entries();

  /* Reschedule cleanup if not exiting */
  if (likely(!we_are_exiting))
    queue_delayed_work(ipfire_wq, &loginfo_cleanup_work, HZ * 10);
}

static void loginfo_unlink_rcu(struct ipfire_loginfo *iplo) {
  list_del_rcu(&iplo->lnode);
  loginfo_entry_counter--;
}

static void pool_free_rcu_callback(struct rcu_head *rcu) {
  struct ipfire_loginfo *entry = container_of(rcu, struct ipfire_loginfo, rcuh);
  unsigned int idx;

  /* Pointer arithmetic to find index */
  idx = entry - loginfo_pool.entries;
  if (idx >= MAX_LOGINFO_ENTRIES)
    return;

  spin_lock_bh(&loginfo_pool.lock);
  loginfo_pool.state[idx] = ENTRY_FREE;
  spin_unlock_bh(&loginfo_pool.lock);
}

static void pool_free_immediate(struct ipfire_loginfo *entry) {
  unsigned int idx;
  if (!entry)
    return;

  idx = entry - loginfo_pool.entries;
  if (idx >= MAX_LOGINFO_ENTRIES)
    return;

  spin_lock_bh(&loginfo_pool.lock);
  loginfo_pool.state[idx] = ENTRY_FREE;
  spin_unlock_bh(&loginfo_pool.lock);
}

static void pool_free_rcu(struct ipfire_loginfo *entry) {
  if (!entry)
    return;

  call_rcu(&entry->rcuh, pool_free_rcu_callback);
}

/*
 * Scans the pool state array starting from head (round-robin)
 * for the first ENTRY_FREE slot. Returns NULL if pool is full.
 * In that case add_packet_to_infolist will recycle the oldest entry.
 */
static struct ipfire_loginfo *pool_alloc(void) {
  struct ipfire_loginfo *entry = NULL;
  unsigned int i, idx;
  unsigned int limit = max_loginfo_entries;

  if (limit > MAX_LOGINFO_ENTRIES)
    limit = MAX_LOGINFO_ENTRIES;

  spin_lock_bh(&loginfo_pool.lock);
  for (i = 0; i < limit; i++) {
    idx = (loginfo_pool.head + i) % limit;
    if (loginfo_pool.state[idx] == ENTRY_FREE) {
      entry = &loginfo_pool.entries[idx];
      loginfo_pool.state[idx] = ENTRY_ACTIVE;
      loginfo_pool.head = (idx + 1) % limit;
      break;
    }
  }
  spin_unlock_bh(&loginfo_pool.lock);

  return entry;
}

void loginfo_expire_entries(void) {
  struct ipfire_loginfo *iplo;
  struct ipfire_loginfo *tmp;
  unsigned long now = jiffies;
  unsigned long expiry = (unsigned long)loginfo_lifetime;

  if (expiry == 0)
    return;

  /* Follow Hierarchy: loginfo_list_lock -> pool_free (takes loginfo_pool.lock)
   */
  spin_lock_bh(&loginfo_list_lock);
  list_for_each_entry_safe(iplo, tmp, &active_logi_list, lnode) {
    if (time_after(now, READ_ONCE(iplo->timestamp) + HZ * expiry)) {
      loginfo_unlink_rcu(iplo);
      pool_free_rcu(iplo);
    }
  }
  spin_unlock_bh(&loginfo_list_lock);
}

inline void update_loginfo_timer(struct ipfire_loginfo *iplo) {
  WRITE_ONCE(iplo->timestamp, jiffies);
}

int build_ipfire_info_from_skb(const struct sk_buff *skb, const ipfi_flow *flow,
                               const struct response *res,
                               const struct info_flags *flags,
                               ipfire_info_t *dest) {
  if (copy_headers(skb, dest) < 0)
    return -1;

  dest->flags = *flags;
  dest->flags.direction = flow->direction;

  if (flow->in)
    strscpy(dest->netdevs.in_devname, flow->in->name, IFNAMSIZ);
  if (flow->out)
    strscpy(dest->netdevs.out_devname, flow->out->name, IFNAMSIZ);
  dest->response = *res;
  return 0;
}

inline int add_packet_to_infolist(const struct sk_buff *skb,
                                  const struct response *res,
                                  const ipfi_flow *flow,
                                  const struct info_flags *flags) {
  struct ipfire_loginfo *ipli;

  if (unlikely(READ_ONCE(we_are_exiting)))
    return -EBUSY;

  /*
   * Consistent locking order: loginfo_list_lock -> pool_alloc (takes pool lock)
   */
  spin_lock_bh(&loginfo_list_lock);

  ipli = pool_alloc();
  if (unlikely(!ipli)) {
    /* Potential "Apocalypse" scenario: pool is full.
     * We unlink the oldest entry to make space for FUTURE packets,
     * but we do NOT reuse the memory immediately to avoid RCU race.
     */
    if (!list_empty(&active_logi_list)) {
      struct ipfire_loginfo *oldest;
      oldest = list_last_entry(&active_logi_list, struct ipfire_loginfo, lnode);
      loginfo_unlink_rcu(oldest);
      pool_free_rcu(oldest);
    }
    /* Packet is dropped because we have no immediate free slot */
    spin_unlock_bh(&loginfo_list_lock);
    return -ENOMEM;
  }

  if (ipli) {
    memset(&ipli->info, 0, sizeof(ipli->info));
    if (build_ipfire_info_from_skb(skb, flow, res, flags, &ipli->info) < 0) {
      spin_unlock_bh(&loginfo_list_lock);
      pool_free_immediate(ipli);
      return -1;
    }
    WRITE_ONCE(ipli->timestamp, jiffies);

    if (unlikely(we_are_exiting)) {
      spin_unlock_bh(&loginfo_list_lock);
      pool_free_immediate(ipli);
      return -EBUSY;
    }

    list_add_rcu(&ipli->lnode, &active_logi_list);
    loginfo_entry_counter++;
  }
  spin_unlock_bh(&loginfo_list_lock);

  return ipli ? 0 : -ENOMEM;
}

inline int iph_compare(const struct iphdr *skb_iphdr, const ipfire_info_t *p2) {
  const struct ip_id *ip = &p2->packet.ip;
  return (skb_iphdr->saddr == ip->saddr) && (skb_iphdr->daddr == ip->daddr);
}

inline int tcph_compare(const struct tcphdr *tcph1, const ipfire_info_t *p2) {
  const struct tcphdr tcph2 = p2->packet.transport_header.tcphead;
  return (tcph1->source == tcph2.source) && (tcph1->dest == tcph2.dest) &&
         (tcph1->fin == tcph2.fin) && (tcph1->syn == tcph2.syn) &&
         (tcph1->ack == tcph2.ack) && (tcph1->urg == tcph2.urg) &&
         (tcph1->rst == tcph2.rst) && (tcph1->psh == tcph2.psh);
}

inline int udph_compare(const struct udphdr *udph1, const ipfire_info_t *p2) {
  struct udphdr udph2;
  udph2 = p2->packet.transport_header.udphead;
  return (udph1->source == udph2.source) && (udph1->dest == udph2.dest);
}

inline int icmph_compare(const struct icmphdr *ich1, const ipfire_info_t *p2) {
  struct icmphdr ich2;
  ich2 = p2->packet.transport_header.icmphead;
  return (ich1->type == ich2.type) && (ich1->code == ich2.code);
}

inline int igmph_compare(const struct igmphdr *igh1, const ipfire_info_t *p2) {
  struct igmphdr igh2;
  igh2 = p2->packet.transport_header.igmphead;
  return (igh1->type == igh2.type) && (igh1->code == igh2.code) &&
         (igh1->group == igh2.group);
}

int packet_matches_log_entry(const struct sk_buff *skb,
                             const struct response *res, const ipfi_flow *flow,
                             const struct info_flags *flags,
                             const ipfire_info_t *p2) {
  struct iphdr *iph = ip_hdr(skb);

  if (iph->protocol != p2->packet.ip.protocol) {
    return -1;
  }
  if (res->st.state != p2->response.st.state) {
    return -1;
  }
  if (flow->direction != p2->flags.direction || flags->nat != p2->flags.nat ||
      flags->snat != p2->flags.snat) {
    return -1;
  }

  if (res->verdict != p2->response.verdict) {
    return -1;
  }
  const char *in_name = flow->in ? flow->in->name : "";
  if (strncmp(in_name, p2->netdevs.in_devname, IFNAMSIZ) != 0) {
    return -1;
  }
  const char *out_name = flow->out ? flow->out->name : "";
  if (strncmp(out_name, p2->netdevs.out_devname, IFNAMSIZ) != 0) {
    return -1;
  }

  if (!iph_compare(iph, p2)) {
    return -1;
  }
  switch (iph->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    if (!tcph_compare(th, p2))
      return -1;
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
    if (!udph_compare(uh, p2))
      return -1;
    break;
  }
  case IPPROTO_ICMP: {
    struct icmphdr *ih = (struct icmphdr *)((void *)iph + iph->ihl * 4);
    if (!icmph_compare(ih, p2))
      return -1;
    break;
  }
  case IPPROTO_IGMP: {
    struct igmphdr *gh = (struct igmphdr *)((void *)iph + iph->ihl * 4);
    if (!igmph_compare(gh, p2))
      return -1;
    break;
  }
  case IPPROTO_GRE:
  case IPPROTO_PIM:
    /* comparison is limited to the checks above, no GRE header comparison is
     * done, no PIM info inspected */
    break;
  default:
    printk("IPFIRE: ipfi_log.c: packet_matches_log_entry(): unsupported "
           "protocol %d.\n",
           iph->protocol);
  }
  return 0;
}

inline int compare_loginfo_packets(const struct sk_buff *skb,
                                   const struct response *res,
                                   const ipfi_flow *flow,
                                   const struct info_flags *flags,
                                   const ipfire_info_t *packet2) {
  if (packet_matches_log_entry(skb, res, flow, flags, packet2) == 0)
    return 1;
  return 0;
}

static unsigned int old_loginfo_counter = 0;

inline int packet_not_seen(const struct sk_buff *skb,
                           const struct response *res, const ipfi_flow *flow,
                           const struct info_flags *flags, int chk_state) {
  struct ipfire_loginfo *loginfo;
  unsigned long now = jiffies;
  unsigned long expiry = (unsigned long)loginfo_lifetime;

  /* Short circuit */
  if (READ_ONCE(loginfo_entry_counter) == 0)
    return 1;

  rcu_read_lock_bh();
  /* Iterates ONLY over the active nodes */
  list_for_each_entry_rcu(loginfo, &active_logi_list, lnode) {
    /* Check for expiration if lifetime is set */
    if (expiry > 0 &&
        time_after(now, READ_ONCE(loginfo->timestamp) + HZ * expiry))
      continue;

    if (compare_loginfo_packets(skb, res, flow, flags, &loginfo->info)) {
      if (!chk_state ||
          (chk_state && (res->st.state == loginfo->info.response.st.state))) {
        /* Update timestamp on seen packet to slide the window */
        update_loginfo_timer(loginfo);
        rcu_read_unlock_bh();
        return 0;
      }
    }
  }
  rcu_read_unlock_bh();
  return 1;
}

int smart_log(const struct sk_buff *skb, const struct response *res,
              const ipfi_flow *flow, const struct info_flags *flags) {
  if (packet_not_seen(skb, res, flow, flags, 0)) {
    add_packet_to_infolist(skb, res, flow, flags);
    return 1;
  }
  return 0;
}

int smart_log_with_state_check(const struct sk_buff *skb,
                               const struct response *res,
                               const ipfi_flow *flow,
                               const struct info_flags *flags) {
  if (packet_not_seen(skb, res, flow, flags, 1)) {
    add_packet_to_infolist(skb, res, flow, flags);
    return 1;
  }
  return 0;
}

int init_log(void) {
  spin_lock_init(&loginfo_pool.lock);

  /* Initialize delayed work for periodic cleanup */
  INIT_DELAYED_WORK(&loginfo_cleanup_work, loginfo_cleanup_worker);
  if (ipfire_wq)
    queue_delayed_work(ipfire_wq, &loginfo_cleanup_work, HZ * 10);

  return 0;
}

void fini_log(void) {
  /* Cancel delayed work first */
  cancel_delayed_work_sync(&loginfo_cleanup_work);
  synchronize_rcu();
}
