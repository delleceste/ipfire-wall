/* ipfi_log.c: a packet to be logged is really sent to userspace only if
 * it is not identical to a one previously sent. This reduces kernel/user
 * communication load */

/***************************************************************************
 *  Copyright  2005  Giacomo
 *  jacum@libero.it
 ****************************************************************************/

#include "logging/log.h"
#include "globals.h"
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>

/*
 * DESIGN:
 *
 * Log entries follow the unified ipfi_entry lifecycle (table_lifecycle.c):
 *
 * 1. ALLOCATION: kmem_cache_alloc from a dedicated slab cache.
 * 2. LIFECYCLE:  Each entry has an individual timer that fires on
 *                expiration. On duplicate match, the timer is refreshed
 *                via ipfi_entry_update_timer() using IPPROTO_IPFI_LOG
 *                as sentinel protocol (throttled to 5s).
 * 3. REMOVAL:    Timer callback calls ipfi_entry_remove + ipfi_entry_put.
 *                ipfi_entry_put defers to workqueue -> timer_delete_sync
 *                -> call_rcu -> kfree (handles kmem_cache objects on 6.x).
 * 4. MAX CAP:    loginfo_entry_counter is checked before allocation.
 *                If at capacity, the oldest entry is evicted.
 */

/* ---- Dedicated slab cache for ipfire_loginfo entries ---- */
struct kmem_cache *loginfo_cache;

/**
 * get_log_hash - compute the hash bucket key for a log-deduplication entry.
 * @saddr:  IPv4 source address (network byte order)
 * @daddr:  IPv4 destination address (network byte order)
 * @proto:  IP protocol number (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, …)
 *
 * DESIGN: 3-TUPLE KEY vs. 5-TUPLE (state/NAT tables)
 * ---------------------------------------------------
 * State and NAT tables use the full 5-tuple (saddr, daddr, sport, dport,
 * proto) as their hash key.  This is correct for those tables because each
 * lookup must retrieve *one specific connection*: sport and dport together
 * make every flow unique, so the extra discrimination cuts collision chains
 * to near-zero even at high connection rates.
 *
 * The log-deduplication table has a different contract.  packet_not_seen()
 * never returns a single authoritative entry; it scans every entry in the
 * bucket and delegates the actual equality test to compare_loginfo_packets(),
 * which performs a full content comparison (IPs, ports, flags, direction,
 * rule ID, connection state).  The hash key here is only a *pre-filter*: its
 * job is to route the lookup to the right bucket quickly, not to identify the
 * entry by itself.
 *
 * Using a 3-tuple (saddr, daddr, proto) trades a slightly longer per-bucket
 * scan in exchange for two concrete advantages:
 *
 *   1. PROTOCOL GENERALITY.  ICMP, IGMP, GRE, PIM and other protocols carry
 *      no port numbers.  A 5-tuple key would require special-casing (zero-
 *      filling sport/dport) for each of these, and would still place all
 *      portless packets from the same host pair in the same bucket — so the
 *      extra complexity buys nothing.  The 3-tuple handles all protocols
 *      uniformly with a single code path.
 *
 *   2. LOG SEMANTIC.  A log entry represents "a class of recently-seen
 *      packets between this src/dst pair using this protocol".  Two TCP
 *      connections from the same client to the same server on different
 *      ephemeral ports are still the same logging event from a firewall
 *      visibility standpoint.  Grouping them in the same bucket is
 *      semantically appropriate; the full comparison in
 *      compare_loginfo_packets() still distinguishes them when needed.
 *
 * Note: with LOG_HASH_BITS=7 (128 buckets) and a typical loginfo table
 * that stays well below max_loginfo_entries, per-bucket chains are short
 * regardless.  A migration to a 5-tuple key (to mirror state/NAT) is a
 * valid future optimisation for very large deployments.
 */
static u32 get_log_hash(__be32 saddr, __be32 daddr, __u8 proto) {
  return jhash_3words((__u32)saddr, (__u32)daddr, proto, 0);
}

/* ---- Timer callback ---- */

static void handle_loginfo_timeout(struct timer_list *t) {
  struct ipfire_loginfo *li = timer_container_of(li, t, h.timer);
  struct ipfi_entry_head *h = &li->h;

  spin_lock_bh(&loginfo_list_lock);
  /*
   * BUG FIX: check REMOVED *before* list_del_rcu.
   *
   * loginfo_evict_oldest() runs under the same lock and does:
   *   list_del_rcu(lnode) → ipfi_entry_remove (sets REMOVED, puts internally)
   *
   * If eviction already ran, lnode.prev/next are LIST_POISON. Calling
   * list_del_rcu again writes to LIST_POISON address → memory corruption
   * → silent hard panic. Guard with the REMOVED bit which is set atomically
   * by ipfi_entry_remove under this same lock.
   */
  if (!test_bit(IPFI_ENTRY_REMOVED, &h->status))
    list_del_rcu(&h->lnode);
  ipfi_entry_remove(h, &loginfo_entry_counter); /* puts internally if winner */
  spin_unlock_bh(&loginfo_list_lock);
}

/* ---- Allocation ---- */

static struct ipfire_loginfo *loginfo_alloc(void) {
  struct ipfire_loginfo *li;

  li = kmem_cache_alloc(loginfo_cache, GFP_ATOMIC);
  if (!li)
    return NULL;

  memset(li, 0, sizeof(*li));
  ipfi_entry_init(&li->h, loginfo_lifetime, handle_loginfo_timeout);
  refcount_set(&li->h.refcnt, 1);

  return li;
}

/* ---- Eviction (when at capacity) ---- */

// must be called under spinlock_bh
static void loginfo_evict_oldest(void) {
  struct ipfire_loginfo *oldest;

  /* Caller MUST hold loginfo_list_lock */
  if (list_empty(&active_logi_list))
    return;

  /* lnode removal: ipfi_entry_remove removes hnode in hash mode, so we
   * remove lnode first to keep active_logi_list consistent before remove. */
  oldest = list_last_entry(&active_logi_list, struct ipfire_loginfo, h.lnode);
  list_del_rcu(&oldest->h.lnode);
  ipfi_entry_remove(&oldest->h, &loginfo_entry_counter); /* puts internally */

  /*
   * BUG FIX: cancel a pending timer before releasing ownership.
   *
   * timer_delete() cancels the timer if it is pending (not yet running).
   * If it is already running on another CPU, that CPU is blocked on
   * loginfo_list_lock (we hold it), so it will check REMOVED (now set)
   * when it gets the lock and will skip list_del_rcu; ipfi_entry_remove
   * will be a no-op (REMOVED bit already set → no put).
   *
   * timer_delete without _sync is safe here: we hold a BH-disabled
   * spinlock and timer_delete_sync would deadlock.
   */
  timer_delete(&oldest->h.timer);
}

/* ---- Header extraction helpers (moved from ipfire.c) ---- */

static void build_tcph_usermess(const struct tcphdr *tcph,
                                ipfire_info_t *ipfi_info) {
  /* we fill in our userspace information */
  memcpy(&(ipfi_info->packet.transport_header.tcphead), tcph,
         sizeof(struct tcphdr));
}

static void build_udph_usermess(const struct udphdr *p_udphead,
                                ipfire_info_t *ipfi_info) {
  memcpy(&(ipfi_info->packet.transport_header).udphead, p_udphead,
         sizeof(*p_udphead));
}

static void build_icmph_usermess(const struct icmphdr *p_icmphead,
                                 ipfire_info_t *ipfi_info) {
  memcpy(&(ipfi_info->packet.transport_header).icmphead, p_icmphead,
         sizeof(*p_icmphead));
}

static void build_igmph_usermess(const struct igmphdr *p_igmphead,
                                 ipfire_info_t *ipfi_info) {
  memcpy(&(ipfi_info->packet.transport_header).igmphead, p_igmphead,
         sizeof(*p_igmphead));
}

static int copy_headers(const struct sk_buff *skb, ipfire_info_t *fireinfo) {
  struct iphdr *iph;
  iph = ip_hdr(skb);
  /* protocol information */
  fireinfo->packet.ip.protocol = iph->protocol;
  fireinfo->packet.ip.saddr = iph->saddr;
  fireinfo->packet.ip.daddr = iph->daddr;
  /* internet header */
  /* tcp, udp icmp headers? */
  if (iph->protocol == IPPROTO_TCP)
    build_tcph_usermess((struct tcphdr *)((void *)iph + iph->ihl * 4),
                        fireinfo);
  else if (iph->protocol == IPPROTO_UDP)
    build_udph_usermess((struct udphdr *)((void *)iph + iph->ihl * 4),
                        fireinfo);
  else if (iph->protocol == IPPROTO_ICMP)
    build_icmph_usermess((struct icmphdr *)((void *)iph + iph->ihl * 4),
                         fireinfo);
  else if (iph->protocol == IPPROTO_IGMP)
    build_igmph_usermess((struct igmphdr *)((void *)iph + iph->ihl * 4),
                         fireinfo); /* since 0.98.7 */
  else {
    /* Unknown protocol: allow logging but skip transport header details. */
    return 0;
  }
  return 0;
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

  ipli = loginfo_alloc();
  if (unlikely(!ipli))
    return -ENOMEM;

  if (build_ipfire_info_from_skb(skb, flow, res, flags, &ipli->info) < 0) {
    ipfi_entry_put(&ipli->h);
    return -1;
  }

  spin_lock_bh(&loginfo_list_lock);

  if (unlikely(we_are_exiting)) {
    spin_unlock_bh(&loginfo_list_lock);
    ipfi_entry_put(&ipli->h);
    return -EBUSY;
  }

  /* Enforce max entries cap */
  if (READ_ONCE(loginfo_entry_counter) >= max_loginfo_entries) {
    loginfo_evict_oldest();
  }

  /* Always add to active list for LRU ordering (eviction uses list_last_entry)
   */
  list_add_rcu(&ipli->h.lnode, &active_logi_list);
  {
    u32 key =
        get_log_hash(ipli->info.packet.ip.saddr, ipli->info.packet.ip.daddr,
                     ipli->info.packet.ip.protocol);
    hash_add_rcu(loginfo_hashtable, &ipli->h.hnode, key);
  }
  loginfo_entry_counter++;

  /*
   * BUG FIX: hold an extra reference across the lock → arm-timer gap.
   *
   * After spin_unlock_bh(), another CPU can see the entry in the list,
   * call loginfo_evict_oldest(), drop refcount to 0, and queue the
   * cleanup work which eventually calls kfree(). If the workqueue runs
   * before ipfi_entry_arm_timer() below, mod_timer() fires on freed
   * memory (UAF). The extra hold keeps refcount ≥ 2 until we arm the
   * timer; the matching put releases it.
   */
  ipfi_entry_hold(&ipli->h);
  spin_unlock_bh(&loginfo_list_lock);

  /* Arm the timer AFTER the entry is on the list */
  ipfi_entry_arm_timer(&ipli->h);

  /* Release the temporary arm-guard hold */
  ipfi_entry_put(&ipli->h);

  return 0;
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
    IPFI_MODERATE_PRINTK(
        PRINT_PROTO_UNSUPPORTED,
        "IPFIRE: ipfi_log.c: packet_matches_log_entry(): unsupported "
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

inline int packet_not_seen(const struct sk_buff *skb,
                           const struct response *res, const ipfi_flow *flow,
                           const struct info_flags *flags, int chk_state) {
  struct ipfire_loginfo *loginfo;

  /* Short circuit */
  if (READ_ONCE(loginfo_entry_counter) == 0)
    return 1;

  rcu_read_lock_bh();
  {
    struct iphdr *iph = ip_hdr(skb);
    u32 key = get_log_hash(iph->saddr, iph->daddr, iph->protocol);
    hash_for_each_possible_rcu(loginfo_hashtable, loginfo, h.hnode, key) {
      if (compare_loginfo_packets(skb, res, flow, flags, &loginfo->info)) {
        if (!chk_state ||
            (chk_state && (res->st.state == loginfo->info.response.st.state))) {
          ipfi_entry_update_timer(&loginfo->h, IPPROTO_IPFI_LOG, 0);
          rcu_read_unlock_bh();
          return 0;
        }
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
  loginfo_cache =
      kmem_cache_create("ipfi_loginfo", sizeof(struct ipfire_loginfo), 0,
                        SLAB_HWCACHE_ALIGN, NULL);
  if (!loginfo_cache) {
    IPFI_PRINTK("IPFIRE: failed to create loginfo slab cache\n");
    return -ENOMEM;
  }
  return 0;
}

void fini_log(void) {
  /* Flush all active entries using the unified lifecycle.
   *
   * BUG FIX (hash mode): ipfi_table_flush_hash() only unlinks hnode;
   * it leaves lnode dangling in active_logi_list → UAF on any further
   * traversal. loginfo entries maintain BOTH lnode and hnode, so we
   * always drain via active_logi_list (lnode-based), which also covers
   * both links. In hash mode, entries are set REMOVED so timer callbacks
   * become no-ops after this.
   */
  ipfi_table_flush_all(&active_logi_list, &loginfo_list_lock,
                       &loginfo_entry_counter);
  /* kmem_cache_destroy deferred to ipfire.c::fini() after
   * destroy_workqueue + rcu_barrier ensure all kfree callbacks ran. */
}
