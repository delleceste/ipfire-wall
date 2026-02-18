/* ipfi_log.c: a packet to be logged is really sent to userspace only if
 * it is not identical to a one previously sent. This reduces kernel/user
 * communication load */

/***************************************************************************
 *  Copyright  2005  Giacomo
 *  jacum@libero.it
 ****************************************************************************/

#include "globals.h"
#include "logging/log.h"
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

/* Dedicated slab cache for ipfire_loginfo entries */
struct kmem_cache *loginfo_cache;

/* ---- Timer callback ---- */

static void handle_loginfo_timeout(struct timer_list *t) {
  struct ipfire_loginfo *li = timer_container_of(li, t, h.timer);
  struct ipfi_entry_head *h = &li->h;

  spin_lock_bh(&loginfo_list_lock);
  ipfi_entry_remove(h, &loginfo_entry_counter);
  spin_unlock_bh(&loginfo_list_lock);

  ipfi_entry_put(h);
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

static void loginfo_evict_oldest(void) {
  struct ipfire_loginfo *oldest;

  /* Caller MUST hold loginfo_list_lock */
  if (list_empty(&active_logi_list))
    return;

  oldest = list_last_entry(&active_logi_list, struct ipfire_loginfo, h.lnode);
  ipfi_entry_remove(&oldest->h, &loginfo_entry_counter);
  ipfi_entry_put(&oldest->h);
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
  if (READ_ONCE(loginfo_entry_counter) >= max_loginfo_entries)
    loginfo_evict_oldest();

  list_add_rcu(&ipli->h.lnode, &active_logi_list);
  loginfo_entry_counter++;
  spin_unlock_bh(&loginfo_list_lock);

  /* Arm the timer AFTER the entry is on the list */
  ipfi_entry_arm_timer(&ipli->h);

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

inline int packet_not_seen(const struct sk_buff *skb,
                           const struct response *res, const ipfi_flow *flow,
                           const struct info_flags *flags, int chk_state) {
  struct ipfire_loginfo *loginfo;

  /* Short circuit */
  if (READ_ONCE(loginfo_entry_counter) == 0)
    return 1;

  rcu_read_lock_bh();
  list_for_each_entry_rcu(loginfo, &active_logi_list, h.lnode) {
    if (compare_loginfo_packets(skb, res, flow, flags, &loginfo->info)) {
      if (!chk_state ||
          (chk_state && (res->st.state == loginfo->info.response.st.state))) {
        /* Refresh timer — extends the suppression window.
         * IPPROTO_IPFI_LOG is a sentinel that makes
         * get_timeout_by_state() return loginfo_lifetime. */
        ipfi_entry_update_timer(&loginfo->h, IPPROTO_IPFI_LOG, 0);
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
  loginfo_cache = kmem_cache_create("ipfi_loginfo",
                                    sizeof(struct ipfire_loginfo),
                                    0, SLAB_HWCACHE_ALIGN, NULL);
  if (!loginfo_cache) {
    IPFI_PRINTK("IPFIRE: failed to create loginfo slab cache\n");
    return -ENOMEM;
  }
  return 0;
}

void fini_log(void) {
  /* Flush all active entries using the unified lifecycle */
  ipfi_table_flush_all(&active_logi_list, &loginfo_list_lock,
                       &loginfo_entry_counter);
  /* kmem_cache_destroy deferred to ipfire.c::fini() after
   * destroy_workqueue + rcu_barrier ensure all kfree callbacks ran. */
}
