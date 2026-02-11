/* ipfi_log.c: a packet to be logged is really sent to userspace only if
 * it is not identical to a one previously sent. This reduces kernel/user
 * communication load */

/***************************************************************************
 *  Copyright  2005  Giacomo
 *  jacum@libero.it
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

/* see ipfi.c for details */

#include "globals.h"
#include "ipfi_log.h"

void free_entry_rcu_call(struct rcu_head *head) {
  struct ipfire_loginfo *ipfl = container_of(head, struct ipfire_loginfo, rcuh);
  kfree(ipfl);
}

/* see get_state_hash in state_table.c for details */
u32 get_loginfo_hash(const struct sk_buff *skb, const struct response *res,
                     const ipfi_flow *flow, const struct info_flags *flags) {
  struct iphdr *iph = ip_hdr(skb);
  u32 saddr = iph->saddr;
  u32 daddr = iph->daddr;
  u16 sport = 0, dport = 0;
  u8 proto = iph->protocol;

  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
    sport = *((u16 *)((void *)iph + iph->ihl * 4));
    dport = *((u16 *)((void *)iph + iph->ihl * 4 + 2));
  } else if (proto == IPPROTO_ICMP) {
    struct icmphdr *ih = (struct icmphdr *)((void *)iph + iph->ihl * 4);
    sport = (__u16)ih->type;
    dport = (__u16)ih->code;
  }

  return jhash_3words(saddr ^ daddr, ((u32)sport << 16) | dport,
                      ((u32)proto << 16) | flow->direction, 0);
}

void free_loginfo_work(struct work_struct *work) {
  struct ipfire_loginfo *ipfilog =
      container_of(work, struct ipfire_loginfo, cleanup_work);

  /* Safe to sync because we are in process context (workqueue worker) */
  timer_delete_sync(&ipfilog->timer_loginfo);

  /* Readers are finished, timer is synced, now we can free after RCU grace. */
  call_rcu(&ipfilog->rcuh, free_entry_rcu_call);
}

void handle_loginfo_entry_timeout(struct timer_list *t) {
  struct ipfire_loginfo *ipfilog =
      timer_container_of(ipfilog, t, timer_loginfo);

  spin_lock_bh(&loginfo_list_lock);
  if (hlist_unhashed(&ipfilog->hnode)) {
    spin_unlock_bh(&loginfo_list_lock);
    return;
  }
  hash_del_rcu(&ipfilog->hnode);
  loginfo_entry_counter--;
  spin_unlock_bh(&loginfo_list_lock);

  if (ipfire_wq)
    queue_work(ipfire_wq, &ipfilog->cleanup_work);
}

/* updates timer of a loginfo entry, when a packet is already
 * present il packlist list. Invoked by packet_not_seen() when
 * it has seen this packet in list.
 * This is called with read lock held and bh interrupts disabled.
 * So timer expiring should not interfere.
 */
inline void update_loginfo_timer(struct ipfire_loginfo *iplo) {
  /* kernel/timer.c says:
   * Note that if there are multiple unserialized concurrent users of the
   * same timer, then modify_timer() is the only safe way to modify the timeout,
   * since add_timer() cannot modify an already running timer...
   * So a read_lock_rcu() is enough, since modify_timer manages concurrent
   * timer users.
   */
  mod_timer(&iplo->timer_loginfo, jiffies + HZ * loginfo_lifetime);
}

inline void fill_timer_loginfo_entry(struct ipfire_loginfo *ipfilog) {
  INIT_WORK(&ipfilog->cleanup_work, free_loginfo_work);
  timer_setup(&ipfilog->timer_loginfo, handle_loginfo_entry_timeout, 0);
  ipfilog->timer_loginfo.expires = jiffies + HZ * loginfo_lifetime;
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

struct ipfire_loginfo *loginfo_new(const struct sk_buff *skb,
                                   const struct response *res,
                                   const ipfi_flow *flow,
                                   const struct info_flags *flags) {
  struct ipfire_loginfo *ipli = (struct ipfire_loginfo *)kmalloc(
      sizeof(struct ipfire_loginfo), GFP_ATOMIC);
  if (ipli) {
    memset(ipli, 0, sizeof(*ipli));
    ipfire_info_t *iit = &ipli->info;
    if (build_ipfire_info_from_skb(skb, flow, res, flags, iit) < 0) {
      kfree(iit);
    }
  }
  return ipli;
}

/* copies a packet to info field of ipfire_loginfo, then initializes
 * timers and adds to packlist list */
inline int add_packet_to_infolist(const struct sk_buff *skb,
                                  const struct response *res,
                                  const ipfi_flow *flow,
                                  const struct info_flags *flags) {
  if (unlikely(READ_ONCE(we_are_exiting)))
    return -EBUSY;

  struct ipfire_loginfo *ipli = loginfo_new(skb, res, flow, flags);
  if (ipli) {
    u32 hash = get_loginfo_hash(skb, res, flow, flags);
    spin_lock_bh(&loginfo_list_lock);

    if (unlikely(we_are_exiting)) {
      spin_unlock_bh(&loginfo_list_lock);
      kfree(ipli);
      return -EBUSY;
    }
    fill_timer_loginfo_entry(ipli);
    /* add timer */
    add_timer(&ipli->timer_loginfo);
    /* add entry to root table */
    hash_add_rcu(loginfo_hashtable, &ipli->hnode, hash);
    loginfo_entry_counter++;
    spin_unlock_bh(&loginfo_list_lock);
    return 0;
  }
  return -1;
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
  /*&
  (ich1->un.echo.id == ich2->un.echo.id) &&
  (ich1->un.echo.sequence == ich2->un.echo.sequence) &&
  (ich1->un.frag.mtu == ich2->un.frag.mtu) */
}

inline int igmph_compare(const struct igmphdr *igh1, const ipfire_info_t *p2) {
  struct igmphdr igh2;
  igh2 = p2->packet.transport_header.igmphead;
  return (igh1->type == igh2.type) && (igh1->code == igh2.code) &&
         (igh1->group == igh2.group);
}

/* returns -1 if packets are different, 0 if equal.
 * Called by compare_loginfo_packets(), which in turn is called by
 * packet_not_seen(), while a read_lock_bh is held and p1 and p2 being
 * kmallocated areas.
 */
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

  /* Compare responses */
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

  /* ip header fields */
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
    printk("IPFIRE: ipfi_log.c: comp_pack(): unsupported protocol %d.\n",
           iph->protocol);
  }
  return 0;
}

/* compares two packets in the shape of ipfire_info_t. All
 * fields are compared, except packet_id, the last one.
 * Called by packet_not_seen(), it executes inside a read_lock
 * and packet1 and packet2 live in a kmallocated area.
 */
inline int compare_loginfo_packets(const struct sk_buff *skb,
                                   const struct response *res,
                                   const ipfi_flow *flow,
                                   const struct info_flags *flags,
                                   const ipfire_info_t *packet2) {
  if (packet_matches_log_entry(skb, res, flow, flags, packet2) == 0)
    return 1; /* success in comparison */
  /* comp_pack has returned -1, that is failure */
  return 0;
}

/* returns 1 if skb has never been seen,
 * 0 otherwise. If a skb is already in list,
 * its timer is updated.
 * We do not update the timer, since every timeout
 * seconds we want the skb to be re printed.
 */
inline int packet_not_seen(const struct sk_buff *skb,
                           const struct response *res, const ipfi_flow *flow,
                           const struct info_flags *flags, int chk_state) {
  struct ipfire_loginfo *loginfo;
  u32 hash = get_loginfo_hash(skb, res, flow, flags);

  rcu_read_lock_bh();
  hash_for_each_possible_rcu(loginfo_hashtable, loginfo, hnode, hash) {
    if (compare_loginfo_packets(skb, res, flow, flags, &loginfo->info)) {
      if (!chk_state ||
          (chk_state && (res->st.state == loginfo->info.response.st.state))) {
        rcu_read_unlock_bh();
        return 0; /* packet in list: already seen */
      }
    }
  }
  rcu_read_unlock_bh();
  return 1;
}

/* Invoked when loglevel is 1, this function compares
 * packet with all other packets seen. If a packet has
 * already been seen, it's not logged and nothing is
 * done, if it is the first packet, it is added to list of seen
 * packets and 1 is return, as to indicate that packet
 * must be logged to userspace. This "smart logging"
 * reduces load in userspace communication via netlink
 * socket. Must return 0 if match is found.
 */
int smart_log(const struct sk_buff *skb, const struct response *res,
              const ipfi_flow *flow, const struct info_flags *flags) {
  if (packet_not_seen(skb, res, flow, flags, 0)) {
    add_packet_to_infolist(skb, res, flow, flags);
    return 1;
  }
  return 0;
}

/* This is registered when the log level is MART_LOG_WITH_STATE_CHECK.
 * Applies all the same procedures as the one above, but also
 * does checks against the state.
 */
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

int free_loginfo_entries(void) {
  struct hlist_node *tmp;
  struct ipfire_loginfo *ilo;
  int counter = 0;
  int bkt;
  spin_lock_bh(&loginfo_list_lock);
  hash_for_each_safe(loginfo_hashtable, bkt, tmp, ilo, hnode) {
    /* Removal under lock - this ensures we win against the timer handler. */
    hash_del_rcu(&ilo->hnode);
    loginfo_entry_counter--;

    /* Now queue work to safely timer_delete_sync and call_rcu
     * outside of the spinlock block.
     */
    if (ipfire_wq)
      queue_work(ipfire_wq, &ilo->cleanup_work);
    counter++;
  }
  spin_unlock_bh(&loginfo_list_lock);
  return counter;
}

// static int __init init(void)
int init_log(void) {
  /* initialize loginfo hashtable */
  hash_init(loginfo_hashtable);
  return 0;
}

// static void __exit fini(void)
void fini_log(void) {
  int ret;
  ret = free_loginfo_entries();
  /* might_sleep(): see linux kernel sources/include/linux.h:
   * this is a macro which will print a stack trace if it is executed in an
   * atomic context (spinlock, irq-handler, ...).
   *
   * This is a useful debugging help to be able to catch problems early and not
   * be biten later when the calling function happens to sleep when it is not
   * supposed to.
   */

  /* See the important comments on ipfi_machine.c fini() */
  might_sleep();
}

MODULE_DESCRIPTION("IPFIRE smart logging module");
MODULE_AUTHOR("Giacomo S. <jacum@libero.it>");
MODULE_LICENSE("GPL");
