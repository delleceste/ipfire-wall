/* nat/snat/snat.c: Source NAT logic for ipfire-wall */

#include "globals.h"
#include "ipfi.h"
#include "ipfi_machine.h"
#include "ipfi_netl.h"
#include "ipfi_state_machine.h"
#include "ipfi_translation.h"
#include "message_builder.h"
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/rcupdate.h> // Added
#include <linux/skbuff.h>
#include <linux/slab.h>   // Added
#include <linux/string.h> // Added
#include <linux/tcp.h>
#include <linux/timer.h> // Added
#include <linux/udp.h>

int snat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                     struct response *resp, struct info_flags *flags) {
  ipfire_rule *snatrule;
  struct snatted_table *snt;

  rcu_read_lock_bh();
  list_for_each_entry_rcu(snatrule, &translation_post.list, list) {
    if (translation_rule_match(skb, flow, flags, snatrule) > 0) {
      if ((snt = add_snatted_entry(skb, flow, resp, flags, snatrule)) != NULL) {
        int status = snat_packet(skb, snt);
        rcu_read_unlock_bh();
        return status;
      }
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

struct snatted_table *add_snatted_entry(const struct sk_buff *skb,
                                        const ipfi_flow *flow,
                                        struct response *resp,
                                        struct info_flags *flags,
                                        const ipfire_rule *snat_rule) {
  struct snatted_table *snatted_entry;
  struct snatted_table lookup_entry;

  if (unlikely(READ_ONCE(we_are_exiting)))
    return NULL;

  fill_snat_entry_net_fields(&lookup_entry, skb, flow, resp, flags, snat_rule);

  if ((snatted_entry = lookup_snatted_table_n_update_timer(
           &lookup_entry, skb, flow, resp, flags)) != NULL) {
    return snatted_entry;
  }

  if (snatted_entry_counter == fwopts.max_nat_entries) {
    int err;
    struct response warn_resp = *resp;
    struct info_flags warn_flags = *flags;
    warn_flags.nat_max_entries = 1;
    struct sk_buff *skb_to_user =
        build_info_t_nlmsg(skb, flow, &warn_resp, &warn_flags, &err);
    if (skb_to_user)
      skb_send_to_user(skb_to_user, LISTENER_DATA);
    return NULL;
  }

  snatted_entry = kmalloc(sizeof(struct snatted_table), GFP_ATOMIC);
  if (!snatted_entry)
    return NULL;

  *snatted_entry = lookup_entry;
  snatted_entry->state = state_machine(skb, snatted_entry->state, 0);
  spin_lock_bh(&snat_list_lock);
  if (unlikely(we_are_exiting)) {
    spin_unlock_bh(&snat_list_lock);
    kfree(snatted_entry);
    return NULL;
  }
  fill_timer_snat_entry(snatted_entry);
  add_timer(&snatted_entry->timer_snattedlist);
  /* TODO: restore hash
  hash_add_rcu(snat_hashtable, &snatted_entry->hnode,
               get_snat_hash(snatted_entry->new_saddr, snatted_entry->new_sport,
                             snatted_entry->old_daddr, snatted_entry->old_dport,
                             snatted_entry->protocol));
  */
  list_add_rcu(&snatted_entry->lnode, &snat_list);
  snatted_entry_counter++;
  spin_unlock_bh(&snat_list_lock);
  return snatted_entry;
}

int de_snat(struct sk_buff *skb, struct snatted_table *snt) {
  struct pkt_manip_info mi;
  mi.sa = 0, mi.da = 1, mi.sp = 0, mi.dp = 1;
  mi.direction = IPFI_INPUT_PRE;
  return manip_skb(skb, 0, 0, snt->old_saddr, snt->old_sport, mi);
}

int de_snat_table_match(struct snatted_table *snt, struct sk_buff *skb) {
  net_quadruplet nquad;
  struct iphdr *iphead = ip_hdr(skb);
  if (iphead == NULL)
    return -1;
  nquad = get_quad_from_skb(skb);
  if (!nquad.valid)
    return -1;
  if (iphead->protocol != snt->protocol)
    return -1;
  if (snt->protocol != IPPROTO_TCP && snt->protocol != IPPROTO_UDP) {
    if ((nquad.saddr == snt->old_daddr) && (nquad.daddr == snt->new_saddr))
      return 1;
  } else {
    if ((nquad.saddr == snt->old_daddr) && (nquad.sport == snt->old_dport) &&
        (nquad.daddr == snt->new_saddr) && (nquad.dport == snt->old_sport))
      return 1;
  }
  return -1;
}

int pre_de_snat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags) {
  struct snatted_table *sntmp;
  /* TODO: restore hash
  int bkt;
  */
  rcu_read_lock_bh();
  /* TODO: restore hash
  hash_for_each_rcu(snat_hashtable, bkt, sntmp, hnode) {
  */
  list_for_each_entry_rcu(sntmp, &snat_list, lnode) {
    if (de_snat_table_match(sntmp, skb) > 0) {
      sntmp->state = state_machine(skb, sntmp->state, 1);
      update_snat_timer(sntmp);
      int ret = de_snat(skb, sntmp);
      rcu_read_unlock_bh();
      return ret;
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

int post_snat_dynamic(struct sk_buff *skb, const ipfi_flow *flow,
                      struct response *resp, struct info_flags *flags) {
  struct dnatted_table *dntmp;
  /* TODO: restore hash
  int bkt;
  */
  rcu_read_lock_bh();
  /* TODO: restore hash
  hash_for_each_rcu(dnat_hashtable, bkt, dntmp, hnode) {
  */
  list_for_each_entry_rcu(dntmp, &dnat_list, lnode) {
    if (snat_dynamic_table_match(dntmp, skb) > 0) {
      dntmp->state = state_machine(skb, dntmp->state, 0);
      update_dnat_timer(dntmp);
      int ret = snat_dynamic_translate(skb, dntmp);
      rcu_read_unlock_bh();
      return ret;
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

int snat_dynamic_translate(struct sk_buff *skb, struct dnatted_table *dnt) {
  struct pkt_manip_info mi;
  memset(&mi, 0, sizeof(mi));
  mi.sa = 1;
  mi.direction = IPFI_OUTPUT_POST;
  dnt->our_ifaddr = get_ifaddr(skb);
  return manip_skb(skb, dnt->our_ifaddr, 0, 0, 0, mi);
}

int snat_dynamic_table_match(const struct dnatted_table *dnt,
                             const struct sk_buff *skb) {
  if (dnt->external || dnt->direction == IPFI_OUTPUT)
    return -1;
  net_quadruplet netq = get_quad_from_skb(skb);
  if (!netq.valid)
    return -1;
  if (dnt->protocol != IPPROTO_TCP && dnt->protocol != IPPROTO_UDP) {
    if ((netq.saddr == dnt->old_saddr) && (netq.daddr == dnt->new_daddr))
      return 1;
  } else {
    if ((netq.saddr == dnt->old_saddr) && (netq.sport == dnt->old_sport) &&
        (netq.daddr == dnt->new_daddr) && (netq.dport == dnt->new_dport))
      return 1;
  }
  return -1;
}

int snat_packet(struct sk_buff *skb, const struct snatted_table *snt) {
  struct pkt_manip_info mi;
  mi.sa = 1, mi.da = 0, mi.sp = (snt->new_sport != snt->old_sport), mi.dp = 0;
  mi.direction = snt->direction;
  return manip_skb(skb, snt->new_saddr, snt->new_sport, 0, 0, mi);
}
