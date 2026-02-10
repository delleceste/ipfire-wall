#include "globals.h"
#include "ipfi.h"
#include "ipfi_machine.h"
#include "ipfi_netl.h"
#include "ipfi_state_machine.h"
#include "ipfi_translation.h"
#include "message_builder.h"
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/stddef.h>

int dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                     struct response *resp, struct info_flags *flags) {
  ipfire_rule *transrule;
  ipfire_rule *dnat_rules = NULL;
  struct dnatted_table *dnt;
  int csum_check;

  if (flow->direction == IPFI_INPUT_PRE)
    dnat_rules = &translation_pre;
  else if (flow->direction == IPFI_OUTPUT)
    dnat_rules = &translation_out;
  if (dnat_rules == NULL)
    return -1;

  rcu_read_lock_bh();
  list_for_each_entry_rcu(transrule, &dnat_rules->list, list) {
    if (translation_rule_match(skb, flow, flags, transrule) > 0) {
      if ((flow->direction == IPFI_INPUT_PRE) &&
          ((csum_check = check_checksums(skb)) < 0)) {
        rcu_read_unlock_bh();
        return csum_error_message("dnat_translation()", csum_check);
      }
      if (public_to_private_address(skb, transrule))
        flags->external = 1;

      if ((dnt = add_dnatted_entry(skb, flow, resp, flags, transrule)) !=
          NULL) {
        dest_translate(skb, dnt);
        rcu_read_unlock_bh();
        return 0;
      }
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

int dest_translate(struct sk_buff *skb, const struct dnatted_table *dnt) {
  struct pkt_manip_info mi;
  memset(&mi, 0, sizeof(mi));
  mi.direction = dnt->direction;
  mi.da = 1, mi.dp = 1;
  return manip_skb(skb, 0, 0, dnt->new_daddr, dnt->new_dport, mi);
}

int de_dnat(struct sk_buff *skb, const struct dnatted_table *dnatt) {
  struct pkt_manip_info mi;
  mi.sa = 1, mi.sp = 1, mi.da = 0, mi.dp = 0;
  mi.direction = IPFI_OUTPUT_POST;
  return manip_skb(skb, dnatt->old_daddr, dnatt->old_dport, dnatt->old_saddr,
                   dnatt->old_sport, mi);
}

int de_dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                        struct response *resp, struct info_flags *flags) {
  struct dnatted_table *dntmp;
  net_quadruplet netq;
  u32 hash;
  netq = get_quad_from_skb(skb);
  if (!netq.valid)
    return -1;
  hash = get_dnat_hash(netq.daddr, netq.dport, netq.saddr, netq.sport,
                       ip_hdr(skb)->protocol);
  rcu_read_lock_bh();
  hash_for_each_possible_rcu(dnat_hashtable, dntmp, hnode, hash) {
    if (de_dnat_table_match(dntmp, skb) > 0) {
      dntmp->state = state_machine(skb, dntmp->state, 1);
      update_dnat_timer(dntmp);
      int ret = de_dnat(skb, dntmp);
      rcu_read_unlock_bh();
      return ret;
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

int de_dnat_table_match(const struct dnatted_table *dnt,
                        const struct sk_buff *skb) {
  net_quadruplet nquad;
  struct iphdr *iphead = ip_hdr(skb);
  if (iphead == NULL)
    return -1;
  if (dnt->direction == IPFI_OUTPUT)
    return -1;
  nquad = get_quad_from_skb(skb);
  if (!nquad.valid)
    return -1;
  if (iphead->protocol != dnt->protocol)
    return -1;
  if (dnt->protocol != IPPROTO_TCP && dnt->protocol != IPPROTO_UDP) {
    if ((nquad.saddr == dnt->new_daddr) && (nquad.daddr == dnt->old_saddr))
      return 1;
  } else {
    if ((nquad.saddr == dnt->new_daddr) && (nquad.sport == dnt->new_dport) &&
        (nquad.daddr == dnt->old_saddr) && (nquad.dport == dnt->old_sport))
      return 1;
  }
  return -1;
}

int pre_de_dnat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags) {
  struct dnatted_table *dntmp;
  int bkt;
  rcu_read_lock_bh();
  hash_for_each_rcu(dnat_hashtable, bkt, dntmp, hnode) {
    if (pre_denat_table_match(dntmp, skb) > 0) {
      dntmp->state = state_machine(skb, dntmp->state, 1);
      update_dnat_timer(dntmp);
      int ret = pre_de_dnat_translate(skb, dntmp);
      rcu_read_unlock_bh();
      return ret;
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

int pre_denat_table_match(const struct dnatted_table *dnt,
                          const struct sk_buff *skb) {
  net_quadruplet netquad;
  struct iphdr *iphead = ip_hdr(skb);
  if (iphead == NULL || dnt == NULL)
    return -1;
  if (dnt->external)
    return -1;
  netquad = get_quad_from_skb(skb);
  if (!netquad.valid)
    return -1;
  if (iphead->protocol != dnt->protocol)
    return -1;
  if (dnt->direction == IPFI_OUTPUT) {
    if (dnt->protocol != IPPROTO_TCP && dnt->protocol != IPPROTO_UDP) {
      if ((netquad.saddr == dnt->new_daddr) &&
          (netquad.daddr == dnt->old_saddr))
        return 1;
    } else {
      if ((netquad.saddr == dnt->new_daddr) &&
          (netquad.sport == dnt->new_dport) &&
          (netquad.daddr == dnt->old_saddr) &&
          (netquad.dport == dnt->old_sport))
        return 1;
    }
  } else {
    if (dnt->protocol != IPPROTO_TCP && dnt->protocol != IPPROTO_UDP) {
      if ((netquad.saddr == dnt->new_daddr) &&
          (netquad.daddr == dnt->old_daddr))
        return 1;
    } else {
      if ((netquad.saddr == dnt->new_daddr) &&
          (netquad.sport == dnt->new_dport) &&
          ((netquad.daddr == dnt->old_daddr) ||
           (netquad.daddr == dnt->our_ifaddr)) &&
          (netquad.dport == dnt->old_sport))
        return 1;
    }
  }
  return -1;
}

int pre_de_dnat_translate(struct sk_buff *skb,
                          const struct dnatted_table *dnt) {
  struct pkt_manip_info mi;
  memset(&mi, 0, sizeof(mi));
  mi.direction = IPFI_INPUT_PRE;
  if (dnt->direction == IPFI_OUTPUT) {
    mi.sa = 1, mi.sp = 1;
    return manip_skb(skb, dnt->old_daddr, dnt->old_dport, 0, 0, mi);
  } else {
    mi.da = 1, mi.dp = 1;
    return manip_skb(skb, 0, 0, dnt->old_saddr, dnt->old_sport, mi);
  }
}

struct dnatted_table *add_dnatted_entry(const struct sk_buff *skb,
                                        const ipfi_flow *flow,
                                        struct response *resp,
                                        struct info_flags *flags,
                                        const ipfire_rule *dnat_rule) {
  struct dnatted_table *newtable;
  struct dnatted_table lookup_entry;
  static unsigned int entry_id = 0;
  u32 hash;

  fill_entry_net_fields(&lookup_entry, skb, flow, resp, flags, dnat_rule);
  hash = get_dnat_hash(lookup_entry.old_saddr, lookup_entry.old_sport,
                       lookup_entry.new_daddr, lookup_entry.new_dport,
                       lookup_entry.protocol);

  if ((newtable = lookup_dnatted_table_n_update_timer(&lookup_entry, skb, flow,
                                                      resp, flags)) != NULL) {
    return newtable;
  }

  if (dnatted_entry_counter == fwopts.max_nat_entries) {
    struct info_flags warn_flags = *flags;
    warn_flags.nat_max_entries = 1;
    struct response warn_resp = *resp;
    int err;
    struct sk_buff *skb_to_user =
        build_info_t_nlmsg(skb, flow, &warn_resp, &warn_flags, &err);
    if (skb_to_user)
      skb_send_to_user(skb_to_user, LISTENER_DATA);
    return NULL;
  }

  newtable = kmalloc(sizeof(struct dnatted_table), GFP_ATOMIC);
  if (newtable == NULL)
    return NULL;

  *newtable = lookup_entry;
  newtable->state = state_machine(skb, newtable->state, 0);
  spin_lock_bh(&dnat_list_lock);
  fill_timer_dnat_entry(newtable);
  newtable->rule_id = entry_id++;
  add_timer(&newtable->timer_dnattedlist);
  hash_add_rcu(dnat_hashtable, &newtable->hnode, hash);
  dnatted_entry_counter++;
  spin_unlock_bh(&dnat_list_lock);
  return newtable;
}
