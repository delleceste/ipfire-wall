/* nat/dnat/dnat.c: Destination NAT logic for ipfire-wall */

#include "dnat.h"
#include "../../filter/state/state_machine.h"
#include "../nat.h"
#include "../nat_table.h"
#include "globals.h"
#include "ipfi_machine.h"
#include "ipfire.h"
#include "netlink/ipfi_netl.h"
#include "netlink/message_builder.h"
#include <linux/hashtable.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/udp.h>

int dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                     struct response *resp, struct info_flags *flags) {
  ipfire_rule *transrule;
  ipfire_rule *dnat_rules = NULL;
  struct nat_table *dnt;
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
        nat_put(dnt);
        rcu_read_unlock_bh();
        return 0;
      }
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

int dest_translate(struct sk_buff *skb, const struct nat_table *dnt) {
  struct pkt_manip_info mi;
  memset(&mi, 0, sizeof(mi));
  mi.direction = dnt->direction;
  mi.da = 1, mi.dp = 1;
  return manip_skb(skb, 0, 0, dnt->new_addr, dnt->new_port, mi);
}

int de_dnat(struct sk_buff *skb, const struct nat_table *dnatt) {
  struct pkt_manip_info mi;
  mi.sa = 1, mi.sp = 1, mi.da = 0, mi.dp = 0;
  mi.direction = IPFI_OUTPUT_POST;
  return manip_skb(skb, dnatt->old_daddr, dnatt->old_dport, dnatt->old_saddr,
                   dnatt->old_sport, mi);
}

int de_dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                        struct response *resp, struct info_flags *flags) {
  struct nat_table *dntmp;
  net_quadruplet netq;

  netq = get_quad_from_skb(skb);
  if (!netq.valid)
    return -1;

  rcu_read_lock_bh();
  {
    struct iphdr *iph = ip_hdr(skb);
    u32 key;
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
      key = get_dnat_hash(netq.saddr, netq.sport, netq.daddr, netq.dport,
                          iph->protocol);
    else
      key = jhash_2words(iph->saddr, iph->daddr, iph->protocol);
    hash_for_each_possible_rcu(nat_hashtables[NAT_DNAT], dntmp, h.hnode, key) {
      if (de_dnat_table_match(dntmp, skb) > 0) {
        dntmp->state = state_machine(skb, dntmp->state, 1);
        ipfi_entry_update_timer(&dntmp->h, dntmp->protocol, dntmp->state);
        int ret = de_dnat(skb, dntmp);
        rcu_read_unlock_bh();
        return ret;
      }
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

int de_dnat_table_match(const struct nat_table *dnt,
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
    if ((nquad.saddr == dnt->new_addr) && (nquad.daddr == dnt->old_saddr))
      return 1;
  } else {
    if ((nquad.saddr == dnt->new_addr) && (nquad.sport == dnt->new_port) &&
        (nquad.daddr == dnt->old_saddr) && (nquad.dport == dnt->old_sport))
      return 1;
  }
  return -1;
}

int pre_de_dnat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags) {
  struct nat_table *dntmp;
  rcu_read_lock_bh();
  {
    struct iphdr *iph = ip_hdr(skb);
    net_quadruplet netq = get_quad_from_skb(skb);
    u32 key;
    if (!netq.valid) {
      rcu_read_unlock_bh();
      return -1;
    }
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
      key = get_dnat_hash(netq.saddr, netq.sport, netq.daddr, netq.dport,
                          iph->protocol);
    else
      key = jhash_2words(iph->saddr, iph->daddr, iph->protocol);
    hash_for_each_possible_rcu(nat_hashtables[NAT_DNAT], dntmp, h.hnode, key) {
      if (pre_denat_table_match(dntmp, skb) > 0) {
        dntmp->state = state_machine(skb, dntmp->state, 1);
        ipfi_entry_update_timer(&dntmp->h, dntmp->protocol, dntmp->state);
        int ret = pre_de_dnat_translate(skb, dntmp);
        rcu_read_unlock_bh();
        return ret;
      }
    }
  }
  rcu_read_unlock_bh();
  return -1;
}

int pre_denat_table_match(const struct nat_table *dnt,
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
      if ((netquad.saddr == dnt->new_addr) && (netquad.daddr == dnt->old_saddr))
        return 1;
    } else {
      if ((netquad.saddr == dnt->new_addr) &&
          (netquad.sport == dnt->new_port) &&
          (netquad.daddr == dnt->old_saddr) &&
          (netquad.dport == dnt->old_sport))
        return 1;
    }
  } else {
    if (dnt->protocol != IPPROTO_TCP && dnt->protocol != IPPROTO_UDP) {
      if ((netquad.saddr == dnt->new_addr) && (netquad.daddr == dnt->old_daddr))
        return 1;
    } else {
      if ((netquad.saddr == dnt->new_addr) &&
          (netquad.sport == dnt->new_port) &&
          ((netquad.daddr == dnt->old_daddr) ||
           (netquad.daddr == dnt->our_ifaddr)) &&
          (netquad.dport == dnt->old_sport))
        return 1;
    }
  }
  return -1;
}

int pre_de_dnat_translate(struct sk_buff *skb, const struct nat_table *dnt) {
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

struct nat_table *add_dnatted_entry(const struct sk_buff *skb,
                                    const ipfi_flow *flow,
                                    struct response *resp,
                                    struct info_flags *flags,
                                    const ipfire_rule *dnat_rule) {
  struct nat_table *newtable;
  unsigned int timeout;

  if (unlikely(READ_ONCE(we_are_exiting)))
    return NULL;

  if (nat_counters[NAT_DNAT] == fwopts.max_nat_entries) {
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

  newtable = kmem_cache_alloc(nat_cache, GFP_ATOMIC);
  if (newtable == NULL)
    return NULL;

  fill_nat_entry_fields(newtable, skb, flow, resp, flags, dnat_rule, NAT_DNAT);
  newtable->state = state_machine(skb, newtable->state, 0);

  refcount_set(&newtable->h.refcnt, 1);

  spin_lock_bh(&nat_locks[NAT_DNAT]);
  if (unlikely(we_are_exiting)) {
    spin_unlock_bh(&nat_locks[NAT_DNAT]);
    kmem_cache_free(nat_cache, newtable);
    return NULL;
  }
  timeout = get_timeout_by_state(newtable->protocol, newtable->state);
  ipfi_entry_init(&newtable->h, timeout, handle_nat_entry_timeout);

  ipfi_entry_hold(&newtable->h); /* table ref */
  {
    u32 key = get_dnat_hash(newtable->old_saddr, newtable->old_sport,
                            newtable->new_addr, newtable->new_port,
                            newtable->protocol);
    hlist_add_head_rcu(
        &newtable->h.hnode,
        &nat_hashtables[NAT_DNAT][key & ((1 << NAT_HASH_BITS) - 1)]);
  }
  nat_counters[NAT_DNAT]++;
  spin_unlock_bh(&nat_locks[NAT_DNAT]);
  ipfi_entry_arm_timer(&newtable->h);
  return newtable;
}
