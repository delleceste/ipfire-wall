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
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Main DNAT entry point.
 * Internally handles rcu_read_lock_bh() for rule list traversal.
 */
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

/* De-DNAT entry point (POSTROUTING).
 * Uses lookup_nat_idx which handles RCU internally.
 */
int de_dnat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                        struct response *resp, struct info_flags *flags) {
  struct nat_table *dntmp =
      lookup_nat_idx(NAT_DNAT, NAT_IDX_POSTNAT, skb); // POSTNAT!
  if (dntmp) {
    if (de_dnat_table_match(dntmp, skb) > 0) {
      dntmp->state = state_machine(skb, dntmp->state, 1);
      ipfi_entry_update_timer(&dntmp->h, dntmp->protocol, dntmp->state);
      int ret = de_dnat(skb, dntmp);
      nat_put(dntmp);
      return ret;
    }
    nat_put(dntmp);
  }
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

/* Destination de-NAT (PREROUTING).
 * Uses lookup_nat_idx which handles RCU internally.
 */
int pre_de_dnat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags) {
  struct nat_table *dntmp = lookup_nat_idx(NAT_DNAT, NAT_IDX_REPLY, skb);

  if (dntmp) {
    if (pre_denat_table_match(dntmp, skb) > 0) {
      dntmp->state = state_machine(skb, dntmp->state, 1);
      ipfi_entry_update_timer(&dntmp->h, dntmp->protocol, dntmp->state);
      int ret = pre_de_dnat_translate(skb, dntmp);
      nat_put(dntmp);
      return ret;
    }
    nat_put(dntmp);
  }
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

  if (unlikely(READ_ONCE(we_are_exiting)))
    return NULL;

  if (percpu_counter_sum_positive(&nat_counters[NAT_DNAT]) >=
      fwopts.max_nat_entries) {
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

  ipfi_entry_init(&newtable->h,
                  get_timeout_by_state(newtable->protocol, newtable->state),
                  handle_nat_entry_timeout);

  refcount_set(&newtable->h.refcnt, 1);

  {
    /* 1. Add ORIG index (A -> B) - already calculated in fill_nat_entry_fields
     */
    unsigned int bkt_orig = newtable->bkts[NAT_IDX_ORIG];
    spin_lock_bh(&nat_bucket_locks[NAT_DNAT][NAT_IDX_ORIG][bkt_orig]);
    if (unlikely(we_are_exiting)) {
      spin_unlock_bh(&nat_bucket_locks[NAT_DNAT][NAT_IDX_ORIG][bkt_orig]);
      kmem_cache_free(nat_cache, newtable);
      return NULL;
    }
    ipfi_entry_hold(&newtable->h);
    hlist_add_head_rcu(&newtable->h.hnode,
                       &nat_hashtables[NAT_DNAT][NAT_IDX_ORIG][bkt_orig]);
    spin_unlock_bh(&nat_bucket_locks[NAT_DNAT][NAT_IDX_ORIG][bkt_orig]);

    /* 2. Add POSTNAT index (A -> C) */
    newtable->keys[NAT_IDX_POSTNAT] = get_nat_tuple_hash(
        newtable->old_saddr, newtable->old_sport, newtable->new_addr,
        newtable->new_port, newtable->protocol);
    newtable->bkts[NAT_IDX_POSTNAT] =
        newtable->keys[NAT_IDX_POSTNAT] & ((1 << NAT_HASH_BITS) - 1);
    spin_lock_bh(&nat_bucket_locks[NAT_DNAT][NAT_IDX_POSTNAT]
                                  [newtable->bkts[NAT_IDX_POSTNAT]]);
    hlist_add_head_rcu(&newtable->h_indices[NAT_IDX_POSTNAT - 1],
                       &nat_hashtables[NAT_DNAT][NAT_IDX_POSTNAT]
                                      [newtable->bkts[NAT_IDX_POSTNAT]]);
    newtable->active_indices |= (1 << NAT_IDX_POSTNAT);
    spin_unlock_bh(&nat_bucket_locks[NAT_DNAT][NAT_IDX_POSTNAT]
                                    [newtable->bkts[NAT_IDX_POSTNAT]]);

    /* 3. Add REPLY index (C -> B) */
    /* Note: B is old_daddr. C is new_addr. */
    if (flags->direction == IPFI_OUTPUT) {
      newtable->keys[NAT_IDX_REPLY] = get_nat_tuple_hash(
          newtable->new_addr, newtable->new_port, newtable->old_saddr,
          newtable->old_sport, newtable->protocol);
    } else {
      newtable->keys[NAT_IDX_REPLY] = get_nat_tuple_hash(
          newtable->new_addr, newtable->new_port, newtable->old_daddr,
          newtable->old_dport, newtable->protocol);
    }
    newtable->bkts[NAT_IDX_REPLY] =
        newtable->keys[NAT_IDX_REPLY] & ((1 << NAT_HASH_BITS) - 1);
    spin_lock_bh(&nat_bucket_locks[NAT_DNAT][NAT_IDX_REPLY]
                                  [newtable->bkts[NAT_IDX_REPLY]]);
    hlist_add_head_rcu(&newtable->h_indices[NAT_IDX_REPLY - 1],
                       &nat_hashtables[NAT_DNAT][NAT_IDX_REPLY]
                                      [newtable->bkts[NAT_IDX_REPLY]]);
    newtable->active_indices |= (1 << NAT_IDX_REPLY);
    spin_unlock_bh(&nat_bucket_locks[NAT_DNAT][NAT_IDX_REPLY]
                                    [newtable->bkts[NAT_IDX_REPLY]]);

    percpu_counter_inc(&nat_counters[NAT_DNAT]);
  }

  ipfi_entry_arm_timer(&newtable->h);
  return newtable;
}
