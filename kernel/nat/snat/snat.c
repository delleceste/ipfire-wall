/* nat/snat/snat.c: Source NAT logic for ipfire-wall */

#include "snat.h"
#include "../../filter/state/state_machine.h"
#include "../dnat/dnat.h"
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
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/timer.h>
#include <linux/udp.h>

int snat_translation(struct sk_buff *skb, const ipfi_flow *flow,
                     struct response *resp, struct info_flags *flags) {
    ipfire_rule *snatrule;
    struct nat_table *snt;

    rcu_read_lock_bh();
    list_for_each_entry_rcu(snatrule, &translation_post.list, list) {
        if (translation_rule_match(skb, flow, flags, snatrule) > 0) {
            if ((snt = add_snatted_entry(skb, flow, resp, flags, snatrule)) != NULL) {
                int status = snat_packet(skb, snt);
                nat_put(snt);
                rcu_read_unlock_bh();
                return status;
            }
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

struct nat_table *add_snatted_entry(const struct sk_buff *skb,
                                    const ipfi_flow *flow,
                                    struct response *resp,
                                    struct info_flags *flags,
                                    const ipfire_rule *snat_rule) {
    struct nat_table *entry;

    if (unlikely(READ_ONCE(we_are_exiting)))
        return NULL;

    if (percpu_counter_read(&nat_counters[NAT_SNAT]) >= fwopts.max_nat_entries) {
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

    entry = kmem_cache_alloc(nat_cache, GFP_ATOMIC);
    if (!entry)
        return NULL;

    fill_nat_entry_fields(entry, skb, flow, resp, flags, snat_rule, NAT_SNAT);
    entry->state = state_machine(skb, entry->state, 0);

    refcount_set(&entry->h.refcnt, 1);

    {
        u32 key = get_snat_hash(entry->new_addr, entry->new_port, entry->old_daddr,
                                entry->old_dport, entry->protocol);
        unsigned int bkt = key & ((1 << NAT_HASH_BITS) - 1);

        spin_lock_bh(&nat_bucket_locks[NAT_SNAT][bkt]);

        if (unlikely(we_are_exiting)) {
            spin_unlock_bh(&nat_bucket_locks[NAT_SNAT][bkt]);
            kmem_cache_free(nat_cache, entry);
            return NULL;
        }

        if (unlikely(percpu_counter_read(&nat_counters[NAT_SNAT]) >=
                     fwopts.max_nat_entries)) {
            spin_unlock_bh(&nat_bucket_locks[NAT_SNAT][bkt]);
            kmem_cache_free(nat_cache, entry);
            /* Warn the user on allocation failure */
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

        ipfi_entry_hold(&entry->h); /* table ref */
        hlist_add_head_rcu(&entry->h.hnode, &nat_hashtables[NAT_SNAT][bkt]);
        percpu_counter_inc(&nat_counters[NAT_SNAT]);

        spin_unlock_bh(&nat_bucket_locks[NAT_SNAT][bkt]);
    }

    ipfi_entry_arm_timer(&entry->h);
    return entry;
}

int de_snat(struct sk_buff *skb, struct nat_table *snt) {
    struct pkt_manip_info mi;
    mi.sa = 0, mi.da = 1, mi.sp = 0, mi.dp = 1;
    mi.direction = IPFI_INPUT_PRE;
    return manip_skb(skb, 0, 0, snt->old_saddr, snt->old_sport, mi);
}

int de_snat_table_match(struct nat_table *snt, struct sk_buff *skb) {
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
        if ((nquad.saddr == snt->old_daddr) && (nquad.daddr == snt->new_addr))
            return 1;
    } else {
        if ((nquad.saddr == snt->old_daddr) && (nquad.sport == snt->old_dport) &&
                (nquad.daddr == snt->new_addr) && (nquad.dport == snt->old_sport))
            return 1;
    }
    return -1;
}

int pre_de_snat(struct sk_buff *skb, const ipfi_flow *flow,
                struct response *resp, struct info_flags *flags) {
    struct nat_table *sntmp;

    rcu_read_lock_bh();
    {
        struct iphdr *iph = ip_hdr(skb);
        net_quadruplet nq = get_quad_from_skb(skb);
        u32 key;
        if (!nq.valid) {
            rcu_read_unlock_bh();
            return -1;
        }
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
            key =
                    get_snat_hash(nq.saddr, nq.sport, nq.daddr, nq.dport, iph->protocol);
        else
            key = jhash_2words(iph->saddr, iph->daddr, iph->protocol);
        hash_for_each_possible_rcu(nat_hashtables[NAT_SNAT], sntmp, h.hnode, key) {
            if (de_snat_table_match(sntmp, skb) > 0) {
                sntmp->state = state_machine(skb, sntmp->state, 1);
                ipfi_entry_update_timer(&sntmp->h, sntmp->protocol, sntmp->state);
                int ret = de_snat(skb, sntmp);
                rcu_read_unlock_bh();
                return ret;
            }
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

int post_snat_dynamic(struct sk_buff *skb, const ipfi_flow *flow,
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
        pr_info("post_snat_dynamic:\n");
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
            key = get_dnat_hash(netq.saddr, netq.sport, netq.daddr, netq.dport,
                                iph->protocol);
        else
            key = jhash_2words(iph->saddr, iph->daddr, iph->protocol);


        hash_for_each_possible_rcu(nat_hashtables[NAT_DNAT], dntmp, h.hnode, key) {
            if (snat_dynamic_table_match(dntmp, skb) > 0) {
                dntmp->state = state_machine(skb, dntmp->state, 0);
                ipfi_entry_update_timer(&dntmp->h, dntmp->protocol, dntmp->state);
                int ret = snat_dynamic_translate(skb, dntmp);
                rcu_read_unlock_bh();
                return ret;
            }
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

int snat_dynamic_translate(struct sk_buff *skb, struct nat_table *dnt) {
    struct pkt_manip_info mi;
    memset(&mi, 0, sizeof(mi));
    mi.sa = 1;
    mi.direction = IPFI_OUTPUT_POST;
    dnt->our_ifaddr = get_ifaddr(skb);
    return manip_skb(skb, dnt->our_ifaddr, 0, 0, 0, mi);
}

int snat_dynamic_table_match(const struct nat_table *dnt,
                             const struct sk_buff *skb) {
    if (dnt->external || dnt->direction == IPFI_OUTPUT)
        return -1;
    net_quadruplet netq = get_quad_from_skb(skb);
    if (!netq.valid)
        return -1;
    if (dnt->protocol != IPPROTO_TCP && dnt->protocol != IPPROTO_UDP) {
        if ((netq.saddr == dnt->old_saddr) && (netq.daddr == dnt->new_addr))
            return 1;
    } else {
        if ((netq.saddr == dnt->old_saddr) && (netq.sport == dnt->old_sport) &&
                (netq.daddr == dnt->new_addr) && (netq.dport == dnt->new_port))
            return 1;
    }
    return -1;
}

int snat_packet(struct sk_buff *skb, const struct nat_table *snt) {
    struct pkt_manip_info mi;
    mi.sa = 1, mi.da = 0, mi.sp = (snt->new_port != snt->old_sport), mi.dp = 0;
    mi.direction = snt->direction;
    return manip_skb(skb, snt->new_addr, snt->new_port, 0, 0, mi);
}
