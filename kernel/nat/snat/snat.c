/* nat/snat/snat.c: Source NAT logic for ipfire-wall */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/rcupdate.h> // Added
#include <linux/slab.h>     // Added
#include <linux/string.h>   // Added
#include <linux/timer.h>    // Added
#include "ipfi.h"
#include "ipfi_netl.h"
#include "ipfi_translation.h"
#include "ipfi_machine.h"
#include "ipfi_state_machine.h"
#include "message_builder.h"
#include "globals.h"

int snat_translation(struct sk_buff *skb,
                     const ipfi_flow *flow,
                     struct response *resp,
                     struct info_flags *flags)
{
    ipfire_rule *snatrule;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(snatrule, &translation_post.list, list)
    {
        if (translation_rule_match(skb, flow, flags, snatrule) > 0)
        {
            if (add_snatted_entry(skb, flow, resp, flags, snatrule) == 0)
                snatted_entry_counter++;
            int status = do_source_nat(skb, snatrule);
            rcu_read_unlock_bh();
            return status;
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

int add_snatted_entry(const struct sk_buff *skb, const ipfi_flow *flow, struct response *resp, struct info_flags *flags, const ipfire_rule *snat_rule)
{
    struct snatted_table *snatted_entry;
    struct iphdr *iph = ip_hdr(skb);
    snatted_entry = kmalloc(sizeof(struct snatted_table), GFP_ATOMIC);
    if (!snatted_entry) return -1;
    memset(snatted_entry, 0, sizeof(struct snatted_table));
    snatted_entry->protocol = iph->protocol;
    snatted_entry->old_saddr = iph->saddr;
    snatted_entry->old_daddr = iph->daddr;
    snatted_entry->in_ifindex = flow->in ? flow->in->ifindex : -1;
    snatted_entry->out_ifindex = flow->out ? flow->out->ifindex : -1;
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        snatted_entry->old_sport = th->source;
        snatted_entry->old_dport = th->dest;
    }
    snatted_entry->direction = flags->direction;
    snatted_entry->external = flags->external;
    snatted_entry->rule_id = resp->rule_id;
    snatted_entry->position = snatted_entry_counter;
    snatted_entry->new_saddr = iph->saddr;
    snatted_entry->new_sport = (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) ? snatted_entry->old_sport : 0;
    if (snat_rule->nflags.newaddr) snatted_entry->new_saddr = snat_rule->newaddr;
    if (snat_rule->nflags.newport) snatted_entry->new_sport = snat_rule->newport;
    if (lookup_snatted_table_n_update_timer(snatted_entry, skb, flow, resp, flags) != NULL) {
        kfree(snatted_entry);
        return 1;
    }
    if (snatted_entry_counter == fwopts.max_nat_entries) {
        int err;
        struct response warn_resp = *resp;
        struct info_flags warn_flags = *flags;
        warn_flags.nat_max_entries = 1;
        struct sk_buff *skb_to_user = build_info_t_nlmsg(skb, flow, &warn_resp, &warn_flags, &err);
        if (skb_to_user) skb_send_to_user(skb_to_user, LISTENER_DATA);
        kfree(snatted_entry);
        return -1;
    }
    snatted_entry->state = state_machine(skb, snatted_entry->state, 0);
    spin_lock_bh(&snat_list_lock);
    fill_timer_snat_entry(snatted_entry);
    add_timer(&snatted_entry->timer_snattedlist);
    INIT_LIST_HEAD(&snatted_entry->list);
    list_add_rcu(&snatted_entry->list, &root_snatted_table.list);
    spin_unlock_bh(&snat_list_lock);
    return 0;
}

int de_snat(struct sk_buff *skb, struct snatted_table *snt)
{
    struct pkt_manip_info mi;
    mi.sa = 0, mi.da = 1, mi.sp = 0, mi.dp = 1;
    mi.direction = IPFI_INPUT_PRE;
    return manip_skb(skb, 0, 0, snt->old_saddr, snt->old_sport, mi);
}

int de_snat_table_match(struct snatted_table *snt, struct sk_buff *skb)
{
    net_quadruplet nquad;
    struct iphdr *iphead = ip_hdr(skb);
    if(iphead == NULL) return -1;
    nquad = get_quad_from_skb(skb);
    if (!nquad.valid) return -1;
    if (iphead->protocol != snt->protocol) return -1;
    if (snt->protocol != IPPROTO_TCP && snt->protocol != IPPROTO_UDP) {
        if ((nquad.saddr == snt->old_daddr) && (nquad.daddr == snt->new_saddr)) return 1;
    } else {
        if ((nquad.saddr == snt->old_daddr) && (nquad.sport == snt->old_dport) &&
            (nquad.daddr == snt->new_saddr) && (nquad.dport == snt->old_sport)) return 1;
    }
    return -1;
}

int pre_de_snat(struct sk_buff *skb, const ipfi_flow *flow, struct response *resp, struct info_flags *flags)
{
    struct snatted_table *sntmp;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(sntmp, &root_snatted_table.list, list) {
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

int post_snat_dynamic(struct sk_buff *skb, const ipfi_flow *flow, struct response *resp, struct info_flags *flags)
{
    struct dnatted_table *dntmp;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(dntmp, &root_dnatted_table.list, list) {
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

int snat_dynamic_translate(struct sk_buff *skb, struct dnatted_table *dnt)
{
    struct pkt_manip_info mi;
    memset(&mi, 0, sizeof(mi));
    mi.sa = 1;
    mi.direction = IPFI_OUTPUT_POST;
    dnt->our_ifaddr = get_ifaddr(skb);
    return manip_skb(skb, dnt->our_ifaddr, 0, 0, 0, mi);
}

int snat_dynamic_table_match(const struct dnatted_table *dnt, const struct sk_buff *skb)
{
    if (dnt->external || dnt->direction == IPFI_OUTPUT) return -1;
    net_quadruplet netq = get_quad_from_skb(skb);
    if (!netq.valid) return -1;
    if (dnt->protocol != IPPROTO_TCP && dnt->protocol != IPPROTO_UDP) {
        if ((netq.saddr == dnt->old_saddr) && (netq.daddr == dnt->new_daddr)) return 1;
    } else {
        if ((netq.saddr == dnt->old_saddr) && (netq.sport == dnt->old_sport) &&
            (netq.daddr == dnt->new_daddr) && (netq.dport == dnt->new_dport)) return 1;
    }
    return -1;
}

int do_source_nat(struct sk_buff *skb, ipfire_rule * ipfr)
{
    struct pkt_manip_info mi;
    mi.sa = 1, mi.da = 0, mi.sp = 1, mi.dp = 0;
    mi.direction = IPFI_OUTPUT_POST;
    return manip_skb(skb, ipfr->newaddr, ipfr->newport, 0, 0, mi);
}
