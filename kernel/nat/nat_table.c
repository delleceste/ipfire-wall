/* nat/nat_table.c: NAT table management for ipfire-wall */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/jhash.h>
#include "ipfi.h"
#include "ipfi_translation.h"
#include "ipfi_machine.h"
#include "ipfi_state_machine.h"
#include "globals.h"

u32 get_dnat_hash(__u32 old_saddr, __u16 old_sport, __u32 new_daddr, __u16 new_dport, __u8 proto)
{
    __u32 a1 = old_saddr, a2 = new_daddr;
    __u16 p1 = old_sport, p2 = new_dport;
    if (a1 > a2 || (a1 == a2 && p1 > p2)) {
        swap(a1, a2);
        swap(p1, p2);
    }
    return jhash_3words(a1, a2, (p1 << 16) | p2, proto);
}

u32 get_snat_hash(__u32 new_saddr, __u16 new_sport, __u32 old_daddr, __u16 old_dport, __u8 proto)
{
    __u32 a1 = new_saddr, a2 = old_daddr;
    __u16 p1 = new_sport, p2 = old_dport;
    if (a1 > a2 || (a1 == a2 && p1 > p2)) {
        swap(a1, a2);
        swap(p1, p2);
    }
    return jhash_3words(a1, a2, (p1 << 16) | p2, proto);
}

int fill_entry_net_fields(struct dnatted_table *dnentry, const struct sk_buff *skb, const ipfi_flow *flow, const struct response *resp, const struct info_flags *flags, const ipfire_rule *dnat_rule)
{
    struct iphdr *iph = ip_hdr(skb);
    memset(dnentry, 0, sizeof(struct dnatted_table));
    dnentry->external = flags->external;
    dnentry->protocol = iph->protocol;
    dnentry->old_saddr = iph->saddr;
    dnentry->old_daddr = iph->daddr;
    dnentry->new_daddr = iph->daddr;
    dnentry->in_ifindex = flow->in ? flow->in->ifindex : -1;
    dnentry->out_ifindex = flow->out ? flow->out->ifindex : -1;
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        dnentry->old_sport = th->source;
        dnentry->old_dport = th->dest;
        dnentry->new_dport = dnentry->old_dport;
    }
    dnentry->direction = flags->direction;
    dnentry->rule_id = resp->rule_id;
    dnentry->position = dnatted_entry_counter;
    if (dnat_rule->nflags.newaddr) dnentry->new_daddr = dnat_rule->newaddr;
    if (dnat_rule->nflags.newport) dnentry->new_dport = dnat_rule->newport;
    return 0;
}

struct dnatted_table *lookup_dnatted_table_n_update_timer(const struct dnatted_table *dne, const struct sk_buff *skb, const ipfi_flow *flow, struct response *resp, struct info_flags *flags)
{
    struct dnatted_table *dntmp;
    u32 hash = get_dnat_hash(dne->old_saddr, dne->old_sport, dne->new_daddr, dne->new_dport, dne->protocol);
    rcu_read_lock_bh();
    hash_for_each_possible_rcu(dnat_hashtable, dntmp, hnode, hash) {
        if (compare_entries(dntmp, dne) == 1) {
            dntmp->state = state_machine(skb, dntmp->state, 0);
            update_dnat_timer(dntmp);
            rcu_read_unlock_bh();
            return dntmp;
        }
    }
    rcu_read_unlock_bh();
    return NULL;
}

struct snatted_table *lookup_snatted_table_n_update_timer(const struct snatted_table *sne, const struct sk_buff *skb, const ipfi_flow *flow, struct response *resp, struct info_flags *flags)
{
    struct snatted_table *sntmp;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(sntmp, &root_snatted_table.list, list) {
        if (compare_snat_entries(sntmp, sne) == 1) {
            sntmp->state = state_machine(skb, sntmp->state, 0);
            update_snat_timer(sntmp);
            rcu_read_unlock_bh();
            return sntmp;
        }
    }
    rcu_read_unlock_bh();
    return NULL;
}

int compare_entries(const struct dnatted_table *dne1, const struct dnatted_table *dne2)
{
    return ((dne1->protocol == dne2->protocol) &&
            (dne1->old_saddr == dne2->old_saddr) &&
            (dne1->old_daddr == dne2->old_daddr) &&
            (dne1->old_dport == dne2->old_dport) &&
            (dne1->old_sport == dne2->old_sport) &&
            (dne1->new_daddr == dne2->new_daddr) &&
            (dne1->new_dport == dne2->new_dport) &&
            (dne1->direction == dne2->direction) &&
            (dne1->in_ifindex == dne2->in_ifindex) &&
            (dne1->out_ifindex == dne2->out_ifindex));
}

int compare_snat_entries(const struct snatted_table *sne1, const struct snatted_table *sne2)
{
    return ((sne1->protocol == sne2->protocol) &&
            (sne1->old_saddr == sne2->old_saddr) &&
            (sne1->old_daddr == sne2->old_daddr) &&
            (sne1->old_dport == sne2->old_dport) &&
            (sne1->old_sport == sne2->old_sport) &&
            (sne1->new_saddr == sne2->new_saddr) &&
            (sne1->new_sport == sne2->new_sport) &&
            (sne1->direction == sne2->direction) &&
            (sne1->in_ifindex == sne2->in_ifindex) &&
            (sne1->out_ifindex == sne2->out_ifindex));
}

void update_dnat_timer(struct dnatted_table *dnt)
{
    unsigned int timeout = get_timeout_by_state(dnt->protocol, dnt->state);
    if (time_after(jiffies, dnt->last_timer_update + HZ)) {
        mod_timer(&dnt->timer_dnattedlist, jiffies + HZ * timeout);
        dnt->last_timer_update = jiffies;
    }
}

void update_snat_timer(struct snatted_table *snt)
{
    unsigned int timeout = get_timeout_by_state(snt->protocol, snt->state);
    if (time_after(jiffies, snt->last_timer_update + HZ)) {
        mod_timer(&snt->timer_snattedlist, jiffies + HZ * timeout);
        snt->last_timer_update = jiffies;
    }
}

void handle_dnatted_entry_timeout(struct timer_list *t)
{
    struct dnatted_table *dnt_to_free = from_timer(dnt_to_free, t, timer_dnattedlist);
    spin_lock_bh(&dnat_list_lock);
    timer_delete_sync(&dnt_to_free->timer_dnattedlist);
    hash_del_rcu(&dnt_to_free->hnode);
    list_del_rcu(&dnt_to_free->list);
    call_rcu(&dnt_to_free->dnat_rcuh, free_dnat_entry_rcu_call);
    dnatted_entry_counter--;
    spin_unlock_bh(&dnat_list_lock);
}

void handle_snatted_entry_timeout(struct timer_list *t)
{
    struct snatted_table *snt_to_free = from_timer(snt_to_free, t, timer_snattedlist);
    spin_lock_bh(&snat_list_lock);
    timer_delete_sync(&snt_to_free->timer_snattedlist);
    list_del_rcu(&snt_to_free->list);
    call_rcu(&snt_to_free->snat_rcuh, free_snat_entry_rcu_call);
    snatted_entry_counter--;
    spin_unlock_bh(&snat_list_lock);
}

void fill_timer_dnat_entry(struct dnatted_table *dnt)
{
    unsigned timeo = get_timeout_by_state(dnt->protocol, dnt->state);
    timer_setup(&dnt->timer_dnattedlist, handle_dnatted_entry_timeout, 0);
    dnt->timer_dnattedlist.expires = jiffies + HZ * timeo;
    dnt->last_timer_update = jiffies;
}

void fill_timer_snat_entry(struct snatted_table *snt)
{
    unsigned timeo = get_timeout_by_state(snt->protocol, snt->state);
    timer_setup(&snt->timer_snattedlist, handle_snatted_entry_timeout, 0);
    snt->timer_snattedlist.expires = jiffies + HZ * timeo;
    snt->last_timer_update = jiffies;
}

void free_dnat_entry_rcu_call(struct rcu_head *head)
{
    struct dnatted_table *dnatt = container_of(head, struct dnatted_table, dnat_rcuh);
    kfree(dnatt);
}

void free_snat_entry_rcu_call(struct rcu_head *head)
{
    struct snatted_table *snatt = container_of(head, struct snatted_table, snat_rcuh);
    kfree(snatt);
}

int free_dnatted_table(void)
{
    struct dnatted_table *dtl, *next;
    int counter = 0;
    spin_lock_bh(&dnat_list_lock);
    list_for_each_entry_safe(dtl, next, &root_dnatted_table.list, list) {
        if(timer_delete_sync(&dtl->timer_dnattedlist)) {
            list_del_rcu(&dtl->list);
            call_rcu(&dtl->dnat_rcuh, free_dnat_entry_rcu_call);
            counter++;
            dnatted_entry_counter--;
        }
    }
    spin_unlock_bh(&dnat_list_lock);
    return counter;
}

int free_snatted_table(void)
{
    struct snatted_table *stl, *next;
    int counter = 0;
    synchronize_net();
    spin_lock_bh(&snat_list_lock);
    list_for_each_entry_safe(stl, next, &root_snatted_table.list, list) {
        if(timer_delete_sync(&stl->timer_snattedlist)) {
            list_del_rcu(&stl->list);
            call_rcu(&stl->snat_rcuh, free_snat_entry_rcu_call);
            counter++;
            snatted_entry_counter--;
        }
    }
    spin_unlock_bh(&snat_list_lock);
    return counter;
}
