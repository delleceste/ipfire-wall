/* filter/state/state_table.c: State table management for ipfire-wall */

#include <linux/module.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include "ipfi.h"
#include "ipfi_machine.h"
#include "ipfi_state_machine.h"
#include "globals.h"

void update_timer_of_state_entry(struct state_table *sttable);

u32 get_state_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto)
{
    __u32 a1 = saddr, a2 = daddr;
    __u16 p1 = sport, p2 = dport;

    if (a1 > a2 || (a1 == a2 && p1 > p2)) {
        swap(a1, a2);
        swap(p1, p2);
    }

    return jhash_3words(a1, a2, (p1 << 16) | p2, proto);
}

int direct_state_match(const struct sk_buff *skb,
                       const struct state_table *entry,
                       const ipfi_flow *flow)
{
    const struct iphdr *iph = ip_hdr(skb);
    if(!iph || entry->protocol != iph->protocol)
        return -1;
    if(iph->saddr != entry->saddr || iph->daddr != entry->daddr)
        return -1;
    switch (iph->protocol)
    {
    case IPPROTO_TCP: {
        struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        if(entry->ftp == FTP_DEFINED) { /* ftp support: discard source port */
            if(th->dest == entry->dport)
                return 1;
        }
        if(th->source != entry->sport || th->dest != entry->dport)
            return -1;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
        if(uh->source != entry->sport || uh->dest != entry->dport)
            return -1;
    }
        break;
    }
    /* ICMP and IGMP treated in l2l3match() */

    if(flow->in && flow->in->ifindex != entry->in_ifindex)
        return -1;
    if(flow->out && flow->out->ifindex != entry->out_ifindex)
        return -1;
    return 1;
}

int reverse_state_match(const struct sk_buff *skb,
                        const struct state_table *entry,
                        const ipfi_flow *flow)
{
    const struct iphdr *iph = ip_hdr(skb);
    if(!iph || entry->protocol != iph->protocol)
        return -1;
    if(iph->saddr != entry->daddr || iph->daddr != entry->saddr)
        return -1;
    switch (iph->protocol)
    {
    case IPPROTO_TCP: {
        struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        if(th->source != entry->dport || th->dest != entry->sport)
            return -1;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
        if(uh->source != entry->dport || uh->dest != entry->sport)
            return -1;
    }
        break;
    }
    /* ICMP and IGMP treated in l2l3match() */
    if(flow->in && flow->in->ifindex != entry->in_ifindex)
        return -1;
    if(flow->out && flow->out->ifindex != entry->out_ifindex)
        return -1;
    return 1;
}

inline int l2l3match(const struct sk_buff * skb,
                     const struct state_table *entry,
                     const ipfi_flow *flow)
{
    const struct iphdr *iph = ip_hdr(skb);
    int inifidx = flow->in ? flow->in->ifindex : -1;
    int outifidx = flow->out ? flow->out->ifindex : -1;

    if((iph->saddr == entry->saddr && iph->daddr == entry->daddr &&
        inifidx == entry->in_ifindex &&
        outifidx == entry->out_ifindex)
            || /* reverse match, for the packet coming back */
            (iph->saddr == entry->daddr && iph->daddr == entry->saddr &&
             inifidx == entry->out_ifindex &&
             outifidx == entry->in_ifindex ))
        return 1;
    else
        return -1;
}

int skb_matches_state_table(const struct sk_buff *skb,
                            const struct state_table *entry,
                            short *reverse,
                            const ipfi_flow *flow)
{
    short tr_match = 0;
    const struct iphdr *iph = ip_hdr(skb);
    *reverse = -1;		/* negative means no match */

    if (iph->protocol != entry->protocol)
        return -1;

    if(iph->protocol == IPPROTO_ICMP || iph->protocol == IPPROTO_IGMP ||
            iph->protocol == IPPROTO_GRE || iph->protocol == IPPROTO_PIM)
        return l2l3match(skb, entry, flow);

    if ((tr_match = direct_state_match(skb, entry, flow)) > 0)
        *reverse = 0;
    else if ((tr_match = reverse_state_match(skb, entry, flow)) > 0)
        *reverse = 1;

    if (flow->direction == IPFI_FWD)
        return tr_match;

    if (flow->direction == entry->direction && *reverse == 0)
        return tr_match;
    else if (flow->direction != entry->direction && *reverse == 1)
        return tr_match;

    return -1;
}

void free_state_entry_rcu_call(struct rcu_head *head)
{
    struct state_table* ipst = NULL;
    if(head == NULL)
    {
        IPFI_PRINTK("Callback: head is null.\n");
        return;
    }
    ipst = container_of(head, struct state_table, state_rcuh);
    if(ipst != NULL)
    {
        kfree(ipst);
    }
}

int fill_net_table_fields(struct state_table *state_t,
                          const struct sk_buff * skb,
                          const ipfi_flow *flow)
{
    struct iphdr *iph = ip_hdr(skb);
    if(iph) {
        state_t->protocol = iph->protocol;
        state_t->saddr = iph->saddr;
        state_t->daddr = iph->daddr;
        switch (iph->protocol)
        {
        case IPPROTO_TCP: {
            struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
            state_t->sport = th->source;
            state_t->dport = th->dest;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
            state_t->sport = uh->source;
            state_t->dport = uh->dest;
            break;
        }
        case IPPROTO_ICMP:
        case IPPROTO_IGMP:
        case IPPROTO_GRE:
        case IPPROTO_PIM:
            state_t->sport = 0;
            state_t->dport = 0;
            break;
        default:
            printk ("IPFIRE: fill_net_table_fields (stateful connection): invalid protocol %d!\n", iph->protocol);
            return -1;
            break;
        }
        state_t->direction = flow->direction;
        state_t->protocol = iph->protocol;
        if(flow->in) {
            state_t->in_ifindex = flow->in->ifindex;
            strncpy(state_t->in_devname, flow->in->name, IFNAMSIZ);
        }
        if(flow->out) {
            state_t->out_ifindex = flow->out->ifindex;
            strncpy(state_t->out_devname, flow->out->name, IFNAMSIZ);
        }
        return 0;
    }
    return -1;
}

int compare_state_entries(const struct state_table *s1,
               const struct state_table *s2)
{
       return (s1->saddr == s2->saddr) &&
               (s1->daddr == s2->daddr) &&
               (s1->sport == s2->sport) &&
               (s1->dport == s2->dport) &&
               (s1->direction == s2->direction) &&
               (s1->protocol == s2->protocol) &&
               (s1->in_ifindex == s2->in_ifindex) &&
               (s1->out_ifindex == s2->out_ifindex);
}

void fill_timer_table_fields(struct state_table *state_t)
{
    long int expi;
    expi = get_timeout_by_state(state_t->protocol, state_t->state.state);

    timer_setup(&state_t->timer_statelist, handle_keep_state_timeout, 0);
    state_t->timer_statelist.expires = jiffies + expi * HZ;
    state_t->last_timer_update = jiffies;
}

struct state_table *lookup_state_table_n_update_timer(const struct state_table *stt, int lock) {
    int counter = 0;
    struct state_table *statet;
    u32 key = get_state_hash(stt->saddr, stt->daddr, stt->sport, stt->dport, stt->protocol);

    if(lock == ACQUIRE_LOCK)
        rcu_read_lock_bh();

    hash_for_each_possible_rcu(state_hashtable, statet, hnode, key) {
        counter++;
        if (compare_state_entries(statet, stt) == 1)
        {
            update_timer_of_state_entry(statet);
            if(lock == ACQUIRE_LOCK)
                rcu_read_unlock_bh();
            return statet;
        }
    }
    if(lock == ACQUIRE_LOCK)
        rcu_read_unlock_bh();
    return NULL;
}

int add_state_table_to_list(struct state_table* newtable)
{
    u32 key = get_state_hash(newtable->saddr, newtable->daddr, newtable->sport, newtable->dport, newtable->protocol);

    spin_lock_bh(&state_list_lock);

    fill_timer_table_fields(newtable);
    add_timer(&newtable->timer_statelist);
    INIT_LIST_HEAD(&newtable->list);
    list_add_rcu(&newtable->list, &root_state_table.list);
    hash_add_rcu(state_hashtable, &newtable->hnode, key);

    state_tables_counter++;
    table_id++;
    spin_unlock_bh(&state_list_lock);
    return 0;
}

void handle_keep_state_timeout(struct timer_list *t)
{
    struct state_table *st_to_free = from_timer(st_to_free, t, timer_statelist);

    spin_lock_bh(&state_list_lock);

    if(we_are_exiting != 0)
    {
        IPFI_PRINTK("data in handle_keep_state_timeout() we are exiting!\n");
        spin_unlock_bh(&state_list_lock);
        return;
    }

    if(st_to_free == NULL)
    {
        IPFI_PRINTK("handle_timeout: null data\n");
        spin_unlock_bh(&state_list_lock);
        return;
    }

    timer_delete(&st_to_free->timer_statelist);
    list_del_rcu(&st_to_free->list);
    hash_del_rcu(&st_to_free->hnode);

    state_tables_counter--;
    call_rcu(&st_to_free->state_rcuh, free_state_entry_rcu_call);
    spin_unlock_bh(&state_list_lock);
}

void update_ifindex_in_state_tables(const char *name, int new_index)
{
    struct state_table *entry;
    spin_lock_bh(&state_list_lock);
    list_for_each_entry(entry, &root_state_table.list, list) {
        if (entry->in_devname[0] && strcmp(entry->in_devname, name) == 0)
            entry->in_ifindex = new_index;
        if (entry->out_devname[0] && strcmp(entry->out_devname, name) == 0)
            entry->out_ifindex = new_index;
    }
    spin_unlock_bh(&state_list_lock);
}

static int ipfire_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);

    if (event == NETDEV_UP || event == NETDEV_CHANGENAME || event == NETDEV_REGISTER) {
        update_ifindex_in_rules(dev->name, dev->ifindex);
        update_ifindex_in_state_tables(dev->name, dev->ifindex);
    } else if (event == NETDEV_UNREGISTER) {
        update_ifindex_in_rules(dev->name, -1);
        update_ifindex_in_state_tables(dev->name, -1);
    }
    return NOTIFY_DONE;
}

static struct notifier_block ipfire_netdev_notifier = {
    .notifier_call = ipfire_netdev_event,
};

void register_ipfire_netdev_notifier(void)
{
    register_netdevice_notifier(&ipfire_netdev_notifier);
}

void unregister_ipfire_netdev_notifier(void)
{
    unregister_netdevice_notifier(&ipfire_netdev_notifier);
}

int free_state_tables(void)
{
    struct state_table *tl;
    int counter = 0, i = 0;
    spin_lock_bh(&state_list_lock);
    list_for_each_entry(tl, &root_state_table.list, list)
    {
        i++;
        if(timer_delete_sync(&tl->timer_statelist) > 0 )
        {
            list_del_rcu(&tl->list);
            hash_del_rcu(&tl->hnode);
            call_rcu(&tl->state_rcuh, free_state_entry_rcu_call);
            counter++;
            state_tables_counter--;
        }
        else
            IPFI_PRINTK("IPFIRE: free_state_tables(): timer already expired for the entry %d.\n", i);
    }
    spin_unlock_bh(&state_list_lock);
    return counter;
}
