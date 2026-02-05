/* filter/filter_engine.c: Main filtering engine for ipfire-wall */

#include <linux/module.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inetdevice.h>
#include <common/ipfi_structures.h>

struct state_table;
#include "ipfi.h"
#include "ipfi_netl.h"
#include "ipfi_machine.h"
#include "message_builder.h"
#include "ipfi_mangle.h"
#include "ipfi_state_machine.h"
#include "globals.h"

struct response ipfire_filter(const ipfire_rule *dropped,
                              const ipfire_rule *allowed,
                              const struct ipfire_options *ipfi_opts,
                              struct sk_buff* skb,
                              const ipfi_flow *flow,
                              struct info_flags *flags)
{
    struct response response = {};
    ipfire_rule *rule;
    short pass;
    short res;
    short drop = 0;
    struct state_table* newtable = NULL;
    struct iphdr *iph = ip_hdr(skb);

    if (flow->direction == IPFI_INPUT || flow->direction == IPFI_OUTPUT || flow->direction == IPFI_FWD)
    {
        {
            __u8 ftp_tmp = flags->ftp;
            response = check_state(skb, flow, &ftp_tmp);
            flags->ftp = ftp_tmp;
        }
        pass = response.verdict;
        if (pass > 0) {
            response.state = 1U;
            return response;
        }
    }

    rcu_read_lock();
    list_for_each_entry_rcu(rule, &dropped->list, list)
    {
        if ((res = direction_filter(flow->direction, rule)) < 0)
            goto next_drop_rule;
        else if (res > 0)
            drop = 1;

        if ((res = device_filter(rule, flow->in, flow->out)) < 0)
            goto next_drop_rule;
        else if (res > 0)
            drop = 1;

        if ((res = ip_layer_filter(iph, rule, flow->direction, flow->in, flow->out)) < 0)
            goto next_drop_rule;
        else if (res > 0)
            drop = 1;

        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
            if ((res = ipfi_tcp_filter(th, rule)) < 0)
                goto next_drop_rule;
            else if (res > 0)
                drop = 1;
        }
        else if (iph->protocol == IPPROTO_UDP)
        {
            struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
            if ((res = udp_filter(uh, rule)) < 0)
                goto next_drop_rule;
            else if (res > 0)
                drop = 1;
        }
        else if (iph->protocol == IPPROTO_ICMP)
        {
            struct icmphdr *ih = (struct icmphdr *)((void *)iph + iph->ihl * 4);
            if ((res = icmp_filter(ih, rule)) < 0)
                goto next_drop_rule;
            else if (res > 0)
                drop = 1;
        }

        if (drop > 0)
        {
            response.state = 0;
            response.verdict = IPFI_DROP;
            response.notify = rule->notify;
            response.rule_id = rule->rule_id;
            rcu_read_unlock();
            return response;
        }

next_drop_rule:;
    }

    pass = 0;
    list_for_each_entry_rcu(rule, &allowed->list, list)
    {
        if ((res = direction_filter(flow->direction, rule)) < 0)
            goto next_pass_rule;
        else if (res > 0)
            pass = 1;

        if ((res = device_filter(rule, flow->in, flow->out)) < 0)
            goto next_pass_rule;
        else if (res > 0)
            pass = 1;

        if ((res = ip_layer_filter(iph, rule, flow->direction, flow->in, flow->out)) < 0)
            goto next_pass_rule;
        else if (res > 0)
            pass = 1;

        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
            if ((res = ipfi_tcp_filter(th, rule)) < 0)
                goto next_pass_rule;
            else if (res > 0)
                pass = 1;
        }
        else if (iph->protocol == IPPROTO_UDP)
        {
            struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
            if ((res = udp_filter(uh, rule)) < 0)
                goto next_pass_rule;
            else if (res > 0)
                pass = 1;
        }
        else if (iph->protocol == IPPROTO_ICMP) {
            struct icmphdr *ih = (struct icmphdr *)((void *)iph + iph->ihl * 4);
            if ((res = icmp_filter(ih, rule)) < 0)
                goto next_pass_rule;
            else if (res > 0)
                pass = 1;
        }

        if(pass > 0)
        {
            response.state = 0U;
            response.verdict = IPFI_ACCEPT;
            response.notify = rule->notify;
            response.rule_id = rule->rule_id;
        }

        if ((pass > 0) && ((rule->state) || (ipfi_opts->all_stateful)) && (ipfi_opts->state)) {
            if (flow->direction == IPFI_INPUT || flow->direction == IPFI_OUTPUT || flow->direction == IPFI_FWD)  {
                newtable = keep_state(skb, rule, flow);
                response.state = 1U;
            }
        }
        if (pass > 0) {
            rcu_read_unlock();
            if(newtable != NULL) {
                add_state_table_to_list(newtable);
            }
            if(mangle_skb(&rule->pkmangle, skb, flow, 0) < 0) {
                IPFI_PRINTK("IPFIRE: ipfire_filter(): MSS mangle failed for rule\n");
            }
            return response;
        }
next_pass_rule:;
    }
    rcu_read_unlock();
    return response;
}

struct state_table* keep_state(const struct sk_buff *skb,
                               const ipfire_rule* p_rule,
                               const ipfi_flow *flow)
{
    ipfire_info_t *ipfi_info_warn;
    if(p_rule == NULL)
        return NULL;

    if (state_tables_counter == max_state_entries)
    {
        ipfi_info_warn = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_ATOMIC);
        if(ipfi_info_warn != NULL)
        {
            memset(ipfi_info_warn, 0, sizeof(ipfire_info_t));
            ipfi_info_warn->flags.state_max_entries = 1;
            struct sk_buff *skbi = build_info_t_packet(ipfi_info_warn);
            if(skbi != NULL && skb_send_to_user(skbi, LISTENER_DATA) < 0)
                IPFI_PRINTK("IPFIRE: error notifying maximum number of state entries to user\n");
            else if(skbi == NULL)
                IPFI_PRINTK("IPFIRE: failed to allocate socket buffer space in keep_state()\n");
            kfree(ipfi_info_warn);
        }
        else
            IPFI_PRINTK("IPFIRE: memory allocation error in keep_state, ipfi_machine.c\n");

        IPFI_PRINTK("IPFIRE: reached maximum count for STATE entries: %u\n",state_tables_counter);
        return NULL;
    }
    struct state_table *state_t = (struct state_table *) kmalloc(sizeof(struct state_table), GFP_ATOMIC);
    memset(state_t, 0, sizeof(struct state_table));
    if (fill_net_table_fields(state_t, skb, flow) < 0) {
        IPFI_PRINTK("IPFIRE: fill_net_table_fields failed, ipfi_machine.c\n");
        kfree(state_t);
        return NULL;
    }
    else if (set_state(skb, state_t, 0) < 0)
    {
        IPFI_PRINTK("IPFIRE: invalid state when adding new state entry!\n");
        kfree(state_t);
        return NULL;
    }
    if(p_rule->nflags.ftp) {
        state_t->ftp = FTP_LOOK_FOR;
    }
    state_t->rule_id = p_rule->rule_id;
    state_t->notify = p_rule->notify;
    state_t->admin = !p_rule->owner;

    return state_t;
}

void fill_state_info(struct state_info *stinfo, const struct state_table* stt)
{
    stinfo->saddr = stt->saddr;
    stinfo->daddr = stt->daddr;
    stinfo->sport = stt->sport;
    stinfo->dport = stt->dport;
    stinfo->protocol = stt->protocol;
    stinfo->state = stt->state;
    stinfo->direction = stt->direction;
    stinfo->ftp = stt->ftp;
}

int get_dev_ifaddr(__u32 * addr, int direction,
                   const struct net_device *in,
                   const struct net_device *out)
{
    switch (direction)
    {
    case IPFI_INPUT:
        if (in && get_ifaddr_by_name(in->name, addr) < 0) {
            IPFI_PRINTK("IPFIRE: direction: input no interface matching name %s!\n",
                        in->name);
            return -1;
        }
        break;
    case IPFI_OUTPUT:
        if (out && get_ifaddr_by_name(out->name, addr) < 0) {
            printk ("IPFIRE: direction: output: no interface matching name %s!\n",
                    out->name);
            return -1;
        }
        break;
    default:
        printk("IPFIRE: cannot get my address for direction %d!\n", direction);
        return -1;
    }
    return 0;
}

int get_ifaddr_by_name(const char *ifname, __u32 * addr)
{
    struct net_device *pnet_device;
    struct in_device *pin_device;
    struct in_ifaddr* inet_ifaddr;

    rcu_read_lock();
    for_each_netdev_rcu(&init_net, pnet_device)
    {
        if ((netif_running(pnet_device))
                && (pnet_device->ip_ptr != NULL)
                && (strcmp(pnet_device->name, ifname) == 0))
        {
            pin_device =
                    (struct in_device *) pnet_device->ip_ptr;
            inet_ifaddr = pin_device->ifa_list;
            if(inet_ifaddr == NULL)
            {
                IPFI_PRINTK("ifa_list is null!\n");
                break;
            }
            *addr = (inet_ifaddr->ifa_local);
            rcu_read_unlock();
            return 1;
        }

    }

    rcu_read_unlock();
    return -1;
}

int add_ftp_dynamic_rule(struct state_table* ftpt)
{
    if (state_tables_counter == max_state_entries)
    {
        IPFI_PRINTK("IPFIRE: reached maximum count for STATE entries "
                    "(adding FTP rule): %u\n", state_tables_counter);
        kfree(ftpt);
        return -1;
    }
    ftpt->state.state = FTP_NEW;

    if(ftpt->ftp != FTP_DEFINED)
    {
        IPFI_PRINTK("IPFIRE: ftp support: you shouldn't be here without FTP_DEFINED set!\n");
        return -1;
    }
    add_state_table_to_list(ftpt);
    return 0;
}

int init_machine(void)
{
    INIT_LIST_HEAD(&root_state_table.list);
    hash_init(state_hashtable);
    register_ipfire_netdev_notifier();
    return 0;
}

void fini_machine(void)
{
    unregister_ipfire_netdev_notifier();
    int ret;
    ret = free_state_tables();
    IPFI_PRINTK("IPFIRE: state tables freed: %d.\n", ret);
    might_sleep();
    rcu_barrier();
}
