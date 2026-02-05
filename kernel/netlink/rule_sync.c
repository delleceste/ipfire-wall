/* netlink/rule_sync.c: Rule synchronization for ipfire-wall */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include "ipfi.h"
#include "ipfi_netl.h"
#include "ipfi_machine.h"
#include "globals.h"

int add_rule_to_list_by_command(command *cmd_with_rule)
{
    ipfire_rule *newrule;
    newrule = (ipfire_rule *) kmalloc(sizeof(ipfire_rule), GFP_KERNEL);
    if(newrule == NULL || cmd_with_rule == NULL)
        return -1;
    memcpy(newrule, &(cmd_with_rule->content.rule), sizeof(ipfire_rule));

    if (newrule->nflags.indev) {
        struct net_device *dev = dev_get_by_name(&init_net, newrule->devpar.in_devname);
        if (dev) {
            newrule->devpar.in_ifindex = dev->ifindex;
            dev_put(dev);
        } else {
            newrule->devpar.in_ifindex = -1;
        }
    }
    if (newrule->nflags.outdev) {
        struct net_device *dev = dev_get_by_name(&init_net, newrule->devpar.out_devname);
        if (dev) {
            newrule->devpar.out_ifindex = dev->ifindex;
            dev_put(dev);
        } else {
            newrule->devpar.out_ifindex = -1;
        }
    }

    INIT_LIST_HEAD(&newrule->list);
    spin_lock(&rulelist_lock);

    if (newrule->direction == IPFI_INPUT)
    {
        if (newrule->nflags.policy == ACCEPT)
            list_add_tail_rcu(&(newrule->list), &in_acc.list);
        else
            list_add_tail_rcu(&(newrule->list), &in_drop.list);
    }
    else if (newrule->direction == IPFI_OUTPUT)
    {
        if (newrule->nflags.policy == ACCEPT)
            list_add_tail_rcu(&(newrule->list), &out_acc.list);
        else if (newrule->nflags.policy == TRANSLATION)
        {
            if (newrule->owner == 0)
                list_add_tail_rcu(&(newrule->list), &translation_out.list);
        }
        else
            list_add_tail_rcu(&(newrule->list), &out_drop.list);
    }
    else if (newrule->direction == IPFI_FWD)
    {
        if (newrule->nflags.policy == ACCEPT)
            list_add_tail_rcu(&(newrule->list), &fwd_acc.list);
        else
            list_add_tail_rcu(&(newrule->list), &fwd_drop.list);
    }
    else if (newrule->direction == IPFI_INPUT_PRE && newrule->nat)
    {
        if (newrule->owner == 0)
            list_add_tail_rcu(&newrule->list, &translation_pre.list);
    }
    else if ((newrule->direction == IPFI_OUTPUT_POST) && ((newrule->nat) || (newrule->masquerade)))
    {
        if (newrule->owner == 0) {
            if (newrule->nat & newrule->snat)
                list_add_tail_rcu(&newrule->list, &translation_post.list);
            else if (newrule->masquerade)
                list_add_tail_rcu(&newrule->list, &masquerade_post.list);
        }
    }
    spin_unlock(&rulelist_lock);
    return 0;
}

int rule_not_loaded(const command* cmd)
{
    ipfire_rule *newrule = (ipfire_rule *) kmalloc(sizeof(ipfire_rule), GFP_KERNEL);
    if(newrule == NULL)
        return 0;
    memcpy(newrule, &(cmd->content.rule), sizeof(ipfire_rule));

    if (!find_rules(&in_acc, newrule) || !find_rules(&in_drop, newrule) ||
        !find_rules(&fwd_drop, newrule) || !find_rules(&fwd_acc, newrule) ||
        !find_rules(&out_acc, newrule) || !find_rules(&out_drop, newrule) ||
        !find_rules(&translation_pre, newrule) || !find_rules(&translation_post, newrule) ||
        !find_rules(&translation_out, newrule) || !find_rules(&masquerade_post, newrule))
    {
        kfree(newrule);
        return 0;
    }
    kfree(newrule);
    return 1;
}

int find_rules(const ipfire_rule *rlist, const ipfire_rule * rule)
{
    ipfire_rule *tmp;
    int len = sizeof(deviceparams) + sizeof(ipparams) +
            sizeof(transparams) + sizeof(icmp_params) +
            sizeof(netflags) + sizeof(meanings) +
            sizeof(u8) + sizeof(u32) + sizeof(u16) +
            sizeof(struct packet_manip);

    rcu_read_lock();
    list_for_each_entry_rcu(tmp, &rlist->list, list)
    {
        if (memcmp(tmp, rule, len) == 0)
        {
            rcu_read_unlock();
            return 0;
        }
    }
    rcu_read_unlock();
    return -1;
}

int manage_rule(command * rule_from_user)
{
    short add = 0;
    uid_t rule_owner;
    if(rule_from_user == NULL)
        return -1;
    rule_owner = rule_from_user->content.rule.owner;

    if ((rule_owner != 0) && (!fwopts.user_allowed))
        rule_from_user->cmd = RULE_NOT_ADDED_NO_PERM;
    else if (rule_not_loaded(rule_from_user))
        add = 1;
    else
        rule_from_user->cmd = RULE_ALREADY_PRESENT;

    if (send_back_command(rule_from_user) < 0)
        return -1;

    if (add > 0)
        add_rule_to_list_by_command(rule_from_user);
    return 0;
}

void update_ifindex_in_rules(const char *name, int new_index)
{
    ipfire_rule *roots[] = {&in_acc, &in_drop, &out_acc, &out_drop, &fwd_acc, &fwd_drop,
                            &translation_pre, &translation_post, &translation_out, &masquerade_post};
    int i;
    ipfire_rule *rule;

    spin_lock(&rulelist_lock);
    for (i = 0; i < 10; i++) {
        list_for_each_entry(rule, &roots[i]->list, list) {
            if (rule->nflags.indev && strcmp(rule->devpar.in_devname, name) == 0)
                rule->devpar.in_ifindex = new_index;
            if (rule->nflags.outdev && strcmp(rule->devpar.out_devname, name) == 0)
                rule->devpar.out_ifindex = new_index;
        }
    }
    spin_unlock(&rulelist_lock);
}

int flush_ruleset(uid_t userspace_commander, int flush_com)
{
    unsigned l = 0, m = 0, n = 0, o = 0, p = 0,
            q = 0, r = 0, s = 0, t = 0, u = 0;

    if ((flush_com == FLUSH_RULES) || (flush_com == FLUSH_DENIAL_RULES))
    {
        l = free_rules(&in_drop, userspace_commander);
        m = free_rules(&out_drop, userspace_commander);
        n = free_rules(&fwd_drop, userspace_commander);
        
        if (flush_com == FLUSH_DENIAL_RULES) {
            free_state_tables();
        }
    }
    if ((flush_com == FLUSH_RULES) || (flush_com == FLUSH_PERMISSION_RULES))
    {
        o = free_rules(&in_acc, userspace_commander);
        p = free_rules(&out_acc, userspace_commander);
        q = free_rules(&fwd_acc, userspace_commander);
    }
    if (((flush_com == FLUSH_RULES) || (flush_com == FLUSH_TRANSLATION_RULES)) && (userspace_commander == 0))
    {
        r = free_rules(&translation_pre, 0);
        s = free_rules(&translation_out, 0);
        t = free_rules(&translation_post, 0);
        u = free_rules(&masquerade_post, 0);
    }
    return l + m + n + o + q + p + r + s + t + u;
}

void free_rule_rcu_call(struct rcu_head* head)
{
    ipfire_rule* ipfirule_entry = container_of(head, ipfire_rule, rule_rcuh);
    kfree(ipfirule_entry);
}

int free_rules(ipfire_rule *rulelist, uid_t user)
{
    int rules_freed = 0;
    ipfire_rule *rule;
    spin_lock(&rulelist_lock);
    list_for_each_entry(rule, &rulelist->list, list)
    {
        if ((rule->owner == user) || (user == 0))
        {
            list_del_rcu(&rule->list);
            call_rcu(&rule->rule_rcuh, free_rule_rcu_call);
            rules_freed++;
        }
    }
    spin_unlock(&rulelist_lock);
    return rules_freed;
}
