/* netlink/netlink_control.c: Netlink control channel for ipfire-wall */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/netlink.h>
#include <linux/user_namespace.h>
#include "ipfi.h"
#include "ipfi_netl.h"
#include "message_builder.h"
#include "ipfi_log.h"
#include "globals.h"

void fill_dnat_info(struct dnat_info *dninfo, const struct dnatted_table *dntt)
{
    dninfo->saddr = dntt->old_saddr;
    dninfo->daddr = dntt->old_daddr;
    dninfo->sport = dntt->old_sport;
    dninfo->dport = dntt->old_dport;
    dninfo->newdport = dntt->new_dport;
    dninfo->newdaddr = dntt->new_daddr;

    dninfo->id = dntt->rule_id;
    dninfo->timeout = (dntt->timer_dnattedlist.expires - jiffies) / HZ;
    dninfo->direction = dntt->direction;
    dninfo->state.state = dntt->state;
    dninfo->in_ifindex = dntt->in_ifindex;
    dninfo->out_ifindex = dntt->out_ifindex;
    dninfo->protocol = dntt->protocol;
}

void fill_snat_info(struct snat_info *sninfo, const struct snatted_table *sntt)
{
    sninfo->saddr = sntt->old_saddr;
    sninfo->daddr = sntt->old_daddr;
    sninfo->sport = sntt->old_sport;
    sninfo->dport = sntt->old_dport;
    sninfo->newsport = sntt->new_sport;
    sninfo->newsaddr = sntt->new_saddr;

    sninfo->id = sntt->rule_id;
    sninfo->timeout = (sntt->timer_snattedlist.expires - jiffies) / HZ;
    sninfo->direction = sntt->direction;
    sninfo->state.state = sntt->state;
    sninfo->in_ifindex = sntt->in_ifindex;
    sninfo->out_ifindex = sntt->out_ifindex;
    sninfo->protocol = sntt->protocol;
}

pid_t get_sender_pid(const struct sk_buff *skbff);

void *extract_data(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int nlmsglen, skblen;
    void *data_pointer;

    skblen = skb->len;
    if (skblen < sizeof(*nlh))
    {
        IPFI_PRINTK("IPFIRE: skblen < sizeof(*nlh) in extract_data()\n");
        return NULL;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    nlh = (struct nlmsghdr *) skb->data;
#else
    nlh = nlmsg_hdr(skb);
#endif
    nlmsglen = nlh->nlmsg_len;
    if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
    {
        IPFI_PRINTK("IPFIRE: nlmsglen < sizeof(*nlh) || skblen < nlmsglen)  in extract_data()\n");
        return NULL;
    }

    data_pointer = NLMSG_DATA(nlh);
    return data_pointer;
}

int process_control_received(struct sk_buff *skb)
{
    uid_t commander;
    short command_id;
    int ret;

    /* We allow messages smaller than sizeof(command) if they contain the shared part.
     * The internal kernel-only fields (list_head and rcu_head) are now at the end.
     */
    if (nlmsg_len(nlmsg_hdr(skb)) < sizeof(command) - sizeof(struct rcu_head) - sizeof(struct list_head))
    {
        IPFI_PRINTK("IPFIRE: process_control_received(): netlink message too small for command (%d < %lu)\n", 
                    nlmsg_len(nlmsg_hdr(skb)), sizeof(command) - sizeof(struct rcu_head) - sizeof(struct list_head));
        return -EINVAL;
    }

    command *cmd_from_user = (command *) extract_data(skb);

    if(cmd_from_user == NULL)
    {
        IPFI_PRINTK("IPFIRE: process_control_received(): error extracting data from socket buffer\n");
        return -1;
    }

    memcpy(&command_id, (short *) cmd_from_user, sizeof(short));

    commander = from_kuid(&init_user_ns, NETLINK_CREDS(skb)->uid);

    if(send_acknowledgement(userspace_control_pid) < 0)
    {
        IPFI_PRINTK("IPFIRE: failed to send acknowledgement to pid %d!! This is strange!\n"
                    "IPFIRE: I will not process the control command!", userspace_control_pid);
        return -1;
    }
    if (command_id == HELLO)
    {
        IPFI_PRINTK("IPFIRE: hello from userspace \"%s\", pid %d, uid %d.\n",  cmd_from_user->content.fwsizes.uspace_firename,
                    userspace_control_pid, cmd_from_user->content.fwsizes.uid);
        return initial_handshake(cmd_from_user, userspace_uid);
    }
    else if (command_id == SIMPLE_GOODBYE)
        return simple_exit();
    else if ((command_id == OPTIONS) & (cmd_from_user->options))
        return set_firewall_options(cmd_from_user, commander);
    else if (command_id == PRINT_RULES)
        return send_rule_list_to_userspace();
    else if (command_id == EXITING)
        return do_userspace_exit_tasks(commander);
    else if(command_id == START_LOGUSER)
    {
        loguser_enabled = 1;
        IPFI_PRINTK("IPFIRE: enabling log to userspace.\n");
        return 0;
    }
    else if(command_id == STOP_LOGUSER)
    {
        loguser_enabled = 0;
        IPFI_PRINTK("IPFIRE: disabling log to userspace.\n");
        return 0;
    }
    else if(command_id == IS_LOGUSER_ENABLED)
    {
        ret = send_loguser_enabled(loguser_enabled);
        return ret;
    }
    else if (command_id == FLUSH_RULES)
    {
        ret = flush_ruleset(commander, FLUSH_RULES);
        tell_user_howmany_rules_flushed(ret);
        return ret;
    } else if (command_id == FLUSH_PERMISSION_RULES)
    {
        ret = flush_ruleset(commander, FLUSH_PERMISSION_RULES);
        tell_user_howmany_rules_flushed(ret);
        return ret;
    }
    else if (command_id == FLUSH_DENIAL_RULES)
    {
        ret = flush_ruleset(commander, FLUSH_DENIAL_RULES);
        tell_user_howmany_rules_flushed(ret);
        return ret;
    }
    else if (command_id == FLUSH_TRANSLATION_RULES)
    {
        ret = flush_ruleset(commander, FLUSH_TRANSLATION_RULES);
        tell_user_howmany_rules_flushed(ret);
        return ret;
    }
    else if (command_id == PRINT_STATE_TABLE)
        return send_tables();

    else if (command_id == PRINT_DNAT_TABLE)
        return send_dnat_tables();
    else if (command_id == PRINT_SNAT_TABLE)
        return send_snat_tables();
    else if(command_id == PRINT_KTABLES_USAGE)
        return send_ktables_usage();

    else if (command_id == KSTATS_REQUEST)
        return send_kstats();
    else if(command_id == KSTATS_LIGHT_REQUEST)
        return send_kstats_light();
    else if(command_id == KSTRUCT_SIZES)
        return send_struct_sizes();
    else if(command_id == SMART_SIMPLE || command_id == SMART_STATE)
        return register_log_function(command_id);
    else if(command_id == SMARTLOG_TYPE)
        return send_smartlog_type();

    else if(command_id == START_NOTIFIER)
    {
        gui_notifier_enabled = 1;
        return 0;
    }
    else if(command_id == STOP_NOTIFIER)
    {
        gui_notifier_enabled = 0;
        return 0;
    }
    else if (cmd_from_user->is_rule)
    {
        if(cmd_from_user->content.rule.owner != commander)
        {
            cmd_from_user->content.rule.owner = commander;
        }
        manage_rule(cmd_from_user);
        return IPFI_ACCEPT;
    }
    else
    {
        IPFI_PRINTK("command id \"%d\" not recognized!\n", command_id);
        return -1;
    }
    return -1;
}

int send_acknowledgement(pid_t uspace_pid)
{
    int ret = -1;
    command *acknow = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(acknow != NULL)
    {
        memset(acknow, 0, sizeof(command) );
        acknow->cmd = ACKNOWLEDGEMENT;
        ret = send_back_command(acknow);
        kfree(acknow);
    }
    return ret;
}

int send_loguser_enabled(int logu_enabled)
{
    int ret = -1;
    command *infologu = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(infologu != NULL)
    {
        memset(infologu, 0, sizeof(command));
        infologu->cmd = IS_LOGUSER_ENABLED;
        infologu->anumber = logu_enabled;
        ret = send_back_command(infologu);
        kfree(infologu);
    }
    return ret;
}

void get_struct_sizes(struct firesizes* fsz)
{
    if(fsz == NULL)
        return;
    fsz->rulesize = sizeof(ipfire_rule);
    fsz->infosize = sizeof(ipfire_info_t);
    fsz->cmdsize = sizeof(command);
    fsz->statesize = sizeof(struct  state_table);
    fsz->snatsize = sizeof(struct snatted_table);
    fsz->dnatsize = sizeof(struct dnatted_table);
    fsz->loginfosize = sizeof(struct ipfire_loginfo);
}

void fill_firesizes_with_kernel_values(command* cmd, size_t krulesize, size_t kinfosize, size_t kcmdsize, uid_t uspace_uid)
{
    struct firesizes fsz = cmd->content.fwsizes;
    fsz.rulesize = krulesize;
    fsz.infosize = kinfosize;
    fsz.cmdsize = kcmdsize;
    fsz.uid = uspace_uid;
}

int initial_handshake(command *hello, uid_t userspace_uid)
{
    int result;
    struct firesizes *kernelsizes;
    struct firesizes fsz = hello->content.fwsizes;
    kernelsizes = (struct firesizes *) kmalloc(sizeof(struct firesizes), GFP_KERNEL);

    if(kernelsizes == NULL)
    {
        IPFI_PRINTK("IPFIRE: failed to allocate memory for struct firesizes in initial_handshake()\n");
        return -1;
    }
    get_struct_sizes(kernelsizes);
    result = HELLO_OK;
    if (fsz.rulesize != kernelsizes->rulesize)
        result = H_RULESIZE_MISMATCH;
    if (fsz.infosize != kernelsizes->infosize)
        result = H_INFOSIZE_MISMATCH;
    if (fsz.cmdsize != kernelsizes->cmdsize)
        result = H_CMDSIZE_MISMATCH;
    
    hello->cmd = result;

    if (result != HELLO_OK)
    {
        IPFI_PRINTK("HELLO FAILED: %d.\n", result);
        fill_firesizes_with_kernel_values(hello, kernelsizes->rulesize,
                                          kernelsizes->infosize, kernelsizes->cmdsize, userspace_uid);
    }

    kfree(kernelsizes);

    if (send_back_command(hello) < 0)
    {
        IPFI_PRINTK("IPFIRE: error sending hello response to userspace!\n");
        return -1;
    }
    return 1;
}

int send_struct_sizes(void)
{
    int ret = -1;
    command *cmdsizes = (command *) kmalloc(sizeof(command), GFP_KERNEL);

    if(cmdsizes != NULL)
    {
        memset(cmdsizes, 0, sizeof(command) );
        get_struct_sizes(&(cmdsizes->content.fwsizes));
        ret = send_back_command(cmdsizes);
        kfree(cmdsizes);
    }
    return ret;
}

int send_smartlog_type(void)
{
    int ret = -1;
    struct sk_buff *to_user;
    command *logtype = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(logtype != NULL)
    {
        memset(logtype, 0, sizeof(command));
        logtype->cmd = SMARTLOG_TYPE;
        logtype->is_rule = 0;
        logtype->anumber = fwopts.loguser;
        to_user = build_command_packet(logtype);
        if(to_user != NULL)
            ret = skb_send_to_user(to_user, CONTROL_DATA);
        kfree(logtype);
    }
    return ret;
}

int set_firewall_options(command *cmd, const uid_t commander)
{
    if (commander == 0)
    {
        check_max_timeout_values(cmd);
        fwopts.nat = cmd->nat;
        fwopts.masquerade = cmd->masquerade;
        fwopts.state = cmd->stateful;
        fwopts.all_stateful = cmd->all_stateful;
        fwopts.user_allowed = cmd->user_allowed;
        fwopts.noflush_on_exit = cmd->noflush_on_exit;
        fwopts.snatted_lifetime = cmd->snatted_lifetime;
        fwopts.dnatted_lifetime = cmd->dnatted_lifetime;
        fwopts.state_lifetime = cmd->state_lifetime;
        fwopts.max_loginfo_entries = cmd->max_loginfo_entries;
        fwopts.loginfo_lifetime = cmd->loginfo_lifetime;
        fwopts.max_nat_entries = cmd->max_nat_entries;
        fwopts.max_state_entries = cmd->max_state_entries;
        state_lifetime = fwopts.state_lifetime;
        setup_shutd_state_lifetime =
                cmd->setup_shutd_state_lifetime;
        fwopts.setup_shutd_state_lifetime =
                cmd->setup_shutd_state_lifetime;
        fwopts.loguser = cmd->loguser;
        loginfo_lifetime = fwopts.loginfo_lifetime;
        max_loginfo_entries = fwopts.max_loginfo_entries;
        max_state_entries = fwopts.max_state_entries;
        fwopts.loglevel = cmd->loglevel;
    }

    if (fwopts.loglevel > 5)
    {
        print_nat_entries_memory_usage();
        print_state_entries_memory_usage();
    }
    register_log_function(fwopts.loguser);

    opts_to_cmd(cmd);
    if (fwopts.loglevel > 2)
        print_command(cmd);
    if (send_back_command(cmd) < 0)
        IPFI_PRINTK("IPFIRE: error sending ack to userspace!\n");
    return IPFI_ACCEPT;
}

int register_log_function(int loglevel)
{
    fwopts.loguser = loglevel;
    switch(loglevel)
    {
    case SMART_LOG:
        smartlog_func = smart_log;
        break;

    case SMART_LOG_WITH_STATE_CHECK:
        smartlog_func = smart_log_with_state_check;
        break;
    default:
        smartlog_func = NULL;
        break;
    }
    return 0;
}

void check_max_timeout_values(command* cmd)
{
    if(cmd->snatted_lifetime > MAX_TIMEOUT)
        cmd->snatted_lifetime = MAX_TIMEOUT;
    if(cmd->dnatted_lifetime > MAX_TIMEOUT)
        cmd->dnatted_lifetime = MAX_TIMEOUT;
    if(cmd->state_lifetime > MAX_TIMEOUT)
        cmd->state_lifetime = MAX_TIMEOUT;
    if(cmd->loginfo_lifetime > MAX_LOGINFO_TIMEOUT)
        cmd->loginfo_lifetime = MAX_LOGINFO_TIMEOUT;
    if(cmd->setup_shutd_state_lifetime > MAX_TIMEOUT)
        cmd->setup_shutd_state_lifetime = MAX_TIMEOUT;
}

void opts_to_cmd(command * cmd)
{
    cmd->nat = fwopts.nat;
    cmd->masquerade = fwopts.masquerade;
    cmd->stateful = fwopts.state;
    cmd->user_allowed = fwopts.user_allowed;
    cmd->snatted_lifetime = fwopts.snatted_lifetime;
    cmd->dnatted_lifetime = fwopts.dnatted_lifetime;
    cmd->state_lifetime = fwopts.state_lifetime;
    cmd->setup_shutd_state_lifetime =
            fwopts.setup_shutd_state_lifetime;
    cmd->noflush_on_exit = fwopts.noflush_on_exit;
    cmd->loglevel = fwopts.loglevel;
    cmd->loguser = fwopts.loguser;
    cmd->max_loginfo_entries = fwopts.max_loginfo_entries;
    cmd->loginfo_lifetime = fwopts.loginfo_lifetime;
    cmd->max_nat_entries = fwopts.max_nat_entries;
    cmd->max_state_entries = max_state_entries;
}

int print_command(const command * opt)
{
    if (opt->nat)
        IPFI_PRINTK("| NAT: ENABLED | ");
    else
        IPFI_PRINTK("| NAT: DISABLED | ");
    if (opt->masquerade)
        IPFI_PRINTK("MASQUERADE: ENABLED | ");
    else
        IPFI_PRINTK("MASQUERADE: DISABLED | ");
    if (opt->stateful)
        IPFI_PRINTK("STATEFUL FIREWALL: ENABLED |\n");
    else
        IPFI_PRINTK("STATEFUL FIREWALL: DISABLED |\n");
    if (opt->user_allowed)
        IPFI_PRINTK("USERS ARE ALLOWED TO INSERT THEIR RULES.\n");
    else
        IPFI_PRINTK("USERS ARE NOT ALLOWED TO INSERT THEIR RULES.\n");
    if (opt->noflush_on_exit)
        IPFI_PRINTK("RULES NOT FLUSHED ON EXIT | ");
    else
        IPFI_PRINTK("RULES FLUSHED ON EXIT | ");
    IPFI_PRINTK("LOGLEVEL: %u | LOGUSER: %u |\n", opt->loglevel,
                opt->loguser);
    return 0;
}

void print_state_entries_memory_usage(void)
{
    IPFI_PRINTK("IPFIRE: state table entries lifetime is %u seconds.\n",
                state_lifetime);
    IPFI_PRINTK("IPFIRE: max. number of entries is %u.\n",
                max_state_entries);
    IPFI_PRINTK("IPFIRE: size of a source nat table is %zu bytes, so"
                " total memory occupied by snat entries is %zu KB.\n",
                sizeof(struct state_table), (max_state_entries *
                                             sizeof(struct state_table)) /
                1024);

}

void print_nat_entries_memory_usage(void)
{
    IPFI_PRINTK("IPFIRE: source nat entries lifetime is %lu seconds.\n",
                fwopts.snatted_lifetime);
    IPFI_PRINTK("IPFIRE: max. number of entries is %lu.\n",
                fwopts.max_nat_entries);
    IPFI_PRINTK("IPFIRE: size of a source nat table is %zu bytes.\nIPFIRE:"
                " total memory occupied by snat entries is %lu KB.\n",
                sizeof(struct snatted_table),
                (unsigned long) ((fwopts.max_nat_entries *
                             sizeof(struct snatted_table)) / 1024));


    IPFI_PRINTK("IPFIRE: destination nat entries lifetime is %lu seconds.\n",
                fwopts.dnatted_lifetime);
    IPFI_PRINTK("IPFIRE: max. number of entries is %lu.\n",
                fwopts.max_nat_entries);
    IPFI_PRINTK("IPFIRE: size of a dest nat table is %zu bytes.\nIPFIRE:"
                " total memory occupied by dnat entries is about %lu KB.\n",
                sizeof(struct dnatted_table),
                (unsigned long) ((fwopts.max_nat_entries *
                             sizeof(struct dnatted_table)) / 1024));

}

void print_loginfo_memory_usage(unsigned long lifetime)
{
    IPFI_PRINTK("IPFIRE: log entry lifetime is %lu seconds, ", lifetime);
    IPFI_PRINTK("max n. of entries is %u\n"
                "IPFIRE: size of an entry is %zu bytes.\nIPFIRE: maximum memory"
                " occupied by log entries is about %lu KB.\n",
                max_loginfo_entries, sizeof(struct ipfire_loginfo),
                (unsigned long) ((max_loginfo_entries * sizeof(struct ipfire_loginfo) / 1024)));

}

int send_rule_list_to_userspace(void)
{
    command *end_list_cmd = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(end_list_cmd == NULL)
        return -1;
    send_a_list(&in_drop);
    send_a_list(&out_drop);
    send_a_list(&fwd_drop);
    send_a_list(&in_acc);
    send_a_list(&out_acc);
    send_a_list(&fwd_acc);
    send_a_list(&translation_pre);
    send_a_list(&translation_out);
    send_a_list(&translation_post);
    send_a_list(&masquerade_post);

    end_list_cmd->cmd = PRINT_FINISHED;
    if (send_back_command(end_list_cmd) < 0)
        IPFI_PRINTK("IPFIRE: error sending end of rules list!\n");
    kfree(end_list_cmd);
    return 0;
}

int send_a_list(ipfire_rule *rlist)
{
    ipfire_rule *tmp = NULL;
    command *cmd = NULL;
    unsigned i = 0;
    list_for_each_entry(tmp, &rlist->list, list)
    {
        i++;
        cmd = (command *) kmalloc(sizeof(command), GFP_KERNEL);
        if(cmd != NULL)
        {
            memset(cmd, 0, sizeof(command));
            cmd->cmd = PRINT_RULES;
            memcpy(&cmd->content.rule, tmp, sizeof(ipfire_rule));
            if (send_back_command(cmd) < 0)
                IPFI_PRINTK("IPFIRE: error sending rule %d to userspace!\n", i);
            kfree(cmd);
        }
    }
    return 0;
}

int send_tables(void)
{
    struct state_table *st;
    struct state_info *endmess;
    struct state_info *st_info;
    struct sk_buff *buf_touser = NULL, *buf_touser_endmess = NULL;

    rcu_read_lock_bh();
    list_for_each_entry_rcu(st, &root_state_table.list, list)
    {
        st_info = (struct state_info *) kmalloc(sizeof(struct state_info), GFP_ATOMIC);
        if(st_info != NULL)
        {
            fill_state_info(st_info, st);
            buf_touser = build_state_info_packet(st_info);
            if (buf_touser != NULL)
                skb_send_to_user(buf_touser, CONTROL_DATA);
            kfree(st_info);
        }
    }
    rcu_read_unlock_bh();

    endmess = (struct state_info *) kmalloc(sizeof(struct state_info), GFP_KERNEL);
    if(endmess != NULL)
    {
        memset(endmess, 0, sizeof(struct state_info));
        endmess->direction = PRINT_FINISHED;
        buf_touser_endmess = build_state_info_packet(endmess);
        if (buf_touser_endmess != NULL)
            skb_send_to_user(buf_touser_endmess, CONTROL_DATA);
        kfree(endmess);
    }
    return 0;
}

int send_dnat_tables(void)
{
    struct dnatted_table *dt;
    struct dnat_info *endmess;
    struct dnat_info *dn_info;
    struct sk_buff *skb_to_user = NULL;

    rcu_read_lock();
    list_for_each_entry_rcu(dt, &root_dnatted_table.list, list)
    {
        dn_info = (struct dnat_info *) kmalloc(sizeof(struct dnat_info), GFP_ATOMIC);
        if(dn_info)
        {
            fill_dnat_info(dn_info, dt);
            skb_to_user = build_dnat_info_packet(dn_info);
            if (skb_to_user != NULL)
                skb_send_to_user(skb_to_user, CONTROL_DATA);
            kfree(dn_info);
        }
    }
    rcu_read_unlock();

    endmess = (struct dnat_info *) kmalloc(sizeof(struct dnat_info), GFP_KERNEL);
    if(endmess != NULL)
    {
        memset(endmess, 0, sizeof(struct dnat_info));
        endmess->direction = PRINT_FINISHED;
        skb_to_user = build_dnat_info_packet(endmess);
        if(skb_to_user != NULL)
            skb_send_to_user(skb_to_user, CONTROL_DATA);
        kfree(endmess);
    }
    return 0;
}

int send_snat_tables(void)
{
    struct snatted_table *st;
    struct snat_info *endmess;
    struct snat_info *sn_info;
    struct sk_buff *skb_to_user = NULL;

    rcu_read_lock();
    list_for_each_entry_rcu(st, &root_snatted_table.list, list)
    {
        sn_info = (struct snat_info *) kmalloc(sizeof(struct snat_info), GFP_ATOMIC);
        if(sn_info != NULL)
        {
            fill_snat_info(sn_info, st);
            skb_to_user = build_snat_info_packet(sn_info);
            if (skb_to_user != NULL)
                skb_send_to_user(skb_to_user, CONTROL_DATA);
            kfree(sn_info);
        }
    }
    rcu_read_unlock();

    endmess = (struct snat_info *) kmalloc(sizeof(struct snat_info), GFP_KERNEL);
    if(endmess != NULL)
    {
        memset(endmess, 0, sizeof(struct snat_info));
        endmess->direction = PRINT_FINISHED;
        skb_to_user = build_snat_info_packet(endmess);
        if (skb_to_user != NULL)
            skb_send_to_user(skb_to_user, CONTROL_DATA);
        kfree(endmess);
    }
    return 0;
}

int send_ktables_usage(void)
{
    struct ktables_usage* ktu;
    struct sk_buff *skb_to_user = NULL;
    int ret = -1;

    ktu = (struct ktables_usage* )kmalloc(sizeof(struct ktables_usage), GFP_KERNEL);
    if(ktu != NULL)
    {
        ktu->state_tables = state_tables_counter;
        ktu->snat_tables = snatted_entry_counter;
        ktu->dnat_tables = dnatted_entry_counter;
        ktu->loginfo_tables = loginfo_entry_counter;
        skb_to_user = build_ktable_info_packet(ktu);
        if(skb_to_user != NULL)
            ret = skb_send_to_user(skb_to_user, CONTROL_DATA);
        kfree(ktu);
    }
    return ret;
}

int tell_user_howmany_rules_flushed(int howmany)
{
    command *cmd = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(cmd != NULL)
    {
        cmd->anumber = 0;
        if (howmany < 0)
            cmd->cmd = ROOT_NOFLUSHED;
        else
        {
            cmd->cmd = FLUSH_RULES;
            cmd->anumber = howmany;
        }
        send_back_command(cmd);
        kfree(cmd);
    }
    return 0;
}

int simple_exit(void)
{
    userspace_control_pid = 0;
    userspace_data_pid = 0;
    IPFI_PRINTK("IPFIRE: received simple exit: resetting counters and"
                " waiting for new connections from userspace.\n");
    return 0;
}

int do_userspace_exit_tasks(uid_t userspace_commander)
{
    ipfire_info_t *ipfi_info_exit = NULL;
    struct sk_buff* skb_touser = NULL;
    int ret = 0;

    if ((userspace_commander == 0) && (fwopts.noflush_on_exit))
    {
        tell_user_howmany_rules_flushed(-1);
        IPFI_PRINTK("IPFIRE: did not flush rules as requested.\n");
    }
    else
    {
        ret = flush_ruleset(userspace_commander, FLUSH_RULES);
        tell_user_howmany_rules_flushed(ret);
    }

    if(gui_notifier_enabled)
    {
        ipfi_info_exit = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_KERNEL);
        if(ipfi_info_exit != NULL)
        {
            memset(ipfi_info_exit, 0, sizeof(ipfire_info_t));
            ipfi_info_exit->flags.exit = 1;
            skb_touser = build_info_t_packet(ipfi_info_exit);
            if(skb_touser != NULL)
                skb_send_to_user(skb_touser, GUI_NOTIF_DATA);
            kfree(ipfi_info_exit);
        }
    }
    userspace_control_pid = 0;
    userspace_data_pid = 0;
    return ret;
}

int send_kstats(void)
{
    int ret = -1;
    struct sk_buff* skbtou;
    struct kernel_stats *ks;
    ks = (struct kernel_stats *)kmalloc(sizeof(struct kernel_stats), GFP_KERNEL);
    if(ks != NULL)
    {
        ipfi_get_total_stats(ks);
        skbtou = build_kstats_packet(ks);
        if(skbtou != NULL)
            ret = skb_send_to_user(skbtou, CONTROL_DATA);
        kfree(ks);
    }
    return ret;
}

int send_kstats_light(void)
{
    int ret = -1;
    struct kstats_light ksl;
    struct sk_buff* skbtou;

    ipfi_get_light_stats(&ksl);
    skbtou = build_kstats_light_packet(&ksl);
    if(skbtou != NULL)
        ret = skb_send_to_user(skbtou, CONTROL_DATA);

    return ret;
}

int send_back_command(const command * cmd)
{
    struct sk_buff *skbtou;
    skbtou = build_command_packet(cmd);
    if(!skbtou)
        return -ENOMEM;
    return skb_send_to_user(skbtou, CONTROL_DATA);
}

int send_back_fw_busy(pid_t pid)
{	
    command *com;
    struct sk_buff *skb;
    int status = -1;
    com = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(com == NULL)
        return status;

    memset(com, 0, sizeof(command));
    com->cmd = ACKNOWLEDGEMENT;
    skb = build_command_packet(com);

    if(skb != NULL)
        status = send_data_to_user(skb, pid, sknl_ipfi_control);
    else
        status = -ENOMEM;

    if (status >= 0)
    {
        com->cmd = IPFIRE_BUSY;
        com->anumber = userspace_control_pid;
        skb = build_command_packet(com);
        if(skb != NULL)
            status = send_data_to_user(skb, pid, sknl_ipfi_control);
        else
            status = -ENOMEM;
    }
    kfree(com);
    return status;
}
