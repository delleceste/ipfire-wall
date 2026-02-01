/* ipfi_netl.c: netlink sockets manage kernel/user communication */ 

/***************************************************************************
 *  Copyright  2005  Giacomo S.
 *  jacum@libero.it
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */
/* see ipfi.c for details */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/notifier.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/list.h>
#include <linux/user_namespace.h>

#include "includes/ipfi.h"
#include "includes/ipfi_netl.h"
#include "includes/ipfi_translation.h"
#include "includes/ipfi_netl_packet_builder.h"
#include "includes/ipfi_mangle.h"

/* variables shared with ipfi module */
static struct sock *sknl_ipfi_control;
static struct sock *sknl_ipfi_data;
static struct sock *sknl_ipfi_gui_notifier;

pid_t userspace_control_pid;
pid_t userspace_data_pid;
uid_t userspace_uid;

static int command_counter = 0;
static int rule_counter = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static void nl_receive_control(struct sk_buff* skb);
static void nl_receive_data(struct sk_buff* skb);
#else
static void nl_receive_control(struct sock *sk, int len);
static void nl_receive_data(struct sock *sk, int len);
#endif

static int create_control_socket(void);
static int create_data_socket(void);

static unsigned long long int in_sent_touser = 0;
static unsigned long long int out_sent_touser = 0;
static unsigned long long int fwd_sent_touser = 0;
static unsigned long long int pre_sent_touser = 0;
static unsigned long long int post_sent_touser = 0;

unsigned int moderate_print[MAXMODERATE_ARGS];
unsigned int moderate_print_limit[MAXMODERATE_ARGS];

short default_policy = IPFIRE_DEFAULT_POLICY;

/* Determines if the user interface wants to receive responses 
 * on packets
 */
short loguser_enabled = 1;

short gui_notifier_enabled = 0;

struct kernel_stats kstats;
struct kstats_light kslight;

/* Lock ruleset before adding/deleting an item.
 * Spinlock is dynamically initialized at module
 * load time. */
spinlock_t rulelist_lock;

ipfire_rule in_drop;
ipfire_rule out_drop;
ipfire_rule fwd_drop;
ipfire_rule in_acc;
ipfire_rule out_acc;
ipfire_rule fwd_acc;
ipfire_rule translation_pre;
ipfire_rule translation_post;
ipfire_rule translation_out;
ipfire_rule masquerade_post;

struct dnatted_table root_dnatted_table;
struct snatted_table root_snatted_table;

extern unsigned long loginfo_lifetime;
extern unsigned long max_loginfo_entries;
extern unsigned long state_lifetime;
extern unsigned long setup_shutd_state_lifetime;

extern unsigned long max_state_entries;

struct ipfire_options fwopts;

int (*smartlog_func) (const ipfire_info_t * info);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif

static int create_control_socket(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
    sknl_ipfi_control =
            netlink_kernel_create(NETLINK_IPFI_CONTROL,
                                  nl_receive_control);

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) 
    sknl_ipfi_control = netlink_kernel_create(NETLINK_IPFI_CONTROL, 0, nl_receive_control, THIS_MODULE);

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    sknl_ipfi_control = netlink_kernel_create(NETLINK_IPFI_CONTROL, 0,
                                              nl_receive_control, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
    sknl_ipfi_control = netlink_kernel_create(&init_net, NETLINK_IPFI_CONTROL, 0, nl_receive_control, NULL, THIS_MODULE);
#else
    struct netlink_kernel_cfg netlink_cfg;
    netlink_cfg.groups = 0;
    netlink_cfg.flags = 0;
    netlink_cfg.input = nl_receive_control;
    netlink_cfg.bind = NULL;
    sknl_ipfi_control = netlink_kernel_create(&init_net, NETLINK_IPFI_CONTROL, &netlink_cfg);

#endif

    userspace_control_pid = 0;
    if (sknl_ipfi_control == NULL)
    {
        IPFI_PRINTK("IPFIRE: create_socket(): failed to create netlink control socket\n");
        return -1;
    }
    return 0;
}

static int create_data_socket(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
    sknl_ipfi_data =
            netlink_kernel_create(NETLINK_IPFI_DATA, nl_receive_data);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    sknl_ipfi_data =
            netlink_kernel_create(NETLINK_IPFI_DATA, 0, nl_receive_data,
                                  THIS_MODULE);

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

    sknl_ipfi_data = netlink_kernel_create(NETLINK_IPFI_DATA, 0, nl_receive_data, NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
    sknl_ipfi_data = netlink_kernel_create(&init_net, NETLINK_IPFI_DATA, 0, nl_receive_data, NULL, THIS_MODULE);
#else
    struct netlink_kernel_cfg netlink_cfg;
    netlink_cfg.groups = 0;
    netlink_cfg.flags = 0;
    netlink_cfg.input = nl_receive_data;
    netlink_cfg.bind = NULL;
    sknl_ipfi_data = netlink_kernel_create(&init_net, NETLINK_IPFI_DATA, &netlink_cfg);
#endif

    userspace_data_pid = 0;
    if (sknl_ipfi_data == NULL)
    {
        printk ("IPFIRE: create_socket(): failed to create netlink data socket\n");
        return -1;
    }
    return 0;
}

/* The NETLINK_IPFI_GUI_NOTIFIER socket has a NULL callback because it never receives
 * data from the userspace.
 * It only sends to the GUI a notification for blocked (explicitly or implicitly) packets
 * if it has been allocated.
 */
static int create_gui_notifier_socket(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
    sknl_ipfi_gui_notifier =
            netlink_kernel_create(NETLINK_IPFI_GUI_NOTIFIER, NULL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    sknl_ipfi_gui_notifier = netlink_kernel_create(NETLINK_IPFI_GUI_NOTIFIER, 0, NULL,  THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

    sknl_ipfi_gui_notifier = netlink_kernel_create(NETLINK_IPFI_GUI_NOTIFIER, 0, NULL,  NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
    sknl_ipfi_gui_notifier = netlink_kernel_create(&init_net, NETLINK_IPFI_GUI_NOTIFIER, 0, NULL,  NULL, THIS_MODULE);
#else
    struct netlink_kernel_cfg netlink_cfg;
    netlink_cfg.groups = 0;
    netlink_cfg.flags = 0;
    netlink_cfg.input = NULL;
    netlink_cfg.bind = NULL;
    sknl_ipfi_gui_notifier = netlink_kernel_create(&init_net, NETLINK_IPFI_GUI_NOTIFIER, &netlink_cfg);
#endif
    userspace_data_pid = 0;
    if (sknl_ipfi_gui_notifier == NULL)
    {
        IPFI_PRINTK("IPFIRE: create_socket(): failed to create netlink gui notifier socket\n");
        return -1;
    }
    return 0;
}

static inline void *extract_data(struct sk_buff *skb)
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
    return data_pointer;	/* pointer to data contained in nlh */
}

/* sends an acknowledgement to userspace program 
 * before actuating a command */
inline int send_acknowledgement(pid_t uspace_pid)
{
    int ret = -1;
    command *acknow = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(acknow != NULL)
    {
        memset(acknow, 0, sizeof(command) );
        acknow->cmd = ACKNOWLEDGEMENT;
        ret = send_back_command(acknow);
        kfree(acknow); /* FREE memory */
    }
    return ret;
}

/* This one tells userspace if loguser is enabled or disabled */
inline int send_loguser_enabled(int logu_enabled)
{
    int ret = -1; /* -1 is to return in case of memory allocation failure or send_back_command() failure */
    command *infologu = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(infologu != NULL) /* good */
    {
        memset(infologu, 0, sizeof(command));
        infologu->cmd = IS_LOGUSER_ENABLED;
        infologu->anumber = logu_enabled;
        ret = send_back_command(infologu);
        /* free allocated memory */
        kfree(infologu);
    }
    return ret; /* -1 or result from send_back_command() */
}

/* This one processes the data received on the control socket, i.e. 
 * main userspace control.
 * The function nl_received_control, which precedes this one, checks
 * the pid stored in the socket buffer and the pid declared inside
 * the netlink header.
 * skb is freed by the caller.
 */
int process_control_received(struct sk_buff *skb)
{
    uid_t commander;
    short command_id;
    int ret;/* a return value */

    /* cmd_from_user lives in the skb memory area and so it is available until
     * skb is available. This means until nl_receive_control() kfrees (skb).
     */
    command *cmd_from_user = (command *) extract_data(skb);

    if(cmd_from_user == NULL)
    {
        IPFI_PRINTK("IPFIRE: process_control_received(): error extracting data from socket buffer\n");
        return -1;
    }

    /* trick to get the first 2 bytes (sizeof short) of the structure received,
     * which contain the field cmd. If you look at command struct, you
     * will notice that it is put at the first position. So, also in case of
     * command size mismatch, we can decode cmd! */
    memcpy(&command_id, (short *) cmd_from_user, sizeof(short));

    /* get the commander from the netlink socket buffer credentials.
     * Since the kernel 2.6.18, the symbol tasklist_lock is no more
     * exported. For this reason, we cannot list the tasks and
     * obtain the user id of the userspace process as it was before.
     * So we trust NETLINK_CREDS stored inside the netlink socket
     * buffer. */
    commander = from_kuid(&init_user_ns, NETLINK_CREDS(skb)->uid);

    /* another level of security: send an acknowledgement to the
     * userspace program: if it fails, no control is processed */
    if(send_acknowledgement(userspace_control_pid) < 0)
    {
        IPFI_PRINTK("IPFIRE: failed to send acknowledgement to pid %d!! This is strange!\n"
                    "IPFIRE: I will not process the control command!", userspace_control_pid);
        return -1;
    }
    /* 1. we have an OPTION  message */
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
    /* Send state, snat and dnat tables */
    else if (command_id == PRINT_STATE_TABLE)
        return send_tables();

    else if (command_id == PRINT_DNAT_TABLE)
        return send_dnat_tables();
    else if (command_id == PRINT_SNAT_TABLE)
        return send_snat_tables();
    else if(command_id == PRINT_KTABLES_USAGE)
        return send_ktables_usage();

    /* kernel statistics */
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
    {			/* 2. we have a rule to add or delete */
        /* Check if the rule owner is the same user stored
         * inside the socket buffer credentials (i.e. commander):
         */
        if(cmd_from_user->content.rule.owner != commander)
        {
            IPFI_PRINTK("IPFIRE: the owner of the rule [%u] is not the same\n"
                        "IPFIRE: user stored inside the socket buffer [%u]\n"
                        "IPFIRE: Did you try to fool me?? ;)\n"
                        "IPFIRE: Anyway, i will set the user id %u as the owner",
                        cmd_from_user->content.rule.owner, commander, commander);
            /* Be good: correct the owner and go on... */
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
}

/* process data received on data socket, i.e. son userspace process (listener) */
static inline int process_data_received(struct sk_buff *skb)
{
    listener_message *listener_mess = (listener_message *) extract_data(skb);
    if(listener_mess == NULL)
    {
        IPFI_PRINTK("IPFIRE: extract_data() failed to extract a listener message!\n");
        return -1;
    }

    /* 1. we have an OPTION  message */
    if (listener_mess->message == STARTING)
    {
        printk ("IPFIRE: userspace listener son started. PID: %d.\n", userspace_data_pid);
        /* do init tasks */
        return 0;
    }
    /* 2. we have a rule to add or delete */
    else if (listener_mess->message == EXITING)
    {
        IPFI_PRINTK("IPFIRE: userspace listener son exiting.\n");
        return 0;
    }
    return 0;
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
    /* get struct firesizes from cmd, then fill it in */
    struct firesizes fsz = cmd->content.fwsizes;
    fsz.rulesize = krulesize;
    fsz.infosize = kinfosize;
    fsz.cmdsize = kcmdsize;
    fsz.uid = uspace_uid;
}

/* Handshake with userspace program: checks if structure sizes 
 * are correct */
int initial_handshake(command *hello, uid_t userspace_uid)
{
    int result;
    struct firesizes *kernelsizes;
    struct firesizes fsz = hello->content.fwsizes; /* firesizes to check */
    /* here we'll put the reference kernel structures sizes */
    kernelsizes = (struct firesizes *) kmalloc(sizeof(struct firesizes), GFP_KERNEL);

    if(kernelsizes == NULL)
    {
        IPFI_PRINTK("IPFIRE: failed to allocate memory for struct firesizes in initial_handshake()\n");
        return -1;
    }
    /* get reference kernel structures sizes */
    get_struct_sizes(kernelsizes);
    /* optimistically initialize the result */
    result = HELLO_OK;
    /* checks */
    if (fsz.rulesize != kernelsizes->rulesize)
        result = H_RULESIZE_MISMATCH;
    if (fsz.infosize != kernelsizes->infosize)
        result = H_INFOSIZE_MISMATCH;
    if (fsz.cmdsize != kernelsizes->cmdsize)
        result = H_CMDSIZE_MISMATCH;
    //	if (fsz.uid != userspace_uid)
    //	{
    //		result = H_UID_MISMATCH;
    //		IPFI_PRINTK("IPFIRE: UID MISMATCH: credentials (true) say that you are user %u.\n"
    //		"        You say you are user %u (false)! Did thou try to fool me? :)\n", userspace_uid, fsz.uid);
    //	}
    /* result is put in cmd */
    hello->cmd = result;

    if (result != HELLO_OK)
    {
        IPFI_PRINTK("HELLO FAILED: %d.\n", result);
        fill_firesizes_with_kernel_values(hello, kernelsizes->rulesize,
                                          kernelsizes->infosize, kernelsizes->cmdsize, userspace_uid);
    }

    /* firesizes copied in hello, can delete kernelsizes */
    kfree(kernelsizes);

    if (send_back_command(hello) < 0)
    {
        IPFI_PRINTK("IPFIRE: error sending hello response to userspace!\n");
        return -1;
    }
    return 1;
}

/* Sends in userspace the struct sizes */
int send_struct_sizes(void)
{
    int ret = -1;

    /* allocate a a command, aimed at transmitting to user space the data structures sizes. */
    command *cmdsizes = (command *) kmalloc(sizeof(command), GFP_KERNEL);

    if(cmdsizes != NULL) /* both not NULL */
    {
        /* initialize memory with zeros */
        memset(cmdsizes, 0, sizeof(command) );
        /* obtain data structure sizes.
       * Note that we can safely pass &cmdsizes->content.fwsizes because
       * cmdsizes is kmallocated and contains content.fwsizes inside the
       * kmallocated area.
       */
        get_struct_sizes(&(cmdsizes->content.fwsizes));
        /* send to the userspace control socket */
        ret = send_back_command(cmdsizes);
        /* once sent, free the dynamically allocated memory */
        kfree(cmdsizes);
    }
    else
        IPFI_PRINTK("IPFIRE: memory allocation failed inside send_struct_sizes(void)\n");

    return ret;
}

/* Sends in userspace the type of logging to userspace in use.
 * Reads fwopts.
 */
int send_smartlog_type(void)
{
    int ret = -1;
    struct sk_buff *to_user;
    /* dynamically allocate a command structure to send log type */
    command *logtype = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(logtype != NULL) /* good, not null, allocation succeeded */
    {
        memset(logtype, 0, sizeof(command));
        logtype->cmd = SMARTLOG_TYPE;
        logtype->is_rule = 0;
        logtype->anumber = fwopts.loguser;
        /* create socket buffer with the command as data */
        to_user = build_command_packet(logtype);
        if(to_user != NULL) /* allocation succeeded */
            ret = skb_send_to_user(to_user, CONTROL_DATA);
        kfree(logtype); /* free memory */
    }
    return ret; /* -1 if allocation failed or skb_send_to_user() return value otherwise */
}

/** sets various options related to firewall behaviour, as specified by
 * command received from userspace.
 * @param cmd must be kmallocated.
 */
int set_firewall_options(command *cmd, const uid_t commander)
{
    command_counter++;
    /* by default, user is allowed to insert his rules. See
     * comment in init_options */
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
    /* register smartlog funcion if required */
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
        if (smartlog_func != NULL)
            IPFI_PRINTK("IPFIRE: unregistering smart_log() function\n");
        smartlog_func = NULL;
        break;
    }
    return 0;
}

/* checks if timeouts are too high and, if so, sets them to the
 * maximum value allowed.
 * In 32 bit architecture, maximum value for timeouts is
 * 2^32/2/HZ, see ipfi_netl.h near the definition of
 * MAX_TIMEOUT.
 */
void check_max_timeout_values(command* cmd)
{
    if(cmd->snatted_lifetime > MAX_TIMEOUT)
    {
        IPFI_PRINTK("IPFIRE: snat timeout %lu too high: "
                    "setting to maximum allowed: %lu\n",
                    cmd->snatted_lifetime, MAX_TIMEOUT);
        cmd->snatted_lifetime = MAX_TIMEOUT;
    }
    if(cmd->dnatted_lifetime > MAX_TIMEOUT)
    {
        IPFI_PRINTK("IPFIRE: dnat timeout %lu too high: "
                    "setting to maximum allowed: %lu\n",
                    cmd->dnatted_lifetime, MAX_TIMEOUT);
        cmd->dnatted_lifetime = MAX_TIMEOUT;
    }
    if(cmd->state_lifetime > MAX_TIMEOUT)
    {
        IPFI_PRINTK("IPFIRE: state timeout %lu too high: "
                    "setting to maximum allowed: %lu\n",
                    cmd->state_lifetime, MAX_TIMEOUT);
        cmd->state_lifetime = MAX_TIMEOUT;
    }
    if(cmd->loginfo_lifetime > MAX_LOGINFO_TIMEOUT)
    {
        IPFI_PRINTK("IPFIRE: state timeout %lu too high: "
                    "setting to maximum allowed: %lu\n",
                    cmd->loginfo_lifetime, MAX_LOGINFO_TIMEOUT);
        cmd->loginfo_lifetime = MAX_LOGINFO_TIMEOUT;
    }
    if(cmd->setup_shutd_state_lifetime > MAX_TIMEOUT)
    {
        IPFI_PRINTK("IPFIRE: state setup/shutdown timeout %lu too high: "
                    "setting to maximum allowed: %lu\n",
                    cmd->setup_shutd_state_lifetime, MAX_TIMEOUT);
        cmd->setup_shutd_state_lifetime = MAX_TIMEOUT;
    }

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
    cmd->loguser = fwopts.loguser;
    cmd->max_state_entries = max_state_entries;
}

int add_rule_to_list_by_command(command *cmd_with_rule)
{
    ipfire_rule *newrule;
    /* allocate the new rule */
    newrule = (ipfire_rule *) kmalloc(sizeof(ipfire_rule), GFP_KERNEL);
    if(newrule == NULL || cmd_with_rule == NULL)
    {
        IPFI_PRINTK("IPFIRE: command passed to add_rule_to_list_by_command() is NULL or unable to allocate memory for new rule!\n");
        return -1;
    }
    /* memory allocation is ok, proceed with filling in the new rule.
     * Take the source rule from the command cmd_with_rule's rule
     */
    memcpy(newrule, &(cmd_with_rule->content.rule), sizeof(ipfire_rule));

    INIT_LIST_HEAD(&newrule->list);

    /* Lock list while adding */
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
        /* Destination NAT for locally generated packets */
        else if (newrule->nflags.policy == TRANSLATION)
        {
            if (newrule->owner != 0)
                IPFI_PRINTK("IPFIRE: only root can modify translation list, not user %d.\n",  newrule->owner);
            else
                list_add_tail_rcu(&(newrule->list), &translation_out.list);
        }
        else	/* DENIAL or BLACKSITE */
            list_add_tail_rcu(&(newrule->list), &out_drop.list);
    }
    else if (newrule->direction == IPFI_FWD)
    {
        if (newrule->nflags.policy == ACCEPT)
            list_add_tail_rcu(&(newrule->list), &fwd_acc.list);
        else
            list_add_tail_rcu(&(newrule->list), &fwd_drop.list);
    }
    /* Destination NAT */
    else if (newrule->direction == IPFI_INPUT_PRE && newrule->nat)
    {
        if (newrule->owner != 0)
            IPFI_PRINTK("IPFIRE: only root can modify translation list, not user %d.\n", newrule->owner);
        else
            list_add_tail_rcu(&newrule->list, &translation_pre.list);
    }
    /* Source NAT or MASQUERADING */
    else if ((newrule->direction == IPFI_OUTPUT_POST) && ((newrule->nat) || (newrule->masquerade)))
    {
        if (newrule->owner != 0)
            IPFI_PRINTK("IPFIRE: only root can modify translation list, not user %d.\n", newrule->owner);
        else if (newrule->nat & newrule->snat)
            list_add_tail_rcu(&newrule->list, &translation_post.list);
        else if (newrule->masquerade)
            list_add_tail_rcu(&newrule->list, &masquerade_post.list);
    }
    else if(newrule->direction == 0)
        IPFI_PRINTK("IPFIRE: rule %d not added: missing direction!\n", newrule->position);

    spin_unlock(&rulelist_lock);
    return 0;
}

int rule_not_already_loaded(const command* cmd)
{
    ipfire_rule *newrule = (ipfire_rule *) kmalloc(sizeof(ipfire_rule), GFP_KERNEL);
    if(newrule == NULL)
    {
        IPFI_PRINTK("IPFIRE: failed to allocate space for an ipfire_rule structure inside rule_not_already_loaded()\n");
        return 0; /* memory problems. Do not add rule */
    }
    /* newrule is not null
   * a. copy the contents of the rule in cmd to newrule; */
    memcpy(newrule, &(cmd->content.rule), sizeof(ipfire_rule));

    /* watch in the list for a rule already present */
    if (!find_rules_in_list(&in_acc, newrule)) /* one found */
    {
        kfree(newrule); /* free newrule */
        return 0;  /* return we have found */
    }
    if (!find_rules_in_list(&in_drop, newrule))
    {
        kfree(newrule);
        return 0;
    }
    if (!find_rules_in_list(&fwd_drop, newrule))
    {
        kfree(newrule);
        return 0;
    }
    if (!find_rules_in_list(&fwd_acc, newrule))
    {
        kfree(newrule);
        return 0;
    }
    if (!find_rules_in_list(&out_acc, newrule))
    {
        kfree(newrule);
        return 0;
    }
    if (!find_rules_in_list(&out_drop, newrule))
    {
        kfree(newrule);
        return 0;
    }
    if (!find_rules_in_list(&translation_pre, newrule))
    {
        kfree(newrule);
        return 0;
    }
    if (!find_rules_in_list(&translation_post, newrule))
    {
        kfree(newrule);
        return 0;
    }
    if (!find_rules_in_list(&translation_out, newrule))
    {
        kfree(newrule);
        return 0;
    }
    if (!find_rules_in_list(&masquerade_post, newrule))
    {
        kfree(newrule);
        return 0;
    }
    /* not present, nor returned yet: free memory and return != 0 */

    kfree(newrule);
    return 1;
}

int find_rules_in_list(const ipfire_rule *rlist, const ipfire_rule * rule)
{
    ipfire_rule *tmp;
    unsigned i = 0;
    /* tail of structure, whose fields do not have to be
     * compared */
    int len = sizeof(deviceparams) + sizeof(ipparams) +
            sizeof(transparams) + sizeof(icmp_params) +
            sizeof(netflags) + sizeof(meanings) +
            sizeof(u8) + sizeof(u32) + sizeof(u16) +
            sizeof(struct packet_manip);

    rcu_read_lock(); 	/* Lock search */

    /* include/linux/rculist.h: list_for_each_entry_rcu(pos, head, member)
      * list_for_each_entry_rcu	-	iterate over rcu list of given type
      * @pos:	the type * to use as a loop cursor.
      * @head:	the head for your list.
      * @member:	the name of the list_struct within the struct.
      *
      * This list-traversal primitive may safely run concurrently with
      * the _rcu list-mutation primitives such as list_add_rcu()
      * as long as the traversal is guarded by rcu_read_lock().
      */
    list_for_each_entry_rcu(tmp, &rlist->list, list)
    {
        i++;
        if (memcmp(tmp, rule, len) == 0)
        {
            rcu_read_unlock();	/* Unlock */
            return 0;
        }
    }
    rcu_read_unlock();  /* Unlock */
    return -1;		/* no match */
}

int manage_rule(command * rule_from_user)
{
    short add = 0;
    uid_t rule_owner;
    if(rule_from_user == NULL)
    {
        IPFI_PRINTK("IPFIRE: failed to allocate memory space needed by a rule object in manage_rule()\n");
        return -1;
    }
    rule_counter++;
    rule_owner = rule_from_user->content.rule.owner;

    if ((rule_owner != 0) && (!fwopts.user_allowed))
    {
        IPFI_PRINTK("IPFIRE: user %u does not have the rights to insert rules.\n", rule_owner);
        rule_from_user->cmd = RULE_NOT_ADDED_NO_PERM;
    }
    else if (rule_not_already_loaded(rule_from_user)) /* we will add rule */
    {
        add = 1;
    }
    else			/* tell userspace that such rule is already present */
    {
        rule_from_user->cmd = RULE_ALREADY_PRESENT;
    }

    /* always send feedback to userspace */
    if (send_back_command(rule_from_user) < 0)
    {
        /* for security reasons, if we fail to send back ack, we don't add
         * rule */
        IPFI_PRINTK("IPFIRE: Error sending ack to userspace! Rule will not be added!\n");
        return -1;
    }

    /* add rule to list, if ok */
    if (add > 0)
        add_rule_to_list_by_command(rule_from_user);
    return 0;
}

/* sends to userspace the passef kernel_stats structure */
int send_kstats()
{
    /* send stats to control socket, i.e. the one in parent userspace
     * process */
    int ret = -1;
    struct sk_buff* skbtou;
    struct kernel_stats *ks;
    ks = (struct kernel_stats *)kmalloc(sizeof(struct kernel_stats), GFP_KERNEL);
    if(ks != NULL)
    {
        memcpy(ks, &kstats, sizeof(struct kernel_stats));
        skbtou = build_kstats_packet(ks);
        if(skbtou != NULL)
        {
            ret = skb_send_to_user(skbtou, CONTROL_DATA);
        }
        kfree(ks);
    }
    return ret;
}

/* sends to userspace the passef kernel_stats light structure */
int send_kstats_light()
{
    /* send stats to control socket, i.e. the one in parent userspace
     * process */
    int ret = -1;
    struct kstats_light *ksl;
    struct sk_buff* skbtou;

    ksl = (struct kstats_light *) kmalloc(sizeof(struct kstats_light), GFP_KERNEL);
    if(ksl != NULL)
    {
        memcpy(ksl, &kslight, sizeof(struct kstats_light));
        skbtou = build_kstats_light_packet(ksl);
        if(skbtou != NULL)
            ret = skb_send_to_user(skbtou, CONTROL_DATA);
        kfree(ksl);
    }
    return ret;
}

/* send back to userspace the new command received as an acknowledgement */
int send_back_command(const command * cmd)
{
    /* send back command to control socket, i.e. the one allocated in parent
     * userspace process.
     */
    struct sk_buff *skbtou;
    skbtou = build_command_packet(cmd);
    if(!skbtou)
    {
        IPFI_PRINTK("IPFIRE: error allocating memory for socket buffer in send_back_command()\n");
        return -ENOMEM;
    }
    return skb_send_to_user(skbtou, CONTROL_DATA);
}

/** @return error code or success code from netlink_unicast()
 *
 * @param skb kmallocated socket buffer, filled with data to send to userspace
 * @param destination_pid process ID of the application in userspace who wants to receive the message
 * @param socket the netlink socket to use to send the message. Can be data, control, GUI notifier.
 */
int send_data_to_user(struct sk_buff *skb, pid_t destination_pid, struct sock *socket)
{
    int ret = -1;
    if(socket != NULL && skb != NULL)
    {
        set_outgoing_skb_params(skb);
        ret = netlink_unicast(socket, skb, destination_pid, MSG_DONTWAIT);
        if(ret < 0)
        {
            IPFI_PRINTK("IPFIRE: netlink_unicast() to pid %d failed with error %d. Errnos in asm-generic/errno-base.h\n", destination_pid, ret);
        }
    }
    else
        IPFI_PRINTK("socket or sk_buff null in send_data_to_user(): socket: 0x%p skb: 0x%p\n", socket, skb);

    return ret;
}

static inline pid_t get_sender_pid(const struct sk_buff *skbff)
{
    int ret = 0;
    pid_t header_pid, credentials_pid;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    struct nlmsghdr *nlh = (struct nlmsghdr *) skbff->data;
#else
    struct nlmsghdr *nlh = nlmsg_hdr(skbff);
#endif
    if(nlh == NULL)
    {
        IPFI_PRINTK("IPFIRE: get_sender_pid(): error extracting nlmsghdr from socket buffer. Cannot determine header pid\n");
        ret = 0;
    }
    else
    {
        header_pid =  nlh->nlmsg_pid;
        if(1)
        {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
            credentials_pid = NETLINK_CB(skbff).pid;
#else
            credentials_pid = NETLINK_CB(skbff).portid;
#endif
            /* first level check: pid got from the netlink header
        * (set by the userspace program) must be equal to the
        * pid got by the netlink credentials.
        */
            if(credentials_pid != header_pid)
            {
                IPFI_PRINTK("IPFIRE: PID mismatch! Did you try to fool me? :)\nIPFIRE: CREDENTIALS PID: %u, HEADER PID: %u\n",
                            credentials_pid, header_pid);
                ret = 0;
            }
            else
                ret = header_pid;
        }
    }
    return ret;
}

void set_outgoing_skb_params(struct sk_buff *skbf)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
    NETLINK_CB(skbf).groups = 0;	/* not in multicast group */
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
    NETLINK_CB(skbf).pid = 0;	/* kernel sending */
#else
    NETLINK_CB(skbf).portid = 0;	/* kernel sending */
#endif

    //	NETLINK_CB(skbf).pid = userspace_control_pid;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
    NETLINK_CB(skbf).dst_groups = 0;	/* unicast */
#else
    NETLINK_CB(skbf).dst_group = 0;
#endif
}

int send_back_fw_busy(pid_t pid)
{	
    command *com;
    struct sk_buff *skb;
    int status = -1;
    /* allocate space for busy command */
    com = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(com == NULL)
    {
        IPFI_PRINTK("IPFIRE: send_back_fw_busy(): Failed to allocate space for the response command\n");
        return status;
    }

    memset(com, 0, sizeof(command));
    /* 1. user waits for an ack */
    com->cmd = ACKNOWLEDGEMENT;
    /* 1a. build command socket buffer for the ACK */
    skb = build_command_packet(com);

    /* 1b. if allocation succeeded, then send the command to userspace, using control socket and destination
     * pid 'pid'.
     */
    if(skb != NULL)
        status = send_data_to_user(skb, pid, sknl_ipfi_control); /* first send */
    else
        status = -ENOMEM;

    if (status >= 0) /* first send successful */
    {
        /* 2. send IPFIRE_BUSY message to tell userspace ipfire-wall to exit */
        com->cmd = IPFIRE_BUSY;
        com->anumber = userspace_control_pid; /* tell userspace the other instance's pid */

        /* 2a. allocate space for skb, which was previously sent and so freed (skb pointer is no more valid) */
        skb = build_command_packet(com);
        if(skb != NULL) /* 2b. send to userspace the control message that will make it exit with an error code */
            status = send_data_to_user(skb, pid, sknl_ipfi_control);
        else
            status = -ENOMEM;
    }

    /* read status and see if one of the send calls failed */
    if(status < 0)
        IPFI_PRINTK("IPFIRE: failed to send firewall busy command to userspace pid %d. Error number: %d (list in asm-generic/errno-base.h)\n", pid, status);
    else
        IPFI_PRINTK("IPFIRE: sent firewall busy to userspace pid %d.\n", pid);

    /* the *com pointer is still allocated: free it now */
    kfree(com);
    return status;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static void nl_receive_control(struct sock *skctrl, int len)
{
    pid_t pid;
    struct sk_buff *skb_ipfi_control = NULL;
    while ((skb_ipfi_control = skb_dequeue(&skctrl->sk_receive_queue)) != NULL)
    {
        pid = get_sender_pid(skb_ipfi_control);
        userspace_uid = NETLINK_CREDS(skb_ipfi_control)->uid;
        if ((userspace_control_pid != 0) && (pid != userspace_control_pid))
            send_back_fw_busy(pid);
        else
        {
            userspace_control_pid = pid;
            process_control_received(skb_ipfi_control);
        }
        /* anyway, free memory */
        kfree_skb(skb_ipfi_control);
    }
}
#else
static void nl_receive_control(struct sk_buff* skb)
{
    pid_t pid;

    pid = get_sender_pid(skb);
    userspace_uid = from_kuid(&init_user_ns, NETLINK_CREDS(skb)->uid);
    if ((userspace_control_pid != 0) &&
            (pid != userspace_control_pid))
        send_back_fw_busy(pid);
    else
    {
        userspace_control_pid = pid;
        process_control_received(skb);
    }
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static void nl_receive_data(struct sock *sk, int len)
{
    struct sk_buff *skb_ipfi_data = NULL;
    while((skb_ipfi_data = skb_dequeue(&sk->sk_receive_queue)) != NULL)
    {
        userspace_data_pid = get_sender_pid(skb_ipfi_data);
        process_data_received(skb_ipfi_data);
        /* free memory */
        kfree_skb(skb_ipfi_data);
    }
}

#else
static void nl_receive_data(struct sk_buff *skb)
{
    userspace_data_pid = get_sender_pid(skb);
    process_data_received(skb);
}
#endif

/* depending on loguser, this function decides if
 * firewall has to send packet info to userspace
 * firewall */
int is_to_send(const struct sk_buff * skb,
               const struct ipfire_options *fwopts,
               const struct response* res,
               const struct info_flags *flags)
{
    if(smartlog_func != NULL)
        return smartlog_func(skb, res, flags);
    else
    {
        /* at level 6 or higher all is sent to user */
        if (fwopts->loguser >= 6)
            return 1;
        /* implicit denial */
        if (info->response.value == 0)
        {
            if (fwopts->loguser >= 2)
                return 1;
        }
        else if (info->response.value > 0)
        {
            if (fwopts->loguser >= 5)
                return 1;
        }
        else if (info->response.value < 0)
        {
            if (fwopts->loguser >= 4)
                return 1;
        }

    }
    return 0;
}

/* packets sent to userspace get the "logu_id" field incremented 
 * by one each time. If this counter exceeds ULONG_MAX, it
 * has to be re-initialized to 0, to prevent overflow
 * Since logu_id is unsigned long, while xxx_sent_touser is
 * unsigned long long, logu_id restarts from 0 every time
 * ULONG_MAX is reached, without the need of writing
 * logu_id = in_sent_touser % ULONG_MAX.
 */
unsigned long long update_sent_counter(int direction)
{
    int sent = 0;
    switch (direction)
    {
    case IPFI_INPUT:
        sent = in_sent_touser;
        in_sent_touser++;
        break;
    case IPFI_OUTPUT:
        sent = out_sent_touser;
        out_sent_touser++;
        break;
    case IPFI_FWD:
        sent = fwd_sent_touser;
        fwd_sent_touser++;
        break;
    case IPFI_INPUT_PRE:
        sent = pre_sent_touser;
        pre_sent_touser++;
        break;
    case IPFI_OUTPUT_POST:
        sent = post_sent_touser;
        post_sent_touser++;
        break;
    default:
        sent = 0;
    }
    kstats.sent_tou++;
    return sent;
}


/* int ipfi_response() in ipfire_core.c invokes this function.
 * The parameter ipfi_info is kmallocated by ipfi_response() itself at the beginning.
 * If allocation succeeds, ipfire_info_t is initialized with socket buffer values
 * and then begins its long travel starting from iph_in_get_response().
 * At the end of ipfi_response, after that the verdict has been decided for the
 * packet inside skb, ipfi_info is kfreed.
 * The main task of iph_in_get_response() is to invoke ipfire_filter for incoming,
 * outgoing and to forward packets. Once the response is determined by ipfire_filter(),
 * this function sends the info_t to userspace, if required - according to is_to_send()
 * return value, and updates some statistics.
 * The value returned is, again, the response obtained by ipfire_filter().
 */
struct response iph_in_get_response(struct sk_buff* skb,
                                    int direction,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    struct info_flags *flags)
{
    struct response response;
    response.value = IPFI_DROP;

    /* invoke engine function passing the appropriate rule lists */
    if (direction == IPFI_INPUT)
        response = ipfire_filter(&in_drop, &in_acc, &fwopts, skb, direction, in, out, flags);
    else if (direction == IPFI_OUTPUT)
        response = ipfire_filter(&out_drop, &out_acc, &fwopts, skb, direction, in, out, flags);
    else if (direction == IPFI_FWD)
        response = ipfire_filter(&fwd_drop, &fwd_acc, &fwopts, skb, direction, in, out, flags);
    else
        IPFI_PRINTK("IPFIRE: iph_in_get_response(): invalid direction!\n");
    return response;
}

int skb_send_to_user(struct sk_buff* skb, int type_of_message)
{
    struct sock *socket = NULL;
    pid_t pid = 0;
    int ret;
    /* set variables depending on type of message */
    if (type_of_message == CONTROL_DATA)
    {
        socket = sknl_ipfi_control;
        pid = userspace_control_pid;
    }
    else if (type_of_message == LISTENER_DATA)
    {
        socket = sknl_ipfi_data;
        pid = userspace_data_pid;
    }
    else if(type_of_message == GUI_NOTIF_DATA)
    {
        socket = sknl_ipfi_gui_notifier;
        pid = userspace_control_pid;
    }
    /* do task */
    if (socket == NULL)
    {			/* perhaps module not loaded */
        IPFI_PRINTK("IPFIRE: netlink socket not allocated!\n");
        return -1;
    }
    if (pid == 0)
    {
        //IPFI_PRINTK("IPFIRE: is userspace firewall running? Its pid seems to be 0!\n");
        return -1;
    }
    /* check for skb not null.. */
    if(skb == NULL)
    {
        IPFI_PRINTK("IPFIRE: socket buffer null in skb_send_to_user(): please check before calling me!\n");
        return -1;
    }
    /* skb not null, pid and socket set: send to userspace */
    ret = send_data_to_user(skb, pid, socket);
    /* in ret the return value of send_data_to_user(), i.e. the return value of netlink_unicast() */
    if(ret < 0)
    {
        if (fwopts.loglevel > 6)
            IPFI_PRINTK("IPFIRE: skb_send_to_user(): send_data_to_user(); sending message to user failed!\n");
        return ret;
    }
    return 0;
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
    IPFI_PRINTK("IPFIRE: state table entries lifetime is %lu seconds.\n",
                state_lifetime);
    IPFI_PRINTK("IPFIRE: max. number of entries is %lu.\n",
                max_state_entries);
    IPFI_PRINTK("IPFIRE: size of a source nat table is %lu bytes, so"
                " total memory occupied by snat entries is %lu KB.\n",
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
    IPFI_PRINTK("IPFIRE: size of a source nat table is %lu bytes.\nIPFIRE:"
                " total memory occupied by snat entries is %lu KB.\n",
                sizeof(struct snatted_table),
                (unsigned) ((fwopts.max_nat_entries *
                             sizeof(struct snatted_table)) / 1024));

    IPFI_PRINTK("IPFIRE: destination nat entries lifetime is %lu seconds.\n",
                fwopts.dnatted_lifetime);
    IPFI_PRINTK("IPFIRE: max. number of entries is %lu.\n",
                fwopts.max_nat_entries);
    IPFI_PRINTK("IPFIRE: size of a dest nat table is %u bytes.\nIPFIRE:"
                " total memory occupied by dnat entries is about %lu KB.\n",
                sizeof(struct dnatted_table),
                (unsigned) ((fwopts.max_nat_entries *
                             sizeof(struct dnatted_table)) / 1024));
}

void print_loginfo_memory_usage(unsigned long lifetime)
{
    IPFI_PRINTK("IPFIRE: log entry lifetime is %lu seconds, ", lifetime);
    IPFI_PRINTK("max n. of entries is %u\n"
                "IPFIRE: size of an entry is %lu bytes.\nIPFIRE: maximum memory"
                " occupied by log entries is about %lu KB.\n",
                max_loginfo_entries, sizeof(struct ipfire_loginfo),
                (unsigned) ((max_loginfo_entries *
                             sizeof(struct ipfire_loginfo) / 1024)));
}

int send_rule_list_to_userspace(void)
{
    /* allocate a command to tell the end of the list */
    command *end_list_cmd = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(end_list_cmd == NULL)
    {
        IPFI_PRINTK("IPFIRE: error allocating a command structure (%lu bytes) in send_rule_list_to_userspace()\n", sizeof(command));
        return -1;
    }
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

    /* send a command to userspace to tell list is ended */
    end_list_cmd->cmd = PRINT_FINISHED;
    if (send_back_command(end_list_cmd) < 0)
        IPFI_PRINTK("IPFIRE: error sending end of rules list!\n");
    /* anyway, free command *end_list_cmd */
    kfree(end_list_cmd);
    return 0;
}

/* sends a list: input output or forward */
int send_a_list(ipfire_rule *rlist)
{
    ipfire_rule *tmp = NULL;
    command *cmd = NULL;

    unsigned i = 0;
    // 	rcu_read_lock(); 	/* Read lock RCU */
    list_for_each_entry(tmp, &rlist->list, list)
    {
        i++;
        /* allocate space for cmd */
        cmd = (command *) kmalloc(sizeof(command), GFP_KERNEL);
        if(cmd == NULL) /* kmalloc failed */
        {
            IPFI_PRINTK("IPFIRE: failed to allocate memory for a command structure in send_a_list()\n");
            return -1;
        }
        else /* cmd successfully allocated */
        {
            memset(cmd, 0, sizeof(command));
            cmd->cmd = PRINT_RULES;
            memcpy(&cmd->content.rule, tmp, sizeof(ipfire_rule));
            /* send kmallocated cmd to userspace */
            if (send_back_command(cmd) < 0)
                IPFI_PRINTK("IPFIRE: error sending rule %d to userspace!\n", i++);
            /* free kmallocated memory associaed to cmd */
            kfree(cmd);
        }

    }
    // 	rcu_read_unlock(); /* unlock */
    return 0;
}

int fill_state_info(struct state_info *stinfo,
                    const struct state_table *stt)
{
    stinfo->saddr = stt->saddr;
    stinfo->daddr = stt->daddr;
    stinfo->sport = stt->sport;
    stinfo->dport = stt->dport;
    stinfo->originating_rule = stt->originating_rule;
    stinfo->admin = stt->admin;
    stinfo->timeout = (stt->timer_statelist.expires - jiffies) / HZ;
    stinfo->direction = stt->direction;
    stinfo->state.state = stt->state.state;
    strncpy(stinfo->in_devname, stt->in_devname, IFNAMSIZ);
    strncpy(stinfo->out_devname, stt->out_devname, IFNAMSIZ);
    stinfo->protocol = stt->protocol;
    stinfo->notify = stt->notify;
    return 0;
}

int send_tables(void)
{
    extern struct state_table root_state_table;
    struct state_table *st;
    struct state_info *endmess;
    struct state_info *st_info;
    struct sk_buff *buf_touser = NULL, *buf_touser_endmess = NULL;

    rcu_read_lock_bh(); /* Lock RCU */
    list_for_each_entry_rcu(st, &root_state_table.list, list)
    {
        st_info = (struct state_info *) kmalloc(sizeof(struct state_info), GFP_ATOMIC);
        if(st_info != NULL)
        {
            fill_state_info(st_info, st);
            buf_touser = build_state_info_packet(st_info);
            if (buf_touser != NULL && skb_send_to_user(buf_touser, CONTROL_DATA) < 0)
                IPFI_PRINTK("IPFIRE: error sending state table to userspace.\n");
            else if(buf_touser == NULL)
                IPFI_PRINTK("IPFIRE: error sending state info table to userspace: skb memory allocation failed in send_tables()\n");

            kfree(st_info);
        }
    }
    rcu_read_unlock_bh(); /* unlock RCU */

    /* last message must have direction field put to PRINT_FINISHED
     * to let userspace program know about the end of the list
     */
    endmess = (struct state_info *) kmalloc(sizeof(struct state_info), GFP_KERNEL);
    if(endmess != NULL)
    {
        memset(endmess, 0, sizeof(struct state_info));
        endmess->direction = PRINT_FINISHED;
        buf_touser_endmess = build_state_info_packet(endmess);
        if (buf_touser_endmess != NULL && skb_send_to_user(buf_touser_endmess, CONTROL_DATA) < 0)
            IPFI_PRINTK("IPFIRE: error sending state table end message to userspace.\n");
        else if(buf_touser == NULL)
            IPFI_PRINTK("IPFIRE: error sending final state info table to userspace: memory allocation failed in send_tables()\n");

        kfree(endmess);
    }
    else
        return -1;

    return 0;
}

int fill_dnat_info(struct dnat_info *dninfo,
                   const struct dnatted_table *dntt)
{
    dninfo->saddr = dntt->old_saddr;
    dninfo->daddr = dntt->old_daddr;
    dninfo->sport = dntt->old_sport;
    dninfo->dport = dntt->old_dport;
    dninfo->newdport = dntt->new_dport;
    dninfo->newdaddr = dntt->new_daddr;

    dninfo->id = dntt->id;
    dninfo->timeout = (dntt->timer_dnattedlist.expires - jiffies) / HZ;
    dninfo->direction = dntt->direction;
    dninfo->state.state = dntt->state;
    strncpy(dninfo->in_devname, dntt->in_devname, IFNAMSIZ);
    strncpy(dninfo->out_devname, dntt->out_devname, IFNAMSIZ);
    dninfo->protocol = dntt->protocol;
    return 0;
}

int send_dnat_tables(void)
{
    extern struct dnatted_table root_dnatted_table;
    struct dnatted_table *dt;
    struct dnat_info *endmess;
    struct dnat_info *dn_info;
    struct sk_buff *skb_to_user = NULL, *skb_to_user_endmess = NULL;

    rcu_read_lock(); /* Lock RCU */
    list_for_each_entry_rcu(dt, &root_dnatted_table.list, list)
    {
        dn_info = (struct dnat_info *) kmalloc(sizeof(struct dnat_info), GFP_ATOMIC);
        if(dn_info)
        {
            fill_dnat_info(dn_info, dt);
            skb_to_user = build_dnat_info_packet(dn_info);
            if (skb_to_user != NULL && skb_send_to_user(skb_to_user, CONTROL_DATA) < 0)
                IPFI_PRINTK("IPFIRE: error sending DNAT table to userspace.\n");
            else if(skb_to_user == NULL)
                IPFI_PRINTK("IPFIRE: error allocating space for socket buffer in send_dnat_tables()\n");
            /* free memory */
            kfree(dn_info);
        }
    }
    rcu_read_unlock(); /* unlock RCU */

    /* last message must have direction field put to PRINT_FINISHED
     * to let userspace program know about the end of the list
     */
    endmess = (struct dnat_info *) kmalloc(sizeof(struct dnat_info), GFP_KERNEL);
    if(endmess != NULL)
    {
        memset(endmess, 0, sizeof(struct dnat_info));
        endmess->direction = PRINT_FINISHED;
        skb_to_user_endmess = build_dnat_info_packet(endmess);
        if(skb_to_user_endmess != NULL && skb_send_to_user(skb_to_user_endmess, CONTROL_DATA) < 0)
            IPFI_PRINTK("IPFIRE: error sending state table end message to userspace.\n");
        else if(skb_to_user_endmess == NULL)
            IPFI_PRINTK("IPFIRE: error allocating space for socket buffer in send_dnat_tables - final end message\n");
        kfree(endmess); /* endmess not null: free memory */
    }
    return 0;
}

int fill_snat_info(struct snat_info *sninfo,
                   const struct snatted_table *sntt)
{
    sninfo->saddr = sntt->old_saddr;
    sninfo->daddr = sntt->old_daddr;
    sninfo->sport = sntt->old_sport;
    sninfo->dport = sntt->old_dport;
    sninfo->newsport = sntt->new_sport;
    sninfo->newsaddr = sntt->new_saddr;

    sninfo->id = sntt->id;
    sninfo->timeout = (sntt->timer_snattedlist.expires - jiffies) / HZ;
    sninfo->direction = sntt->direction;
    sninfo->state.state = sntt->state;
    strncpy(sninfo->in_devname, sntt->in_devname, IFNAMSIZ);
    strncpy(sninfo->out_devname, sntt->out_devname, IFNAMSIZ);
    sninfo->protocol = sntt->protocol;
    return 0;
}


int send_ktables_usage(void)
{
    extern unsigned int dnatted_entry_counter;
    extern unsigned int snatted_entry_counter;
    extern unsigned int state_tables_counter;
    extern unsigned int loginfo_entry_counter;
    struct ktables_usage* ktu;
    struct sk_buff *skb_to_user = NULL;

    /* return value */
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
        if(ret < 0)
            IPFI_PRINTK("IPFIRE: failed to send kernel tables usage to userspace\n");
    }
    return ret;
}

int send_snat_tables(void)
{
    extern struct snatted_table root_snatted_table;
    struct snatted_table *st;
    struct snat_info *endmess;
    struct snat_info *sn_info;
    struct sk_buff *skb_to_user = NULL, *skb_to_user_endmess = NULL;

    rcu_read_lock(); /* Lock RCU */
    list_for_each_entry_rcu(st, &root_snatted_table.list, list)
    {
        sn_info = (struct snat_info *) kmalloc(sizeof(struct snat_info), GFP_ATOMIC);
        if(sn_info != NULL)
        {
            fill_snat_info(sn_info, st);
            skb_to_user = build_snat_info_packet(sn_info);
            if (skb_to_user != NULL && skb_send_to_user(skb_to_user, CONTROL_DATA) < 0)
                IPFI_PRINTK("IPFIRE: error sending DNAT table to userspace.\n");
            else if(skb_to_user == NULL)
                IPFI_PRINTK("IPFIRE: error allocating space for socket buffer in send_snat_tables()\n");

            kfree(sn_info);
        }
    }
    rcu_read_unlock(); /* unlock RCU */

    /* last message must have direction field put to PRINT_FINISHED
     * to let userspace program know about the end of the list
     */
    endmess = (struct snat_info *) kmalloc(sizeof(struct snat_info), GFP_KERNEL);
    if(endmess != NULL) /* dynamic allocation (might be interrupted!) - success */
    {
        memset(endmess, 0, sizeof(struct snat_info));
        endmess->direction = PRINT_FINISHED;
        skb_to_user_endmess = build_snat_info_packet(endmess);
        if (skb_to_user_endmess != NULL && skb_send_to_user(skb_to_user_endmess, CONTROL_DATA) < 0)
            IPFI_PRINTK("IPFIRE: error sending state table end message to userspace.\n");
        else if(skb_to_user_endmess == NULL)
            IPFI_PRINTK("IPFIRE: error allocating space for socket buffer in send_snat_tables - final end message\n");
        kfree(endmess);
    }
    else /* kmalloc failed */
        return -1;

    return 0;
}

/* we have to free rules in firewall which were inserted by 
 * a particular user id.
 */
int flush_ruleset(uid_t userspace_commander, int flush_com)
{
    unsigned l = 0, m = 0, n = 0, o = 0, p = 0,
            q = 0, r = 0, s = 0, t = 0, u = 0;
    r = 0, s = 0, t = 0, u = 0;

    if ((flush_com == FLUSH_RULES) || (flush_com == FLUSH_DENIAL_RULES))
    {
        l = free_rules(&in_drop, userspace_commander);
        m = free_rules(&out_drop, userspace_commander);
        n = free_rules(&fwd_drop, userspace_commander);
    }
    if ((flush_com == FLUSH_RULES) ||
            (flush_com == FLUSH_PERMISSION_RULES))
    {
        o = free_rules(&in_acc, userspace_commander);
        p = free_rules(&out_acc, userspace_commander);
        q = free_rules(&fwd_acc, userspace_commander);
    }
    /* translation rules */
    if (((flush_com == FLUSH_RULES) ||
         (flush_com == FLUSH_TRANSLATION_RULES)) &
            (userspace_commander == 0))
    {
        r = free_rules(&translation_pre, 0);
        s = free_rules(&translation_out, 0);
        t = free_rules(&translation_post, 0);
        u = free_rules(&masquerade_post, 0);
    }
    IPFI_PRINTK("IPFIRE: freed %u in, %u out, %u "
                "fwd rules owned by user %u. perm: %u den: %u transl: %u",
                l + o, m + p, n + q, userspace_commander, o+p+q, l+m+n, r+s+t+u);
    IPFI_PRINTK(" Freed %d transl, %d masq. rules.\n", r + s + t, u);
    return l + m + n + o + q + p + r + s + t + u;
}

int tell_user_howmany_rules_flushed(int howmany)
{
    command *cmd = (command *) kmalloc(sizeof(command), GFP_KERNEL);
    if(cmd == NULL)
    {
        IPFI_PRINTK("IPFIRE: failed to allocate memory for a command structure in tell_user_howmany_rules_flushed()\n");
    }
    else /* cmd not null: compile cmd and then free it before returning */
    {
        /* allocation succeeded */
        cmd->anumber = 0;
        if (howmany < 0)
            cmd->cmd = ROOT_NOFLUSHED;
        else
        {
            cmd->cmd = FLUSH_RULES;
            cmd->anumber = howmany;
        }
        if (send_back_command(cmd) < 0)
            IPFI_PRINTK("IPFIRE: failed to tell user how many rules were flushed: send_back_command() failed\n");

        kfree(cmd);
    }
    return 0;
}

/* This function is invoked when userspace firewall 
 * sends a simple exit command. It resets counters and
 * pid values for accepting new registrations for right
 * userspace firewalls */
int simple_exit(void)
{
    /* reset sent to userspace packet counter */
    in_sent_touser = out_sent_touser = fwd_sent_touser = 0;
    pre_sent_touser = post_sent_touser = 0;
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

    /* reset sent to userspace packet counter */
    in_sent_touser = out_sent_touser = fwd_sent_touser = 0;
    pre_sent_touser = post_sent_touser = 0;

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

    /* The gui has a thread reading the DATA from the kernel.
     * This message tells it to exit.
     */
    if(gui_notifier_enabled)  /* executed only when userspace program is the GUI */
    {
        /* allocate _dynamic_ space for ipfire_info_t */
        ipfi_info_exit = (ipfire_info_t *) kmalloc(sizeof(ipfire_info_t), GFP_KERNEL);
        if(ipfi_info_exit != NULL) /* good... go on */
        {
            memset(ipfi_info_exit, 0, sizeof(ipfire_info_t));
            ipfi_info_exit->exit = 1;
            /* copy data contained into ipfi_info_exit into the socket buffer destined to
           * the user */
            skb_touser = build_info_t_packet(ipfi_info_exit);
            if(skb_touser != NULL)
            {
                if (skb_send_to_user(skb_touser, GUI_NOTIF_DATA) < 0)
                    IPFI_PRINTK("IPFIRE: error sending goodbye over the gui notifier socket!\n");
            }
            /* data is copied into socket buffer and sent: delete it now */
            kfree(ipfi_info_exit); /* delete pointer */
        }
        if(ipfi_info_exit == NULL || skb_touser == NULL) /* something went wrong: log it */
            IPFI_PRINTK("IPFIRE: memory allocation failed in do_userspace_exit_tasks(): could not notify to GUI\n");
    }
    userspace_control_pid = 0;
    userspace_data_pid = 0;
    return ret;
}

/* Callback to free a rule removed from the linked list. */
void free_rule_rcu_call(struct rcu_head* head)
{
    ipfire_rule* ipfirule_entry =
            container_of(head, ipfire_rule, rule_rcuh);
    kfree(ipfirule_entry);
}

int free_rules(ipfire_rule *rulelist, uid_t user)
{
    int rules_freed = 0;
    ipfire_rule *rule;
    /* see Documentation/RCU/whatisRCU.txt for an example */
    spin_lock(&rulelist_lock);
    /* writers can just use list_for_each_entry(), since there cannot be two simultaneous writers. -> DocBook/kernel-locking  */
    list_for_each_entry(rule, &rulelist->list, list)
    {
        /* only user who owns rule can delete it, unless he is root */
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

void init_options(struct ipfire_options *opts)
{
    memset(opts, 0, sizeof(struct ipfire_options));
    /* by default, users are allowed to insert their rules.
     * Administrator, to aviod users' rules, have to start
     * firewall with option noflush and disabling users */
    opts->user_allowed = 1;
}

/* given a direction or a constant identifying the counter
 * which has to be incremented, this function increments
 * corresponding counter. Response is unsigned long
 * because if the counter to be incremented is total_lost
 * (last case), printk logs the packet_id field of packet
 * that failed to be sent. Moreover, response field is
 * copied to last_failed field of kernel stats structure.
 */
void update_kernel_stats(int counter_to_increment, short int response)
{
    switch (counter_to_increment)
    {
    case IPFI_INPUT:
        kstats.in_rcv++;
        //	if (kstats.in_rcv % LOG_PACKETS_RECV == 0)
        //		IPFI_PRINTK("IPFIRE: input counter: %llu.\n",
        //		       kstats.in_rcv);

        /* response */
        if (response == 0 && default_policy == 0)
        {
            kstats.in_drop++;
            kslight.blocked++;
            kstats.in_drop_impl++;
        }
        else if(response == 0 && default_policy == 1)
        {
            kstats.in_acc++;
            kslight.allowed++;
            kstats.in_acc_impl++;
        }
        else if (response < 0)
        {
            kslight.blocked++;
            kstats.in_drop++;
        }
        else
        {
            kslight.allowed++;
            kstats.in_acc++;
        }
        break;

    case IPFI_OUTPUT:
        kstats.out_rcv++;
        //	if (kstats.out_rcv % LOG_PACKETS_RECV == 0)
        //		IPFI_PRINTK("IPFIRE: output counter: %llu.\n",
        //		       kstats.out_rcv);
        /* response */
        if (response == 0 && default_policy == 0)
        {
            kstats.out_drop++;
            kslight.blocked++;
            kstats.out_drop_impl++;
        }
        else if(response == 0 && default_policy == 1)
        {
            kstats.out_acc++;
            kslight.allowed++;
            kstats.out_acc_impl++;
        }
        else if (response < 0)
        {
            kslight.blocked++;
            kstats.out_drop++;
        }
        else
        {
            kslight.allowed++;
            kstats.out_acc++;
        }
        break;

    case IPFI_FWD:
        kstats.fwd_rcv++;
        //	if (kstats.fwd_rcv % LOG_PACKETS_RECV == 0)
        //		IPFI_PRINTK("IPFIRE: forward counter: %llu.\n",
        //		       kstats.fwd_rcv);
        /* response */
        if (response == 0 && default_policy == 0)
        {
            kslight.blocked++;
            kstats.fwd_drop++;
            kstats.fwd_drop_impl++;
        }
        else if(response == 0 && default_policy == 1)
        {
            kslight.allowed++;
            kstats.fwd_acc++;
            kstats.fwd_acc_impl++;
        }
        else if (response < 0)
        {
            kstats.fwd_drop++;
            kslight.blocked++;
        }
        else
        {
            kslight.allowed++;
            kstats.fwd_acc++;
        }
        break;

    case IPFI_INPUT_PRE:
        kstats.pre_rcv++;
        //	if (kstats.pre_rcv % LOG_PACKETS_RECV == 0)
        //		IPFI_PRINTK("IPFIRE: prerout. counter: %llu.\n",
        //		       kstats.pre_rcv);
        break;

    case IPFI_OUTPUT_POST:
        kstats.post_rcv++;
        //	if (kstats.post_rcv % LOG_PACKETS_RECV == 0)
        //		IPFI_PRINTK("IPFIRE: postrout. counter: %llu.\n",
        //		       kstats.post_rcv);
        break;

    case IPFI_FAILED_NETLINK_USPACE:
        if ((( unsigned) kstats.total_lost % 25000 == 0)
                && (kstats.total_lost != 0))
            printk
                    ("IPFIRE: failed to send %llu packets to userspace "
                     "via netlink socket [loguser: %d, response: %lu]!\n",
                     kstats.total_lost, fwopts.loguser,
                     response);
        kstats.total_lost++;
        kstats.last_failed = response;
        break;
    }
}

//static int __init init(void)
int init_netl(void)
{
    int ctrl_so, data_so, gui_so;
    data_so = 0, ctrl_so = 0, gui_so = 0;
    ctrl_so = create_control_socket();
    data_so = create_data_socket();
    gui_so = create_gui_notifier_socket();

    memset(moderate_print, 0, sizeof(unsigned int) * MAXMODERATE_ARGS);
    memset(moderate_print_limit, 0, sizeof(unsigned int) * MAXMODERATE_ARGS);
    moderate_print_limit[PRINT_PROTO_UNSUPPORTED] = 10000;

    /* initialize list */
    INIT_LIST_HEAD(&in_drop.list);
    INIT_LIST_HEAD(&out_drop.list);
    INIT_LIST_HEAD(&fwd_drop.list);
    INIT_LIST_HEAD(&in_acc.list);
    INIT_LIST_HEAD(&out_acc.list);
    INIT_LIST_HEAD(&fwd_acc.list);
    INIT_LIST_HEAD(&translation_pre.list);
    INIT_LIST_HEAD(&translation_out.list);
    INIT_LIST_HEAD(&translation_post.list);
    INIT_LIST_HEAD(&masquerade_post.list);

    // 	spin_lock_init(&rulelist_lock);
    /* all options disabled */
    init_options(&fwopts);
    memset(&kslight, 0, sizeof(kslight));
    if (ctrl_so == 0 && data_so == 0 && gui_so == 0)
        return 0;
    else
        return -1;
}

//static void __exit fini(void)
void fini_netl(void)
{
    IPFI_PRINTK("IPFIRE: Closing netlink sockets: control... ");
    //	synchronize_net(); /* already called in ipfi.c */
    /* NOTE: modern kernels provide netlink_kernel_release() to release the netlink socket */
    if (sknl_ipfi_control != NULL)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        sock_release(sknl_ipfi_control->sk_socket);
#else
        netlink_kernel_release(sknl_ipfi_control);
#endif
    }
    else
        IPFI_PRINTK("IPFIRE: NULL control netlink socket!\n");

    IPFI_PRINTK("data... ");

    if (sknl_ipfi_data != NULL)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        sock_release(sknl_ipfi_data->sk_socket);
#else
        netlink_kernel_release(sknl_ipfi_data);
#endif
    }
    else
        IPFI_PRINTK("IPFIRE: NULL data netlink socket!\n");

    IPFI_PRINTK("GUI notifier.\n");

    //	synchronize_net(); /* already called in ipfi.c */
    if (sknl_ipfi_gui_notifier != NULL)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        sock_release(sknl_ipfi_gui_notifier->sk_socket);
#else
        netlink_kernel_release(sknl_ipfi_gui_notifier);
#endif
    }
    else
        IPFI_PRINTK("IPFIRE: the gui notifier socket is already NULL (disabled)!\n");
}

/* Riporto la struttura netlink_skb_parms da include/linux/netlink.h 
   struct netlink_skb_parms
   {
   struct ucred		creds;		// Skb credentials
   __u32			pid;
   __u32			groups;
   __u32			dst_pid;
   __u32			dst_groups;
   kernel_cap_t		eff_cap;
   };

#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
*/
