/* netlink/netlink_data.c: Netlink data channel for ipfire-wall */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include "ipfi.h"
#include "ipfi_netl.h"
#include "ipfi_log.h"
#include "globals.h"

#include "globals.h"

int process_data_received(struct sk_buff *skb)
{
    if (nlmsg_len(nlmsg_hdr(skb)) < sizeof(listener_message))
    {
        IPFI_PRINTK("IPFIRE: process_data_received(): netlink message too small for listener_message (%d < %lu)\n", 
                    nlmsg_len(nlmsg_hdr(skb)), sizeof(listener_message));
        return -EINVAL;
    }

    listener_message *listener_mess = (listener_message *) extract_data(skb);
    if(listener_mess == NULL)
        return -1;

    if (listener_mess->message == STARTING)
    {
        printk ("IPFIRE: userspace listener son started. PID: %d.\n", userspace_data_pid);
        return 0;
    }
    else if (listener_mess->message == EXITING)
    {
        IPFI_PRINTK("IPFIRE: userspace listener son exiting.\n");
        return 0;
    }
    return 0;
}

int is_to_send(const struct sk_buff * skb,
               const struct ipfire_options *fwopts,
               const struct response* res,
               const ipfi_flow* flow,
               const struct info_flags *flags) {
    printk("smartlog_func: %p\n", smartlog_func);
    if(smartlog_func != NULL)
        return smartlog_func(skb, res, flow, flags);
    else {
        if (fwopts->loguser >= 6)
            return 1;
        if (res->verdict == IPFI_IMPLICIT && fwopts->loguser >= 2) {
                return 1;
        }
        else if (res->verdict == IPFI_ACCEPT && fwopts->loguser >= 5) {
            return 1;
        }
        else if (res->verdict == IPFI_DROP && fwopts->loguser >= 4) {
            return 1;
        }
    }
    return 0;
}

unsigned long long update_sent_counter(int direction)
{
    unsigned long long sent = 0;
    switch (direction)
    {
    case IPFI_INPUT:
        sent = this_cpu_inc_return(ipfi_counters->in_sent_touser) - 1;
        break;
    case IPFI_OUTPUT:
        sent = this_cpu_inc_return(ipfi_counters->out_sent_touser) - 1;
        break;
    case IPFI_FWD:
        sent = this_cpu_inc_return(ipfi_counters->fwd_sent_touser) - 1;
        break;
    case IPFI_INPUT_PRE:
        sent = this_cpu_inc_return(ipfi_counters->pre_sent_touser) - 1;
        break;
    case IPFI_OUTPUT_POST:
        sent = this_cpu_inc_return(ipfi_counters->post_sent_touser) - 1;
        break;
    default:
        sent = 0;
    }
    IPFI_STAT_INC(sent_tou);
    return sent;
}

int skb_send_to_user(struct sk_buff* skb, int type_of_message)
{
    struct sock *socket = NULL;
    pid_t pid = 0;
    int ret;
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
    if (socket == NULL || pid == 0)
    {
        if (skb) kfree_skb(skb);
        return -1;
    }
    if(skb == NULL)
        return -1;
    ret = send_data_to_user(skb, pid, socket);
    if(ret < 0)
        return ret;
    return 0;
}
