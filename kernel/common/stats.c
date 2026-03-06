#include <linux/module.h>
#include "globals.h"

void update_kernel_stats(int counter_to_increment, short int response)
{
    switch (counter_to_increment)
    {
    case IPFI_INPUT:
        IPFI_STAT_INC(in_rcv);
        if (response == IPFI_IMPLICIT && default_policy == IPFI_DROP)
        {
            IPFI_STAT_INC(in_drop);
            IPFI_STAT_INC(blocked);
            IPFI_STAT_INC(in_drop_impl);
        }
        else if(response == IPFI_IMPLICIT && default_policy == IPFI_ACCEPT)
        {
            IPFI_STAT_INC(in_acc);
            IPFI_STAT_INC(allowed);
            IPFI_STAT_INC(in_acc_impl);
        }
        else if (response == IPFI_DROP)
        {
            IPFI_STAT_INC(blocked);
            IPFI_STAT_INC(in_drop);
        }
        else
        {
            IPFI_STAT_INC(allowed);
            IPFI_STAT_INC(in_acc);
        }
        break;

    case IPFI_OUTPUT:
        IPFI_STAT_INC(out_rcv);
        if (response == IPFI_IMPLICIT && default_policy == IPFI_DROP)
        {
            IPFI_STAT_INC(out_drop);
            IPFI_STAT_INC(blocked);
            IPFI_STAT_INC(out_drop_impl);
        }
        else if(response == IPFI_IMPLICIT && default_policy == IPFI_ACCEPT)
        {
            IPFI_STAT_INC(out_acc);
            IPFI_STAT_INC(allowed);
            IPFI_STAT_INC(out_acc_impl);
        }
        else if (response == IPFI_DROP)
        {
            IPFI_STAT_INC(blocked);
            IPFI_STAT_INC(out_drop);
        }
        else
        {
            IPFI_STAT_INC(allowed);
            IPFI_STAT_INC(out_acc);
        }
        break;

    case IPFI_FWD:
        IPFI_STAT_INC(fwd_rcv);
        if (response == IPFI_IMPLICIT && default_policy == IPFI_DROP)
        {
            IPFI_STAT_INC(blocked);
            IPFI_STAT_INC(fwd_drop);
            IPFI_STAT_INC(fwd_drop_impl);
        }
        else if(response == IPFI_IMPLICIT && default_policy == IPFI_ACCEPT)
        {
            IPFI_STAT_INC(allowed);
            IPFI_STAT_INC(fwd_acc);
            IPFI_STAT_INC(fwd_acc_impl);
        }
        else if (response == IPFI_DROP)
        {
            IPFI_STAT_INC(fwd_drop);
            IPFI_STAT_INC(blocked);
        }
        else
        {
            IPFI_STAT_INC(allowed);
            IPFI_STAT_INC(fwd_acc);
        }
        break;

    case IPFI_INPUT_PRE:
        IPFI_STAT_INC(pre_rcv);
        break;

    case IPFI_OUTPUT_POST:
        IPFI_STAT_INC(post_rcv);
        break;

    case IPFI_FAILED_NETLINK_USPACE:
        /* Since total_lost is now per-CPU, a precise global check here is expensive.
         * We do a best-effort per-CPU check for logging. */
        if ((this_cpu_read(ipfi_counters->total_lost) % 25000 == 0)
                && (this_cpu_read(ipfi_counters->total_lost) != 0))
            IPFI_PRINTK("IPFIRE: failed to send %llu packets to userspace "
                     "via netlink socket [loguser: %d, response: %d]!\n",
                     this_cpu_read(ipfi_counters->total_lost), fwopts.loguser,
                     response);
        IPFI_STAT_INC(total_lost);
        this_cpu_write(ipfi_counters->last_failed, (unsigned long long)response);
        break;
    }
}
