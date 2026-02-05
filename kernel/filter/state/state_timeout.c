/* filter/state/state_timeout.c: Timeout and timer management for ipfire-wall */

#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/ip.h>
#include "ipfi.h"
#include "ipfi_machine.h"

unsigned int syn_lifetime = 2 * 60;
unsigned int synack_lifetime = 60;
unsigned int est_lifetime = 5 * 60;
unsigned int close_wait_lifetime = 60;
unsigned int fin_wait_lifetime = 2 * 60;
unsigned int last_ack_lifetime =  30;
unsigned int time_wait_lifetime = 2 * 60;
unsigned int close_lifetime = 10;
unsigned int udp_new_lifetime = 30;
unsigned int udp_lifetime = 180;
unsigned int icmp_lifetime = 180;
unsigned int igmp_lifetime = 180;
unsigned int l3generic_proto_lifetime = 180;

inline unsigned int get_timeout_by_state(int protocol, int state)
{
    unsigned int timeout = close_lifetime;

    if(protocol == IPPROTO_TCP)
    {
        switch(state)
        {
        case ESTABLISHED:
        case GUESS_ESTABLISHED:
            timeout = est_lifetime;
            break;
        case SYN_RECV:
        case GUESS_SYN_RECV:
            timeout = synack_lifetime;
            break;
        case SYN_SENT:
        case FTP_NEW:
            timeout = syn_lifetime;
            break;
        case CLOSE_WAIT:
            timeout = close_wait_lifetime;
            break;
        case IPFI_TIME_WAIT:
            timeout = time_wait_lifetime;
            break;
        case LAST_ACK:
            timeout = last_ack_lifetime;
            break;
        case FIN_WAIT:
            timeout = fin_wait_lifetime;
            break;
        case CLOSED:
        case GUESS_CLOSING:
        default:
            timeout = close_lifetime;
            break;
        }
    }
    else if(protocol == IPPROTO_UDP)
    {
        switch(state)
        {
        case UDP_ESTAB:
            timeout = udp_lifetime;
            break;
        case UDP_NEW:
        default:
            timeout = udp_new_lifetime;
            break;
        }
    }
    else if(protocol == IPPROTO_ICMP || protocol == IPPROTO_IGMP ||
            protocol == IPPROTO_GRE || protocol == IPPROTO_PIM)
    {
        timeout = l3generic_proto_lifetime;
    }
    return timeout;
}

inline void update_timer_of_state_entry(struct state_table *sttable)
{
    unsigned int timeout = get_timeout_by_state(sttable->protocol, sttable->state.state);

    if (time_after(jiffies, sttable->last_timer_update + HZ)) {
        mod_timer(&sttable->timer_statelist, jiffies + HZ * timeout);
        sttable->last_timer_update = jiffies;
    }
}
