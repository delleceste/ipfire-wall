#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <net/ip.h>
/// toglier
#include <linux/tcp.h>

#include "ipfi.h"
#include "ipfi_defrag.h"

/* Returns new sk_buff, or NULL */
int ipfi_gather_frags(struct sk_buff *skb, u_int32_t user)
{
    int err;

    skb_orphan(skb);

    local_bh_disable();
    /* Process an incoming IP datagram fragment. - net/ipv4/ip_fragment.c */
    err = ip_defrag(&init_net, skb, user);
    local_bh_enable();

    if (!err)
        ip_send_check(ip_hdr(skb)); /* Generate a checksum for an outgoing IP datagram. (net/ipv4/ip_output.c) */

    return err;
}

unsigned int ipfi_defrag(void *priv,
                      struct sk_buff *skb,
                      const struct nf_hook_state *state)
{
    unsigned int hooknum = state->hook;
    /* Gather fragments. */
    /* Fragment Offset: 13-bits  used to identify where each of the fragments belong at the time of reassembly.
     * IP_MF = 0x2000, IP_OFFSET = 0x1FFF -> ored make 13 bits.
	 * NF_STOLEN means don't continue to process the packet and not deallocate it.
	 * NF_DROP, equivalent to IPFI_ACCEPT, means don't continue to process the packet, but deallocate it. 
	 */
    if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) 
    {
		 /* include/net/ip.h defines IP_DEFRAG_CONNTRACK_IN and IP_DEFRAG_CONNTRACK_OUT: might suit */
        if (ipfi_gather_frags(skb, 
		  hooknum == NF_INET_PRE_ROUTING ? IP_DEFRAG_CONNTRACK_IN : IP_DEFRAG_CONNTRACK_OUT))
		{
            return NF_STOLEN;
		}
    }
    return NF_ACCEPT;
}

