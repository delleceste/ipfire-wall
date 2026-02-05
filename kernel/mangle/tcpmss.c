#include "ipfi_tcpmss.h"
#include <net/tcp.h> /* TCPOLEN_MSS... */
#include <linux/version.h>

/* private manip function */
int __tcpmss_mangle_packet(struct sk_buff *skb,  short unsigned int option, __u16 mss);

/* TCPOLEN_MSS: length of the tcp header mss option, from include/net/tcp.h 
 * TCPOPT_MSS: segment size negotiating, from include/net/tcp.h
 * TCPOPT_NOP: padding, from include/net/tcp.h
 */

/**
 * packet_suitable_for_mss_change() - Determine if packet is suitable for TCP MSS manipulation
 * @skb: socket buffer containing the packet
 * @flow: flow information (direction, interfaces)
 * @reverse: flag indicating if this is a reverse-direction packet (reply)
 *
 * TCP MSS (Maximum Segment Size) mangling is needed for Path MTU Discovery (PMTUD).
 * When packets traverse networks with different MTUs (e.g., PPPoE with 1492 vs Ethernet 1500),
 * the firewall may need to clamp MSS to prevent fragmentation issues.
 *
 * MSS mangling is ONLY applicable to TCP SYN packets because:
 * - MSS option is negotiated during connection establishment (SYN, SYN/ACK)
 * - Once negotiated, it cannot be changed mid-connection
 * - Mangling non-SYN packets would break the connection
 *
 * Returns: 1 if packet is suitable for MSS manipulation, 0 otherwise
 */
int packet_suitable_for_mss_change(const struct sk_buff *skb, 
                                     const ipfi_flow *flow, short reverse)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    
    /* Extract IP header from socket buffer */
    iph = ip_hdr(skb);
    if (!iph)
        return 0;
    
    /* MSS mangling only applies to TCP protocol */
    if (iph->protocol != IPPROTO_TCP)
        return 0;
    
    /* Extract TCP header (located iph->ihl * 4 bytes after IP header) */
    tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
    
    /* CASE 1: Outgoing SYN packet (connection initiation)
     * - SYN=1, ACK=0 indicates initial SYN packet from client
     * - This is where initial MSS is advertised
     * - We may need to clamp it to prevent PMTU issues
     */
    if (tcph->syn == 1 && tcph->ack == 0)
        return 1;
    
    /* CASE 2: Forwarded SYN/ACK packet in reverse direction (server reply)
     * - Direction is FORWARD (packet being routed)
     * - SYN=1, ACK=1 indicates SYN/ACK reply from server  
     * - reverse=1 means this is the return packet of an established flow
     * - Server's MSS also needs clamping to match path MTU
     */
    if (flow->direction == IPFI_FWD && tcph->syn == 1 && 
        tcph->ack == 1 && reverse)
        return 1;
    
    /* Diagnostic: SYN/ACK in forward but not reverse - shouldn't happen normally
     * This indicates a potential state tracking issue
     */
    if (flow->direction == IPFI_FWD && tcph->syn == 1 && 
        tcph->ack == 1 && !reverse)
        IPFI_PRINTK("IPFIRE: SYN+ACK packet not marked as reverse - unexpected!\\n");
    
    /* All other packets (data, ACK, FIN, etc.) are not suitable for MSS mangling */
    return 0;
}

int optlen(const u_int8_t *opt, unsigned int offset)
{
    /* Beware zero-length options: make finite progress */
    if (opt[offset] <= TCPOPT_NOP || opt[offset+1] == 0)
        return 1;
    else
        return opt[offset+1];
}

/* code taken from xt_TCPMSS.c, net/netfilter */
u_int32_t get_net_mtu(__u32 address)
{
    /* generic internet flow structure */
    struct rtable *rt;
    u_int32_t mtu     = ~0U;
    /* ipv4 only */
    struct flowi4 fl4 = {
        .daddr = address,
    };

    rt = ip_route_output_key(&init_net, &fl4);
    if (!IS_ERR(rt)) {
        mtu = dst_mtu(&rt->dst);
        ip_rt_put(rt);
    }
    return mtu;
}

/**
 * tcpmss_mangle_packet() - Mangle TCP MSS option in a packet
 * @skb: socket buffer containing the packet to modify
 * @tcpmss_option: type of MSS manipulation (MSS_VALUE or ADJUST_MSS_TO_PMTU)
 * @mss: target MSS value (only used if tcpmss_option == MSS_VALUE)
 *
 * This is the main entry point for TCP MSS manipulation. It:
 * 1. Calls __tcpmss_mangle_packet() to modify the MSS option in TCP header
 * 2. If successful, updates the IP header total_length and checksum
 *
 * The function may enlarge the packet if the MSS option needs to be added.
 * In this case, ret > 0 indicates how many bytes were added.
 *
 * Returns: <0 on error, 0 if no change needed, >0 if packet was enlarged
 */
int tcpmss_mangle_packet(struct sk_buff *skb, short unsigned int tcpmss_option, __u16 mss)
{
    int ret, newlen;
    struct iphdr *iph;

    /* Perform the actual MSS mangling */
    ret = __tcpmss_mangle_packet(skb, tcpmss_option, mss);

    /* If packet was enlarged (MSS option was added), update IP header */
    if (ret > 0)  {
        iph = ip_hdr(skb);
        /* Socket buffer has been enlarged by 'ret' bytes
         * Calculate new total length: old_length + bytes_added
         */
        newlen = htons(ntohs(iph->tot_len) + ret);
        
        /* Update IP header checksum to reflect new total length 
         * csum_replace2(): efficiently updates checksum by replacing old value with new
         */
        csum_replace2(&iph->check, iph->tot_len, newlen);
        iph->tot_len = newlen;
    }
    return ret;
}

int __tcpmss_mangle_packet(struct sk_buff *skb,
                           short unsigned int tcpmss_option,
                           __u16 mss/*,
                           ipfire_info_t *info*/)
{

    struct tcphdr *tcph;
    struct iphdr *iph;
    unsigned int tcplen, i, tcphoff, mtu_minlen;
    __be16 oldval;
    __u16 newmss;
    u_int16_t oldmss;
    u32 net_mtu;
    u8 *opt;
    mtu_minlen = sizeof(struct iphdr) + sizeof(struct tcphdr);

    if (skb_ensure_writable(skb, skb->len))
    {
        IPFI_PRINTK("IPFI: __tcpmss_mangle_packet(): skb_ensure_writable failed\n");
        return -1;
    }
    /* reload pointers after skb_make_writable() call */
    iph = ip_hdr(skb);
    tcphoff = iph->ihl * 4;
    tcplen = skb->len - tcphoff;
    tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);

    /* (1) Since it passed flags test in tcp match, we know it is is
     * not a fragment, and has data >= tcp header length.  SYN
     * packets should not contain data: if they did, then we risk
     * running over MTU, sending Frag Needed and breaking things
     * badly. --RR
     *
         * (1) Quoted from net/netfilter/xt_TCPMSS.c
     */
    if (tcplen != tcph->doff * 4)
    {
        IPFI_PRINTK("IPFIRE: __tcpmss_mangle_packet(): bad tcp header length (%u bytes)\n", skb->len);
        return -1;
    }

    if(tcpmss_option == ADJUST_MSS_TO_PMTU) {
        struct dst_entry *dst_en = skb_dst(skb);
        net_mtu = get_net_mtu(iph->saddr);
        if(dst_mtu(dst_en) <= mtu_minlen)
        {
            IPFI_PRINTK("__tcpmss_mangle_packet(): unknown or invalid skb PATH-MTU (%u)\n", dst_mtu(dst_en));
            return -1;
        }
        if(net_mtu <= mtu_minlen)
        {
            IPFI_PRINTK("__tcpmss_mangle_packet(): unknown or invalid calculated PATH-MTU (%u)\n", net_mtu);
            return -1;
        }
        newmss = min(dst_mtu(dst_en), net_mtu) - mtu_minlen;
    }
    else
    {
        newmss = mss;
    }

    /* first byte of the tcp header */
    opt = (u_int8_t *)tcph;
    /* cycle: start: i: first byte after the end of the tcp header;
     *        test:  i: less than tcp header data offset (start of data) - the number of 32 bit words in the TCP Header
     *   increment:  i: length of option
     */
    for (i = sizeof(struct tcphdr); i < tcph->doff * 4; i += optlen(opt, i))
    {
        /* TCPOLEN_MSS: length of the tcp header mss option, from include/net/tcp.h
           * TCPOPT_MSS: option `segment size negotiating', from include/net/tcp.h
           * Maximum Segment Size

            +--------+--------+---------+--------+
            |00000010|00000100|   max seg size   |
            +--------+--------+---------+--------+
            Kind      Length:4
           *
           * note: tcph->doff * 4 - i must be greater than or equal TCPOLEN_MSS (4 bytes: 1:kind,2:length,3,4:mss)
           */
        if (opt[i] == TCPOPT_MSS && tcph->doff * 4 - i >= TCPOLEN_MSS && opt[i+1] == TCPOLEN_MSS)
        {
            oldmss = (opt[i+2] << 8) | opt[i+3];
            // 			IPFI_PRINTK("oldmss: %u   ----------------  new mss (possibile): %u [i = %d]\n", oldmss, newmss, i);
            /* Never increase MSS, even when setting it, as
             * doing so results in problems for hosts that rely
             * on MSS being set correctly.
             */
            // info->manipinfo.pmanip.mss.enabled = 1;
            if (oldmss <= newmss)
            {
                // info->manipinfo.pmanip.mss.old_lessthan = 1;
                // info->manipinfo.pmanip.mss.mss = oldmss;
                return 0;
            }
            /* else: fill in the new mss */
            opt[i+2] = (newmss & 0xff00) >> 8;
            opt[i+3] = newmss & 0x00ff;
            // info->manipinfo.pmanip.mss.mss = newmss;
            /* update checksum */
            inet_proto_csum_replace2(&tcph->check, skb,
                                     htons(oldmss), htons(newmss),
                                     0);
            return 0;
        }
    }

    IPFI_PRINTK("IPFIRE: mss option not found. Adding\n");
    /*
     * MSS Option not found ?! add it..
     */
    if (skb_tailroom(skb) < TCPOLEN_MSS)
    {
        if (pskb_expand_head(skb, 0,  TCPOLEN_MSS - skb_tailroom(skb), GFP_ATOMIC))
            return -1;
        tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
    }

    /* net/core/skbuff.c: skb_put - add data to a buffer.
     * Extends the used data area of the buffer of an amount TCPOLEN_MSS
     */
    skb_put(skb, TCPOLEN_MSS);
    opt = (u_int8_t *)tcph + sizeof(struct tcphdr);
    /* (tcplen = skb->len - tcphoff) move memory pointed by opt (tcph + sizeof(struct tcphdr) = start of data
     * into opt + TCPOLEN+MSS
     */
    memmove(opt + TCPOLEN_MSS, opt, tcplen - sizeof(struct tcphdr));

    inet_proto_csum_replace2(&tcph->check, skb,  htons(tcplen), htons(tcplen + TCPOLEN_MSS), 1);
    opt[0] = TCPOPT_MSS;
    opt[1] = TCPOLEN_MSS;
    opt[2] = (newmss & 0xff00) >> 8;
    opt[3] = newmss & 0x00ff;

    inet_proto_csum_replace4(&tcph->check, skb, 0, *((__be32 *)opt), 0);

    oldval = ((__be16 *)tcph)[6];  /* old value calculation to use in csum_replace.. below */
    tcph->doff += TCPOLEN_MSS/4;   /* new start of data position */
    inet_proto_csum_replace2(&tcph->check, skb, oldval, ((__be16 *)tcph)[6], 0);
    // info->manipinfo.pmanip.mss.skb_enlarged = 1;
    return TCPOLEN_MSS;
}

EXPORT_SYMBOL(packet_suitable_for_mss_change);
EXPORT_SYMBOL(tcpmss_mangle_packet);
