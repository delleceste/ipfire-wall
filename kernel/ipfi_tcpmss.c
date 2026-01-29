#include "includes/ipfi_tcpmss.h"
#include <net/tcp.h> /* TCPOLEN_MSS... */
#include <linux/version.h>

/* private manip function */
int __tcpmss_mangle_packet(struct sk_buff *skb,  short unsigned int option, __u16 mss, ipfire_info_t *info);

/* TCPOLEN_MSS: length of the tcp header mss option, from include/net/tcp.h 
 * TCPOPT_MSS: segment size negotiating, from include/net/tcp.h 
 * TCPOPT_NOP: padding, from include/net/tcp.h 
 */

int packet_suitable_for_mss_change(const ipfire_info_t *info)
{
//   return 0;
  if(info->protocol == IPPROTO_TCP && info->transport_header.tcphead.syn == 1 &&
    info->transport_header.tcphead.ack == 0)
    return 1;
  else if(info->protocol == IPPROTO_TCP && info->direction == IPFI_FWD && info->transport_header.tcphead.syn == 1 &&
    info->transport_header.tcphead.ack == 1 && info->reverse)
    return 1;
  else if(info->protocol == IPPROTO_TCP && info->direction == IPFI_FWD  && info->transport_header.tcphead.syn == 1 &&
    info->transport_header.tcphead.ack == 1 && !info->reverse)
      IPFI_PRINTK("IPFIRE: syn and ack true but no reverse set: packet not manip suitable\n");
  
  
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

int tcpmss_mangle_packet(struct sk_buff *skb, short unsigned int tcpmss_option, __u16 mss, ipfire_info_t *info)
{
  int ret, newlen;
  struct iphdr *iph;
  
  ret = __tcpmss_mangle_packet(skb, tcpmss_option, mss, info);
  
  /* __tcpmss_mangle_packet() might add the mss option */
  if (ret > 0) 
  {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	iph = skb->nh.iph;
#else
	iph = ip_hdr(skb);
#endif
	/* socket buffer has been enlarged */
	newlen = htons(ntohs(iph->tot_len) + ret);
	csum_replace2(&iph->check, iph->tot_len, newlen);
	iph->tot_len = newlen;
  }
  return ret;
}

int __tcpmss_mangle_packet(struct sk_buff *skb, short unsigned int tcpmss_option, __u16 mss, ipfire_info_t *info)
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
	 * (1) Cited from net/netfilter/xt_TCPMSS.c
	 */
	if (tcplen != tcph->doff * 4) 
	{
		IPFI_PRINTK("IPFIRE: __tcpmss_mangle_packet(): bad tcp header length (%u bytes)\n", skb->len);
		return -1;
	}

	if(tcpmss_option == ADJUST_MSS_TO_PMTU)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
	  struct dst_entry *dst_en = skb->dst;
#else
	  struct dst_entry *dst_en = skb_dst(skb);
#endif
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
			info->manipinfo.pmanip.mss.enabled = 1;
			if (oldmss <= newmss)
			{
			  info->manipinfo.pmanip.mss.old_lessthan = 1;
			  info->manipinfo.pmanip.mss.mss = oldmss;
			  return 0;
			}
			/* else: fill in the new mss */
			opt[i+2] = (newmss & 0xff00) >> 8;
			opt[i+3] = newmss & 0x00ff;
			info->manipinfo.pmanip.mss.mss = newmss;
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
	info->manipinfo.pmanip.mss.skb_enlarged = 1;
	return TCPOLEN_MSS;
}

EXPORT_SYMBOL(packet_suitable_for_mss_change);
EXPORT_SYMBOL(tcpmss_mangle_packet);
