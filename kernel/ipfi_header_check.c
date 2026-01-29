#include "includes/ipfi_header_check.h"



int check_tcp_header(const struct tcphdr *th, int datalen)
{
	if (th == NULL)
	{
		printk("IPFIRE: check_tcp_header(): NULL tcp heaader passed!.\n");
		return -1;
	}
	/* Malformed packet or header not complete th->doff *4 is thlen - transport header length - */
	if (th->doff * 4 < sizeof(struct tcphdr) || datalen < th->doff * 4)
	{
		printk("IPFIRE: check_tcp_header(): truncated or malformed packet.\n");
		return -1;
	}
	return 0;
}

int check_udp_header(const struct udphdr *uh, int datalen)
{
	if (uh == NULL)
	{
		printk("IPFIRE: NULL UDP header passsed!\n");
		return -1;
	}
	/* Truncated/malformed packets */
	if (ntohs(uh->len) > datalen || ntohs(uh->len) < sizeof(*uh))
	{
		printk("IPFIRE: check_udp_header():  UDP header malformed or truncated.\n");
		return -1;
	}
	return 0;
}


int check_tcp_header_from_skb(const struct sk_buff *skb, const struct tcphdr* tcph)
{
  int datalen;
  struct iphdr *iph;
  
  if(skb != NULL)
  {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	iph = skb->nh.iph;
#else
	iph = ip_hdr(skb);
#endif

    if(iph != NULL && tcph != NULL)
    {
      datalen = skb->len - iph->ihl * 4;
      return check_tcp_header(tcph, datalen);
    }
  }
  
  printk("IPFIRE: check_tcp_header_from_skb(): skb NULL or ip header NULL!\n");
  return -1;
}

int check_udp_header_from_skb(const struct sk_buff *skb, const struct udphdr* udph)
{
  int datalen;
  struct iphdr *iph;
  
  if(skb != NULL)
  {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	iph = skb->nh.iph;
#else
	iph = ip_hdr(skb);
#endif

    if(iph != NULL && udph != NULL)
    {
      datalen = skb->len - iph->ihl * 4;
      return check_udp_header(udph, datalen);
    }
  }
  
  printk("IPFIRE: check_tcp_header_from_skb(): skb NULL or ip header NULL or passed udp header NULL!\n");
  return -1;
}

int network_header_null(const char *funcname, const char *message)
{
	printk("IPFIRE: %s: %s\n", funcname, message);
	return -1;
}



