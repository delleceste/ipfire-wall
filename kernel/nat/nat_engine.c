/* nat/nat_engine.c: NAT engine entry point for ipfire-wall */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/netfilter_ipv4.h>
#include "ipfi.h"
#include "ipfi_netl.h"
#include "ipfi_translation.h"
#include "ipfi_machine.h"
#include "ipfi_state_machine.h"
#include "globals.h"

int translation_rule_match(const struct sk_buff *skb,
                           const ipfi_flow *flow,
                           const struct info_flags *flags,
                           const ipfire_rule *r)
{
    struct iphdr *iph = ip_hdr(skb);
    if (r->direction != flags->direction)
        return -1;
    if (r->ip.protocol != iph->protocol)
        return -1;
    if (r->nflags.indev && r->devpar.in_ifindex != (flow->in ? flow->in->ifindex : -1))
        return -1;
    if (r->nflags.outdev && r->devpar.out_ifindex != (flow->out ? flow->out->ifindex : -1))
        return -1;
    if (address_match(iph, r, flags->direction, NULL, NULL) < 0)
        return -1;
    switch (iph->protocol)
    {
    case IPPROTO_TCP: {
        struct tcphdr *th = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        if (port_match(th, NULL, r, IPPROTO_TCP) < 0)
            return -1;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
        if (port_match(NULL, uh, r, IPPROTO_UDP) < 0)
            return -1;
        break;
    }
    }
    return 1;
}

int manip_skb(struct sk_buff *skb, __u32 saddr, __u16 sport,
              __u32 daddr, __u16 dport, struct pkt_manip_info mi)
{
    struct iphdr *ipheader;
    int csum_check;
    unsigned int l4hdroff;
    struct tcphdr *ptcphead = NULL;
    struct udphdr *pudphead = NULL;
    unsigned int writable_len = 0;
    __u32 oldaddr = 0, newaddr = 0;
    __u16 oldport = 0, newport = 0;
    bool check_csum = mi.direction < IPFI_OUTPUT ? true : false;

    ipheader = ip_hdr(skb);
    if (ipheader == NULL || skb == NULL)
        return -1;

    l4hdroff = ipheader->ihl * 4;

    if (check_csum)
    {
        if ((csum_check = check_checksums(skb)) < 0)
            return csum_error_message("manip_skb()", csum_check);
    }

    if((mi.sp ^ mi.dp) && ipheader->protocol == IPPROTO_TCP)
        writable_len = l4hdroff + sizeof(struct tcphdr);
    else if((mi.sp ^ mi.dp)  && ipheader->protocol == IPPROTO_UDP)
        writable_len = l4hdroff + sizeof(struct udphdr);
    else
        writable_len = l4hdroff;

    if(skb_ensure_writable(skb, writable_len))
        return -1;
    
    ipheader = ip_hdr(skb);

    if(ipheader->protocol == IPPROTO_TCP)
        ptcphead = (struct tcphdr *)(skb->data + l4hdroff);
    else if(ipheader->protocol == IPPROTO_UDP)
        pudphead =  (struct udphdr *)(skb->data + l4hdroff);

    if(mi.sa) {
        oldaddr = ipheader->saddr;
        newaddr = saddr;
        ipheader->saddr = saddr;
    } else if (mi.da) {
        oldaddr = ipheader->daddr;
        newaddr = daddr;
        ipheader->daddr = daddr;
    }

    if(mi.sp ^ mi.dp)
    {
        switch (ipheader->protocol)
        {
        case IPPROTO_TCP:
            if (mi.sp) {
                oldport = ptcphead->source;
                newport = sport;
                ptcphead->source = newport;
            } else if (mi.dp) {
                oldport = ptcphead->dest;
                newport = dport;
                ptcphead->dest = newport;
            }
            break;
        case IPPROTO_UDP:
            if (mi.sp)  {
                oldport = pudphead->source;
                newport = sport;
                pudphead->source = newport;
            } else if (mi.dp) {
                oldport = pudphead->dest;
                newport = dport;
                pudphead->dest = newport;
            }
            break;
        }
    }

    if(mi.sa ^ mi.da) {
        csum_replace4(&ipheader->check, oldaddr, newaddr);
        switch(ipheader->protocol) {
        case IPPROTO_TCP:
            inet_proto_csum_replace4(&ptcphead->check, skb, oldaddr, newaddr, 1);
            break;
        case IPPROTO_UDP:
            if (pudphead->check || skb->ip_summed == CHECKSUM_PARTIAL) {
                inet_proto_csum_replace4(&pudphead->check, skb, oldaddr, newaddr, 1);
                if (!pudphead->check)
                    pudphead->check = CSUM_MANGLED_0;
            }
            break;
        }
    }
    if(mi.sp ^ mi.dp) {
        switch(ipheader->protocol)  {
        case IPPROTO_UDP:
            if (pudphead->check || skb->ip_summed == CHECKSUM_PARTIAL)   {
                inet_proto_csum_replace2(&pudphead->check, skb, oldport, newport, 0);
                if (!pudphead->check)
                    pudphead->check = CSUM_MANGLED_0;
            }
            break;
        case IPPROTO_TCP:
            inet_proto_csum_replace2(&ptcphead->check, skb, oldport, newport, 0);
            break;
        }
    }
    return 1;
}

net_quadruplet get_quad_from_skb(const struct sk_buff* skb)
{
    struct iphdr *iphdr;
    net_quadruplet netquad;
    memset(&netquad, 0, sizeof(net_quadruplet));
    if (skb == NULL) return netquad;
    iphdr = ip_hdr(skb);
    if(iphdr == NULL) return netquad;
    netquad.saddr = iphdr->saddr;
    netquad.daddr = iphdr->daddr;
    netquad.valid = 1;
    switch (iphdr->protocol)
    {
    case IPPROTO_TCP: {
        struct tcphdr *th = (struct tcphdr *)((void *)iphdr + iphdr->ihl * 4);
        netquad.sport = th->source;
        netquad.dport = th->dest;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *uh = (struct udphdr *)((void *)iphdr + iphdr->ihl * 4);
        netquad.sport = uh->source;
        netquad.dport = uh->dest;
        break;
    }
    }
    return netquad;
}

int get_original_dest(struct sock *sk, int optval, void __user * user, int *len)
{
    struct inet_sock *inet;
    struct sockaddr_in *sin;
    if (strcmp(sk->sk_prot->name, "TCP")) return -ENOPROTOOPT;
    if ((unsigned int) *len < sizeof(struct sockaddr_in)) return -EINVAL;
    sin = kmalloc(sizeof(struct sockaddr_in), GFP_ATOMIC);
    if (!sin) return -ENOMEM;
    inet = (struct inet_sock *) sk;
    net_quadruplet n4 = { inet->inet_rcv_saddr, inet->inet_daddr, inet->inet_sport, inet->inet_dport, 1};
    if (lookup_dnat_table_and_getorigdst(&n4, sin) < 0) {
        kfree(sin);
        return -ENOENT;
    }
    sin->sin_family = AF_INET;
    if (copy_to_user(user, sin, sizeof(struct sockaddr_in)) != 0) {
        kfree(sin);
        return -EFAULT;
    }
    kfree(sin);
    return 0;
}

int get_orig_from_dnat_entry(const struct dnatted_table *dnt, const net_quadruplet * n4, struct sockaddr_in *sin)
{
    if (dnt->protocol != IPPROTO_TCP) return -1;
    if ((dnt->old_saddr == n4->daddr) && (dnt->new_daddr == n4->saddr) &&
        (dnt->old_sport == n4->dport) && (dnt->new_dport == n4->sport))
    {
        sin->sin_addr.s_addr = dnt->old_daddr;
        sin->sin_port = dnt->old_dport;
        return 1;
    }
    return -1;
}

int lookup_dnat_table_and_getorigdst(const net_quadruplet *n4, struct sockaddr_in *sin) {
    struct dnatted_table *dntmp;
    rcu_read_lock_bh();
    list_for_each_entry_rcu(dntmp, &root_dnatted_table.list, list) {
        if (get_orig_from_dnat_entry(dntmp, n4, sin) == 1) {
            rcu_read_unlock_bh();
            return 0;
        }
    }
    rcu_read_unlock_bh();
    return -1;
}

inline int private_address(__u32 addr)
{
    __u32 haddr = ntohl(addr);
    if ((haddr >= 0x0a000000) && (haddr <= 0x0affffff)) return 1;
    if ((haddr >= 0xac100000) && (haddr <= 0xac1fffff)) return 1;
    if ((haddr >= 0xc0a80000) && (haddr <= 0xc0a8ffff)) return 1;
    return 0;
}

inline int public_to_private_address(const struct sk_buff *skb, const ipfire_rule * ipfr) {
    struct iphdr* iphead = ip_hdr(skb);
    if(iphead == NULL) return -1;
    if (private_address(iphead->saddr)) return 0;
    if (private_address(ipfr->newaddr)) return 1;
    return 0;
}

int csum_error_message(const char *origin, int enum_code)
{
    IPFI_PRINTK("IPFIRE: %s: checksum error: %d\n", origin, enum_code);
    return -1;
}

int check_checksums(const struct sk_buff *skb)
{
    __u16 check;
    int datalen;
    struct iphdr *iph = ip_hdr(skb);
    if(iph == NULL) return -1;
    datalen = skb->len - iph->ihl * 4;
    check = iph->check;
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *) iph, iph->ihl);
    if (iph->check != check) return -BAD_IP_CSUM;
    switch (iph->protocol)
    {
    case IPPROTO_TCP: {
        if (skb->ip_summed != CHECKSUM_UNNECESSARY &&
            csum_tcpudp_magic(iph->saddr, iph->daddr, datalen, IPPROTO_TCP,
                              skb->ip_summed == CHECKSUM_COMPLETE ? skb->csum : skb_checksum(skb, iph->ihl * 4, datalen, 0)))
            return -BAD_TCPHEAD_CSUM;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
        if (!uh->check) return 0;
        if (csum_tcpudp_magic (iph->saddr, iph->daddr, datalen, IPPROTO_UDP,
                               skb->ip_summed == CHECKSUM_COMPLETE ? skb->csum : skb_checksum(skb, iph->ihl * 4, datalen, 0)))
            return -BAD_UDPHEAD_CSUM;
        break;
    }
    }
    return 0;
}

static struct nf_sockopt_ops so_getoriginal_dst = {
    .pf = PF_INET,
    .get_optmin = SO_IPFI_GETORIG_DST,
    .get_optmax = SO_IPFI_GETORIG_DST + 1,
    .get = &get_original_dest,
};

int init_translation(void)
{
    INIT_LIST_HEAD(&root_dnatted_table.list);
    INIT_LIST_HEAD(&root_snatted_table.list);
    hash_init(dnat_hashtable);
    hash_init(snat_hashtable);
    return nf_register_sockopt(&so_getoriginal_dst);
}

void fini_translation(void)
{
    free_dnatted_table();
    free_snatted_table();
    might_sleep();
    rcu_barrier();
    nf_unregister_sockopt(&so_getoriginal_dst);
}
